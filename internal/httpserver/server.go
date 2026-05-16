// Package httpserver wires the public HTTP surface for SealKeeper.
//
// Routes wired in this skeleton:
//
//	GET  /healthz                 — liveness, no dependencies
//	GET  /readyz                  — readiness aggregate (DB ping etc.)
//	GET  /metrics                 — Prometheus exposition (optional bearer)
//	GET  /version                 — build metadata
//	GET  /                        — landing page (HTML stub)
//	POST /api/v1/request          — issue a reveal token + capture/send mail
//	GET  /api/v1/policy           — public policy; single-use consumption
//	                                when ?token=… is supplied (FR-B.36)
//	GET  /reveal/{token}          — reveal page HTML (loads UMD bundle)
//	GET  /static/*                — JS bundle + assets (config.WebDir)
//	GET  /__captured_mail         — eval-only mail queue
package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/policy"
	"github.com/sched75/sealkeeper/internal/ratelimit"
	"github.com/sched75/sealkeeper/internal/readiness"
	"github.com/sched75/sealkeeper/internal/tokens"
	"github.com/sched75/sealkeeper/internal/version"
)

// Server is the HTTP service.
type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	readyz   *readiness.Set
	mail     *mailcapture.Store
	sender   mailer.Sender // never nil — defaults to capture in eval, noop otherwise
	tokens   *tokens.Repo  // optional — nil when storage is unavailable
	audit    *audit.Repo   // optional — nil when storage is unavailable
	limiter  ratelimit.Composite
	reqCount *prometheus.CounterVec
	reqDur   *prometheus.HistogramVec
	rateHits *prometheus.CounterVec
	registry *prometheus.Registry

	revealTpl *htmltemplate.Template

	adminRepo  *admin.Repo
	adminLabel string
	adminTpl   *htmltemplate.Template

	domains    *domains.Repo
	policies   *policies.Repo
	elevations *elevations.Repo
}

// New builds an HTTP server with the given configuration.
func New(cfg config.Config, logger *slog.Logger) *Server {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	reqCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sealkeeper_requests_total",
		Help: "Total HTTP requests handled, partitioned by route and status.",
	}, []string{"route", "status"})
	reqDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sealkeeper_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
	rateHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sealkeeper_rate_limit_hits_total",
		Help: "Number of rate-limited POST /api/v1/request hits.",
	}, []string{"dimension"})
	reg.MustRegister(reqCount, reqDur, rateHits)

	limiter := ratelimit.Composite{
		Email: ratelimit.New(cfg.RateLimitEmailPerHour, time.Hour),
		IP:    ratelimit.New(cfg.RateLimitIPPerHour, time.Hour),
	}

	mailStore := mailcapture.NewStore(100)
	// Default sender: in eval mode mails are captured for /__captured_mail;
	// in production with no SMTP wired we fall back to a no-op (the
	// SetSender call from main.go will replace this when SMTP is configured).
	var defaultSender mailer.Sender = mailer.NopSender{}
	if cfg.IsEval() {
		defaultSender = &mailer.CaptureSender{Store: mailStore}
	}

	return &Server{
		cfg:        cfg,
		logger:     logger,
		readyz:     readiness.New(),
		mail:       mailStore,
		sender:     defaultSender,
		limiter:    limiter,
		reqCount:   reqCount,
		reqDur:     reqDur,
		rateHits:   rateHits,
		registry:   reg,
		revealTpl:  htmltemplate.Must(htmltemplate.New("reveal").Parse(revealHTML)),
		adminLabel: cfg.InstanceDomain,
		adminTpl:   adminTpls,
	}
}

// MailStore returns the underlying mail capture store (eval mode).
func (s *Server) MailStore() *mailcapture.Store { return s.mail }

// Readiness returns the underlying readiness set.
func (s *Server) Readiness() *readiness.Set { return s.readyz }

// SetTokens binds the token repository. When nil, /api/v1/request returns a
// 503 — useful for tests that exercise the static surface only.
func (s *Server) SetTokens(repo *tokens.Repo) { s.tokens = repo }

// SetAudit binds the audit log writer. When nil, audit events are dropped
// (logged via slog instead) — useful for skeleton tests.
func (s *Server) SetAudit(repo *audit.Repo) { s.audit = repo }

// SetSender overrides the mail sender. When called with a CaptureSender that
// shares the server's MailStore the /__captured_mail endpoint stays in sync.
func (s *Server) SetSender(sender mailer.Sender) {
	if sender != nil {
		s.sender = sender
	}
}

// SetDomains binds the allowlist repo. When nil, every domain is accepted —
// matching the zero-config eval behaviour.
func (s *Server) SetDomains(repo *domains.Repo) { s.domains = repo }

// SetPolicies binds the policies + elevations repos used to resolve a
// request to a concrete PolicyDescriptor. When both repos are nil the
// server keeps returning policy.Default() — handy for the zero-config eval
// pitch and the public smoke tests.
func (s *Server) SetPolicies(p *policies.Repo, e *elevations.Repo) {
	s.policies = p
	s.elevations = e
}

// Limiter exposes the composite limiter so callers can pre-warm it or read
// its current state (operator endpoints in a future module).
func (s *Server) Limiter() ratelimit.Composite { return s.limiter }

// Router builds the chi router with all routes wired.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.instrumentation)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealthz)
	r.Method(http.MethodGet, "/readyz", s.readyz.Handler(2*time.Second))
	r.Method(http.MethodGet, "/metrics", s.metricsHandler())
	r.Get("/version", s.handleVersion)
	r.Get("/", s.handleRoot)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/policy", s.handlePolicy)
		r.Post("/request", s.handleRequest)
	})

	r.Get("/reveal/{token}", s.handleRevealPage)

	if s.cfg.WebDir != "" {
		fs := http.FileServer(http.Dir(s.cfg.WebDir))
		r.Handle("/static/*", http.StripPrefix("/static/", noListing(fs)))
	}

	if s.cfg.IsEval() {
		r.Method(http.MethodGet, "/__captured_mail", s.mail.Handler())
	}

	if s.adminRepo != nil {
		s.registerAdminRoutes(r)
	}

	return r
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("http server starting", "addr", s.cfg.Listen, "mode", string(s.cfg.Mode))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.logger.Info("http server shutting down")
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// ----- handlers -------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_date": version.BuildDate,
		"go":         version.GoVersion(),
		"mode":       string(s.cfg.Mode),
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	banner := ""
	if s.cfg.IsEval() {
		banner = `<div style="background:#f59e0b;color:#111;padding:0.5em 1em;font-family:system-ui">⚠ Evaluation mode — not for production</div>`
	}
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SealKeeper</title></head>
<body>` + banner + `
<main style="font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem">
<h1>SealKeeper ` + version.Version + `</h1>
<p>Request a password by emailing yourself a one-shot reveal link.</p>
<form method="POST" action="/api/v1/request" onsubmit="return submitRequest(event)">
  <label>Your professional email:
    <input type="email" name="email" required autocomplete="off" style="margin-left:0.5rem;padding:0.4em">
  </label>
  <button type="submit" style="margin-left:0.5rem;padding:0.5em 1em">Generate a password</button>
</form>
<p id="ack" style="margin-top:1rem;color:#374151"></p>
<details style="margin-top:2rem"><summary>Operator endpoints</summary>
<ul>
  <li><a href="/healthz">/healthz</a></li>
  <li><a href="/readyz">/readyz</a></li>
  <li><a href="/metrics">/metrics</a></li>
  <li><a href="/api/v1/policy">/api/v1/policy</a></li>
  <li><a href="/version">/version</a></li>
</ul></details>
<script>
async function submitRequest(ev){
  ev.preventDefault();
  const email = ev.target.email.value;
  await fetch('/api/v1/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email})});
  document.getElementById('ack').textContent = 'If this address is authorised, an email is on its way. Check your inbox.';
  return false;
}
</script>
</main></body></html>`))
}

type requestPayload struct {
	Email   string `json:"email"`
	Domain  string `json:"domain"`
	Subject string `json:"subject"`
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// FR-B.7 invariant — every code path below returns the SAME 202 body.
	// Failure information stays in the audit log, never in the response.
	acceptedResp := func(extra map[string]string) {
		body := map[string]string{"status": "accepted"}
		for k, v := range extra {
			body[k] = v
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(body)
	}

	var p requestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		// Malformed payload is the one case we DO surface — it cannot leak
		// allowlist info and helps integrators debug client code.
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
		return
	}
	if p.Email == "" {
		http.Error(w, `{"error":"email_required"}`, http.StatusBadRequest)
		return
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	email := strings.ToLower(strings.TrimSpace(p.Email))
	ip := clientIP(r)
	ipHash := hashShort(ip)
	uaHash := hashShort(r.UserAgent())

	// FR-B.11..13 — apply rate limits BEFORE issuing anything. The hit is
	// observable only via the audit log + Prometheus counter.
	decision := s.limiter.Check(email, ip)
	if !decision.Allowed {
		s.rateHits.WithLabelValues(decision.Reason).Inc()
		s.auditAppend(r.Context(), audit.EventRateLimited, email, decision.Reason, map[string]any{
			"ip_hash": ipHash,
			"ua_hash": uaHash,
			"limit_email_per_hour": s.cfg.RateLimitEmailPerHour,
			"limit_ip_per_hour":    s.cfg.RateLimitIPPerHour,
		})
		s.logger.Info("rate-limited request silently dropped",
			"email", email, "dimension", decision.Reason,
		)
		acceptedResp(nil) // identical response — FR-B.13
		return
	}

	// FR-C.20..23 — consult the domain allowlist when it has any entries.
	// An empty table keeps the zero-config eval flow open. A denied domain
	// is FR-B.9-silent: same response, audit log carries the truth.
	if s.domains != nil {
		emailDomain := ""
		if at := strings.LastIndex(email, "@"); at > 0 && at+1 < len(email) {
			emailDomain = email[at+1:]
		}
		ok, err := s.domains.Allows(r.Context(), emailDomain)
		if err != nil {
			s.logger.Error("domains.Allows failed", "err", err)
			// Fail-safe: deny silently so a database hiccup can't open the gate.
			acceptedResp(nil)
			return
		}
		if !ok {
			s.auditAppend(r.Context(), "request.domain_blocked", email, emailDomain, map[string]any{
				"ip_hash": ipHash,
				"ua_hash": uaHash,
			})
			s.logger.Info("domain not in allowlist — silent drop",
				"email", email, "domain", emailDomain,
			)
			acceptedResp(nil) // FR-B.13
			return
		}
	}

	// FR-C.27..28 — resolve a policy NOW so we never mint a token that
	// nobody can consume. The resolution honours the elevation lists and
	// the per-(domain, level) policy mapping.
	//
	// Zero-config fallback: when no policies are configured, skip the gate
	// entirely and let handlePolicy serve the built-in Default. The moment
	// the admin adds a row the gate activates.
	if s.policies != nil {
		count, err := s.policies.Count(r.Context())
		if err != nil {
			s.logger.Error("policies.Count failed", "err", err)
			acceptedResp(nil)
			return
		}
		if count > 0 {
			if _, err := s.policies.Resolve(r.Context(), email); errors.Is(err, policies.ErrNoPolicy) {
				s.auditAppend(r.Context(), "request.policy_not_found", email, "", map[string]any{
					"ip_hash": ipHash,
					"ua_hash": uaHash,
				})
				s.logger.Info("no policy resolved for email — silent drop", "email", email)
				acceptedResp(nil) // FR-B.13
				return
			} else if err != nil {
				s.logger.Error("policies.Resolve failed", "err", err)
				acceptedResp(nil) // fail-safe deny
				return
			}
		}
	}

	tok, err := s.tokens.Issue(r.Context(), tokens.IssueOptions{
		Email:  email,
		Domain: p.Domain,
		IPHash: ipHash,
		UAHash: uaHash,
		TTL:    tokens.DefaultTTL,
	})
	if err != nil {
		s.logger.Error("tokens.Issue failed", "err", err)
		s.auditAppend(r.Context(), "request.issue_failed", email, "", map[string]any{
			"error": err.Error(),
		})
		// Still return 202 — anti-enumeration. The audit log carries the
		// truth for operators.
		acceptedResp(nil)
		return
	}

	revealURL := strings.TrimRight(s.cfg.BaseURL, "/") + "/reveal/" + tok.Token
	msg, err := mail.BuildReveal(mail.RevealInputs{
		To:              tok.Email,
		InstanceDomain:  s.cfg.InstanceDomain,
		RevealURL:       revealURL,
		ValidityMinutes: int(tokens.DefaultTTL / time.Minute),
	})
	if err != nil {
		s.logger.Error("mail.BuildReveal failed", "err", err)
		acceptedResp(nil)
		return
	}

	// Capture-with-callback lets us surface the eval-mode capture id without
	// the handler caring which Sender it is talking to.
	captureID := ""
	if cs, ok := s.sender.(*mailer.CaptureSender); ok {
		cs.CaptureIDCallback = func(id string) { captureID = id }
	}

	if err := s.sender.Send(r.Context(), msg); err != nil {
		s.logger.Error("mail send failed", "transport", s.sender.Name(), "err", err)
		s.auditAppend(r.Context(), "mail.send_failed", email, tok.Token, map[string]any{
			"transport": s.sender.Name(),
			"error":     err.Error(),
		})
		// FR-B.13 anti-enumeration: still acknowledge.
		acceptedResp(nil)
		return
	}

	s.auditAppend(r.Context(), audit.EventTokenIssued, email, tok.Token, map[string]any{
		"ip_hash":   ipHash,
		"ua_hash":   uaHash,
		"domain":    tok.Domain,
		"transport": s.sender.Name(),
	})

	extra := map[string]string{}
	if s.cfg.IsEval() && captureID != "" {
		extra["capture"] = captureID
		extra["debug_reveal_url"] = revealURL
	}
	acceptedResp(extra)
}

// auditAppend is a fire-and-forget audit helper. Errors are logged but never
// propagated — the audit log is best-effort during the request critical path.
func (s *Server) auditAppend(ctx context.Context, event, actor, target string, details map[string]any) {
	if s.audit == nil {
		return
	}
	if _, err := s.audit.Append(ctx, event, actor, target, details); err != nil {
		s.logger.Warn("audit.Append failed", "event", event, "err", err)
	}
}

// clientIP returns the best-guess client IP for a request. Honours
// X-Forwarded-For only when the immediate peer is within
// SK_TRUSTED_PROXY_CIDRS; otherwise uses r.RemoteAddr (FR-H.42).
//
// For v0.1 the trusted-proxy filter just trusts XFF when set — the strict
// CIDR check lands when the reverse-proxy middleware is wired in module D.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First entry is the originating client.
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	// r.RemoteAddr looks like "host:port".
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// handlePolicy serves /api/v1/policy. With ?token=… present, the token is
// consumed atomically and the policy is returned. Without a token, returns
// the default policy descriptor (for documentation / Swagger).
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	tokenParam := strings.TrimSpace(r.URL.Query().Get("token"))
	if tokenParam == "" {
		policy.Handler().ServeHTTP(w, r)
		return
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	tok, err := s.tokens.Consume(r.Context(), tokenParam, hashShort(r.RemoteAddr), hashShort(r.UserAgent()))
	switch {
	case errors.Is(err, tokens.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "token_not_found", "Unknown reveal token.")
		return
	case errors.Is(err, tokens.ErrExpired):
		writeJSONError(w, http.StatusGone, "token_expired", "Reveal link expired. Request a new one.")
		return
	case errors.Is(err, tokens.ErrConsumed):
		writeJSONError(w, http.StatusGone, "token_consumed", "Link already used. Request a new one if needed.")
		return
	case err != nil:
		s.logger.Error("tokens.Consume failed", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	resolved := s.resolvedPolicy(r.Context(), tok.Email)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy":     resolved,
		"expires_at": tok.ExpiresAt.Format(time.RFC3339),
		"issued_at":  tok.IssuedAt.Format(time.RFC3339),
	})
}

// resolvedPolicy returns the PolicyDescriptor for `email`. Falls back to the
// built-in default when no policy is configured yet (zero-config eval).
// The shape mirrors module A's PolicyDescriptor so the JS bundle in the
// reveal page can consume it without translation.
func (s *Server) resolvedPolicy(ctx context.Context, email string) map[string]any {
	if s.policies == nil {
		return policyDefaultMap()
	}
	row, err := s.policies.Resolve(ctx, email)
	if err != nil {
		return policyDefaultMap()
	}
	out := map[string]any{
		"id":               row.ID,
		"domain":           row.DomainName,
		"anssiLevel":       string(row.ANSSILevel),
		"generator":        string(row.Generator),
		"proposalCount":    row.ProposalCount,
		"regenerateLimit":  row.RegenerateLimit,
		"sessionTTLSec":    row.SessionTTLSeconds,
		"notifyOnConsult":  row.NotifyOnConsult,
	}
	// `parameters` is admin-supplied JSON — preserve it as-is.
	if len(row.Params) > 0 {
		var params any
		if err := json.Unmarshal(row.Params, &params); err == nil {
			out["parameters"] = params
		} else {
			out["parameters"] = map[string]any{}
		}
	} else {
		out["parameters"] = map[string]any{}
	}
	return out
}

func policyDefaultMap() map[string]any {
	def := policy.Default()
	return map[string]any{
		"version":          def.Version,
		"generators":       def.Generators,
		"min_entropy_bits": def.MinEntropy,
		"length":           def.Length,
		"levels":           def.Levels,
		"transforms":       def.Transforms,
		"updated_at":       def.UpdatedAt,
	}
}

// handleRevealPage serves the reveal HTML. The token is NOT consumed here —
// the user has to click "Décoder" first (FR-B.22). Token validity is
// previewed via tokens.Get so a clearly-expired link can show a polite
// "expired" page instead of revealing nothing.
func (s *Server) handleRevealPage(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	state := "ready"
	if s.tokens != nil {
		if tok, err := s.tokens.Get(r.Context(), token); err == nil {
			if tok.ConsumedAt != nil {
				state = "consumed"
			} else if !time.Now().Before(tok.ExpiresAt) {
				state = "expired"
			}
		} else if errors.Is(err, tokens.ErrNotFound) {
			state = "unknown"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = s.revealTpl.Execute(w, struct {
		Token      string
		State      string
		Version    string
		EvalBanner bool
	}{
		Token:      token,
		State:      state,
		Version:    version.Version,
		EvalBanner: s.cfg.IsEval(),
	})
}

func (s *Server) metricsHandler() http.Handler {
	base := promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{Registry: s.registry})
	if s.cfg.MetricsToken == "" {
		return base
	}
	expected := "Bearer " + s.cfg.MetricsToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Authorization"), expected) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		base.ServeHTTP(w, r)
	})
}

// ----- helpers --------------------------------------------------------------

func hashShort(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func writeJSONError(w http.ResponseWriter, code int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  slug,
		"status": code,
		"detail": detail,
	})
}

func noListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ----- middleware -----------------------------------------------------------

func (s *Server) instrumentation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = r.URL.Path
		}
		s.reqDur.WithLabelValues(route).Observe(time.Since(start).Seconds())
		s.reqCount.WithLabelValues(route, statusBucket(ww.Status())).Inc()
	})
}

func statusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// ----- reveal page template -------------------------------------------------

const revealHTML = `<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SealKeeper — Reveal</title>
<style>
  :root { font-family: system-ui, -apple-system, sans-serif; color-scheme: light dark; }
  body { max-width: 42rem; margin: 2rem auto; padding: 0 1rem; }
  .banner { background: #f59e0b; color: #111; padding: 0.5rem 1rem; }
  .card { border: 1px solid #d1d5db; border-radius: 0.5rem; padding: 1rem; margin: 0.75rem 0; }
  .pwd { font-family: ui-monospace, monospace; font-size: 1.15rem; word-break: break-all; }
  .badge { display:inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; background: #1d4ed8; color: white; font-size: 0.8rem; }
  button { padding: 0.5rem 1rem; border-radius: 0.375rem; border: 1px solid #1d4ed8; background: #1d4ed8; color: white; cursor: pointer; }
  button.secondary { background: transparent; color: #1d4ed8; }
  .err { color: #991b1b; }
  .gauge { height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; margin-top: 0.5rem; }
  .gauge > div { height: 100%; background: linear-gradient(90deg, #ef4444 0%, #f59e0b 50%, #10b981 100%); }
</style>
</head>
<body>
{{ if .EvalBanner }}<div class="banner">⚠ Evaluation mode — not for production</div>{{ end }}
<h1>SealKeeper {{ .Version }}</h1>

{{ if eq .State "expired" }}
  <p class="err">This reveal link has expired. Please request a new one.</p>
{{ else if eq .State "consumed" }}
  <p class="err">This reveal link has already been used. Request a new one if necessary.</p>
{{ else if eq .State "unknown" }}
  <p class="err">Unknown reveal link. Please request a new one.</p>
{{ else }}
  <p>Click the button below to reveal your password proposals. The link is single-use; once consumed it can no longer be re-opened.</p>
  <p><button id="decode-btn" type="button">Décoder</button></p>
  <div id="proposals" data-testid="proposals" hidden></div>
  <p id="error" class="err" hidden></p>
  <script src="/static/sealkeeper-generation.umd.js"></script>
  <script>
    const token = {{ .Token }};
    const btn = document.getElementById('decode-btn');
    const out = document.getElementById('proposals');
    const errEl = document.getElementById('error');

    btn.addEventListener('click', async () => {
      btn.disabled = true; btn.textContent = '…';
      try {
        const r = await fetch('/api/v1/policy?token=' + encodeURIComponent(token));
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          throw new Error(j.detail || ('HTTP ' + r.status));
        }
        const body = await r.json();
        const policy = body.policy ? body.policy : body;
        const wrapped = {
          generator: (policy.generators && policy.generators[1]) || 'G2',
          proposalCount: 5,
          parameters: {}
        };
        const proposals = await window.SealKeeper.Generation.generate(wrapped);
        out.hidden = false;
        out.innerHTML = proposals.map((p, i) => '<div class="card" data-testid="proposal">' +
          '<div class="pwd" data-testid="password">' + escapeHtml(p.password) + '</div>' +
          '<div><span class="badge" data-testid="anssi">' + p.anssiLevel + '</span> ' +
          '<small>' + p.entropyBits.toFixed(1) + ' bits</small></div>' +
          '<div class="gauge"><div style="width:' + Math.min(100, p.entropyBits) + '%"></div></div>' +
          '<p style="margin-top:0.5rem"><button type="button" class="secondary" data-copy="' + i + '">Copier</button></p>' +
          '</div>').join('');
        out.querySelectorAll('[data-copy]').forEach((b, i) => b.addEventListener('click', async () => {
          await navigator.clipboard.writeText(proposals[i].password);
          b.textContent = 'Copié';
          setTimeout(() => { b.textContent = 'Copier'; navigator.clipboard.writeText(''); }, 30000);
        }));
      } catch (e) {
        errEl.hidden = false;
        errEl.textContent = e.message || String(e);
      }
    });

    function escapeHtml(s){ return s.replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\'':'&#39;','"':'&quot;'}[c])); }
  </script>
{{ end }}
</body></html>`
