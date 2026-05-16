// Package httpserver wires the public HTTP surface for SealKeeper.
//
// At the skeleton stage this exposes the minimum required for the smoke tests
// in release.yml plus the operator endpoints from FR-D.49..52:
//
//	GET  /healthz                — liveness, no dependencies
//	GET  /readyz                 — readiness aggregate
//	GET  /metrics                — Prometheus exposition (optional bearer)
//	GET  /version                — build metadata
//	GET  /                       — landing page (HTML stub)
//	GET  /api/v1/policy          — public password policy JSON
//	POST /api/v1/request         — placeholder request endpoint (captures mail
//	                                in eval mode)
//	GET  /__captured_mail        — eval-only mail queue
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/policy"
	"github.com/sched75/sealkeeper/internal/readiness"
	"github.com/sched75/sealkeeper/internal/version"
)

// Server is the HTTP service.
type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	readyz    *readiness.Set
	mail      *mailcapture.Store
	reqCount  *prometheus.CounterVec
	reqDur    *prometheus.HistogramVec
	registry  *prometheus.Registry
}

// New builds an HTTP server wired with the given configuration.
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
	reg.MustRegister(reqCount, reqDur)

	s := &Server{
		cfg:      cfg,
		logger:   logger,
		readyz:   readiness.New(),
		mail:     mailcapture.NewStore(100),
		reqCount: reqCount,
		reqDur:   reqDur,
		registry: reg,
	}
	return s
}

// MailStore returns the underlying mail capture store (eval mode).
func (s *Server) MailStore() *mailcapture.Store { return s.mail }

// Readiness returns the underlying readiness set so callers can register
// subsystem checks.
func (s *Server) Readiness() *readiness.Set { return s.readyz }

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
		r.Get("/policy", policy.Handler())
		r.Post("/request", s.handleRequest)
	})

	if s.cfg.IsEval() {
		r.Method(http.MethodGet, "/__captured_mail", s.mail.Handler())
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
<p>The full UI is not part of this skeleton build. The HTTP surface is ready:</p>
<ul>
  <li><a href="/healthz">/healthz</a></li>
  <li><a href="/readyz">/readyz</a></li>
  <li><a href="/metrics">/metrics</a></li>
  <li><a href="/api/v1/policy">/api/v1/policy</a></li>
  <li><a href="/version">/version</a></li>
</ul>
</main></body></html>`))
}

type requestPayload struct {
	Email   string `json:"email"`
	Domain  string `json:"domain"`
	Subject string `json:"subject"`
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var p requestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
		return
	}
	if p.Email == "" {
		http.Error(w, `{"error":"email_required"}`, http.StatusBadRequest)
		return
	}

	id := "skeleton-request"
	if s.cfg.IsEval() {
		body := "Subject: " + p.Subject + "\nDomain: " + p.Domain + "\n\nA generated password would be delivered here."
		id = s.mail.Capture(p.Email, "Your SealKeeper password", body)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"capture": id,
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
