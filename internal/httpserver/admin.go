package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/totp"
)

// opaqueToken returns n random bytes encoded as URL-safe base64 (no padding).
func opaqueToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// adminConstantTime is the minimum wall-clock cost of POST /admin/login.
// FR-C.9 — pad fast paths so success / failure / "not found" look identical
// to a stopwatch attacker.
const adminConstantTime = 300 * time.Millisecond

const (
	cookieAdminSession = "sk_admin_session"
	cookieAdminCSRF    = "sk_admin_csrf"
	cookieLoginCSRF    = "sk_admin_login_csrf"
)

// SetAdmin binds the admin repo + cryptobox. /admin/* routes only mount when
// this has been called.
func (s *Server) SetAdmin(repo *admin.Repo, instanceLabel string) {
	s.adminRepo = repo
	if instanceLabel != "" {
		s.adminLabel = instanceLabel
	} else {
		s.adminLabel = s.cfg.InstanceDomain
	}
}

func (s *Server) registerAdminRoutes(r chi.Router) {
	r.Route("/admin", func(r chi.Router) {
		r.Get("/", s.handleAdminRoot)
		r.Get("/login", s.handleAdminLoginGet)
		r.Post("/login", s.handleAdminLoginPost)
		r.Post("/logout", s.handleAdminLogout)
		r.Group(func(r chi.Router) {
			r.Use(s.adminRequireSession)
			r.Get("/setup", s.handleAdminSetupGet)
			r.Post("/setup", s.handleAdminSetupPost)
			r.Get("/dashboard", s.handleAdminDashboard)
			r.Get("/audit", s.handleAdminAudit)
			r.Get("/captured-mail", s.handleAdminCapturedMail)
			r.Get("/domains", s.handleAdminDomains)
			r.Post("/domains/add", s.handleAdminDomainAdd)
			r.Post("/domains/{id}/toggle", s.handleAdminDomainToggle)
			r.Post("/domains/{id}/delete", s.handleAdminDomainDelete)
			r.Get("/policies", s.handleAdminPolicies)
			r.Post("/policies/add", s.handleAdminPolicyAdd)
			r.Post("/policies/{id}/toggle", s.handleAdminPolicyToggle)
			r.Post("/policies/{id}/delete", s.handleAdminPolicyDelete)
			r.Get("/elevations", s.handleAdminElevations)
			r.Post("/elevations/add", s.handleAdminElevationAdd)
			r.Post("/elevations/{id}/delete", s.handleAdminElevationDelete)
			r.Get("/libraries", s.handleAdminLibraries)
			r.Post("/libraries/upload", s.handleAdminLibraryUpload)
			r.Get("/libraries/{id}/download", s.handleAdminLibraryDownload)
			r.Get("/libraries/{id}/sample", s.handleAdminLibrarySample)
			r.Post("/libraries/{id}/delete", s.handleAdminLibraryDelete)
			r.Get("/templates", s.handleAdminTemplates)
			r.Get("/templates/edit", s.handleAdminTemplateEdit)
			r.Post("/templates/save", s.handleAdminTemplateSave)
			r.Post("/templates/preview", s.handleAdminTemplatePreview)
			r.Post("/templates/reset", s.handleAdminTemplateReset)
			r.Get("/integrations", s.handleAdminIntegrations)
			r.Post("/integrations/add", s.handleAdminIntegrationAdd)
			r.Post("/integrations/{id}/toggle", s.handleAdminIntegrationToggle)
			r.Post("/integrations/{id}/delete", s.handleAdminIntegrationDelete)
			r.Post("/integrations/{id}/test", s.handleAdminIntegrationTest)
			r.Get("/branding", s.handleAdminBranding)
			r.Post("/branding/save", s.handleAdminBrandingSave)
			r.Post("/branding/logo", s.handleAdminBrandingLogo)
			r.Post("/branding/logo/clear", s.handleAdminBrandingLogoClear)
		})
	})
}

// adminRequireSession is the gate for everything past /admin/login. It
// loads the session, redirects to /admin/login on miss, and forces the
// setup flow when password / TOTP enrollment is pending.
func (s *Server) adminRequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ad, err := s.loadAdminSession(r)
		if err != nil {
			s.clearAdminCookies(w)
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		// FR-C.3 / FR-C.4: until both bits clear, the only allowed route is
		// /admin/setup. Logout stays available so a stuck user can bail out.
		needsSetup := ad.ForcePasswordChange || ad.ForceTOTPEnroll
		if needsSetup && !strings.HasPrefix(r.URL.Path, "/admin/setup") {
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyAdmin, ad)
		ctx = context.WithValue(ctx, ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type adminCtxKey struct{ name string }

var (
	ctxKeyAdmin   = adminCtxKey{name: "admin"}
	ctxKeySession = adminCtxKey{name: "admin-session"}
)

func adminFromCtx(r *http.Request) (admin.Admin, admin.Session, bool) {
	a, _ := r.Context().Value(ctxKeyAdmin).(admin.Admin)
	s, _ := r.Context().Value(ctxKeySession).(admin.Session)
	return a, s, a.ID != 0
}

// ----- handlers -------------------------------------------------------------

func (s *Server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.loadAdminSession(r); err == nil {
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (s *Server) handleAdminLoginGet(w http.ResponseWriter, r *http.Request) {
	if s.adminRepo == nil {
		http.Error(w, "admin disabled (no storage)", http.StatusServiceUnavailable)
		return
	}
	csrf, _ := opaqueToken(24)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieLoginCSRF,
		Value:    csrf,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(15 * time.Minute),
	})
	s.renderAdmin(w, "login", map[string]any{
		"CSRF":       csrf,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Error":      r.URL.Query().Get("err"),
	})
}

func (s *Server) handleAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(adminConstantTime)
	defer func() {
		if rem := time.Until(deadline); rem > 0 {
			time.Sleep(rem)
		}
	}()

	if s.adminRepo == nil {
		http.Error(w, "admin disabled (no storage)", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminLoginError(w, r, "bad_form")
		return
	}
	if !s.checkLoginCSRF(r) {
		s.adminLoginError(w, r, "csrf")
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	totpCode := strings.TrimSpace(r.FormValue("totp"))

	res, err := s.adminRepo.Authenticate(r.Context(), email, password, totpCode)
	switch {
	case errors.Is(err, admin.ErrInvalidCreds):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "credentials"})
		s.adminLoginError(w, r, "bad_creds")
		return
	case errors.Is(err, admin.ErrAccountLocked):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "locked"})
		s.adminLoginError(w, r, "locked")
		return
	case errors.Is(err, admin.ErrAccountDisabled):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "disabled"})
		s.adminLoginError(w, r, "disabled")
		return
	case errors.Is(err, admin.ErrTOTPRequired):
		// First-stage submit with only email+password — re-render the form
		// asking for the TOTP code on top of the existing inputs.
		s.adminLoginError(w, r, "totp_required")
		return
	case err != nil:
		s.logger.Error("admin.Authenticate failed", "err", err)
		s.adminLoginError(w, r, "internal")
		return
	}

	sess, err := s.adminRepo.CreateSession(r.Context(), res.Admin.ID,
		hashShort(clientIP(r)), hashShort(r.UserAgent()))
	if err != nil {
		s.logger.Error("admin.CreateSession failed", "err", err)
		s.adminLoginError(w, r, "internal")
		return
	}
	s.setAdminCookies(w, sess)
	s.auditAppend(r.Context(), "admin.login", res.Admin.Email, "", map[string]any{
		"needs_setup": res.NeedsPasswordChange || res.NeedsTOTPEnrollment,
	})
	if res.NeedsPasswordChange || res.NeedsTOTPEnrollment {
		http.Redirect(w, r, "/admin/setup", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieAdminSession); err == nil {
		_ = s.adminRepo.RevokeSession(r.Context(), c.Value)
	}
	s.clearAdminCookies(w)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (s *Server) handleAdminSetupGet(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	secret, otpURL, codes := s.draftSetup(r)

	s.renderAdmin(w, "setup", map[string]any{
		"Admin":               a,
		"EvalBanner":          s.cfg.IsEval(),
		"Label":               s.adminLabel,
		"NeedsPasswordChange": a.ForcePasswordChange,
		"NeedsTOTP":           a.ForceTOTPEnroll,
		"Secret":              secret,
		"OtpauthURL":          otpURL,
		"RecoveryCodes":       codes,
		"CSRF":                s.requireSessionCSRF(r),
	})
}

func (s *Server) handleAdminSetupPost(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}

	// Step 1 — password change.
	if a.ForcePasswordChange {
		np := r.FormValue("new_password")
		conf := r.FormValue("new_password_confirm")
		if np == "" || np != conf {
			s.adminSetupError(w, r, "passwords_mismatch")
			return
		}
		if err := s.adminRepo.ChangePassword(r.Context(), a.ID, np); err != nil {
			s.logger.Error("ChangePassword failed", "err", err)
			s.adminSetupError(w, r, "password_invalid")
			return
		}
		s.auditAppend(r.Context(), "admin.password_changed", a.Email, "", nil)
	}

	// Step 2 — TOTP enrollment + verify a fresh code so we know the user
	// scanned the QR successfully.
	if a.ForceTOTPEnroll {
		secretStr := strings.TrimSpace(r.FormValue("totp_secret"))
		code := strings.TrimSpace(r.FormValue("totp_code"))
		codesRaw := strings.TrimSpace(r.FormValue("recovery_codes"))
		if secretStr == "" || code == "" {
			s.adminSetupError(w, r, "totp_required")
			return
		}
		ok, err := totp.Verify(totp.Secret(secretStr), code, time.Now())
		if err != nil || !ok {
			s.adminSetupError(w, r, "totp_invalid")
			return
		}
		codes := strings.Split(codesRaw, ",")
		if err := s.adminRepo.EnrollTOTP(r.Context(), a.ID, totp.Secret(secretStr), codes); err != nil {
			s.logger.Error("EnrollTOTP failed", "err", err)
			s.adminSetupError(w, r, "internal")
			return
		}
		s.auditAppend(r.Context(), "admin.totp_enrolled", a.Email, "", nil)
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	count := int64(0)
	if s.audit != nil {
		count, _ = s.audit.Count(r.Context())
	}
	s.renderAdmin(w, "dashboard", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"AuditCount": count,
		"CSRF":       sess.CSRFToken,
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.audit == nil || s.adminRepo == nil {
		http.Error(w, "audit not wired", http.StatusServiceUnavailable)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50

	rows, err := s.adminRepo.DB().QueryContext(r.Context(),
		`SELECT sequence_no, occurred_at, event_type,
		 COALESCE(actor, ''), COALESCE(target, ''), details_json
		 FROM audit_log
		 ORDER BY sequence_no DESC
		 LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("audit query failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type entry struct {
		SequenceNo int64
		Occurred   string
		EventType  string
		Actor      string
		Target     string
		Details    string
	}
	var items []entry
	for rows.Next() {
		var e entry
		var occurred any
		if err := rows.Scan(&e.SequenceNo, &occurred, &e.EventType, &e.Actor, &e.Target, &e.Details); err != nil {
			continue
		}
		e.Occurred = fmt.Sprintf("%v", occurred)
		items = append(items, e)
	}

	chainOK := true
	if bad, _ := s.audit.VerifyChain(r.Context()); bad != 0 {
		chainOK = false
	}

	s.renderAdmin(w, "audit", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      items,
		"Page":       page,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"ChainOK":    chainOK,
	})
}

// ----- domains --------------------------------------------------------------

func (s *Server) handleAdminDomains(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.domains == nil {
		http.Error(w, "domains repo not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.domains.List(r.Context())
	if err != nil {
		s.logger.Error("domains.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "domains", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"Error":      r.URL.Query().Get("err"),
		"OK":         r.URL.Query().Get("ok"),
	})
}

func (s *Server) handleAdminDomainAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	name := r.FormValue("name")
	description := r.FormValue("description")
	active := r.FormValue("active") == "on"

	d, err := s.domains.Create(r.Context(), name, description, active, &a.ID)
	switch {
	case errors.Is(err, domains.ErrInvalidName):
		http.Redirect(w, r, "/admin/domains?err=invalid_name", http.StatusSeeOther)
		return
	case errors.Is(err, domains.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/domains?err=already_exists", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("domains.Create failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "domain.created", a.Email, d.Name, map[string]any{
		"id":     d.ID,
		"active": d.Active,
	})
	http.Redirect(w, r, "/admin/domains?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminDomainToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d, err := s.domains.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/domains?err=not_found", http.StatusSeeOther)
		return
	}
	next := !d.Active
	if err := s.domains.SetActive(r.Context(), id, next); err != nil {
		s.logger.Error("domains.SetActive failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	event := "domain.disabled"
	if next {
		event = "domain.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, d.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/domains?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminDomainDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d, err := s.domains.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/domains?err=not_found", http.StatusSeeOther)
		return
	}
	// FR-C.24 double-confirmation: the form must echo the domain name in a
	// `confirm` field so a stray click does not nuke a row.
	if strings.TrimSpace(r.FormValue("confirm")) != d.Name {
		http.Redirect(w, r, "/admin/domains?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.domains.Delete(r.Context(), id); err != nil {
		s.logger.Error("domains.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "domain.deleted", a.Email, d.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/domains?ok=deleted", http.StatusSeeOther)
}

// ----- policies -------------------------------------------------------------

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.policies == nil || s.domains == nil {
		http.Error(w, "policies not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.policies.ListAll(r.Context())
	if err != nil {
		s.logger.Error("policies.ListAll failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	doms, _ := s.domains.List(r.Context())
	s.renderAdmin(w, "policies", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"Domains":    doms,
		"CSRF":       sess.CSRFToken,
		"Error":      r.URL.Query().Get("err"),
		"OK":         r.URL.Query().Get("ok"),
	})
}

func (s *Server) handleAdminPolicyAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	in := policies.CreateInputs{
		DomainID:          domainID,
		ANSSILevel:        elevations.Level(strings.TrimSpace(r.FormValue("anssi_level"))),
		Name:              r.FormValue("name"),
		Generator:         policies.Generator(strings.TrimSpace(r.FormValue("generator"))),
		ParamsJSON:        r.FormValue("params_json"),
		ProposalCount:     atoiOr(r.FormValue("proposal_count"), 5),
		RegenerateLimit:   atoiOr(r.FormValue("regenerate_limit"), 3),
		SessionTTLSeconds: atoiOr(r.FormValue("session_ttl_seconds"), 900),
		NotifyOnConsult:   r.FormValue("notify_on_consult") == "on",
		Active:            r.FormValue("active") == "on",
	}
	p, err := s.policies.Create(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, policies.ErrInvalidShape):
		http.Redirect(w, r, "/admin/policies?err=invalid", http.StatusSeeOther)
		return
	case errors.Is(err, policies.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/policies?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("policies.Create failed", "err", err)
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "policy.created", a.Email, fmt.Sprintf("%d", p.ID), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
		"generator": string(p.Generator),
	})
	http.Redirect(w, r, "/admin/policies?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminPolicyToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := s.policies.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/policies?err=not_found", http.StatusSeeOther)
		return
	}
	next := !p.Active
	if err := s.policies.SetActive(r.Context(), id, next); err != nil {
		s.logger.Error("policies.SetActive failed", "err", err)
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	event := "policy.disabled"
	if next {
		event = "policy.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, fmt.Sprintf("%d", id), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
	})
	http.Redirect(w, r, "/admin/policies?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminPolicyDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := s.policies.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/policies?err=not_found", http.StatusSeeOther)
		return
	}
	confirm := strings.TrimSpace(r.FormValue("confirm"))
	if confirm != p.Name {
		http.Redirect(w, r, "/admin/policies?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.policies.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "policy.deleted", a.Email, fmt.Sprintf("%d", id), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
	})
	http.Redirect(w, r, "/admin/policies?ok=deleted", http.StatusSeeOther)
}

// ----- elevations -----------------------------------------------------------

func (s *Server) handleAdminElevations(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.elevations == nil || s.domains == nil {
		http.Error(w, "elevations not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.elevations.ListAll(r.Context())
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	doms, _ := s.domains.List(r.Context())
	s.renderAdmin(w, "elevations", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"Domains":    doms,
		"CSRF":       sess.CSRFToken,
		"Error":      r.URL.Query().Get("err"),
		"OK":         r.URL.Query().Get("ok"),
	})
}

func (s *Server) handleAdminElevationAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	level := elevations.Level(strings.TrimSpace(r.FormValue("level")))
	email := r.FormValue("email")
	reason := r.FormValue("reason")
	e, err := s.elevations.Create(r.Context(), domainID, email, level, reason, &a.ID)
	switch {
	case errors.Is(err, elevations.ErrInvalidLevel):
		http.Redirect(w, r, "/admin/elevations?err=invalid_level", http.StatusSeeOther)
		return
	case errors.Is(err, elevations.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/elevations?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("elevations.Create failed", "err", err)
		http.Redirect(w, r, "/admin/elevations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "elevation.created", a.Email, e.Email, map[string]any{
		"domain_id": e.DomainID,
		"level":     string(e.Level),
	})
	http.Redirect(w, r, "/admin/elevations?ok=added", http.StatusSeeOther)
}

func (s *Server) handleAdminElevationDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	e, err := s.elevations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/elevations?err=not_found", http.StatusSeeOther)
		return
	}
	if err := s.elevations.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/elevations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "elevation.deleted", a.Email, e.Email, map[string]any{
		"domain_id": e.DomainID,
		"level":     string(e.Level),
	})
	http.Redirect(w, r, "/admin/elevations?ok=removed", http.StatusSeeOther)
}

func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return def
}

// ----- libraries ------------------------------------------------------------

func (s *Server) handleAdminLibraries(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.libraries.List(r.Context())
	if err != nil {
		s.logger.Error("libraries.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "libraries", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"Error":      r.URL.Query().Get("err"),
		"OK":         r.URL.Query().Get("ok"),
		"Details":    r.URL.Query().Get("details"),
	})
}

const adminMaxLibraryBytes = 32 * 1024 * 1024 // 32 MB hard ceiling

func (s *Server) handleAdminLibraryUpload(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxLibraryBytes)
	if err := r.ParseMultipartForm(adminMaxLibraryBytes); err != nil {
		http.Redirect(w, r, "/admin/libraries?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	kind := libraries.Kind(strings.TrimSpace(r.FormValue("kind")))
	name := r.FormValue("name")
	language := r.FormValue("language")
	description := r.FormValue("description")

	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/admin/libraries?err=no_file", http.StatusSeeOther)
		return
	}
	defer file.Close()

	lib, report, err := s.libraries.Upload(r.Context(), libraries.UploadInputs{
		Name:        name,
		Kind:        kind,
		Language:    language,
		Description: description,
		Content:     file,
		AdminID:     &a.ID,
	})
	switch {
	case errors.Is(err, libraries.ErrAlreadyExists):
		s.auditAppend(r.Context(), "library.duplicate_upload", a.Email, lib.SHA256, map[string]any{
			"existing_id":   lib.ID,
			"existing_name": lib.Name,
		})
		http.Redirect(w, r, "/admin/libraries?err=duplicate&details="+lib.Name, http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrInvalidEncoding):
		http.Redirect(w, r, "/admin/libraries?err=encoding", http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrEmptyFile):
		http.Redirect(w, r, "/admin/libraries?err=empty", http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrUnknownKind):
		http.Redirect(w, r, "/admin/libraries?err=kind", http.StatusSeeOther)
		return
	case err != nil && report.HasErrors():
		// Format the first error so the admin can fix the file.
		detail := url.QueryEscape(report.FirstErrors[0].Error())
		http.Redirect(w, r, "/admin/libraries?err=validation&details="+detail, http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("libraries.Upload failed", "err", err)
		http.Redirect(w, r, "/admin/libraries?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "library.uploaded", a.Email, lib.SHA256, map[string]any{
		"id":         lib.ID,
		"kind":       string(lib.Kind),
		"language":   lib.Language,
		"entries":    lib.EntryCount,
		"size_bytes": lib.SizeBytes,
		"filename":   hdr.Filename,
	})
	msg := "uploaded"
	if len(report.Warnings) > 0 {
		msg = "uploaded_with_warnings"
	}
	http.Redirect(w, r, "/admin/libraries?ok="+msg, http.StatusSeeOther)
}

func (s *Server) handleAdminLibraryDownload(w http.ResponseWriter, r *http.Request) {
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, rc, err := s.libraries.Open(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s-%s.txt"`, lib.Kind, lib.Name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleAdminLibrarySample(w http.ResponseWriter, r *http.Request) {
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, sample, err := s.libraries.Sample(r.Context(), id, 10)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      lib.ID,
		"name":    lib.Name,
		"kind":    string(lib.Kind),
		"entries": sample,
		"count":   lib.EntryCount,
	})
}

func (s *Server) handleAdminLibraryDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, err := s.libraries.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/libraries?err=not_found", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != lib.Name {
		http.Redirect(w, r, "/admin/libraries?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	switch err := s.libraries.Delete(r.Context(), id); {
	case errors.Is(err, libraries.ErrSystemReadOnly):
		http.Redirect(w, r, "/admin/libraries?err=system_readonly", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("libraries.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/libraries?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "library.deleted", a.Email, lib.SHA256, map[string]any{
		"id":   lib.ID,
		"name": lib.Name,
	})
	http.Redirect(w, r, "/admin/libraries?ok=deleted", http.StatusSeeOther)
}

// ----- mail templates -------------------------------------------------------

func (s *Server) handleAdminTemplates(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.mailTpls == nil {
		http.Error(w, "mail templates not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.mailTpls.List(r.Context())
	if err != nil {
		s.logger.Error("mailtemplates.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "templates", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"OK":         r.URL.Query().Get("ok"),
		"Error":      r.URL.Query().Get("err"),
	})
}

func (s *Server) handleAdminTemplateEdit(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.mailTpls == nil {
		http.Error(w, "mail templates not wired", http.StatusServiceUnavailable)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.URL.Query().Get("kind")))
	lang := strings.TrimSpace(r.URL.Query().Get("language"))
	tpl, err := s.mailTpls.Get(r.Context(), kind, lang)
	if err != nil {
		http.Redirect(w, r, "/admin/templates?err=not_found", http.StatusSeeOther)
		return
	}
	s.renderAdmin(w, "template_edit", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"CSRF":       sess.CSRFToken,
		"Template":   tpl,
		"Vars":       templateVarsDocumentation(),
		"OK":         r.URL.Query().Get("ok"),
		"Error":      r.URL.Query().Get("err"),
		"Preview":    "",
	})
}

func (s *Server) handleAdminTemplateSave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	subject := r.FormValue("subject")
	text := r.FormValue("text_body")
	html := r.FormValue("html_body")

	if err := s.mailTpls.Upsert(r.Context(), kind, lang, subject, text, html, &a.ID); err != nil {
		if errors.Is(err, mailtemplates.ErrParse) {
			http.Redirect(w, r, fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&err=%s",
				kind, lang, url.QueryEscape(err.Error())), http.StatusSeeOther)
			return
		}
		s.logger.Error("mailtemplates.Upsert failed", "err", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&err=internal",
			kind, lang), http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "template.saved", a.Email,
		fmt.Sprintf("%s/%s", kind, lang), map[string]any{"kind": string(kind), "language": lang})
	http.Redirect(w, r,
		fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&ok=saved", kind, lang),
		http.StatusSeeOther)
}

func (s *Server) handleAdminTemplatePreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	subject := r.FormValue("subject")
	text := r.FormValue("text_body")
	html := r.FormValue("html_body")

	if err := mailtemplates.ValidateTemplates(subject, text, html); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse_failed", err.Error())
		return
	}

	rendered, rerr := renderInline(kind, lang, subject, text, html, samplePreviewVars(s.adminLabel))
	if rerr != nil {
		writeJSONError(w, http.StatusBadRequest, "render_failed", rerr.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":  rendered.Subject,
		"text":     rendered.Text,
		"html":     rendered.HTML,
		"kind":     string(rendered.Kind),
		"language": rendered.Language,
	})
}

func (s *Server) handleAdminTemplateReset(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	if err := s.mailTpls.Reset(r.Context(), kind, lang); err != nil {
		s.logger.Error("mailtemplates.Reset failed", "err", err)
		http.Redirect(w, r, "/admin/templates?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "template.reset", a.Email,
		fmt.Sprintf("%s/%s", kind, lang), map[string]any{"kind": string(kind), "language": lang})
	http.Redirect(w, r,
		fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&ok=reset", kind, lang),
		http.StatusSeeOther)
}

// renderInline mirrors mailtemplates.Repo.Render but takes raw template
// sources instead of a stored row — handy for the live preview form.
func renderInline(kind mailtemplates.Kind, lang, subject, text, html string, vars mailtemplates.Vars) (mailtemplates.Rendered, error) {
	// Reuse mailtemplates' validation + rendering by faking a Template row.
	tpl := mailtemplates.Template{Kind: kind, Language: lang, Subject: subject, Text: text, HTML: html}
	return mailtemplates.RenderTemplate(tpl, vars)
}

func samplePreviewVars(instance string) mailtemplates.Vars {
	return mailtemplates.Vars{
		RevealURL:          "https://example.com/reveal/preview-token-deadbeef",
		UserEmail:          "preview@example.com",
		ExpiresAt:          time.Now().Add(15 * time.Minute),
		ValidityMinutes:    15,
		InstanceName:       instance,
		InstanceDomain:     instance,
		ContactURL:         "https://example.com/contact",
		ConsultedAt:        time.Now().Format(time.RFC3339),
		ConsultedIP:        "203.0.113.42",
		ConsultedUserAgent: "Mozilla/5.0 (preview)",
	}
}

func templateVarsDocumentation() []map[string]string {
	return []map[string]string{
		{"name": ".RevealURL", "doc": "Absolute URL the user clicks to land on /reveal/{token}."},
		{"name": ".UserEmail", "doc": "Recipient email address (lowercased)."},
		{"name": ".ExpiresAt", "doc": "Token expiry timestamp (time.Time)."},
		{"name": ".ValidityMinutes", "doc": "Convenience integer matching the TTL."},
		{"name": ".InstanceName", "doc": "Human label of this SealKeeper instance."},
		{"name": ".InstanceDomain", "doc": "Bare hostname (used in From:)."},
		{"name": ".ContactURL", "doc": "Optional support URL — wrap with `{{ if .ContactURL }}…{{ end }}`."},
		{"name": ".ConsultedAt", "doc": "RFC 3339 timestamp of a consultation (post-consultation template only)."},
		{"name": ".ConsultedIP", "doc": "Source IP of the consultation."},
		{"name": ".ConsultedUserAgent", "doc": "User-Agent of the consultation."},
	}
}

// ----- integrations ---------------------------------------------------------

func (s *Server) handleAdminIntegrations(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.integrations == nil {
		http.Error(w, "integrations not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.integrations.List(r.Context())
	if err != nil {
		s.logger.Error("integrations.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	stats := integrations.Stats{}
	if s.dispatcher != nil {
		stats = s.dispatcher.Stats()
	}
	s.renderAdmin(w, "integrations", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"Stats":      stats,
		"OK":         r.URL.Query().Get("ok"),
		"Error":      r.URL.Query().Get("err"),
		"Details":    r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminIntegrationAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	in := integrations.CreateInputs{
		Name:        r.FormValue("name"),
		Kind:        integrations.Kind(strings.TrimSpace(r.FormValue("kind"))),
		Enabled:     r.FormValue("enabled") == "on",
		ConfigJSON:  r.FormValue("config_json"),
		FiltersJSON: r.FormValue("filters_json"),
	}
	row, err := s.integrations.Create(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, integrations.ErrInvalidKind):
		http.Redirect(w, r, "/admin/integrations?err=invalid_kind", http.StatusSeeOther)
		return
	case errors.Is(err, integrations.ErrInvalidConfig):
		http.Redirect(w, r,
			"/admin/integrations?err=invalid_config&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	case errors.Is(err, integrations.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/integrations?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("integrations.Create failed", "err", err)
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.created", a.Email, row.Name, map[string]any{
		"id":   row.ID,
		"kind": string(row.Kind),
	})
	http.Redirect(w, r, "/admin/integrations?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	next := !row.Enabled
	if err := s.integrations.SetEnabled(r.Context(), id, next); err != nil {
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	event := "integration.disabled"
	if next {
		event = "integration.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, row.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/integrations?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != row.Name {
		http.Redirect(w, r, "/admin/integrations?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.integrations.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.deleted", a.Email, row.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/integrations?ok=deleted", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationTest(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	if err := integrations.TestSink(r.Context(), row, s.cfg.InstanceDomain); err != nil {
		s.auditAppend(r.Context(), "integration.test_failed", a.Email, row.Name, map[string]any{
			"error": err.Error(),
		})
		http.Redirect(w, r,
			"/admin/integrations?err=test_failed&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.test_ok", a.Email, row.Name, nil)
	http.Redirect(w, r, "/admin/integrations?ok=test_ok", http.StatusSeeOther)
}

// ----- branding -------------------------------------------------------------

const adminMaxLogoBytes = 256 * 1024 // mirrors branding.MaxLogoBytes

func (s *Server) handleAdminBranding(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.branding == nil {
		http.Error(w, "branding not wired", http.StatusServiceUnavailable)
		return
	}
	row, err := s.branding.Get(r.Context())
	if err != nil {
		s.logger.Error("branding.Get failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "branding", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"Label":      s.adminLabel,
		"Branding":   row,
		"CSRF":       sess.CSRFToken,
		"OK":         r.URL.Query().Get("ok"),
		"Error":      r.URL.Query().Get("err"),
		"Details":    r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminBrandingSave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	in := branding.UpdateInputs{
		InstanceName:   r.FormValue("instance_name"),
		PrimaryColor:   r.FormValue("primary_color"),
		SecondaryColor: r.FormValue("secondary_color"),
		TertiaryColor:  r.FormValue("tertiary_color"),
		ContactURL:     r.FormValue("contact_url"),
	}
	err := s.branding.Update(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, branding.ErrInvalidName):
		http.Redirect(w, r, "/admin/branding?err=invalid_name", http.StatusSeeOther)
		return
	case errors.Is(err, branding.ErrInvalidColor):
		http.Redirect(w, r,
			"/admin/branding?err=invalid_color&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("branding.Update failed", "err", err)
		http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "branding.updated", a.Email, "", map[string]any{
		"instance_name": in.InstanceName,
	})
	http.Redirect(w, r, "/admin/branding?ok=saved", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogo(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.branding == nil {
		http.Error(w, "branding not wired", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxLogoBytes+4*1024) // small slack for form headers
	if err := r.ParseMultipartForm(adminMaxLogoBytes); err != nil {
		http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	file, hdr, err := r.FormFile("logo")
	if err != nil {
		http.Redirect(w, r, "/admin/branding?err=no_file", http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, adminMaxLogoBytes+1))
	if err != nil {
		http.Redirect(w, r, "/admin/branding?err=read_failed", http.StatusSeeOther)
		return
	}
	if len(data) > adminMaxLogoBytes {
		http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		return
	}

	mime := hdr.Header.Get("Content-Type")
	if mime == "" {
		mime = http.DetectContentType(data)
	}
	// http.DetectContentType might miss SVG when the buffer starts with
	// whitespace; sniff for the literal '<svg' prefix as a fallback.
	if mime == "text/xml; charset=utf-8" || mime == "application/xml" {
		mime = "image/svg+xml"
	}

	if err := s.branding.SetLogo(r.Context(), mime, data, &a.ID); err != nil {
		switch {
		case errors.Is(err, branding.ErrInvalidLogo):
			http.Redirect(w, r, "/admin/branding?err=invalid_logo", http.StatusSeeOther)
		case errors.Is(err, branding.ErrLogoTooLarge):
			http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		default:
			s.logger.Error("branding.SetLogo failed", "err", err)
			http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		}
		return
	}
	s.auditAppend(r.Context(), "branding.logo_updated", a.Email, "", map[string]any{
		"mime":  mime,
		"bytes": len(data),
	})
	http.Redirect(w, r, "/admin/branding?ok=logo_uploaded", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogoClear(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.branding.ClearLogo(r.Context(), &a.ID); err != nil {
		http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "branding.logo_cleared", a.Email, "", nil)
	http.Redirect(w, r, "/admin/branding?ok=logo_cleared", http.StatusSeeOther)
}

func (s *Server) handleAdminCapturedMail(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if !s.cfg.IsEval() {
		http.Error(w, "captured-mail is only available in eval mode", http.StatusNotFound)
		return
	}
	items := s.mail.Snapshot()
	s.renderAdmin(w, "captured", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": true,
		"Label":      s.adminLabel,
		"Items":      items,
	})
}

// ----- helpers --------------------------------------------------------------

func (s *Server) loadAdminSession(r *http.Request) (admin.Session, admin.Admin, error) {
	if s.adminRepo == nil {
		return admin.Session{}, admin.Admin{}, errors.New("admin repo not wired")
	}
	c, err := r.Cookie(cookieAdminSession)
	if err != nil {
		return admin.Session{}, admin.Admin{}, err
	}
	return s.adminRepo.LookupSession(r.Context(), c.Value)
}

func (s *Server) setAdminCookies(w http.ResponseWriter, sess admin.Session) {
	secure := !s.cfg.IsEval()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminSession,
		Value:    sess.Token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Expires:  sess.ExpiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminCSRF,
		Value:    sess.CSRFToken,
		Path:     "/admin",
		HttpOnly: false, // readable by JS for header-based CSRF if we add an SPA later
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Expires:  sess.ExpiresAt,
	})
}

func (s *Server) clearAdminCookies(w http.ResponseWriter) {
	for _, name := range []string{cookieAdminSession, cookieAdminCSRF, cookieLoginCSRF} {
		http.SetCookie(w, &http.Cookie{
			Name:    name,
			Value:   "",
			Path:    "/admin",
			Expires: time.Unix(0, 0),
			MaxAge:  -1,
		})
	}
}

func (s *Server) checkLoginCSRF(r *http.Request) bool {
	c, err := r.Cookie(cookieLoginCSRF)
	if err != nil {
		return false
	}
	form := r.FormValue("csrf_token")
	return constantTimeEqualString(c.Value, form)
}

func (s *Server) checkSessionCSRF(r *http.Request) bool {
	c, err := r.Cookie(cookieAdminCSRF)
	if err != nil {
		return false
	}
	form := r.FormValue("csrf_token")
	if form == "" {
		form = r.Header.Get("X-CSRF-Token")
	}
	return constantTimeEqualString(c.Value, form)
}

func (s *Server) requireSessionCSRF(r *http.Request) string {
	if c, err := r.Cookie(cookieAdminCSRF); err == nil {
		return c.Value
	}
	return ""
}

func constantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// draftSetup builds the TOTP secret / otpauth / recovery codes shown on the
// setup page. Generated once per GET and embedded in the form so POST can
// commit them atomically.
func (s *Server) draftSetup(r *http.Request) (totp.Secret, string, []string) {
	a, _, _ := adminFromCtx(r)
	if !a.ForceTOTPEnroll {
		return "", "", nil
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.logger.Error("totp.NewSecret failed", "err", err)
		return "", "", nil
	}
	codes, err := totp.NewRecoveryCodes(8)
	if err != nil {
		s.logger.Error("totp.NewRecoveryCodes failed", "err", err)
		return "", "", nil
	}
	return secret, totp.Otpauth(secret, s.adminLabel, a.Email), codes
}

func (s *Server) adminLoginError(w http.ResponseWriter, r *http.Request, slug string) {
	q := "?err=" + slug
	if email := strings.TrimSpace(r.FormValue("email")); email != "" {
		q += "&email=" + email
	}
	http.Redirect(w, r, "/admin/login"+q, http.StatusSeeOther)
}

func (s *Server) adminSetupError(w http.ResponseWriter, r *http.Request, slug string) {
	http.Redirect(w, r, "/admin/setup?err="+slug, http.StatusSeeOther)
}

// renderAdmin executes the matching template against `data`.
func (s *Server) renderAdmin(w http.ResponseWriter, name string, data map[string]any) {
	if s.adminTpl == nil {
		http.Error(w, "admin templates not loaded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.adminTpl.ExecuteTemplate(w, name+".html", data); err != nil {
		s.logger.Error("admin template render failed", "name", name, "err", err)
	}
}

// ----- HTML templates -------------------------------------------------------

var adminTpls = htmltemplate.Must(htmltemplate.New("admin").Parse(adminBaseTpl + adminLoginTpl +
	adminSetupTpl + adminDashboardTpl + adminAuditTpl + adminCapturedTpl + adminDomainsTpl +
	adminPoliciesTpl + adminElevationsTpl + adminLibrariesTpl +
	adminTemplatesTpl + adminTemplateEditTpl + adminIntegrationsTpl + adminBrandingTpl))

const adminBaseTpl = `{{define "header"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SealKeeper admin — {{ .Label }}</title>
<style>
  :root { font-family: system-ui, -apple-system, sans-serif; color-scheme: light dark; }
  body { max-width: 60rem; margin: 1rem auto; padding: 0 1rem; }
  header { display: flex; align-items: center; gap: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid #d1d5db; margin-bottom: 1.5rem; }
  header h1 { margin: 0; font-size: 1.25rem; }
  nav a { margin-left: 1rem; text-decoration: none; color: #1d4ed8; }
  .banner { background: #f59e0b; color: #111; padding: 0.5rem 1rem; margin-bottom: 1rem; border-radius: 4px; }
  .err { background: #fee2e2; color: #991b1b; padding: 0.5rem 1rem; border-radius: 4px; margin-bottom: 1rem; }
  label { display: block; margin: 0.75rem 0 0.25rem; font-weight: 600; }
  input[type=email], input[type=password], input[type=text] { width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; }
  button { padding: 0.5rem 1rem; background: #1d4ed8; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }
  button.secondary { background: transparent; color: #1d4ed8; border: 1px solid #1d4ed8; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  code { font-family: ui-monospace, monospace; }
  pre { white-space: pre-wrap; word-break: break-all; background: #f3f4f6; padding: 0.5rem; border-radius: 4px; }
</style>
</head>
<body>
{{ if .EvalBanner }}<div class="banner">⚠ Evaluation mode — not for production</div>{{ end }}
<header>
  <h1>SealKeeper admin <small style="color:#6b7280">— {{ .Label }}</small></h1>
  {{ if .Admin }}<nav>
    <a href="/admin/dashboard">Dashboard</a>
    <a href="/admin/domains">Domains</a>
    <a href="/admin/policies">Policies</a>
    <a href="/admin/elevations">Elevations</a>
    <a href="/admin/libraries">Libraries</a>
    <a href="/admin/templates">Email templates</a>
    <a href="/admin/integrations">Integrations</a>
    <a href="/admin/branding">Branding</a>
    <a href="/admin/audit">Audit log</a>
    {{ if .EvalBanner }}<a href="/admin/captured-mail">Captured mail</a>{{ end }}
    <form method="POST" action="/admin/logout" style="display:inline;margin-left:1rem">
      <button type="submit" class="secondary">Logout {{ .Admin.Email }}</button>
    </form>
  </nav>{{ end }}
</header>
{{end}}

{{define "footer"}}
</body></html>
{{end}}
`

const adminLoginTpl = `{{define "login.html"}}{{template "header" .}}
<main>
<h2>Sign in</h2>
{{ if .Error }}<div class="err" data-testid="error">{{ .Error }}</div>{{ end }}
<form method="POST" action="/admin/login" data-testid="login-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autofocus autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <label for="totp">TOTP code <small>(omit on first sign-in)</small></label>
  <input id="totp" name="totp" type="text" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
  <p style="margin-top:1rem"><button type="submit">Sign in</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminSetupTpl = `{{define "setup.html"}}{{template "header" .}}
<main>
<h2>Account setup required</h2>
<p>Before you can use the console you must {{ if .NeedsPasswordChange }}change the bootstrap password{{ end }}{{ if and .NeedsPasswordChange .NeedsTOTP }} and {{ end }}{{ if .NeedsTOTP }}enrol an authenticator{{ end }}.</p>
<form method="POST" action="/admin/setup">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  {{ if .NeedsPasswordChange }}
  <fieldset><legend>New password</legend>
    <label for="np">New password (≥ 12 chars)</label>
    <input id="np" name="new_password" type="password" minlength="12" required autocomplete="new-password">
    <label for="np2">Confirm new password</label>
    <input id="np2" name="new_password_confirm" type="password" minlength="12" required autocomplete="new-password">
  </fieldset>
  {{ end }}
  {{ if .NeedsTOTP }}
  <fieldset style="margin-top:1.5rem"><legend>Authenticator (TOTP)</legend>
    <p>Scan the URL with your authenticator app, then enter the 6-digit code it displays.</p>
    <p><strong>Manual entry secret:</strong> <code data-testid="totp-secret">{{ .Secret }}</code></p>
    <p><strong>otpauth URL:</strong></p>
    <pre data-testid="otpauth">{{ .OtpauthURL }}</pre>
    <p><strong>Recovery codes (save these now — they will not be shown again):</strong></p>
    <ul data-testid="recovery-codes">{{ range .RecoveryCodes }}<li><code>{{ . }}</code></li>{{ end }}</ul>
    <input type="hidden" name="totp_secret" value="{{ .Secret }}">
    <input type="hidden" name="recovery_codes" value="{{ range $i, $c := .RecoveryCodes }}{{ if $i }},{{ end }}{{ $c }}{{ end }}">
    <label for="tc">Code from your authenticator</label>
    <input id="tc" name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{6}" required>
  </fieldset>
  {{ end }}
  <p style="margin-top:1rem"><button type="submit">Save and continue</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminDashboardTpl = `{{define "dashboard.html"}}{{template "header" .}}
<main>
<h2>Welcome, {{ .Admin.Email }}</h2>
<ul>
  <li>Audit log entries: <strong>{{ .AuditCount }}</strong></li>
  <li>Session expires: <code>{{ .Session.ExpiresAt }}</code></li>
  <li>Last login: <code>{{ if .Admin.LastLoginAt }}{{ .Admin.LastLoginAt }}{{ else }}—{{ end }}</code></li>
</ul>
<p>Configuration surfaces (domains, policies, libraries, SMTP, branding, templates, integrations) land in upcoming layers. The audit log and captured-mail viewers are wired today.</p>
</main>
{{template "footer" .}}{{end}}
`

const adminAuditTpl = `{{define "audit.html"}}{{template "header" .}}
<main>
<h2>Audit log{{ if not .ChainOK }} <span class="err" style="display:inline-block">⚠ chain integrity break</span>{{ end }}</h2>
<table><thead><tr><th>#</th><th>When (UTC)</th><th>Event</th><th>Actor</th><th>Target</th><th>Details</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .SequenceNo }}</td>
  <td><code>{{ .Occurred }}</code></td>
  <td><code>{{ .EventType }}</code></td>
  <td>{{ .Actor }}</td>
  <td><code>{{ .Target }}</code></td>
  <td><details><summary>view</summary><pre>{{ .Details }}</pre></details></td>
</tr>{{ else }}<tr><td colspan="6"><em>No entries yet.</em></td></tr>{{ end }}
</tbody></table>
<p style="margin-top:1rem">
  {{ if gt .PrevPage 0 }}<a href="/admin/audit?page={{ .PrevPage }}">← previous</a>{{ end }}
  <a href="/admin/audit?page={{ .NextPage }}" style="margin-left:1rem">next →</a>
</p>
</main>
{{template "footer" .}}{{end}}
`

const adminDomainsTpl = `{{define "domains.html"}}{{template "header" .}}
<main>
<h2>Allowed domains</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>An empty list keeps the public flow open (handy for eval). As soon as you add one entry the allowlist gates every <code>POST /api/v1/request</code>. Use <code>*.entreprise.com</code> to match any subdomain (does not match the bare apex).</p>

<table data-testid="domains-table"><thead><tr><th>Name</th><th>Description</th><th>Active</th><th>Created</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .Name }}</code></td>
  <td>{{ .Description }}</td>
  <td>{{ if .Active }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02 15:04 UTC" }}</code></td>
  <td>
    <form method="POST" action="/admin/domains/{{ .ID }}/toggle" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Active }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/domains/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="5"><em>No domains yet — the public flow accepts every recipient.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add a domain</h3>
<form method="POST" action="/admin/domains/add" data-testid="add-domain-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="name">Name (FQDN or <code>*.example.com</code>)</label>
  <input id="name" name="name" type="text" required>
  <label for="description">Description (optional)</label>
  <input id="description" name="description" type="text">
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="active" checked> Active immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add domain</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminPoliciesTpl = `{{define "policies.html"}}{{template "header" .}}
<main>
<h2>Policies</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>One policy per (domain, ANSSI level). When no policy is configured for an email's bucket the public flow drops the request silently (FR-B.13). Policies must reference an allowed domain — add one in <a href="/admin/domains">Domains</a> first.</p>

<table data-testid="policies-table"><thead><tr><th>Domain</th><th>Level</th><th>Name</th><th>Generator</th><th>N props</th><th>Active</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .DomainName }}</code></td>
  <td><span class="badge">{{ .ANSSILevel }}</span></td>
  <td>{{ .Name }}</td>
  <td><code>{{ .Generator }}</code></td>
  <td>{{ .ProposalCount }}</td>
  <td>{{ if .Active }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <form method="POST" action="/admin/policies/{{ .ID }}/toggle" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Active }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/policies/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="8"><em>No policies yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add a policy</h3>
<form method="POST" action="/admin/policies/add">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="domain_id">Domain</label>
  <select id="domain_id" name="domain_id" required>
    {{ range .Domains }}<option value="{{ .ID }}">{{ .Name }}</option>{{ else }}<option value="" disabled selected>(add a domain first)</option>{{ end }}
  </select>
  <label for="anssi_level">ANSSI level</label>
  <select id="anssi_level" name="anssi_level" required>
    <option value="B1">B1 — default (every user not elevated)</option>
    <option value="B2">B2 — elevated managers</option>
    <option value="B3">B3 — elevated system admins</option>
  </select>
  <label for="name">Name</label>
  <input id="name" name="name" type="text" required>
  <label for="generator">Generator</label>
  <select id="generator" name="generator" required>
    <option value="G1">G1 — citation + transforms (B1 target)</option>
    <option value="G2" selected>G2 — Diceware (B2 target)</option>
    <option value="G3">G3 — random alphanumeric (B3 target)</option>
  </select>
  <label for="params_json">Parameters (JSON)</label>
  <textarea id="params_json" name="params_json" rows="8" style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{
  "library": ["alpha","beta","gamma","delta","epsilon","zeta","eta","theta"],
  "numberOfWords": 6,
  "separatorOptions": ["-","_",".","/","+",":","|",";",",","~"]
}</textarea>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">PolicyDescriptor parameters per module A. Validated as a JSON object.</small>
  <label for="proposal_count">Proposals shown</label>
  <input id="proposal_count" name="proposal_count" type="number" value="5" min="1" max="20">
  <label for="regenerate_limit">Re-generate limit</label>
  <input id="regenerate_limit" name="regenerate_limit" type="number" value="3" min="0" max="10">
  <label for="session_ttl_seconds">Session TTL (seconds)</label>
  <input id="session_ttl_seconds" name="session_ttl_seconds" type="number" value="900" min="60" max="86400">
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="notify_on_consult"> Email notification post-consultation
  </label><br>
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.25rem">
    <input type="checkbox" name="active" checked> Active immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add policy</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminElevationsTpl = `{{define "elevations.html"}}{{template "header" .}}
<main>
<h2>Elevations</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Elevations bind a specific email to the B2 or B3 policy of its domain (FR-C.38..46). An email can be in at most one list per domain.</p>

<table data-testid="elevations-table"><thead><tr><th>Domain</th><th>Email</th><th>Level</th><th>Reason</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>id={{ .DomainID }}</code></td>
  <td>{{ .Email }}</td>
  <td><span class="badge">{{ .Level }}</span></td>
  <td>{{ .Reason }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02" }}</code></td>
  <td>{{ if .LastUsedAt }}<code>{{ .LastUsedAt.Format "2006-01-02" }}</code>{{ else }}—{{ end }}</td>
  <td>
    <form method="POST" action="/admin/elevations/{{ .ID }}/delete">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">Remove</button>
    </form>
  </td>
</tr>{{ else }}<tr><td colspan="7"><em>No elevations yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add an elevation</h3>
<form method="POST" action="/admin/elevations/add">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="el-domain">Domain</label>
  <select id="el-domain" name="domain_id" required>
    {{ range .Domains }}<option value="{{ .ID }}">{{ .Name }}</option>{{ else }}<option value="" disabled selected>(add a domain first)</option>{{ end }}
  </select>
  <label for="el-email">Email</label>
  <input id="el-email" name="email" type="email" required>
  <label for="el-level">Level</label>
  <select id="el-level" name="level" required>
    <option value="B2">B2 — manager bucket</option>
    <option value="B3">B3 — system admin bucket</option>
  </select>
  <label for="el-reason">Reason (optional)</label>
  <input id="el-reason" name="reason" type="text">
  <p style="margin-top:1rem"><button type="submit">Add elevation</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminLibrariesTpl = `{{define "libraries.html"}}{{template "header" .}}
<main>
<h2>Libraries</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
<p>Two kinds of libraries: <strong>dictionaries</strong> (one word per line, 4-12 letters, used by generator G2) and <strong>corpora</strong> (one citation per line, 3-25 words, used by generator G1). Comments lines starting with <code>#</code> are ignored. Files MUST be UTF-8 without BOM (module A §5.2/5.3). Identical content uploaded twice deduplicates via the SHA-256 hash.</p>

<table data-testid="libraries-table"><thead><tr><th>Name</th><th>Kind</th><th>Lang</th><th>Entries</th><th>Size</th><th>SHA-256</th><th>System</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .Name }}</td>
  <td><span class="badge">{{ .Kind }}</span></td>
  <td><code>{{ .Language }}</code></td>
  <td>{{ .EntryCount }}</td>
  <td>{{ printf "%d" .SizeBytes }} B</td>
  <td><code title="{{ .SHA256 }}">{{ slice .SHA256 0 12 }}…</code></td>
  <td>{{ if .System }}<strong>yes</strong>{{ else }}no{{ end }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <a class="secondary" href="/admin/libraries/{{ .ID }}/download" style="display:inline-block;padding:0.4rem 0.75rem;border:1px solid #1d4ed8;border-radius:4px;text-decoration:none">Download</a>
    <a class="secondary" href="/admin/libraries/{{ .ID }}/sample" style="display:inline-block;padding:0.4rem 0.75rem;border:1px solid #1d4ed8;border-radius:4px;text-decoration:none;margin-left:0.25rem" target="_blank">Sample</a>
    {{ if not .System }}<details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/libraries/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>{{ end }}
  </td>
</tr>{{ else }}<tr><td colspan="9"><em>No libraries uploaded yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Upload a library</h3>
<form method="POST" action="/admin/libraries/upload" enctype="multipart/form-data" data-testid="upload-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="kind">Kind</label>
  <select id="kind" name="kind" required>
    <option value="dictionary">Dictionary (one word per line)</option>
    <option value="corpus">Corpus (one citation per line)</option>
  </select>
  <label for="name">Name</label>
  <input id="name" name="name" type="text" required>
  <label for="language">Language code</label>
  <input id="language" name="language" type="text" placeholder="fr, en, es…" required>
  <label for="description">Description (optional)</label>
  <input id="description" name="description" type="text">
  <label for="file">File (UTF-8 plain text, ≤ 32 MB)</label>
  <input id="file" name="file" type="file" required accept=".txt,text/plain">
  <p style="margin-top:1rem"><button type="submit">Upload</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminTemplatesTpl = `{{define "templates.html"}}{{template "header" .}}
<main>
<h2>Email templates</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Two kinds are wired: <code>reveal_link</code> (used now by every request issuance) and <code>post_consultation</code> (used by the post-reveal notification when that feature ships). When the row is marked <em>system</em>, the built-in default applies; once you save changes the override takes precedence.</p>

<table><thead><tr><th>Kind</th><th>Language</th><th>Subject preview</th><th>Status</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .Kind }}</code></td>
  <td><code>{{ .Language }}</code></td>
  <td>{{ .Subject }}</td>
  <td>{{ if .IsSystem }}<span style="color:#6b7280">system</span>{{ else }}<strong style="color:#1d4ed8">customised</strong>{{ end }}</td>
  <td>{{ if .UpdatedAt.IsZero }}—{{ else }}<code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code>{{ end }}</td>
  <td><a href="/admin/templates/edit?kind={{ .Kind }}&language={{ .Language }}">Edit</a></td>
</tr>{{ end }}
</tbody></table>
</main>
{{template "footer" .}}{{end}}
`

const adminTemplateEditTpl = `{{define "template_edit.html"}}{{template "header" .}}
<main>
<h2>Edit template — <code>{{ .Template.Kind }}</code> / <code>{{ .Template.Language }}</code>
{{ if .Template.IsSystem }}<span style="color:#6b7280;font-size:1rem">(system default)</span>{{ end }}</h2>
{{ if .Error }}<div class="err"><pre style="white-space:pre-wrap">{{ .Error }}</pre></div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}

<details style="margin-bottom:1.5rem"><summary>Variables available (FR-C.72)</summary>
<table style="margin-top:0.5rem"><thead><tr><th>Name</th><th>Meaning</th></tr></thead><tbody>
{{ range .Vars }}<tr><td><code>{{ index . "name" }}</code></td><td>{{ index . "doc" }}</td></tr>{{ end }}
</tbody></table></details>

<form method="POST" action="/admin/templates/save">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <input type="hidden" name="kind" value="{{ .Template.Kind }}">
  <input type="hidden" name="language" value="{{ .Template.Language }}">

  <label for="subject">Subject (text/template)</label>
  <input id="subject" name="subject" type="text" value="{{ .Template.Subject }}" required>

  <label for="text_body">Plain text body (text/template)</label>
  <textarea id="text_body" name="text_body" rows="14" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{{ .Template.Text }}</textarea>

  <label for="html_body">HTML body (html/template — auto-escaped)</label>
  <textarea id="html_body" name="html_body" rows="14" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{{ .Template.HTML }}</textarea>

  <p style="margin-top:1rem">
    <button type="submit">Save</button>
    <button type="button" id="preview-btn" class="secondary" style="margin-left:0.5rem">Preview</button>
  </p>
</form>

<form method="POST" action="/admin/templates/reset" style="margin-top:0.5rem">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <input type="hidden" name="kind" value="{{ .Template.Kind }}">
  <input type="hidden" name="language" value="{{ .Template.Language }}">
  <button type="submit" class="secondary" onclick="return confirm('Reset this template to the built-in default?')">Reset to system default</button>
</form>

<section id="preview-out" hidden style="margin-top:2rem;border-top:1px solid #d1d5db;padding-top:1rem">
  <h3>Preview</h3>
  <p><strong>Subject:</strong> <code id="prev-subject"></code></p>
  <details open><summary>Plain text</summary><pre id="prev-text" style="background:#f3f4f6;padding:0.5rem"></pre></details>
  <details><summary>HTML (rendered)</summary><iframe id="prev-html" sandbox="" style="width:100%;height:24rem;border:1px solid #d1d5db"></iframe></details>
</section>

<script>
document.getElementById('preview-btn').addEventListener('click', async () => {
  const fd = new FormData();
  fd.set('csrf_token', '{{ .CSRF }}');
  fd.set('kind', '{{ .Template.Kind }}');
  fd.set('language', '{{ .Template.Language }}');
  fd.set('subject', document.getElementById('subject').value);
  fd.set('text_body', document.getElementById('text_body').value);
  fd.set('html_body', document.getElementById('html_body').value);
  const r = await fetch('/admin/templates/preview', { method: 'POST', body: fd });
  const body = await r.json();
  if (!r.ok) {
    alert('Preview failed: ' + (body.detail || r.status));
    return;
  }
  document.getElementById('prev-subject').textContent = body.subject;
  document.getElementById('prev-text').textContent = body.text;
  const ifr = document.getElementById('prev-html');
  ifr.srcdoc = body.html;
  document.getElementById('preview-out').hidden = false;
});
</script>
</main>
{{template "footer" .}}{{end}}
`

const adminIntegrationsTpl = `{{define "integrations.html"}}{{template "header" .}}
<main>
<h2>Outbound integrations</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
<p>Forward audit events to a SIEM or webhook. Five kinds are wired: <code>webhook</code> (generic JSON POST), <code>splunk</code> (HEC), <code>sentinel</code> (Log Analytics Data Collector), <code>elastic</code> (_bulk), <code>syslog</code> (RFC 5424). Configuration is per-kind JSON — examples in the form below.</p>
<p style="font-size:0.875rem;color:#4b5563">Dispatcher stats: delivered <strong>{{ .Stats.Delivered }}</strong> · failed <strong>{{ .Stats.Failed }}</strong> · drops <strong>{{ .Stats.Drops }}</strong></p>

<table><thead><tr><th>Name</th><th>Kind</th><th>Enabled</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .Name }}</td>
  <td><code>{{ .Kind }}</code></td>
  <td>{{ if .Enabled }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <form method="POST" action="/admin/integrations/{{ .ID }}/toggle" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Enabled }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <form method="POST" action="/admin/integrations/{{ .ID }}/test" style="display:inline;margin-left:0.25rem">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">Test</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/integrations/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="5"><em>No integrations configured yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add an integration</h3>
<form method="POST" action="/admin/integrations/add">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="name">Name (unique)</label>
  <input id="name" name="name" type="text" required>
  <label for="kind">Kind</label>
  <select id="kind" name="kind" required>
    <option value="webhook">webhook — generic JSON POST</option>
    <option value="splunk">splunk — HTTP Event Collector</option>
    <option value="sentinel">sentinel — MS Sentinel Log Analytics</option>
    <option value="elastic">elastic — Elasticsearch _bulk</option>
    <option value="syslog">syslog — RFC 5424 UDP/TCP</option>
  </select>
  <label for="config_json">Configuration (JSON)</label>
  <textarea id="config_json" name="config_json" rows="10" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{
  "url": "https://example.com/events",
  "bearer_token": "REPLACE_ME",
  "timeout_sec": 5
}</textarea>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">
    webhook: <code>url, bearer_token|basic_user+basic_pass, headers, timeout_sec</code>.
    splunk: <code>url, token, index, sourcetype</code>.
    sentinel: <code>workspace_id, shared_key (base64), log_type</code>.
    elastic: <code>url, index, api_key|bearer_token</code>.
    syslog: <code>address ("host:port"), network ("udp"|"tcp"), facility, hostname, app_name</code>.
  </small>
  <label for="filters_json">Filters (JSON, optional)</label>
  <input id="filters_json" name="filters_json" type="text" placeholder='{"event_types":["admin.","request.rate_limited"]}'>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">Empty filters forward every event. Entries ending in <code>.</code> match by prefix.</small>
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="enabled" checked> Enabled immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add integration</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminBrandingTpl = `{{define "branding.html"}}{{template "header" .}}
<main>
<h2>Branding</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Customise the instance name, three accent colours, support contact and logo. The public landing page, the reveal page and outbound emails all consume these values. Live preview on user pages is reported to v0.2 (FR-C.68); for now use the public links below the form to eyeball.</p>

<section style="display:grid;grid-template-columns:1fr 1fr;gap:2rem">
  <div>
    <h3>Identity</h3>
    <form method="POST" action="/admin/branding/save">
      <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
      <label for="instance_name">Instance name</label>
      <input id="instance_name" name="instance_name" type="text" required value="{{ .Branding.InstanceName }}">
      <label for="primary_color">Primary colour</label>
      <input id="primary_color" name="primary_color" type="color" value="{{ .Branding.PrimaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.PrimaryColor }}</code></small>
      <label for="secondary_color">Secondary colour (banner + accent)</label>
      <input id="secondary_color" name="secondary_color" type="color" value="{{ .Branding.SecondaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.SecondaryColor }}</code></small>
      <label for="tertiary_color">Tertiary colour (titles)</label>
      <input id="tertiary_color" name="tertiary_color" type="color" value="{{ .Branding.TertiaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.TertiaryColor }}</code></small>
      <label for="contact_url">Support / contact URL (optional)</label>
      <input id="contact_url" name="contact_url" type="url" value="{{ .Branding.ContactURL }}" placeholder="https://example.com/support">
      <p style="margin-top:1rem"><button type="submit">Save</button></p>
    </form>
  </div>

  <div>
    <h3>Logo</h3>
    {{ if .Branding.HasLogo }}
      <p><img src="/static/branding/logo" alt="Current logo" style="max-height:64px;border:1px solid #d1d5db;padding:0.5rem;background:white"></p>
      <p style="font-size:0.875rem;color:#4b5563">Stored type: <code>{{ .Branding.LogoMIME }}</code></p>
      <form method="POST" action="/admin/branding/logo/clear" style="margin-bottom:1rem">
        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
        <button type="submit" class="secondary">Remove logo</button>
      </form>
    {{ else }}
      <p style="color:#6b7280">No logo uploaded yet. The public pages hide the image when this is empty.</p>
    {{ end }}
    <form method="POST" action="/admin/branding/logo" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
      <label for="logo">Upload (PNG or SVG, ≤ 256 KB, ~64 px height)</label>
      <input id="logo" name="logo" type="file" accept="image/png,image/svg+xml" required>
      <p style="margin-top:1rem"><button type="submit">Upload logo</button></p>
    </form>
  </div>
</section>

<hr style="margin:2rem 0">
<p style="font-size:0.875rem;color:#4b5563">
  Preview targets:
  <a href="/" target="_blank">public landing</a> ·
  outbound email subject is rendered live in
  <a href="/admin/templates">Email templates</a>.
</p>
</main>
{{template "footer" .}}{{end}}
`

const adminCapturedTpl = `{{define "captured.html"}}{{template "header" .}}
<main>
<h2>Captured mail (eval mode)</h2>
<table><thead><tr><th>#</th><th>When (UTC)</th><th>To</th><th>Subject</th><th>Body</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .ID }}</td>
  <td><code>{{ .Timestamp }}</code></td>
  <td>{{ .To }}</td>
  <td>{{ .Subject }}</td>
  <td><details><summary>view</summary><pre>{{ .Body }}</pre></details></td>
</tr>{{ else }}<tr><td colspan="5"><em>No captured mail yet.</em></td></tr>{{ end }}
</tbody></table>
</main>
{{template "footer" .}}{{end}}
`
