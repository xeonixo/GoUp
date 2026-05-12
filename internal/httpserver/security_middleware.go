package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"goup/internal/auth"
	store "goup/internal/store/sqlite"
)

type localLoginAttempt struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

const (
	localLoginMaxFailures    = 5
	localLoginWindow         = 10 * time.Minute
	localLoginLockout        = 15 * time.Minute
	adminAccessMaxFailures   = 10
	adminAccessWindow        = 5 * time.Minute
	adminAccessLockout       = 30 * time.Minute
	bootstrapMaxFailures     = 8
	bootstrapWindow          = 5 * time.Minute
	bootstrapLockout         = 15 * time.Minute
	passwordResetTTL         = 15 * time.Minute
	controlPlaneAdminTTL     = 1 * time.Hour
	controlPlaneTOTPStageTTL = 5 * time.Minute
	controlPlaneCookie       = "goup_cp_admin"
	controlPlaneTOTPCookie   = "goup_cp_admin_totp"
)

func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	expected, err := url.Parse(s.cfg.BaseURL)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return next
	}
	expectedScheme := strings.ToLower(strings.TrimSpace(expected.Scheme))
	expectedHost := strings.ToLower(strings.TrimSpace(expected.Hostname()))
	expectedPort := strings.TrimSpace(expected.Port())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/node/") {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}

		allowedOrigins := make(map[string]struct{})
		for _, origin := range buildAllowedOrigins(expectedScheme, expectedHost, expectedPort, r) {
			allowedOrigins[origin] = struct{}{}
		}

		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			normalizedOrigin := normalizeOrigin(origin)
			if normalizedOrigin == "" {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedOrigin]; !ok {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
			normalizedRefererOrigin := normalizeRefererOrigin(referer)
			if normalizedRefererOrigin == "" {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedRefererOrigin]; !ok {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Neither Origin nor Referer present on a mutating request: reject.
		// Legitimate browser-initiated form submissions always include at least one.
		// Non-browser API clients should supply Origin.
		http.Error(w, "origin or referer required", http.StatusForbidden)
	})
}

func buildAllowedOrigins(expectedScheme, expectedHost, expectedPort string, r *http.Request) []string {
	origins := make(map[string]struct{})
	addOriginCandidate(origins, expectedScheme, expectedHost, expectedPort)

	requestScheme := expectedScheme
	if strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")) != "" {
		requestScheme = strings.ToLower(strings.TrimSpace(strings.Split(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), ",")[0]))
	}
	requestHost := strings.ToLower(strings.TrimSpace(r.Host))
	if requestHost != "" {
		hostname := requestHost
		port := ""
		if strings.Contains(requestHost, ":") {
			if parsedHost, parsedPort, err := net.SplitHostPort(requestHost); err == nil {
				hostname = strings.ToLower(strings.TrimSpace(parsedHost))
				port = strings.TrimSpace(parsedPort)
			}
		}
		addOriginCandidate(origins, requestScheme, hostname, port)
	}

	for _, host := range []string{expectedHost, strings.ToLower(strings.TrimSpace(r.URL.Hostname()))} {
		if host == "" {
			continue
		}
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			for _, alt := range []string{"localhost", "127.0.0.1", "[::1]"} {
				addOriginCandidate(origins, expectedScheme, alt, expectedPort)
			}
		}
	}

	result := make([]string, 0, len(origins))
	for value := range origins {
		result = append(result, value)
	}
	return result
}

func addOriginCandidate(set map[string]struct{}, scheme, host, port string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "http"
	}
	port = strings.TrimSpace(port)
	if port != "" {
		set[scheme+"://"+strings.ToLower(host)+":"+port] = struct{}{}
		return
	}
	set[scheme+"://"+strings.ToLower(host)] = struct{}{}
}

func normalizeOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}

func normalizeRefererOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Clickjacking protection
		h.Set("X-Frame-Options", "DENY")
		// MIME-type sniffing protection
		h.Set("X-Content-Type-Options", "nosniff")
		// Referrer leakage: only send origin on cross-origin requests
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Disable browser features not needed
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		// Content Security Policy: only same-origin assets, including locally served icon cache/uploads
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		// HSTS: only set when using HTTPS
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionForRequest(r)
		if err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}

		if tenantID := tenantIDFromRequest(r); tenantID > 0 && session != nil && session.TenantID > 0 && session.TenantID != tenantID {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireUserManagement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionForRequest(r)
		if err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		if tenantID := tenantIDFromRequest(r); tenantID > 0 && session.TenantID > 0 && session.TenantID != tenantID {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		if !strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdminWhenAuth blocks write operations for authenticated non-admin users.
// When no session exists (auth-disabled tenant) the request is passed through.
func (s *Server) requireAdminWhenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionForRequest(r)
		if err == nil {
			if tenantID := tenantIDFromRequest(r); tenantID > 0 && session.TenantID > 0 && session.TenantID != tenantID {
				slug := tenantSlugFromRequest(r)
				if slug != "" {
					http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
				} else {
					http.Redirect(w, r, "/", http.StatusSeeOther)
				}
				return
			}
			if !strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
				http.Error(w, "forbidden: admin role required", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireControlPlaneAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(s.adminCookieKey) == "" {
			http.Error(w, "control-plane admin access is not configured", http.StatusForbidden)
			return
		}
		if !s.hasControlPlaneAdminCookie(r) {
			http.Redirect(w, r, "/admin/access", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isControlPlaneAdminRequest(r *http.Request) bool {
	if r == nil || !strings.HasPrefix(r.URL.Path, "/admin") {
		return false
	}
	if strings.TrimSpace(s.adminCookieKey) == "" {
		return false
	}
	return s.hasControlPlaneAdminCookie(r)
}

func (s *Server) hasControlPlaneAdminCookie(r *http.Request) bool {
	cookie, err := r.Cookie(controlPlaneCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	if subtle.ConstantTimeCompare(providedSig, h.Sum(nil)) != 1 {
		return false
	}
	payloadParts := strings.Split(string(payload), "|")
	if len(payloadParts) != 2 {
		return false
	}
	expiresUnix, err := strconv.ParseInt(payloadParts[0], 10, 64)
	if err != nil {
		return false
	}
	if !time.Now().UTC().Before(time.Unix(expiresUnix, 0)) {
		return false
	}
	version, err := strconv.ParseInt(payloadParts[1], 10, 64)
	if err != nil || version <= 0 {
		return false
	}
	admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
	if err != nil {
		return false
	}
	return admin.SessionVersion == version
}

func (s *Server) setControlPlaneAdminCookie(w http.ResponseWriter, sessionVersion int64) {
	if sessionVersion <= 0 {
		sessionVersion = 1
	}
	expiresAt := time.Now().UTC().Add(controlPlaneAdminTTL)
	payload := []byte(strconv.FormatInt(expiresAt.Unix(), 10) + "|" + strconv.FormatInt(sessionVersion, 10))
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneCookie,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(controlPlaneAdminTTL.Seconds()),
	})
}

func (s *Server) hasControlPlaneTOTPCookie(r *http.Request, username string) bool {
	cookie, err := r.Cookie(controlPlaneTOTPCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	if subtle.ConstantTimeCompare(providedSig, h.Sum(nil)) != 1 {
		return false
	}
	payloadParts := strings.SplitN(string(payload), "|", 2)
	if len(payloadParts) != 2 {
		return false
	}
	expiresUnix, err := strconv.ParseInt(payloadParts[0], 10, 64)
	if err != nil {
		return false
	}
	if !time.Now().UTC().Before(time.Unix(expiresUnix, 0)) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(payloadParts[1]), strings.TrimSpace(username))
}

func (s *Server) setControlPlaneTOTPCookie(w http.ResponseWriter, username string) {
	expiresAt := time.Now().UTC().Add(controlPlaneTOTPStageTTL)
	payload := []byte(strconv.FormatInt(expiresAt.Unix(), 10) + "|" + strings.TrimSpace(username))
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneTOTPCookie,
		Value:    token,
		Path:     "/admin/access",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(controlPlaneTOTPStageTTL.Seconds()),
	})
}

func (s *Server) clearControlPlaneTOTPCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneTOTPCookie,
		Value:    "",
		Path:     "/admin/access",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *Server) clearControlPlaneAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneCookie,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *Server) clientIP(r *http.Request) string {
	// Only use RemoteAddr. X-Forwarded-For is trivially spoofable by clients
	// and must not be trusted for security decisions unless the server is behind
	// a trusted reverse proxy that strips/overwrites the header.
	clientIP := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(clientIP); err == nil && host != "" {
		clientIP = host
	}
	if clientIP == "" {
		clientIP = "unknown"
	}
	return clientIP
}

func (s *Server) localLoginKey(r *http.Request, tenantID int64, loginName string) string {
	return fmt.Sprintf("%d|%s|%s", tenantID, strings.ToLower(strings.TrimSpace(loginName)), s.clientIP(r))
}

func (s *Server) localLoginAllowed(key string, now time.Time) (bool, time.Duration) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt, ok := s.localLoginAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > localLoginWindow {
		delete(s.localLoginAttempts, key)
	}
	return true, 0
}

func (s *Server) registerLocalLoginFailure(key string, now time.Time) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt := s.localLoginAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > localLoginWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.localLoginAttempts[key] = attempt
		return
	}

	attempt.Failures++
	if attempt.Failures >= localLoginMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(localLoginLockout)
	}
	s.localLoginAttempts[key] = attempt
}

func (s *Server) clearLocalLoginAttempts(key string) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()
	delete(s.localLoginAttempts, key)
}

func (s *Server) adminAccessKey(r *http.Request) string {
	return "admin|" + s.clientIP(r)
}

func (s *Server) adminAccessAllowed(key string, now time.Time) (bool, time.Duration) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt, ok := s.adminAccessAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > adminAccessWindow {
		delete(s.adminAccessAttempts, key)
	}
	return true, 0
}

func (s *Server) registerAdminAccessFailure(key string, now time.Time) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt := s.adminAccessAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > adminAccessWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.adminAccessAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= adminAccessMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(adminAccessLockout)
	}
	s.adminAccessAttempts[key] = attempt
}

func (s *Server) clearAdminAccessAttempts(key string) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	delete(s.adminAccessAttempts, key)
}

func (s *Server) bootstrapAttemptKey(r *http.Request, nodeID string) string {
	return "node-bootstrap|" + strings.ToLower(strings.TrimSpace(nodeID)) + "|" + s.clientIP(r)
}

func (s *Server) bootstrapAllowed(key string, now time.Time) (bool, time.Duration) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt, ok := s.bootstrapAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > bootstrapWindow {
		delete(s.bootstrapAttempts, key)
	}
	return true, 0
}

func (s *Server) registerBootstrapFailure(key string, now time.Time) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt := s.bootstrapAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > bootstrapWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.bootstrapAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= bootstrapMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(bootstrapLockout)
	}
	s.bootstrapAttempts[key] = attempt
}

func (s *Server) clearBootstrapAttempts(key string) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	delete(s.bootstrapAttempts, key)
}

func (s *Server) currentUser(r *http.Request) *auth.UserSession {
	session, err := s.sessionForRequest(r)
	if err != nil {
		return nil
	}
	return session
}

func (s *Server) sessionForRequest(r *http.Request) (*auth.UserSession, error) {
	var (
		session *auth.UserSession
		err     error
	)
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		session, err = s.sessions.GetForTenant(r, slug)
	} else {
		session, err = s.sessions.Get(r)
	}
	if err != nil {
		return nil, err
	}
	if err := s.validateTenantSession(r.Context(), session); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Server) validateTenantSession(ctx context.Context, session *auth.UserSession) error {
	if session == nil {
		return http.ErrNoCookie
	}
	if s.controlStore == nil || session.TenantID <= 0 || session.UserID <= 0 {
		return nil
	}
	if session.SessionVersion <= 0 {
		return errors.New("session version missing")
	}
	version, err := s.controlStore.GetTenantMembershipSessionVersion(ctx, session.TenantID, session.UserID)
	if err != nil {
		return err
	}
	if version != session.SessionVersion {
		return errors.New("session version mismatch")
	}
	return nil
}

func (s *Server) appStore(r *http.Request) (*store.Store, error) {
	if s.tenantStores == nil {
		return s.store, nil
	}
	if tenantID := tenantIDFromRequest(r); tenantID > 0 {
		return s.tenantStores.StoreForTenant(r.Context(), tenantID)
	}
	currentUser := s.currentUser(r)
	if currentUser == nil || currentUser.TenantID <= 0 {
		return s.store, nil
	}
	return s.tenantStores.StoreForTenant(r.Context(), currentUser.TenantID)
}

func (s *Server) tenantSlugForRequest(r *http.Request) string {
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		return slug
	}
	if currentUser := s.currentUser(r); currentUser != nil && strings.TrimSpace(currentUser.TenantSlug) != "" {
		return strings.TrimSpace(currentUser.TenantSlug)
	}
	if slug := strings.TrimSpace(s.defaultTenant.Slug); slug != "" {
		return slug
	}
	return "default"
}
