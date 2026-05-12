package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
