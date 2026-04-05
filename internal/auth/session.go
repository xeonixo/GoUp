package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "goup_session"

type UserSession struct {
	UserID       int64     `json:"uid,omitempty"`
	Subject      string    `json:"sub"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	TenantID     int64     `json:"tenant_id,omitempty"`
	TenantSlug   string    `json:"tenant_slug,omitempty"`
	TenantName   string    `json:"tenant_name,omitempty"`
	Role         string    `json:"role,omitempty"`
	AuthProvider string    `json:"auth_provider,omitempty"`
	ExpiresAt    time.Time `json:"exp"`
}

type SessionManager struct {
	key    []byte
	secure bool
}

func NewSessionManager(key []byte, secure bool) *SessionManager {
	return &SessionManager{key: key, secure: secure}
}

func (m *SessionManager) Get(r *http.Request) (*UserSession, error) {
	return m.GetForTenant(r, "")
}

func (m *SessionManager) GetForTenant(r *http.Request, tenantSlug string) (*UserSession, error) {
	tenantSlug = strings.ToLower(strings.TrimSpace(tenantSlug))
	var lastErr error
	for _, cookie := range r.Cookies() {
		if cookie == nil || cookie.Name != sessionCookieName {
			continue
		}
		session, err := m.parseCookieValue(cookie.Value)
		if err != nil {
			lastErr = err
			continue
		}
		if tenantSlug != "" {
			if strings.ToLower(strings.TrimSpace(session.TenantSlug)) != tenantSlug {
				continue
			}
		}
		return session, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, http.ErrNoCookie
}

func (m *SessionManager) Set(w http.ResponseWriter, session UserSession) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}

	path := "/"
	if slug := strings.Trim(strings.TrimSpace(session.TenantSlug), "/"); slug != "" {
		path = "/" + slug
	}

	value := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(m.sign(payload))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
	})

	return nil
}

func (m *SessionManager) Clear(w http.ResponseWriter) {
	m.ClearForTenant(w, "")
}

func (m *SessionManager) ClearForTenant(w http.ResponseWriter, tenantSlug string) {
	path := "/"
	if slug := strings.Trim(strings.TrimSpace(tenantSlug), "/"); slug != "" {
		path = "/" + slug
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     path,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (m *SessionManager) parseCookieValue(value string) (*UserSession, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session cookie format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	expected := m.sign(payload)
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("invalid session signature")
	}

	var session UserSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	return &session, nil
}

func (m *SessionManager) sign(payload []byte) []byte {
	h := hmac.New(sha256.New, m.key)
	h.Write(payload)
	return h.Sum(nil)
}
