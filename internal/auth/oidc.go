package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"goup/internal/config"
)

const (
	oidcStateCookieName = "goup_oidc_state"
	oidcNonceCookieName = "goup_oidc_nonce"
)

type Identity struct {
	Subject string
	Email   string
	Name    string
}

type OIDCManager struct {
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth2Config  oauth2.Config
	secureCookies bool
}

func NewOIDCManager(ctx context.Context, cfg config.Config) (*OIDCManager, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Auth.OIDC.IssuerURL)
	if err != nil {
		return nil, err
	}

	return &OIDCManager{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.Auth.OIDC.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.Auth.OIDC.ClientID,
			ClientSecret: cfg.Auth.OIDC.ClientSecret,
			RedirectURL:  cfg.Auth.OIDC.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		secureCookies: cfg.SecureCookies(),
	}, nil
}

func (m *OIDCManager) BeginAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := randomString(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomString(32)
	if err != nil {
		return "", err
	}

	m.setEphemeralCookie(w, oidcStateCookieName, state)
	m.setEphemeralCookie(w, oidcNonceCookieName, nonce)

	return m.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), nil
}

func (m *OIDCManager) CompleteAuth(ctx context.Context, r *http.Request) (*Identity, error) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		return nil, errors.New("missing state or code")
	}

	expectedState, err := readCookie(r, oidcStateCookieName)
	if err != nil {
		return nil, err
	}
	if state != expectedState {
		return nil, errors.New("invalid oidc state")
	}

	expectedNonce, err := readCookie(r, oidcNonceCookieName)
	if err != nil {
		return nil, err
	}

	token, err := m.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("missing id_token in oauth2 token response")
	}

	idToken, err := m.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Nonce   string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}
	if claims.Nonce != expectedNonce {
		return nil, errors.New("invalid oidc nonce")
	}
	if claims.Subject == "" {
		return nil, errors.New("id token missing subject")
	}

	return &Identity{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}, nil
}

func (m *OIDCManager) ClearEphemeralCookies(w http.ResponseWriter) {
	for _, name := range []string{oidcStateCookieName, oidcNonceCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   m.secureCookies,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

func (m *OIDCManager) setEphemeralCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
		Expires:  time.Now().Add(10 * time.Minute),
	})
}

func readCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("empty cookie")
	}
	return cookie.Value, nil
}

func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
