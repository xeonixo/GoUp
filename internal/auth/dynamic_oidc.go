package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"goup/internal/netguard"
)

// TenantOIDCConfig holds OIDC configuration for a specific tenant
type TenantOIDCConfig struct {
	TenantSlug   string
	ProviderKey  string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// maxDynamicOIDCCacheEntries bounds the provider/verifier caches so that
// tenant admins cannot grow server memory by registering many issuers.
const maxDynamicOIDCCacheEntries = 64

// DynamicOIDCManager manages OIDC flows for tenants on-demand, caching providers
type DynamicOIDCManager struct {
	mu        sync.RWMutex
	providers map[string]*oidc.Provider // key: issuer_url
	verifiers map[string]*oidc.IDTokenVerifier
	order     []string // insertion order of provider keys, for eviction
	client    *http.Client
}

// NewDynamicOIDCManager creates a manager whose outbound requests (discovery,
// JWKS, token exchange) go through an SSRF-guarded HTTP client. Private
// destinations are only reachable when allowPrivate is true.
func NewDynamicOIDCManager(allowPrivate bool) *DynamicOIDCManager {
	return &DynamicOIDCManager{
		providers: make(map[string]*oidc.Provider),
		verifiers: make(map[string]*oidc.IDTokenVerifier),
		client: netguard.NewHTTPClient(netguard.Options{
			Timeout:      15 * time.Second,
			AllowPrivate: allowPrivate,
			MaxRedirects: 3,
			KeepAlives:   true,
		}),
	}
}

// requestContext attaches the guarded HTTP client to ctx. It is used for every
// call into go-oidc / oauth2, which pick the client up from the context.
func (m *DynamicOIDCManager) requestContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, m.client)
}

// ForgetIssuer drops cached state for an issuer (e.g. after provider edits).
func (m *DynamicOIDCManager) ForgetIssuer(issuerURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forgetLocked(issuerURL)
}

func (m *DynamicOIDCManager) forgetLocked(issuerURL string) {
	delete(m.providers, issuerURL)
	for key := range m.verifiers {
		if strings.HasPrefix(key, issuerURL+"::") {
			delete(m.verifiers, key)
		}
	}
	for i, key := range m.order {
		if key == issuerURL {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// getOrCreateProvider retrieves or creates an OIDC provider for a given issuer URL
func (m *DynamicOIDCManager) getOrCreateProvider(ctx context.Context, issuerURL string) (*oidc.Provider, error) {
	m.mu.RLock()
	if provider, ok := m.providers[issuerURL]; ok {
		m.mu.RUnlock()
		return provider, nil
	}
	m.mu.RUnlock()

	// Not cached, create new. The provider keeps the context for later JWKS
	// fetches, so it must not be tied to the (cancellable) request.
	provider, err := oidc.NewProvider(m.requestContext(context.WithoutCancel(ctx)), issuerURL)
	if err != nil {
		return nil, fmt.Errorf("create oidc provider: %w", err)
	}

	m.mu.Lock()
	if _, exists := m.providers[issuerURL]; !exists {
		for len(m.order) >= maxDynamicOIDCCacheEntries {
			m.forgetLocked(m.order[0])
		}
		m.order = append(m.order, issuerURL)
	}
	m.providers[issuerURL] = provider
	m.mu.Unlock()

	return provider, nil
}

// getOrCreateVerifier retrieves or creates an ID token verifier
func (m *DynamicOIDCManager) getOrCreateVerifier(ctx context.Context, issuerURL, clientID string) (*oidc.IDTokenVerifier, error) {
	key := issuerURL + "::" + clientID
	m.mu.RLock()
	if verifier, ok := m.verifiers[key]; ok {
		m.mu.RUnlock()
		return verifier, nil
	}
	m.mu.RUnlock()

	provider, err := m.getOrCreateProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	m.mu.Lock()
	m.verifiers[key] = verifier
	m.mu.Unlock()

	return verifier, nil
}

// BeginAuthForTenant starts the OIDC authorization flow for a tenant
func (m *DynamicOIDCManager) BeginAuthForTenant(w http.ResponseWriter, r *http.Request, cfg TenantOIDCConfig, secureCookies bool) (string, error) {
	provider, err := m.getOrCreateProvider(r.Context(), cfg.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("get provider for auth begin: %w", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	stateCookieName, nonceCookieName, providerCookieName := tenantOIDCCookieNames(cfg.TenantSlug)

	// Store state, nonce and provider in tenant-scoped cookies.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     nonceCookieName,
		Value:    nonce,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     providerCookieName,
		Value:    strings.TrimSpace(cfg.ProviderKey),
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))
	return redirectURL, nil
}

// CompleteAuthForTenant completes the OIDC callback for a tenant
func (m *DynamicOIDCManager) CompleteAuthForTenant(ctx context.Context, r *http.Request, cfg TenantOIDCConfig) (Identity, error) {
	stateCookieName, nonceCookieName, _ := tenantOIDCCookieNames(cfg.TenantSlug)

	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil {
		// Backward compatibility for cookies written before tenant scoping.
		stateCookie, err = r.Cookie(oidcStateCookieName)
	}
	if err != nil {
		return Identity{}, fmt.Errorf("state cookie missing: %w", err)
	}
	nonceCookie, err := r.Cookie(nonceCookieName)
	if err != nil {
		// Backward compatibility for cookies written before tenant scoping.
		nonceCookie, err = r.Cookie(oidcNonceCookieName)
	}
	if err != nil {
		return Identity{}, fmt.Errorf("nonce cookie missing: %w", err)
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state != stateCookie.Value {
		return Identity{}, fmt.Errorf("state mismatch")
	}

	provider, err := m.getOrCreateProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return Identity{}, fmt.Errorf("get provider for auth complete: %w", err)
	}

	verifier, err := m.getOrCreateVerifier(ctx, cfg.IssuerURL, cfg.ClientID)
	if err != nil {
		return Identity{}, fmt.Errorf("get verifier for auth complete: %w", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	token, err := oauthCfg.Exchange(m.requestContext(ctx), code)
	if err != nil {
		return Identity{}, fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return Identity{}, fmt.Errorf("id_token not in token response")
	}

	idToken, err := verifier.Verify(m.requestContext(ctx), rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id token: %w", err)
	}

	// Verify nonce
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("unmarshal id token claims: %w", err)
	}
	if claims.Nonce != nonceCookie.Value {
		return Identity{}, fmt.Errorf("nonce mismatch")
	}

	// Extract identity info
	var identity Identity
	var claims2 struct {
		Email         string      `json:"email"`
		Name          string      `json:"name"`
		GivenName     string      `json:"given_name"`
		FamilyName    string      `json:"family_name"`
		EmailVerified *bool       `json:"email_verified"`
		Groups        flexStrings `json:"groups"`
	}
	if err := idToken.Claims(&claims2); err != nil {
		return Identity{}, fmt.Errorf("unmarshal identity claims: %w", err)
	}

	identity.Subject = idToken.Subject
	identity.Email = claims2.Email
	identity.EmailVerified = claims2.EmailVerified
	identity.Groups = []string(claims2.Groups)
	identity.Name = claims2.Name
	if identity.Name == "" {
		identity.Name = claims2.GivenName + " " + claims2.FamilyName
		identity.Name = cleanSpaces(identity.Name)
	}

	return identity, nil
}

func (m *DynamicOIDCManager) ClearEphemeralCookiesForTenant(w http.ResponseWriter, tenantSlug string, secureCookies bool) {
	stateCookieName, nonceCookieName, providerCookieName := tenantOIDCCookieNames(tenantSlug)
	for _, name := range []string{stateCookieName, nonceCookieName, providerCookieName, oidcStateCookieName, oidcNonceCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secureCookies,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func (m *DynamicOIDCManager) ProviderKeyFromRequest(r *http.Request, tenantSlug string) string {
	_, _, providerCookieName := tenantOIDCCookieNames(tenantSlug)
	cookie, err := r.Cookie(providerCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func tenantOIDCCookieNames(tenantSlug string) (stateCookieName string, nonceCookieName string, providerCookieName string) {
	slug := normalizeTenantCookieKey(tenantSlug)
	if slug == "" {
		return oidcStateCookieName, oidcNonceCookieName, "goup_oidc_provider"
	}
	return oidcStateCookieName + "_" + slug, oidcNonceCookieName + "_" + slug, "goup_oidc_provider_" + slug
}

func normalizeTenantCookieKey(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

func cleanSpaces(s string) string {
	result := ""
	lastWasSpace := false
	for _, r := range s {
		if r == ' ' {
			if !lastWasSpace {
				result += " "
				lastWasSpace = true
			}
		} else {
			result += string(r)
			lastWasSpace = false
		}
	}
	return result
}
