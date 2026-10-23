package httpserver

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"goup/internal/version"
	"goup/web"
)

const (
	pwaThemeColor        = "#0b1020"
	swVersionPlaceholder = "__GOUP_VERSION__"
	swSourcePath         = "sw.js"
	// A tenant name at most this long is used as the home-screen label.
	pwaShortNameMaxRunes = 12
)

var (
	assetVersionOnce  sync.Once
	assetVersionValue string
)

// assetVersion identifies the running build. It is appended to static asset
// URLs (?v=...) for cache busting and is baked into the service worker cache
// name. Release builds use the ldflags version; dev builds fall back to the
// process start time so that every restart invalidates stale caches.
func assetVersion() string {
	assetVersionOnce.Do(func() {
		v := sanitizeAssetVersion(version.Version)
		if v == "" || v == "dev" {
			v = "dev-" + strconv.FormatInt(time.Now().Unix(), 36)
		}
		assetVersionValue = v
	})
	return assetVersionValue
}

// sanitizeAssetVersion keeps only characters that are safe inside a URL query
// value and a JavaScript string literal.
func sanitizeAssetVersion(raw string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// staticFileHandler serves embedded static assets. Requests carrying the
// build version (?v=<version>) are immutable and cached for a year; anything
// else must be revalidated so a deploy is picked up quickly.
func staticFileHandler(fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == assetVersion() {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// handleServiceWorker serves the service worker from the site root so that it
// can control the whole origin. The build version is injected so every release
// gets its own cache namespace. It must never be cached by the HTTP cache,
// otherwise updates to the worker would be delayed.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	payload, err := fs.ReadFile(web.FS, "static/"+swSourcePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	body := strings.ReplaceAll(string(payload), swVersionPlaceholder, assetVersion())
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Service-Worker-Allowed", "/")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(body))
}

// handleOffline renders the standalone offline fallback page. It is public and
// contains no tenant or user data; the service worker precaches it.
func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, "offline", pageData{
		UILanguage: normalizeUILanguage(detectPreferredLanguage(r)),
		Title:      "GoUp",
	})
}

type webManifestIcon struct {
	Src     string `json:"src"`
	Sizes   string `json:"sizes"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
}

type webManifestShortcut struct {
	Name      string            `json:"name"`
	ShortName string            `json:"short_name,omitempty"`
	URL       string            `json:"url"`
	Icons     []webManifestIcon `json:"icons,omitempty"`
}

type webManifest struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	ShortName       string                `json:"short_name"`
	StartURL        string                `json:"start_url"`
	Scope           string                `json:"scope"`
	Display         string                `json:"display"`
	ThemeColor      string                `json:"theme_color"`
	BackgroundColor string                `json:"background_color"`
	Icons           []webManifestIcon     `json:"icons"`
	Shortcuts       []webManifestShortcut `json:"shortcuts,omitempty"`
}

func pwaIcons() []webManifestIcon {
	return []webManifestIcon{
		{Src: "/android-chrome-192x192.png", Sizes: "192x192", Type: "image/png", Purpose: "any"},
		{Src: "/android-chrome-512x512.png", Sizes: "512x512", Type: "image/png", Purpose: "any"},
		{Src: "/favicon/maskable-512x512.png", Sizes: "512x512", Type: "image/png", Purpose: "maskable"},
	}
}

// handleTenantManifest serves /{slug}/manifest.webmanifest.
//
// The manifest is intentionally reachable without a session: iOS/Android fetch
// it while installing the app and browsers fetch manifests without credentials
// for cross-origin-style requests. It only contains the tenant slug and display
// name (already visible on the public login page) and static asset URLs. The
// caller (handlePrettyTenantPath) only dispatches here for existing, active
// tenants, so unknown or disabled slugs get a 404 and tenants cannot be
// enumerated beyond what the login page already reveals.
func (s *Server) handleTenantManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := tenantSlugFromRequest(r)
	if slug == "" || s.controlStore == nil {
		http.NotFound(w, r)
		return
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), slug)
	if err != nil || !tenant.Active {
		http.NotFound(w, r)
		return
	}

	lang := normalizeUILanguage(detectPreferredLanguage(r))
	tr := s.translationsForLanguage(lang)
	tenantName := strings.TrimSpace(tenant.Name)
	if tenantName == "" {
		tenantName = tenant.Slug
	}
	base := "/" + tenant.Slug + "/"
	manifest := webManifest{
		ID:              base,
		Name:            "GoUp · " + tenantName,
		ShortName:       pwaShortName(tenantName),
		StartURL:        base,
		Scope:           base,
		Display:         "standalone",
		ThemeColor:      pwaThemeColor,
		BackgroundColor: pwaThemeColor,
		Icons:           pwaIcons(),
		Shortcuts: []webManifestShortcut{
			{Name: manifestLabel(tr, "pwa.shortcut_dashboard", "Dashboard"), URL: base},
			{Name: manifestLabel(tr, "pwa.shortcut_history", "History"), URL: base + "state-events"},
		},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		http.Error(w, "manifest unavailable", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/manifest+json; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("Vary", "Accept-Language")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(payload)
}

func pwaShortName(tenantName string) string {
	if n := utf8.RuneCountInString(tenantName); n > 0 && n <= pwaShortNameMaxRunes {
		return tenantName
	}
	return "GoUp"
}

func manifestLabel(tr map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(tr[key]); v != "" {
		return v
	}
	return fallback
}

// pwaTenantBase returns "/{slug}/" when the page belongs to a tenant, else "".
func pwaTenantBase(data *pageData) string {
	if data.ControlPlaneAdmin {
		return ""
	}
	switch {
	case data.AppBase != "" && data.AppBase != "/":
		return data.AppBase
	case data.TenantSlug != "":
		return "/" + data.TenantSlug + "/"
	case data.User != nil && data.User.TenantSlug != "":
		return "/" + data.User.TenantSlug + "/"
	}
	return ""
}

// applyPWAPageData fills the manifest link and home-screen title. Tenant pages
// link to the per-tenant manifest (scope /{slug}/); everything else, including
// the admin area, uses the static manifest.
func (s *Server) applyPWAPageData(data *pageData, name string) {
	data.ManifestURL = "/site.webmanifest"
	data.AppTitle = "GoUp"
	base := pwaTenantBase(data)
	if base == "" || name == "offline" {
		return
	}
	data.ManifestURL = base + "manifest.webmanifest"
	tenantName := strings.TrimSpace(data.TenantName)
	if tenantName == "" && data.User != nil {
		tenantName = strings.TrimSpace(data.User.TenantName)
	}
	if tenantName != "" {
		data.AppTitle = pwaShortName(tenantName)
	}
}

// applyNavBack derives the consistent "back" link shown above the page content
// (important in standalone mode, where there is no browser chrome). It is
// driven by the template name so that individual templates need no copies.
func (s *Server) applyNavBack(data *pageData, name string) {
	if data.NavBackURL != "" {
		return
	}
	tr := data.Translations
	set := func(url, key string) {
		data.NavBackURL = url
		data.NavBackLabel = manifestLabel(tr, key, manifestLabel(tr, "common.back", "Back"))
	}
	tenantID := data.AdminTenant.ID
	switch name {
	case "admin_tenants", "admin_providers_overview", "admin_users_overview", "admin_remote_nodes_overview", "admin_security":
		set("/admin/", "layout.back_admin")
	case "admin_tenant_form":
		set("/admin/tenants", "layout.back_tenants")
	case "admin_providers", "admin_local_users", "admin_remote_nodes":
		set("/admin/tenants", "layout.back_tenants")
	case "admin_provider_form":
		if tenantID > 0 {
			set("/admin/tenants/"+strconv.FormatInt(tenantID, 10)+"/providers", "layout.back_up")
		}
	case "admin_local_user_form":
		if tenantID > 0 {
			set("/admin/tenants/"+strconv.FormatInt(tenantID, 10)+"/local-users", "layout.back_up")
		}
	case "settings_users", "settings_profile", "settings_webhooks", "settings_providers", "settings_remote_nodes", "settings_status_page", "settings_maintenance",
		"state_events_history", "notification_events_history", "monitors_import":
		if base := pwaTenantBase(data); base != "" {
			set(base, "layout.back_dashboard")
		}
	case "settings_provider_form":
		if base := pwaTenantBase(data); base != "" {
			set(base+"settings/providers", "layout.back_up")
		}
	case "monitors_import_preview":
		if base := pwaTenantBase(data); base != "" {
			set(base+"monitors/import", "layout.back_up")
		}
	}
}
