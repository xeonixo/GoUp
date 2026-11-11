package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/internal/version"
)

const (
	statusPageCacheTTL       = 30 * time.Second
	statusPageHistoryDays    = 90
	statusPageIncidentLimit  = 20
	statusPageLogoNamePrefix = "status-logo-"
)

var statusPageTrendRange = trendRange{Value: "90d", Label: "90d", BucketSize: 24 * time.Hour, Buckets: statusPageHistoryDays, Step: "day"}

// statusPageBarView is one day in the 90-day uptime bar.
type statusPageBarView struct {
	Class string
	Label string
}

type statusPageMonitorView struct {
	Name        string
	StatusClass string
	StatusLabel string
	UptimeLabel string
	Bars        []statusPageBarView
}

type statusPageGroupView struct {
	Name     string
	Monitors []statusPageMonitorView
}

// statusPageMaintenanceView describes an announced or running maintenance window.
type statusPageMaintenanceView struct {
	Title    string
	StartsAt string
	EndsAt   string
}

type statusPageIncidentView struct {
	Name       string
	StartedAt  string
	ResolvedAt string
	Open       bool
}

type statusPageSubscribeMonitorView struct {
	ID   int64
	Name string
}

// statusPageView is the public view model. It deliberately has no field for targets, hosts,
// URLs, error messages or latencies.
type statusPageView struct {
	Title          string
	Description    string
	LogoURL        string
	BrandCSSURL    string
	FeedURL        string
	SubscribeURL   string
	HideGoUpFooter bool
	OverallClass   string
	OverallLabel   string
	UpdatedAt      string
	Groups         []statusPageGroupView
	// MaintenanceNotices lists running and upcoming (within announce_hours) maintenance
	// windows that affect at least one shown monitor. Only title and time range are public.
	MaintenanceNotices []statusPageMaintenanceView
	Incidents          []statusPageIncidentView
	SubscribeMonitors  []statusPageSubscribeMonitorView
	SubscriptionsOn    bool
	Notice             string
	Error              string
}

func statusPageLanguage(r *http.Request) string {
	header := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(header, "de") {
		return "de"
	}
	if strings.HasPrefix(header, "en") {
		return "en"
	}
	return defaultUILanguage
}

func (s *Server) loadEnabledStatusPageSettings(r *http.Request) (store.StatusPageSettings, bool, error) {
	appStore, err := s.appStore(r)
	if err != nil {
		return store.StatusPageSettings{}, false, err
	}
	settings, err := appStore.GetStatusPageSettings(r.Context())
	if err != nil {
		return store.StatusPageSettings{}, false, err
	}
	if !settings.Enabled {
		return settings, false, nil
	}
	return settings, true, nil
}

// authorizeStatusPageAccess enforces optional bearer token access for the public status page.
func (s *Server) authorizeStatusPageAccess(w http.ResponseWriter, r *http.Request, settings store.StatusPageSettings) bool {
	if settings.AccessMode != "token" {
		return true
	}
	limiterKey := "status-page|" + s.rateLimitIP(r)
	if allowed, wait := s.bootstrapAllowed(limiterKey, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return false
	}
	if store.StatusPageAccessTokenMatches(bearerToken(r), settings.AccessTokenHash) {
		return true
	}
	s.registerBootstrapFailure(limiterKey, time.Now())
	w.Header().Set("WWW-Authenticate", `Bearer realm="goup-status"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func applyStatusPageHeaders(w http.ResponseWriter, settings store.StatusPageSettings) {
	if settings.NoIndex {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	}
	if settings.AccessMode == "token" {
		w.Header().Set("Cache-Control", "private, no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=30")
	}
}

// handleStatusPage serves the public, login-free status page of a tenant at /{slug}/status.
func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.NotFound(w, r)
		return
	}
	settings, enabled, err := s.loadEnabledStatusPageSettings(r)
	if err != nil {
		s.logger.Error("load status page settings failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	if !enabled {
		http.NotFound(w, r)
		return
	}
	if !s.authorizeStatusPageAccess(w, r, settings) {
		return
	}

	lang := statusPageLanguage(r)
	subsOn := s.statusSubscriptionsEnabled(r)
	key := statusPageCacheKey(tenantID, lang, subsOn)
	now := time.Now()
	flash := strings.TrimSpace(r.URL.Query().Get("notice")) != "" || strings.TrimSpace(r.URL.Query().Get("error")) != ""
	useCache := settings.AccessMode != "token" && !flash

	var (
		entry statusPageCacheEntry
		ok    bool
	)
	if useCache {
		entry, ok = s.statusCache.get(key, now)
	}
	if !ok {
		body, err := s.buildStatusPage(r, tenantID, settings, lang, now)
		if err != nil {
			s.logger.Error("render status page failed", "tenant_id", tenantID, "error", err)
			http.Error(w, "status page unavailable", http.StatusInternalServerError)
			return
		}
		entry = statusPageCacheEntry{body: body, expiresAt: now.Add(statusPageCacheTTL)}
		if useCache {
			s.statusCache.put(key, entry, now)
		}
	}
	if entry.body == nil {
		http.NotFound(w, r)
		return
	}
	applyStatusPageHeaders(w, settings)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Accept-Language, Authorization")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(entry.body)
}

// handleStatusPageLogo serves the uploaded status-page logo at /{slug}/status/logo.
func (s *Server) handleStatusPageLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	settings, enabled, err := s.loadEnabledStatusPageSettings(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	if !enabled || strings.TrimSpace(settings.LogoRef) == "" {
		http.NotFound(w, r)
		return
	}
	if !s.authorizeStatusPageAccess(w, r, settings) {
		return
	}
	fileName := sanitizeUploadedIconName(settings.LogoRef)
	if fileName == "" || !strings.HasPrefix(fileName, statusPageLogoNamePrefix) {
		http.NotFound(w, r)
		return
	}
	payload, contentType, err := s.loadUploadedIcon(r, fileName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	applyStatusPageHeaders(w, settings)
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(payload)
}

// handleStatusPageBrandCSS serves a tiny stylesheet that sets --status-brand.
func (s *Server) handleStatusPageBrandCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	settings, enabled, err := s.loadEnabledStatusPageSettings(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	if !enabled || strings.TrimSpace(settings.BrandColor) == "" {
		http.NotFound(w, r)
		return
	}
	if !s.authorizeStatusPageAccess(w, r, settings) {
		return
	}
	applyStatusPageHeaders(w, settings)
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, ".status-page{--status-brand:%s;}\n", settings.BrandColor)
}

// buildStatusPage renders the page; it returns a nil body when the page is not enabled.
func (s *Server) buildStatusPage(r *http.Request, tenantID int64, settings store.StatusPageSettings, lang string, now time.Time) ([]byte, error) {
	appStore, err := s.appStore(r)
	if err != nil {
		return nil, err
	}
	if !settings.Enabled {
		return nil, nil
	}
	selected, err := appStore.ListStatusPageMonitors(r.Context())
	if err != nil {
		return nil, err
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return nil, err
	}
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendRangeStart(now, statusPageTrendRange))
	if err != nil {
		s.logger.Warn("load status page rollups failed", "tenant_id", tenantID, "error", err)
		rollups = nil
	}
	monitorIDs := make([]int64, 0, len(selected))
	for _, item := range selected {
		monitorIDs = append(monitorIDs, item.MonitorID)
	}
	incidents, err := appStore.ListStatusPageIncidents(r.Context(), monitorIDs, statusPageIncidentLimit)
	if err != nil {
		s.logger.Warn("load status page incidents failed", "tenant_id", tenantID, "error", err)
		incidents = nil
	}

	tenantName := ""
	if tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err == nil {
		tenantName = tenant.Name
	}
	translations := s.translationsForLanguage(lang)
	slug := tenantSlugFromRequest(r)
	view := buildStatusPageView(settings, selected, snapshots, rollups, incidents, tenantName, translations, now, appStore.MaintenanceSet(r.Context()), slug)
	view.SubscriptionsOn = s.statusSubscriptionsEnabled(r)
	view.Notice = resolveStatusPageFlash(translations, r.URL.Query().Get("notice"))
	view.Error = resolveStatusPageFlash(translations, r.URL.Query().Get("error"))

	data := pageData{
		Title:        view.Title,
		UILanguage:   lang,
		Translations: translations,
		HideTopbar:   true,
		StatusPage:   &view,
		Version:      version.Version,
		AssetVersion: assetVersion(),
		ManifestURL:  "/site.webmanifest",
		AppTitle:     "GoUp",
	}
	tmpl, ok := s.templates["status_page"]
	if !ok {
		return nil, http.ErrNotSupported
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildStatusPageView(settings store.StatusPageSettings, selected []store.StatusPageMonitor, snapshots []monitor.Snapshot, rollups []store.MonitorHourlyRollup, incidents []store.StatusPageIncident, tenantName string, tr map[string]string, now time.Time, maintenance monitor.MaintenanceSet, slug string) statusPageView {
	byID := make(map[int64]monitor.Snapshot, len(snapshots))
	for _, snap := range snapshots {
		byID[snap.Monitor.ID] = snap
	}
	rollupsByMonitor := groupRollupsByMonitor(rollups)

	view := statusPageView{
		Title:          strings.TrimSpace(settings.Title),
		Description:    strings.TrimSpace(settings.Description),
		HideGoUpFooter: settings.HideGoUpFooter,
		UpdatedAt:      now.UTC().Format("2006-01-02 15:04 UTC"),
	}
	if view.Title == "" {
		view.Title = strings.TrimSpace(tenantName)
	}
	if view.Title == "" {
		view.Title = "Status"
	}
	if strings.TrimSpace(settings.LogoRef) != "" && slug != "" {
		view.LogoURL = "/" + slug + "/status/logo"
	}
	if strings.TrimSpace(settings.BrandColor) != "" && slug != "" {
		view.BrandCSSURL = "/" + slug + "/status/brand.css"
	}
	if slug != "" {
		view.FeedURL = "/" + slug + "/status/feed.xml"
		view.SubscribeURL = "/" + slug + "/status/subscribe"
	}
	for _, item := range selected {
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			if snap, ok := byID[item.MonitorID]; ok {
				name = strings.TrimSpace(snap.Monitor.Name)
			}
		}
		if name == "" {
			continue
		}
		view.SubscribeMonitors = append(view.SubscribeMonitors, statusPageSubscribeMonitorView{
			ID:   item.MonitorID,
			Name: name,
		})
	}

	groupIndex := make(map[string]int)
	active, down, impaired, underMaintenance := 0, 0, 0, 0
	for _, item := range selected {
		snap, ok := byID[item.MonitorID]
		if !ok {
			continue
		}
		status := publicMonitorStatus(snap)
		if _, inMaintenance := maintenance.Active(snap.Monitor.ID, snap.Monitor.Group, now); inMaintenance && snap.Monitor.Enabled {
			status = "maintenance"
		}
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			name = strings.TrimSpace(snap.Monitor.Name)
		}
		points := buildTrendPoints(rollupsByMonitor[item.MonitorID], now, statusPageTrendRange)
		mv := statusPageMonitorView{
			Name:        name,
			StatusClass: "status-" + strings.ToUpper(status),
			StatusLabel: statusPageTr(tr, "status_page.status."+status, status),
			UptimeLabel: statusPageTr(tr, "status_page.no_data", "No data"),
			Bars:        make([]statusPageBarView, 0, len(points)),
		}
		up, effective := 0, 0
		for _, p := range points {
			day := p.BucketRaw
			if len(day) >= 10 {
				day = day[:10]
			}
			label := day + " · " + statusPageTr(tr, "status_page.no_data", "No data")
			if p.Class != "trend-none" {
				label = day + " · " + formatUptimePercent(p.UpChecks, p.EffectiveChecks)
				up += p.UpChecks
				effective += p.EffectiveChecks
			}
			mv.Bars = append(mv.Bars, statusPageBarView{Class: p.Class, Label: label})
		}
		if effective > 0 {
			mv.UptimeLabel = formatUptimePercent(up, effective)
		}

		switch status {
		case "down":
			active++
			down++
		case "degraded":
			active++
			impaired++
		case "up", "unknown":
			active++
		case "maintenance":
			underMaintenance++
		}

		group := strings.TrimSpace(snap.Monitor.Group)
		idx, exists := groupIndex[group]
		if !exists {
			idx = len(view.Groups)
			groupIndex[group] = idx
			view.Groups = append(view.Groups, statusPageGroupView{Name: group})
		}
		view.Groups[idx].Monitors = append(view.Groups[idx].Monitors, mv)
	}

	switch {
	case len(view.Groups) == 0:
		view.OverallClass = "is-none"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.empty", "No services to display")
	case active == 0 && underMaintenance > 0:
		view.OverallClass = "is-maintenance"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.maintenance", "Scheduled maintenance")
	case active > 0 && down == active:
		view.OverallClass = "is-down"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.down", "Outage")
	case down > 0 || impaired > 0:
		view.OverallClass = "is-partial"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.partial", "Partial outage")
	default:
		view.OverallClass = "is-ok"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.ok", "All systems operational")
	}
	view.MaintenanceNotices = buildStatusPageMaintenance(maintenance, selected, byID, now, settings.AnnounceHours)
	view.Incidents = buildStatusPageIncidents(incidents, tr)
	return view
}

func buildStatusPageIncidents(items []store.StatusPageIncident, tr map[string]string) []statusPageIncidentView {
	out := make([]statusPageIncidentView, 0, len(items))
	for _, item := range items {
		view := statusPageIncidentView{
			Name:      strings.TrimSpace(item.DisplayName),
			StartedAt: item.StartedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Open:      item.ResolvedAt == nil,
		}
		if item.ResolvedAt != nil {
			view.ResolvedAt = item.ResolvedAt.UTC().Format("2006-01-02 15:04 UTC")
		} else {
			view.ResolvedAt = statusPageTr(tr, "status_page.incident_ongoing", "Ongoing")
		}
		out = append(out, view)
	}
	return out
}

// buildStatusPageMaintenance lists running windows and those starting within announceHours
// that cover at least one monitor shown on the page. Descriptions and targets are never exposed.
func buildStatusPageMaintenance(set monitor.MaintenanceSet, selected []store.StatusPageMonitor, byID map[int64]monitor.Snapshot, now time.Time, announceHours int) []statusPageMaintenanceView {
	horizon := time.Duration(store.NormalizeAnnounceHours(announceHours)) * time.Hour
	var notices []statusPageMaintenanceView
	for _, occ := range set.Upcoming(now, now.Add(horizon)) {
		affects := false
		for _, item := range selected {
			if snap, ok := byID[item.MonitorID]; ok && occ.Window.Covers(snap.Monitor.ID, snap.Monitor.Group) {
				affects = true
				break
			}
		}
		if !affects {
			continue
		}
		notices = append(notices, statusPageMaintenanceView{
			Title:    strings.TrimSpace(occ.Window.Title),
			StartsAt: occ.Start.UTC().Format("2006-01-02 15:04 UTC"),
			EndsAt:   occ.End.UTC().Format("2006-01-02 15:04 UTC"),
		})
	}
	return notices
}

// publicMonitorStatus maps a snapshot to up, degraded, down, unknown or paused.
func publicMonitorStatus(snap monitor.Snapshot) string {
	if !snap.Monitor.Enabled {
		return "paused"
	}
	if snap.LastResult == nil {
		return "unknown"
	}
	switch snap.LastResult.Status {
	case monitor.StatusUp:
		return "up"
	case monitor.StatusDegraded:
		return "degraded"
	case monitor.StatusDown:
		return "down"
	}
	return "unknown"
}

func statusPageTr(tr map[string]string, key, fallback string) string {
	if value := strings.TrimSpace(tr[key]); value != "" {
		return value
	}
	return fallback
}

func (s *Server) storeUploadedStatusLogo(r *http.Request) (string, error) {
	file, header, err := r.FormFile("logo_upload")
	if err != nil {
		if err == http.ErrMissingFile {
			return "", nil
		}
		return "", fmt.Errorf("logo upload could not be read")
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, groupIconUploadMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("logo upload could not be read")
	}
	if len(payload) == 0 {
		return "", nil
	}
	if len(payload) > groupIconUploadMaxBytes {
		return "", fmt.Errorf("logo upload is too large (max. 2 MB)")
	}
	contentType := http.DetectContentType(payload)
	ext, ok := detectUploadedIconExtension(contentType, header.Filename)
	if !ok {
		return "", fmt.Errorf("only SVG, PNG, WEBP, JPEG or ICO logos are supported")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	baseName := sanitizeUploadedIconBaseName(header.Filename)
	if baseName == "" {
		baseName = "logo"
	}
	dir := s.uploadedIconsDir(s.tenantSlugForRequest(r))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("upload directory could not be prepared")
	}
	prefix := statusPageLogoNamePrefix + hash + "-"
	if existing := findUploadedIconByHashPrefix(dir, prefix); existing != "" {
		return existing, nil
	}
	fileName := prefix + baseName + ext
	iconPath, err := safePathWithinDir(dir, fileName)
	if err != nil {
		return "", fmt.Errorf("logo upload could not be stored")
	}
	if err := os.WriteFile(iconPath, payload, 0o644); err != nil {
		return "", fmt.Errorf("logo upload could not be stored")
	}
	return fileName, nil
}

func findUploadedIconByHashPrefix(dir, prefix string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		name := sanitizeUploadedIconName(item.Name())
		if strings.HasPrefix(name, prefix) {
			return name
		}
	}
	return ""
}
