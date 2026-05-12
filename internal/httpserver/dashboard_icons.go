package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	store "goup/internal/store/sqlite"
)

type dashboardIconAsset struct {
	Payload     []byte
	ContentType string
}

type dashboardIconMetadata struct {
	Aliases    []string `json:"aliases"`
	Categories []string `json:"categories"`
}

type dashboardIconEntry struct {
	Slug       string
	Label      string
	SearchText string
	Value      string
	Source     string
	Preferred  bool
}

type dashboardIconSearchResult struct {
	Value     string `json:"value"`
	Slug      string `json:"slug"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	Source    string `json:"source"`
	Preferred bool   `json:"preferred"`
}

var (
	tenantIconDirKeyPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	dashboardIconFileSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

func (s *Server) handleSearchDashboardIcons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}
	results, err := s.searchDashboardIcons(r.Context(), s.tenantSlugForRequest(r), appStore, s.tenantAppBase(r), strings.TrimSpace(r.URL.Query().Get("q")), dashboardIconSearchLimit)
	if err != nil {
		http.Error(w, "unable to search dashboard icons", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Results []dashboardIconSearchResult `json:"results"`
	}{Results: results}); err != nil {
		http.Error(w, "unable to encode dashboard icons", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRenderIcon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ref := normalizeGroupIconReference(strings.TrimSpace(r.URL.Query().Get("ref")))
	if ref == "" {
		http.NotFound(w, r)
		return
	}

	var (
		payload     []byte
		contentType string
		err         error
	)
	switch kind, value := splitGroupIconReference(ref); kind {
	case groupIconSourceUpload:
		payload, contentType, err = s.loadUploadedIcon(r, value)
	default:
		payload, contentType, err = s.loadDashboardIconAsset(r.Context(), s.tenantSlugForRequest(r), value)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(payload)
}

func (s *Server) uploadedIconsDir(tenantSlug string) string {
	tenantSlug = normalizeTenantIconDirKey(tenantSlug)
	if tenantSlug == "" {
		tenantSlug = "default"
	}
	return filepath.Join(s.cfg.DataDir, "icons", tenantSlug)
}

func (s *Server) persistedDashboardIconsDir(tenantSlug string) string {
	return filepath.Join(s.uploadedIconsDir(tenantSlug), "dashboard")
}

func (s *Server) storeUploadedGroupIcon(r *http.Request, groupName string) (string, error) {
	file, header, err := r.FormFile("icon_upload")
	if err != nil {
		if err == http.ErrMissingFile {
			return "", nil
		}
		return "", fmt.Errorf("Icon-Upload konnte nicht gelesen werden")
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, groupIconUploadMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gelesen werden")
	}
	if len(payload) == 0 {
		return "", nil
	}
	if len(payload) > groupIconUploadMaxBytes {
		return "", fmt.Errorf("Icon-Upload ist zu groß (max. 2 MB)")
	}

	contentType := http.DetectContentType(payload)
	ext, ok := detectUploadedIconExtension(contentType, header.Filename)
	if !ok {
		return "", fmt.Errorf("Nur SVG, PNG, WEBP, JPEG oder ICO werden als Gruppen-Icon unterstützt")
	}

	hashBytes := sha256.Sum256(payload)
	hash := hex.EncodeToString(hashBytes[:])
	baseName := sanitizeUploadedIconBaseName(header.Filename)
	if baseName == "" {
		baseName = normalizeDashboardIconSlug(groupName)
	}
	if baseName == "" {
		baseName = "custom-icon"
	}

	dir := s.uploadedIconsDir(s.tenantSlugForRequest(r))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("Upload-Verzeichnis konnte nicht vorbereitet werden")
	}
	if existing := findUploadedIconByHash(dir, hash); existing != "" {
		return groupIconUploadPrefix + existing, nil
	}

	fileName := hash + "-" + baseName + ext
	iconPath, err := safePathWithinDir(dir, fileName)
	if err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gespeichert werden")
	}
	if err := os.WriteFile(iconPath, payload, 0o644); err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gespeichert werden")
	}
	return groupIconUploadPrefix + fileName, nil
}

func (s *Server) loadUploadedIcon(r *http.Request, fileName string) ([]byte, string, error) {
	fileName = sanitizeUploadedIconName(fileName)
	if fileName == "" {
		return nil, "", os.ErrNotExist
	}
	iconPath, err := safePathWithinDir(s.uploadedIconsDir(s.tenantSlugForRequest(r)), fileName)
	if err != nil {
		return nil, "", os.ErrNotExist
	}
	payload, err := os.ReadFile(iconPath)
	if err != nil {
		return nil, "", err
	}
	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		contentType = http.DetectContentType(payload)
	}
	return payload, contentType, nil
}

func (s *Server) persistSelectedDashboardIcon(ctx context.Context, tenantSlug string, ref string) error {
	kind, slug := splitGroupIconReference(ref)
	slug = sanitizeDashboardIconFileSlug(slug)
	if kind != groupIconSourceDashboard || slug == "" {
		return nil
	}
	known, err := s.dashboardIconExists(ctx, slug)
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht geprüft werden")
	}
	if !known {
		return nil
	}
	payload, _, err := s.loadDashboardIconAsset(ctx, tenantSlug, slug)
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	dir := s.persistedDashboardIconsDir(tenantSlug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("Dashboard-Icon-Verzeichnis konnte nicht vorbereitet werden")
	}
	iconPath, err := safePathWithinDir(dir, slug+".svg")
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	if err := os.WriteFile(iconPath, payload, 0o644); err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	return nil
}

func (s *Server) dashboardIconExists(ctx context.Context, slug string) (bool, error) {
	slug = sanitizeDashboardIconFileSlug(slug)
	if slug == "" {
		return false, nil
	}
	entries, err := s.loadDashboardIconIndex(ctx)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Source == groupIconSourceDashboard && entry.Slug == slug {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) loadPersistedDashboardIcon(tenantSlug string, slug string) ([]byte, string, error) {
	slug = sanitizeDashboardIconFileSlug(slug)
	if slug == "" {
		return nil, "", os.ErrNotExist
	}
	iconPath, err := safePathWithinDir(s.persistedDashboardIconsDir(tenantSlug), slug+".svg")
	if err != nil {
		return nil, "", os.ErrNotExist
	}
	payload, err := os.ReadFile(iconPath)
	if err != nil {
		return nil, "", err
	}
	contentType := mime.TypeByExtension(".svg")
	if contentType == "" {
		contentType = http.DetectContentType(payload)
	}
	return payload, contentType, nil
}

func sanitizeUploadedIconName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == ".." || name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\\`) {
		return ""
	}
	return name
}

func sanitizeDashboardIconFileSlug(slug string) string {
	slug = normalizeDashboardIconSlug(slug)
	if slug == "" || strings.Contains(slug, "..") || strings.ContainsAny(slug, `/\\`) {
		return ""
	}
	if !dashboardIconFileSlugPattern.MatchString(slug) {
		return ""
	}
	return slug
}

func normalizeTenantIconDirKey(slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return ""
	}
	if !tenantIconDirKeyPattern.MatchString(slug) {
		return ""
	}
	return slug
}

func safePathWithinDir(baseDir string, name string) (string, error) {
	baseDir = strings.TrimSpace(baseDir)
	name = strings.TrimSpace(name)
	if baseDir == "" || name == "" {
		return "", fmt.Errorf("invalid path")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("invalid path")
	}
	cleanName := filepath.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(absBaseDir, cleanName)
	rel, err := filepath.Rel(absBaseDir, fullPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	return fullPath, nil
}

func sanitizeUploadedIconBaseName(name string) string {
	name = sanitizeUploadedIconName(name)
	if name == "" {
		return ""
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	base = normalizeDashboardIconSlug(base)
	if base == "" {
		return ""
	}
	return base
}

// detectUploadedIconExtension validates an uploaded icon by requiring BOTH a
// whitelisted file extension AND a matching MIME type.  Checking the extension
// first prevents an attacker from uploading a file whose content passes MIME
// sniffing but whose extension hints at a dangerous type.
func detectUploadedIconExtension(contentType string, originalName string) (string, bool) {
	// Step 1: validate the file extension against the strict whitelist.
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(originalName)))
	if ext == ".jpeg" {
		ext = ".jpg"
	}
	allowedExts := map[string]string{
		".svg":  "image/svg+xml",
		".png":  "image/png",
		".webp": "image/webp",
		".jpg":  "image/jpeg",
		".ico":  "image/x-icon",
	}
	expectedMIME, extOK := allowedExts[ext]
	if !extOK {
		return "", false
	}

	// Step 2: confirm the detected MIME type matches the extension.
	detectedMIME := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch detectedMIME {
	case "image/svg+xml", "image/png", "image/webp", "image/jpeg",
		"image/x-icon", "image/vnd.microsoft.icon":
		// Acceptable MIME; verify it corresponds to the declared extension.
		if detectedMIME == "image/vnd.microsoft.icon" {
			detectedMIME = "image/x-icon"
		}
		if detectedMIME != expectedMIME {
			return "", false
		}
		return ext, true
	default:
		return "", false
	}
}

func findUploadedIconByHash(dir string, hash string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	prefix := hash + "-"
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

func formatUploadedIconLabel(fileName string) string {
	name := sanitizeUploadedIconName(fileName)
	if name == "" {
		return "Eigenes Icon"
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if len(base) > 65 && base[64] == '-' {
		base = base[65:]
	}
	label := formatDashboardIconLabel(base)
	if label == "" {
		return "Eigenes Icon"
	}
	return label
}

func normalizeDashboardIconSlug(slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	slug = strings.ReplaceAll(slug, " ", "-")
	return slug
}

const (
	groupIconSourceDashboard = "dashboard"
	groupIconSourceUpload    = "upload"
)

func normalizeGroupIconReference(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(ref), groupIconUploadPrefix) {
		name := sanitizeUploadedIconName(strings.TrimSpace(ref[len(groupIconUploadPrefix):]))
		if name == "" {
			return ""
		}
		return groupIconUploadPrefix + name
	}
	return normalizeDashboardIconSlug(ref)
}

func splitGroupIconReference(ref string) (kind string, value string) {
	ref = normalizeGroupIconReference(ref)
	if strings.HasPrefix(ref, groupIconUploadPrefix) {
		return groupIconSourceUpload, strings.TrimSpace(ref[len(groupIconUploadPrefix):])
	}
	return groupIconSourceDashboard, normalizeDashboardIconSlug(ref)
}

func effectiveGroupIconReference(groupName string, storedRef string) string {
	storedRef = normalizeGroupIconReference(storedRef)
	if storedRef != "" {
		return storedRef
	}
	return normalizeDashboardIconSlug(groupName)
}

func localIconURL(appBase string, ref string) string {
	ref = normalizeGroupIconReference(ref)
	if ref == "" {
		return ""
	}
	base := strings.TrimSpace(appBase)
	if base == "" {
		base = "/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + "icons/render?ref=" + url.QueryEscape(ref)
}

func (s *Server) searchDashboardIcons(ctx context.Context, tenantSlug string, appStore *store.Store, appBase string, query string, limit int) ([]dashboardIconSearchResult, error) {
	remoteEntries, err := s.loadDashboardIconIndex(ctx)
	if err != nil {
		return nil, err
	}
	entries := s.mergeIconEntries(s.loadRecycledIconEntries(ctx, tenantSlug, appStore), remoteEntries)
	if limit <= 0 {
		limit = dashboardIconSearchLimit
	}
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	type scoredIcon struct {
		entry     dashboardIconEntry
		score     int
		preferred bool
	}
	scored := make([]scoredIcon, 0, len(entries))
	for _, entry := range entries {
		score := 99
		switch {
		case normalizedQuery == "":
			score = 0
		case entry.Slug == normalizedQuery:
			score = 0
		case strings.HasPrefix(entry.Slug, normalizedQuery):
			score = 1
		case strings.HasPrefix(strings.ToLower(entry.Label), normalizedQuery):
			score = 2
		case strings.Contains(entry.Slug, normalizedQuery):
			score = 3
		case strings.Contains(entry.SearchText, normalizedQuery):
			score = 4
		default:
			continue
		}
		scored = append(scored, scoredIcon{entry: entry, score: score, preferred: entry.Preferred})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		if scored[i].preferred != scored[j].preferred {
			return scored[i].preferred
		}
		if scored[i].entry.Source != scored[j].entry.Source {
			return scored[i].entry.Source < scored[j].entry.Source
		}
		return scored[i].entry.Slug < scored[j].entry.Slug
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	results := make([]dashboardIconSearchResult, 0, len(scored))
	for _, item := range scored {
		results = append(results, dashboardIconSearchResult{
			Value:     item.entry.Value,
			Slug:      item.entry.Slug,
			Label:     item.entry.Label,
			URL:       localIconURL(appBase, item.entry.Value),
			Source:    item.entry.Source,
			Preferred: item.entry.Preferred,
		})
	}
	return results, nil
}

func (s *Server) loadDashboardIconIndex(ctx context.Context) ([]dashboardIconEntry, error) {
	s.iconIndexMu.RLock()
	if len(s.iconIndex) > 0 {
		cached := append([]dashboardIconEntry(nil), s.iconIndex...)
		s.iconIndexMu.RUnlock()
		return cached, nil
	}
	s.iconIndexMu.RUnlock()

	s.iconIndexMu.Lock()
	defer s.iconIndexMu.Unlock()
	if len(s.iconIndex) > 0 {
		return append([]dashboardIconEntry(nil), s.iconIndex...), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dashboardIconsMetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build dashboard icons metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch dashboard icons metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard icons metadata returned %s", resp.Status)
	}
	metadata := make(map[string]dashboardIconMetadata)
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode dashboard icons metadata: %w", err)
	}
	entries := make([]dashboardIconEntry, 0, len(metadata))
	for slug, meta := range metadata {
		normalizedSlug := normalizeDashboardIconSlug(slug)
		if normalizedSlug == "" {
			continue
		}
		entries = append(entries, dashboardIconEntry{
			Slug:       normalizedSlug,
			Label:      formatDashboardIconLabel(normalizedSlug),
			SearchText: buildDashboardIconSearchText(normalizedSlug, meta),
			Value:      normalizedSlug,
			Source:     groupIconSourceDashboard,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Slug < entries[j].Slug
	})
	s.iconIndex = entries
	return append([]dashboardIconEntry(nil), entries...), nil
}

func (s *Server) mergeIconEntries(priority []dashboardIconEntry, fallback []dashboardIconEntry) []dashboardIconEntry {
	merged := make([]dashboardIconEntry, 0, len(priority)+len(fallback))
	seen := make(map[string]struct{}, len(priority)+len(fallback))
	for _, entry := range append(append([]dashboardIconEntry(nil), priority...), fallback...) {
		value := normalizeGroupIconReference(entry.Value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		entry.Value = value
		entry.Slug = strings.TrimSpace(entry.Slug)
		if entry.Slug == "" {
			_, entry.Slug = splitGroupIconReference(value)
		}
		seen[value] = struct{}{}
		merged = append(merged, entry)
	}
	return merged
}

func (s *Server) loadRecycledIconEntries(ctx context.Context, tenantSlug string, appStore *store.Store) []dashboardIconEntry {
	metadata, err := appStore.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return s.loadUploadedIconEntries(tenantSlug, nil)
	}

	usedRefs := make(map[string][]string, len(metadata))
	entries := make([]dashboardIconEntry, 0, len(metadata))
	for _, item := range metadata {
		ref := normalizeGroupIconReference(item.IconSlug)
		if ref == "" {
			continue
		}
		usedRefs[ref] = append(usedRefs[ref], strings.TrimSpace(item.Name))
	}
	for ref, groupNames := range usedRefs {
		kind, value := splitGroupIconReference(ref)
		label := formatDashboardIconLabel(value)
		searchParts := []string{strings.ToLower(label), strings.ToLower(value)}
		if kind == groupIconSourceUpload {
			label = formatUploadedIconLabel(value)
			searchParts = append(searchParts, strings.ToLower(strings.TrimSuffix(value, filepath.Ext(value))), "upload", "custom")
		}
		for _, groupName := range groupNames {
			if trimmed := strings.ToLower(strings.TrimSpace(groupName)); trimmed != "" {
				searchParts = append(searchParts, trimmed)
			}
		}
		entries = append(entries, dashboardIconEntry{
			Slug:       value,
			Label:      label,
			SearchText: strings.Join(searchParts, " "),
			Value:      ref,
			Source:     kind,
			Preferred:  true,
		})
	}
	return s.mergeIconEntries(entries, s.loadUploadedIconEntries(tenantSlug, usedRefs))
}

func (s *Server) loadUploadedIconEntries(tenantSlug string, usedRefs map[string][]string) []dashboardIconEntry {
	dir := s.uploadedIconsDir(tenantSlug)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	results := make([]dashboardIconEntry, 0, len(entries))
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		name := sanitizeUploadedIconName(item.Name())
		if name == "" {
			continue
		}
		ref := groupIconUploadPrefix + name
		label := formatUploadedIconLabel(name)
		searchParts := []string{strings.ToLower(label), strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name))), "upload", "custom"}
		preferred := false
		if usedRefs != nil {
			if groups := usedRefs[ref]; len(groups) > 0 {
				preferred = true
				for _, groupName := range groups {
					if trimmed := strings.ToLower(strings.TrimSpace(groupName)); trimmed != "" {
						searchParts = append(searchParts, trimmed)
					}
				}
			}
		}
		results = append(results, dashboardIconEntry{
			Slug:       strings.TrimSuffix(name, filepath.Ext(name)),
			Label:      label,
			SearchText: strings.Join(searchParts, " "),
			Value:      ref,
			Source:     groupIconSourceUpload,
			Preferred:  preferred,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Preferred != results[j].Preferred {
			return results[i].Preferred
		}
		return results[i].Label < results[j].Label
	})
	return results
}

func (s *Server) loadDashboardIconAsset(ctx context.Context, tenantSlug string, slug string) ([]byte, string, error) {
	slug = normalizeDashboardIconSlug(slug)
	if slug == "" {
		return nil, "", os.ErrNotExist
	}

	if payload, contentType, err := s.loadPersistedDashboardIcon(tenantSlug, slug); err == nil {
		return payload, contentType, nil
	}

	s.iconAssetMu.RLock()
	if asset, ok := s.iconAssets[slug]; ok && len(asset.Payload) > 0 {
		payload := append([]byte(nil), asset.Payload...)
		contentType := asset.ContentType
		s.iconAssetMu.RUnlock()
		return payload, contentType, nil
	}
	s.iconAssetMu.RUnlock()

	s.iconAssetMu.Lock()
	defer s.iconAssetMu.Unlock()
	if asset, ok := s.iconAssets[slug]; ok && len(asset.Payload) > 0 {
		return append([]byte(nil), asset.Payload...), asset.ContentType, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dashboardIconsBaseURL+"/svg/"+url.PathEscape(slug)+".svg", nil)
	if err != nil {
		return nil, "", fmt.Errorf("build dashboard icon request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch dashboard icon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("dashboard icon returned %s", resp.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, groupIconUploadMaxBytes))
	if err != nil {
		return nil, "", fmt.Errorf("read dashboard icon: %w", err)
	}
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = mime.TypeByExtension(".svg")
	}
	asset := dashboardIconAsset{Payload: payload, ContentType: contentType}
	s.iconAssets[slug] = asset
	return append([]byte(nil), payload...), contentType, nil
}

func buildDashboardIconSearchText(slug string, meta dashboardIconMetadata) string {
	parts := []string{strings.ToLower(strings.TrimSpace(slug)), strings.ToLower(formatDashboardIconLabel(slug))}
	for _, alias := range meta.Aliases {
		if value := strings.ToLower(strings.TrimSpace(alias)); value != "" {
			parts = append(parts, value)
		}
	}
	for _, category := range meta.Categories {
		if value := strings.ToLower(strings.TrimSpace(category)); value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " ")
}

func formatDashboardIconLabel(slug string) string {
	parts := strings.Fields(strings.ReplaceAll(normalizeDashboardIconSlug(slug), "-", " "))
	for idx, part := range parts {
		if part == "" {
			continue
		}
		parts[idx] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
