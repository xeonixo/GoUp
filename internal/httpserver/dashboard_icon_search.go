package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	store "goup/internal/store/sqlite"
)

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
			URL:       searchResultIconURL(appBase, item.entry),
			Source:    item.entry.Source,
			Preferred: item.entry.Preferred,
		})
	}
	return results, nil
}

func searchResultIconURL(appBase string, entry dashboardIconEntry) string {
	iconURL := localIconURL(appBase, entry.Value)
	if iconURL != "" && entry.Source == groupIconSourceDashboard {
		iconURL += "&remote=1"
	}
	return iconURL
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

func (s *Server) loadDashboardIconAsset(ctx context.Context, tenantSlug string, slug string, allowRemote bool) ([]byte, string, error) {
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
	if !allowRemote {
		return nil, "", os.ErrNotExist
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
