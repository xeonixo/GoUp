package httpserver

import (
	"net/url"
	"strings"
)

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
