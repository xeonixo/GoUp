package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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
