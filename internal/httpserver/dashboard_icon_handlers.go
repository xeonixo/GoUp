package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
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
		payload, contentType, err = s.loadDashboardIconAsset(r.Context(), s.tenantSlugForRequest(r), value, r.URL.Query().Get("remote") == "1")
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
