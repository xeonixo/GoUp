package httpserver

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type atomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	Title   string      `xml:"title"`
	Links   []atomLink  `xml:"link"`
	ID      string      `xml:"id"`
	Updated string      `xml:"updated"`
	Entries []atomEntry `xml:"entry"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
}

type atomEntry struct {
	Title     string    `xml:"title"`
	ID        string    `xml:"id"`
	Updated   string    `xml:"updated"`
	Published string    `xml:"published"`
	Links     []atomLink `xml:"link"`
	Summary   string    `xml:"summary"`
}

// handleStatusPageFeed serves an Atom feed of public status-page incidents at
// /{slug}/status/feed.xml (and .atom).
func (s *Server) handleStatusPageFeed(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("load status page settings for feed failed", "tenant_id", tenantID, "error", err)
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

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	selected, err := appStore.ListStatusPageMonitors(r.Context())
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	monitorIDs := make([]int64, 0, len(selected))
	for _, item := range selected {
		monitorIDs = append(monitorIDs, item.MonitorID)
	}
	incidents, err := appStore.ListStatusPageIncidents(r.Context(), monitorIDs, statusPageIncidentLimit)
	if err != nil {
		s.logger.Warn("load status page feed incidents failed", "tenant_id", tenantID, "error", err)
		incidents = nil
	}

	lang := statusPageLanguage(r)
	tr := s.translationsForLanguage(lang)
	slug := tenantSlugFromRequest(r)
	base := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	pageURL := base + "/" + slug + "/status"
	feedURL := pageURL + "/feed.xml"

	title := strings.TrimSpace(settings.Title)
	if title == "" {
		if tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err == nil {
			title = strings.TrimSpace(tenant.Name)
		}
	}
	if title == "" {
		title = "Status"
	}
	feedTitle := title + " — " + statusPageTr(tr, "status_page.incidents", "Recent incidents")

	now := time.Now().UTC()
	updated := now
	entries := make([]atomEntry, 0, len(incidents))
	for _, item := range incidents {
		entryUpdated := item.StartedAt.UTC()
		if item.ResolvedAt != nil {
			entryUpdated = item.ResolvedAt.UTC()
		}
		if entryUpdated.After(updated) {
			updated = entryUpdated
		}
		name := strings.TrimSpace(item.DisplayName)
		state := statusPageTr(tr, "status_page.incident_ongoing", "Ongoing")
		summary := name + " — " + statusPageTr(tr, "status_page.status.down", "Outage") + " · " + item.StartedAt.UTC().Format(time.RFC3339)
		if item.ResolvedAt != nil {
			state = statusPageTr(tr, "status_page.status.up", "Operational")
			summary = name + " — " + statusPageTr(tr, "status_page.feed.resolved", "Resolved") + " · " +
				item.StartedAt.UTC().Format(time.RFC3339) + " – " + item.ResolvedAt.UTC().Format(time.RFC3339)
		}
		entryTitle := name + " — " + state
		entries = append(entries, atomEntry{
			Title:     entryTitle,
			ID:        fmt.Sprintf("tag:goup:%s:incident:%d:%d", slug, item.MonitorID, item.StartedAt.UTC().Unix()),
			Updated:   entryUpdated.Format(time.RFC3339),
			Published: item.StartedAt.UTC().Format(time.RFC3339),
			Links:     []atomLink{{Href: pageURL, Rel: "alternate", Type: "text/html"}},
			Summary:   summary,
		})
	}

	feed := atomFeed{
		Xmlns:   "http://www.w3.org/2005/Atom",
		Title:   feedTitle,
		ID:      "tag:goup:" + slug + ":status",
		Updated: updated.Format(time.RFC3339),
		Links: []atomLink{
			{Href: pageURL, Rel: "alternate", Type: "text/html"},
			{Href: feedURL, Rel: "self", Type: "application/atom+xml"},
		},
		Entries: entries,
	}

	payload, err := xml.MarshalIndent(feed, "", "  ")
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	body := append([]byte(xml.Header), payload...)

	applyStatusPageHeaders(w, settings)
	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("Vary", "Accept-Language, Authorization")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// statusPageFeedPath reports whether path parts refer to the Atom feed endpoint.
func statusPageFeedPath(parts []string) bool {
	if len(parts) != 3 || parts[1] != "status" {
		return false
	}
	switch strings.ToLower(parts[2]) {
	case "feed.xml", "feed.atom":
		return true
	default:
		return false
	}
}
