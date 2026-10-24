package httpserver

import (
	"database/sql"
	"fmt"
	"goup/internal/monitor"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// heartbeatPingURL builds the public ping URL of a heartbeat monitor.
func heartbeatPingURL(baseURL, tenantSlug, token string) string {
	if token == "" {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/hb/" + url.PathEscape(tenantSlug) + "/" + token
}

// applyHeartbeatURLs fills the ping URL of heartbeat monitors in views for admins; the token is
// a secret, so read-only users never receive it.
func (s *Server) applyHeartbeatURLs(r *http.Request, views []monitorView) {
	user := s.currentUser(r)
	isAdmin := user == nil || strings.EqualFold(strings.TrimSpace(user.Role), "admin")
	slug := s.tenantSlugForRequest(r)
	for i := range views {
		if views[i].HeartbeatToken == "" {
			continue
		}
		if isAdmin {
			pingURL := heartbeatPingURL(s.cfg.BaseURL, slug, views[i].HeartbeatToken)
			views[i].HeartbeatURL = pingURL
			views[i].HeartbeatCurl = "curl -fsS -m 10 --retry 3 " + shellQuote(pingURL)
			views[i].HeartbeatCurlFail = "curl -fsS -m 10 --retry 3 --data-raw 'error message' " + shellQuote(pingURL+"/fail")
		}
		views[i].HeartbeatToken = ""
	}
}

// shellQuote wraps value in single quotes for safe use in a POSIX shell command line.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// heartbeatSubtitle is the card subtitle of a heartbeat monitor, e.g. "Heartbeat · alle 1d · Toleranz 5m".
func heartbeatSubtitle(item monitor.Monitor) string {
	return fmt.Sprintf("Heartbeat · alle %s · Toleranz %s", formatCompactDuration(item.Interval), formatCompactDuration(item.Timeout))
}

// formatCompactDuration renders whole periods compactly: 90s, 5m, 2h, 1d, 1h30m.
func formatCompactDuration(d time.Duration) string {
	seconds := int64(d / time.Second)
	if seconds <= 0 {
		return "0s"
	}
	switch {
	case seconds%86400 == 0:
		return strconv.FormatInt(seconds/86400, 10) + "d"
	case seconds%3600 == 0:
		return strconv.FormatInt(seconds/3600, 10) + "h"
	case seconds%60 == 0 && seconds < 3600:
		return strconv.FormatInt(seconds/60, 10) + "m"
	case seconds%60 == 0:
		return fmt.Sprintf("%dh%dm", seconds/3600, seconds%3600/60)
	}
	return strconv.FormatInt(seconds, 10) + "s"
}

// handleRegenerateHeartbeatToken replaces the ping token; the old URL stops working at once.
func (s *Server) handleRegenerateHeartbeatToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := s.tenantAppBase(r)
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, base+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, base+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, base+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}
	if _, err := appStore.RegenerateHeartbeatToken(r.Context(), id); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, base+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, base+"?error="+url.QueryEscape("Token konnte nicht erzeugt werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "monitor.heartbeat.regenerate", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))
	http.Redirect(w, r, base+"monitors/"+strconv.FormatInt(id, 10)+"?notice="+url.QueryEscape("Heartbeat-URL neu erzeugt"), http.StatusSeeOther)
}
