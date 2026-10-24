package httpserver

import (
	"encoding/json"
	"goup/internal/monitor"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type monitorExportRecord struct {
	Name                 string `json:"name"`
	Group                string `json:"group"`
	Kind                 string `json:"kind"`
	Target               string `json:"target"`
	IntervalSeconds      int    `json:"interval_seconds"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
	Enabled              bool   `json:"enabled"`
	TLSMode              string `json:"tls_mode"`
	ExpectedStatusCode   *int   `json:"expected_status_code"`
	ExpectedText         string `json:"expected_text"`
	NotifyOnRecovery     bool   `json:"notify_on_recovery"`
	RetryCount           int    `json:"retry_count"`
	RetryIntervalSeconds int    `json:"retry_interval_seconds"`
	ConfirmAfter         int    `json:"confirm_after,omitempty"`
	RemindEveryMinutes   int    `json:"remind_every_minutes,omitempty"`
	ExecutorKind         string `json:"executor_kind"`
	ExecutorRef          string `json:"executor_ref"`
}

type monitorExportPayload struct {
	Version    int                   `json:"version"`
	ExportedAt string                `json:"exported_at"`
	Monitors   []monitorExportRecord `json:"monitors"`
}

// importPreviewRow holds one monitor's data for the preview/edit template.
type importPreviewRow struct {
	Index                int
	Name                 string
	Group                string
	Kind                 string
	Target               string
	IntervalSeconds      int
	TimeoutSeconds       int
	Enabled              bool
	TLSMode              string
	ExpectedStatusCode   string // empty string means null
	ExpectedText         string
	NotifyOnRecovery     bool
	RetryCount           int
	RetryIntervalSeconds int
	ConfirmAfter         int
	RemindEveryMinutes   int
	ExecutorKind         string
	ExecutorRef          string
}

func (s *Server) handleMonitorExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	// Optional ?id= filters the export to a single monitor.
	var filterID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("id")); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || parsed <= 0 {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
			return
		}
		filterID = parsed
	}

	records := make([]monitorExportRecord, 0, len(snapshots))
	for _, snap := range snapshots {
		m := snap.Monitor
		if filterID != 0 && m.ID != filterID {
			continue
		}
		executorKind := m.ExecutorKind
		if executorKind == "" {
			executorKind = "local"
		}
		records = append(records, monitorExportRecord{
			Name:                 m.Name,
			Group:                m.Group,
			Kind:                 string(m.Kind),
			Target:               m.Target,
			IntervalSeconds:      int(m.Interval.Seconds()),
			TimeoutSeconds:       int(m.Timeout.Seconds()),
			Enabled:              m.Enabled,
			TLSMode:              string(m.TLSMode),
			ExpectedStatusCode:   m.ExpectedStatusCode,
			ExpectedText:         m.ExpectedText,
			NotifyOnRecovery:     m.NotifyOnRecovery,
			RetryCount:           m.RetryCount,
			RetryIntervalSeconds: int(m.RetryInterval.Seconds()),
			ConfirmAfter:         max(m.ConfirmAfter, 1),
			RemindEveryMinutes:   m.RemindEveryMinutes,
			ExecutorKind:         executorKind,
			ExecutorRef:          m.ExecutorRef,
		})
	}

	if filterID != 0 && len(records) == 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
		return
	}

	payload := monitorExportPayload{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Monitors:   records,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}

	var filename string
	if filterID != 0 && len(records) == 1 {
		slug := monitorNameToSlug(records[0].Name)
		filename = "goup-monitor-" + slug + "-" + time.Now().UTC().Format("2006-01-02") + ".json"
	} else {
		filename = "goup-monitors-" + time.Now().UTC().Format("2006-01-02") + ".json"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write(data)
}

// monitorNameToSlug converts a monitor name to a safe ASCII filename slug.
func monitorNameToSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "monitor"
	}
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return slug
}

// sanitizeRemindEvery maps values that are not an offered reminder interval to "off", so one
// odd value in an import file does not reject the whole monitor.
func sanitizeRemindEvery(minutes int) int {
	if monitor.ValidRemindEvery(minutes) {
		return minutes
	}
	return 0
}
