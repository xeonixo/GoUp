package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
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

func (s *Server) handleMonitorImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.render(w, "monitors_import", pageData{
		Title:   "Monitore importieren · GoUp",
		User:    s.currentUser(r),
		AppBase: s.tenantAppBase(r),
		Error:   strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleMonitorImportPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	importBase := s.tenantAppBase(r) + "monitors/import"

	if err := r.ParseMultipartForm(4 << 20); err != nil {
		http.Redirect(w, r, importBase+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	var rawJSON []byte
	if file, _, fileErr := r.FormFile("file"); fileErr == nil {
		defer file.Close()
		rawJSON, _ = io.ReadAll(io.LimitReader(file, 4<<20))
	}
	if len(rawJSON) == 0 {
		rawJSON = []byte(strings.TrimSpace(r.FormValue("json_paste")))
	}
	if len(rawJSON) == 0 {
		http.Redirect(w, r, importBase+"?error="+url.QueryEscape("Keine Daten angegeben"), http.StatusSeeOther)
		return
	}

	var payload monitorExportPayload
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		http.Redirect(w, r, importBase+"?error="+url.QueryEscape("Ungültiges JSON-Format"), http.StatusSeeOther)
		return
	}
	if payload.Version != 1 {
		http.Redirect(w, r, importBase+"?error="+url.QueryEscape("Nicht unterstützte Export-Version"), http.StatusSeeOther)
		return
	}
	if len(payload.Monitors) == 0 {
		http.Redirect(w, r, importBase+"?error="+url.QueryEscape("Keine Monitore in der Datei"), http.StatusSeeOther)
		return
	}

	rows := make([]importPreviewRow, 0, len(payload.Monitors))
	for i, rec := range payload.Monitors {
		statusCodeStr := ""
		if rec.ExpectedStatusCode != nil {
			statusCodeStr = strconv.Itoa(*rec.ExpectedStatusCode)
		}
		executorKind := rec.ExecutorKind
		if executorKind == "" {
			executorKind = "local"
		}
		rows = append(rows, importPreviewRow{
			Index:                i,
			Name:                 rec.Name,
			Group:                rec.Group,
			Kind:                 rec.Kind,
			Target:               rec.Target,
			IntervalSeconds:      rec.IntervalSeconds,
			TimeoutSeconds:       rec.TimeoutSeconds,
			Enabled:              rec.Enabled,
			TLSMode:              rec.TLSMode,
			ExpectedStatusCode:   statusCodeStr,
			ExpectedText:         rec.ExpectedText,
			NotifyOnRecovery:     rec.NotifyOnRecovery,
			RetryCount:           rec.RetryCount,
			RetryIntervalSeconds: rec.RetryIntervalSeconds,
			ExecutorKind:         executorKind,
			ExecutorRef:          rec.ExecutorRef,
		})
	}

	s.render(w, "monitors_import_preview", pageData{
		Title:      "Import-Vorschau · GoUp",
		User:       s.currentUser(r),
		AppBase:    s.tenantAppBase(r),
		ImportRows: rows,
	})
}

func (s *Server) handleMonitorImportConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	count, err := strconv.Atoi(strings.TrimSpace(r.FormValue("count")))
	if err != nil || count <= 0 || count > 500 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Importdaten"), http.StatusSeeOther)
		return
	}

	created := 0
	var firstErr error
	for i := 0; i < count; i++ {
		idx := strconv.Itoa(i)
		if r.FormValue("skip_"+idx) == "on" {
			continue
		}

		intervalSec, parseErr := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_seconds_" + idx)))
		if parseErr != nil {
			continue
		}
		timeoutSec, parseErr := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds_" + idx)))
		if parseErr != nil {
			continue
		}
		retrySec, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("retry_interval_seconds_" + idx)))
		retryCount, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("retry_count_" + idx)))

		var expectedStatusCode *int
		if raw := strings.TrimSpace(r.FormValue("expected_status_code_" + idx)); raw != "" {
			v, parseErr := strconv.Atoi(raw)
			if parseErr == nil {
				expectedStatusCode = &v
			}
		}

		executorKind := strings.TrimSpace(r.FormValue("executor_kind_" + idx))
		if executorKind == "" {
			executorKind = "local"
		}

		params := store.CreateMonitorParams{
			Name:               strings.TrimSpace(r.FormValue("name_" + idx)),
			Group:              strings.TrimSpace(r.FormValue("group_" + idx)),
			Kind:               monitor.Kind(strings.TrimSpace(r.FormValue("kind_" + idx))),
			Target:             strings.TrimSpace(r.FormValue("target_" + idx)),
			Interval:           time.Duration(intervalSec) * time.Second,
			Timeout:            time.Duration(timeoutSec) * time.Second,
			Enabled:            r.FormValue("enabled_"+idx) == "on",
			TLSMode:            monitor.TLSMode(strings.TrimSpace(r.FormValue("tls_mode_" + idx))),
			ExpectedStatusCode: expectedStatusCode,
			ExpectedText:       strings.TrimSpace(r.FormValue("expected_text_" + idx)),
			NotifyOnRecovery:   r.FormValue("notify_on_recovery_"+idx) == "on",
			RetryCount:         retryCount,
			RetryInterval:      time.Duration(retrySec) * time.Second,
			ExecutorKind:       executorKind,
			ExecutorRef:        strings.TrimSpace(r.FormValue("executor_ref_" + idx)),
		}

		if _, createErr := appStore.CreateMonitor(r.Context(), params); createErr != nil {
			if firstErr == nil {
				firstErr = createErr
			}
		} else {
			created++
		}
	}

	if firstErr != nil && created == 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitore konnten nicht importiert werden: "+firstErr.Error()), http.StatusSeeOther)
		return
	}

	notice := fmt.Sprintf("%d Monitor(e) importiert", created)
	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
