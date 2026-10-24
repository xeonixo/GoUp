package httpserver

import (
	"encoding/json"
	"fmt"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
			ConfirmAfter:         max(rec.ConfirmAfter, 1),
			RemindEveryMinutes:   sanitizeRemindEvery(rec.RemindEveryMinutes),
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
		confirmAfter, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("confirm_after_" + idx)))
		remindEvery, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("remind_every_" + idx)))

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
			ConfirmAfter:       confirmAfter,
			RemindEveryMinutes: sanitizeRemindEvery(remindEvery),
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
