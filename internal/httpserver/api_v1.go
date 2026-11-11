package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type apiMonitorDTO struct {
	ID int64 `json:"id"`
	monitorExportRecord
}

type apiIncidentDTO struct {
	ID         int64   `json:"id"`
	StartedAt  string  `json:"started_at"`
	ResolvedAt *string `json:"resolved_at"`
	Cause      string  `json:"cause"`
}

type apiResultDTO struct {
	ID               int64   `json:"id"`
	CheckedAt        string  `json:"checked_at"`
	Status           string  `json:"status"`
	LatencyMs        int64   `json:"latency_ms"`
	Message          string  `json:"message"`
	HTTPStatusCode   *int    `json:"http_status_code,omitempty"`
	TLSValid         *bool   `json:"tls_valid,omitempty"`
	TLSNotAfter      *string `json:"tls_not_after,omitempty"`
	TLSDaysRemaining *int    `json:"tls_days_remaining,omitempty"`
	InMaintenance    bool    `json:"in_maintenance"`
}

func snapshotToAPIMonitor(snap monitor.Snapshot) apiMonitorDTO {
	m := snap.Monitor
	executorKind := m.ExecutorKind
	if executorKind == "" {
		executorKind = "local"
	}
	return apiMonitorDTO{
		ID: m.ID,
		monitorExportRecord: monitorExportRecord{
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
			HTTPMethod:           m.HTTPMethod,
			RequestHeaders:       m.RequestHeaders,
			RequestBody:          m.RequestBody,
			JSONPath:             m.JSONPath,
			JSONPathExpected:     m.JSONPathExpected,
			CheckMode:            m.CheckMode,
			NotifyOnRecovery:     m.NotifyOnRecovery,
			RetryCount:           m.RetryCount,
			RetryIntervalSeconds: int(m.RetryInterval.Seconds()),
			ConfirmAfter:         max(m.ConfirmAfter, 1),
			RemindEveryMinutes:   m.RemindEveryMinutes,
			ExecutorKind:         executorKind,
			ExecutorRef:          m.ExecutorRef,
		},
	}
}

func exportRecordToCreateParams(rec monitorExportRecord) store.CreateMonitorParams {
	intervalSec := rec.IntervalSeconds
	if intervalSec <= 0 {
		intervalSec = 60
	}
	timeoutSec := rec.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	executorKind := strings.TrimSpace(rec.ExecutorKind)
	if executorKind == "" {
		executorKind = "local"
	}
	tlsMode := strings.TrimSpace(rec.TLSMode)
	if tlsMode == "" {
		tlsMode = string(monitor.TLSModeNone)
	}
	return store.CreateMonitorParams{
		Name:               strings.TrimSpace(rec.Name),
		Group:              strings.TrimSpace(rec.Group),
		Kind:               monitor.Kind(strings.TrimSpace(rec.Kind)),
		Target:             strings.TrimSpace(rec.Target),
		Interval:           time.Duration(intervalSec) * time.Second,
		Timeout:            time.Duration(timeoutSec) * time.Second,
		Enabled:            rec.Enabled,
		TLSMode:            monitor.TLSMode(tlsMode),
		ExpectedStatusCode: rec.ExpectedStatusCode,
		ExpectedText:       strings.TrimSpace(rec.ExpectedText),
		HTTPMethod:         strings.TrimSpace(rec.HTTPMethod),
		RequestHeaders:     strings.TrimSpace(rec.RequestHeaders),
		RequestBody:        rec.RequestBody,
		JSONPath:           strings.TrimSpace(rec.JSONPath),
		JSONPathExpected:   strings.TrimSpace(rec.JSONPathExpected),
		CheckMode:          strings.TrimSpace(rec.CheckMode),
		NotifyOnRecovery:   rec.NotifyOnRecovery,
		RetryCount:         rec.RetryCount,
		RetryInterval:      time.Duration(rec.RetryIntervalSeconds) * time.Second,
		ConfirmAfter:       rec.ConfirmAfter,
		RemindEveryMinutes: sanitizeRemindEvery(rec.RemindEveryMinutes),
		ExecutorKind:       executorKind,
		ExecutorRef:        strings.TrimSpace(rec.ExecutorRef),
		CertWarningDays:    7,
	}
}

func (s *Server) requireAPIToken(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := tenantIDFromRequest(r)
			if tenantID <= 0 {
				http.NotFound(w, r)
				return
			}
			limiterKey := "api-v1|" + s.rateLimitIP(r)
			if allowed, wait := s.bootstrapAllowed(limiterKey, time.Now()); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
				http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
				return
			}
			ok, err := s.controlStore.AuthenticateAPITokenWithScopes(r.Context(), tenantID, bearerToken(r), scopes...)
			if err != nil {
				s.logger.Error("api v1 token lookup failed", "tenant_id", tenantID, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !ok {
				s.registerBootstrapFailure(limiterKey, time.Now())
				w.Header().Set("WWW-Authenticate", `Bearer realm="goup-api"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAPIJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeAPIJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleAPIV1ListMonitors(w http.ResponseWriter, r *http.Request) {
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to list monitors")
		return
	}
	items := make([]apiMonitorDTO, 0, len(snapshots))
	for _, snap := range snapshots {
		items = append(items, snapshotToAPIMonitor(snap))
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"monitors": items})
}

func (s *Server) handleAPIV1CreateMonitor(w http.ResponseWriter, r *http.Request) {
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	var rec monitorExportRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	params := exportRecordToCreateParams(rec)
	id, err := appStore.CreateMonitor(r.Context(), params)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, err := appStore.GetMonitorSnapshot(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "monitor created but could not be loaded")
		return
	}
	s.writeAudit(r, "api.monitor.create", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))
	writeAPIJSON(w, http.StatusCreated, snapshotToAPIMonitor(snap))
}

func (s *Server) parseAPIMonitorID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid monitor id")
	}
	return id, nil
}

func (s *Server) handleAPIV1GetMonitor(w http.ResponseWriter, r *http.Request) {
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	snap, err := appStore.GetMonitorSnapshot(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "monitor not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "unable to load monitor")
		return
	}
	writeAPIJSON(w, http.StatusOK, snapshotToAPIMonitor(snap))
}

func (s *Server) handleAPIV1UpdateMonitor(w http.ResponseWriter, r *http.Request) {
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	var rec monitorExportRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	params := exportRecordToCreateParams(rec)
	if err := appStore.UpdateMonitor(r.Context(), store.UpdateMonitorParams{ID: id, CreateMonitorParams: params}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "monitor not found")
			return
		}
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, err := appStore.GetMonitorSnapshot(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "monitor updated but could not be loaded")
		return
	}
	s.writeAudit(r, "api.monitor.update", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))
	writeAPIJSON(w, http.StatusOK, snapshotToAPIMonitor(snap))
}

func (s *Server) handleAPIV1DeleteMonitor(w http.ResponseWriter, r *http.Request) {
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	if err := appStore.DeleteMonitor(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "monitor not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "unable to delete monitor")
		return
	}
	s.writeAudit(r, "api.monitor.delete", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAPIV1MonitorIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	if _, err := appStore.GetMonitorSnapshot(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "monitor not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "unable to load monitor")
		return
	}
	items, err := appStore.ListMonitorIncidents(r.Context(), id, 50)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to list incidents")
		return
	}
	out := make([]apiIncidentDTO, 0, len(items))
	for _, item := range items {
		dto := apiIncidentDTO{
			ID:        item.ID,
			StartedAt: item.StartedAt.UTC().Format(time.RFC3339),
			Cause:     item.Cause,
		}
		if item.ResolvedAt != nil {
			v := item.ResolvedAt.UTC().Format(time.RFC3339)
			dto.ResolvedAt = &v
		}
		out = append(out, dto)
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"incidents": out})
}

func (s *Server) handleAPIV1MonitorResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	if _, err := appStore.GetMonitorSnapshot(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAPIError(w, http.StatusNotFound, "monitor not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "unable to load monitor")
		return
	}
	items, err := appStore.ListMonitorResults(r.Context(), id, limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to list results")
		return
	}
	out := make([]apiResultDTO, 0, len(items))
	for _, item := range items {
		dto := apiResultDTO{
			ID:               item.ID,
			CheckedAt:        item.CheckedAt.UTC().Format(time.RFC3339),
			Status:           string(item.Status),
			LatencyMs:        item.Latency.Milliseconds(),
			Message:          item.Message,
			HTTPStatusCode:   item.HTTPStatusCode,
			TLSValid:         item.TLSValid,
			TLSDaysRemaining: item.TLSDaysRemaining,
			InMaintenance:    item.InMaintenance,
		}
		if item.TLSNotAfter != nil {
			v := item.TLSNotAfter.UTC().Format(time.RFC3339)
			dto.TLSNotAfter = &v
		}
		out = append(out, dto)
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (s *Server) handleAPIV1CheckMonitorNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, err := s.parseAPIMonitorID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to resolve tenant")
		return
	}
	result, err := s.runMonitorCheckNow(r.Context(), appStore, id)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeAPIError(w, http.StatusNotFound, "monitor not found")
		case errors.Is(err, errRemoteCheckDisabled):
			writeAPIError(w, http.StatusConflict, err.Error())
		case errors.Is(err, errUnsupportedMonitorKind):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.writeAudit(r, "api.monitor.check_now", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"checked_at": result.CheckedAt.UTC().Format(time.RFC3339),
		"status":     string(result.Status),
		"message":    strings.TrimSpace(result.Message),
	})
}

var (
	errRemoteCheckDisabled    = errors.New("manual checks are disabled for remote-node monitors")
	errUnsupportedMonitorKind = errors.New("monitor kind is not supported")
)

func (s *Server) runMonitorCheckNow(ctx context.Context, appStore *store.Store, id int64) (monitor.Result, error) {
	snap, err := appStore.GetMonitorSnapshot(ctx, id)
	if err != nil {
		return monitor.Result{}, err
	}
	if strings.EqualFold(strings.TrimSpace(snap.Monitor.ExecutorKind), "remote") {
		return monitor.Result{}, errRemoteCheckDisabled
	}
	checker, ok := checkerForMonitorKind(snap.Monitor.Kind)
	if !ok {
		return monitor.Result{}, errUnsupportedMonitorKind
	}
	runCtx, cancel := context.WithTimeout(ctx, snap.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, snap.Monitor)
	cancel()
	if err := appStore.SaveMonitorResult(ctx, result); err != nil {
		return monitor.Result{}, fmt.Errorf("unable to store check result")
	}
	if err := appStore.RecordMonitorState(ctx, snap.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
		return monitor.Result{}, fmt.Errorf("unable to store monitor state")
	}
	return result, nil
}
