package httpserver

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleAdminAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.controlStore == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	auditAction := strings.TrimSpace(firstNonEmpty(r.FormValue("audit_action"), r.URL.Query().Get("audit_action")))
	auditActor := strings.TrimSpace(firstNonEmpty(r.FormValue("audit_actor"), r.URL.Query().Get("audit_actor")))
	auditTargetType := strings.TrimSpace(firstNonEmpty(r.FormValue("audit_target"), r.URL.Query().Get("audit_target")))
	format := strings.ToLower(strings.TrimSpace(firstNonEmpty(r.FormValue("format"), r.URL.Query().Get("format"))))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
		return
	}

	events, err := s.controlStore.ExportAuditEventsFiltered(r.Context(), auditAction, auditActor, auditTargetType)
	if err != nil {
		s.logger.Error("admin audit export failed", "error", err)
		http.Error(w, "unable to export audit events", http.StatusInternalServerError)
		return
	}

	s.writeAudit(r, "control_plane.audit.export", "system", 1, fmt.Sprintf("format=%s count=%d action=%s actor=%s target=%s", format, len(events), auditAction, auditActor, auditTargetType))

	stamp := time.Now().UTC().Format("2006-01-02")
	filename := "goup-audit-" + stamp + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		payload := make([]map[string]any, 0, len(events))
		for _, event := range events {
			payload = append(payload, map[string]any{
				"id":          event.ID,
				"actor":       event.Actor,
				"action":      event.Action,
				"target_type": event.TargetType,
				"target_id":   event.TargetID,
				"details":     event.Details,
				"created_at":  event.CreatedAt.UTC().Format(time.RFC3339),
			})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "created_at", "actor", "action", "target_type", "target_id", "details"})
		for _, event := range events {
			_ = cw.Write([]string{
				strconv.FormatInt(event.ID, 10),
				event.CreatedAt.UTC().Format(time.RFC3339),
				event.Actor,
				event.Action,
				event.TargetType,
				strconv.FormatInt(event.TargetID, 10),
				event.Details,
			})
		}
		cw.Flush()
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
