package httpserver

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) adminActor(r *http.Request) string {
	if s.isControlPlaneAdminRequest(r) {
		return "control-plane-admin"
	}
	user := s.currentUser(r)
	if user == nil {
		return "anonymous"
	}
	if strings.TrimSpace(user.Email) != "" {
		return strings.TrimSpace(user.Email)
	}
	if strings.TrimSpace(user.Name) != "" {
		return strings.TrimSpace(user.Name)
	}
	return fmt.Sprintf("user:%d", user.UserID)
}

func (s *Server) writeAudit(r *http.Request, action, targetType string, targetID int64, details string) {
	if err := s.controlStore.InsertAuditEvent(r.Context(), s.adminActor(r), action, targetType, targetID, details); err != nil {
		s.logger.Warn("write audit event failed", "action", action, "target_type", targetType, "target_id", targetID, "error", err)
	}
}
