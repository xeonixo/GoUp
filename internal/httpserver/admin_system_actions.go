package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	store "goup/internal/store/sqlite"
)

func (s *Server) handleAdminSystemBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.controlStore == nil {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape("control plane unavailable"), http.StatusSeeOther)
		return
	}

	tenants, err := s.controlStore.GetAllTenants(r.Context())
	if err != nil {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	backupDir, err := store.BackupAll(r.Context(), s.cfg.DataDir, s.cfg.ControlPlaneDBPath, s.controlStore.DB(), tenants, "")
	if err != nil {
		s.logger.Error("admin system backup failed", "error", err)
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/system?notice="+url.QueryEscape("Backup written to "+backupDir), http.StatusSeeOther)
}

func (s *Server) handleAdminSystemRekeySecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.controlStore == nil {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape("control plane unavailable"), http.StatusSeeOther)
		return
	}
	confirm := strings.ToLower(strings.TrimSpace(r.FormValue("confirm")))
	if confirm != "1" && confirm != "yes" && confirm != "on" {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape("rekey requires confirmation"), http.StatusSeeOther)
		return
	}

	updated, err := s.controlStore.ReencryptAllSecrets(r.Context())
	if err != nil {
		s.logger.Error("admin system rekey failed", "error", err)
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/system?notice="+url.QueryEscape(fmt.Sprintf("Re-encrypted %d secrets with the primary key", updated)), http.StatusSeeOther)
}

func (s *Server) handleAdminSystemRotateVAPID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.controlStore == nil {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape("control plane unavailable"), http.StatusSeeOther)
		return
	}
	confirm := strings.ToLower(strings.TrimSpace(r.FormValue("confirm")))
	if confirm != "1" && confirm != "yes" && confirm != "on" {
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape("VAPID rotation requires confirmation"), http.StatusSeeOther)
		return
	}

	_, cleared, err := s.controlStore.RotateVAPIDKeys(r.Context())
	if err != nil {
		s.logger.Error("admin system vapid rotate failed", "error", err)
		http.Redirect(w, r, "/admin/system?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.pushSender().InvalidateCachedKeys()
	notice := fmt.Sprintf(
		"VAPID keys rotated; cleared %d push subscription(s). Users must reopen the app and re-enable push notifications.",
		cleared,
	)
	http.Redirect(w, r, "/admin/system?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
