package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	statusPageSubscribeIPLimit    = 10
	statusPageSubscribeEmailLimit = 5
	statusPageSubscribeRateWindow = time.Hour
)

func (s *Server) statusSubscriptionsEnabled(r *http.Request) bool {
	if s.controlStore == nil {
		return false
	}
	smtpCfg, err := s.controlStore.GetGlobalSMTPSettings(r.Context())
	if err != nil {
		return false
	}
	return strings.TrimSpace(smtpCfg.Host) != "" && strings.TrimSpace(smtpCfg.FromEmail) != "" && smtpCfg.PasswordConfigured
}

func (s *Server) statusPageRedirect(w http.ResponseWriter, r *http.Request, slug, kind, messageKey string) {
	target := statusPagePublicPathPrefix(r, slug)
	if kind != "" && messageKey != "" {
		target += "?" + kind + "=" + url.QueryEscape(messageKey)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// handleStatusPageSubscribe accepts a double-opt-in email subscription request.
func (s *Server) handleStatusPageSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := tenantSlugFromRequest(r)
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	settings, enabled, err := s.loadEnabledStatusPageSettings(r)
	if err != nil {
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
	if !s.statusSubscriptionsEnabled(r) {
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.unavailable")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.invalid")
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	lang := statusPageLanguage(r)
	if v := strings.TrimSpace(r.FormValue("language")); v != "" {
		lang = v
	}
	monitorIDs := parseStatusPageMonitorIDs(r.Form["monitor_id"])

	now := time.Now()
	if !s.allowResetRequest("status-sub-ip|"+s.rateLimitIP(r), statusPageSubscribeIPLimit, statusPageSubscribeRateWindow, now) ||
		!s.allowResetRequest(fmt.Sprintf("status-sub-email|%d|%s", tenantIDFromRequest(r), strings.ToLower(email)), statusPageSubscribeEmailLimit, statusPageSubscribeRateWindow, now) {
		s.statusPageRedirect(w, r, slug, "notice", "status_page.subscribe.check_email")
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	confirmToken, err := appStore.UpsertPendingStatusPageSubscription(r.Context(), email, lang, monitorIDs)
	if err != nil {
		s.logger.Warn("status page subscribe failed", "error", err)
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.invalid")
		return
	}
	if confirmToken == "" {
		s.statusPageRedirect(w, r, slug, "notice", "status_page.subscribe.updated")
		return
	}

	deliveryCfg, err := s.controlStore.GetGlobalSMTPDeliveryConfig(r.Context())
	if err != nil {
		s.logger.Error("load smtp for status page subscribe", "error", err)
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.unavailable")
		return
	}
	tr := s.translationsForLanguage(normalizeUILanguage(lang))
	confirmLink := strings.TrimRight(s.cfg.BaseURL, "/") + "/" + slug + "/status/subscribe/confirm?token=" + url.QueryEscape(confirmToken)
	subject := translateFlashMessage(tr, "email.status_subscribe.confirm_subject", "Confirm your status subscription", nil)
	body := strings.Join([]string{
		translateFlashMessage(tr, "email.status_subscribe.confirm_intro", "Please confirm your subscription to status updates.", nil),
		"",
		translateFlashMessage(tr, "email.status_subscribe.confirm_link", "Confirm: {link}", map[string]string{"link": confirmLink}),
		"",
		translateFlashMessage(tr, "email.status_subscribe.confirm_expiry", "This link is valid for 48 hours.", nil),
		translateFlashMessage(tr, "email.status_subscribe.confirm_ignore", "If you did not request this, you can ignore this email.", nil),
	}, "\n")

	go func(recipient string) {
		if err := sendSMTPMail(deliveryCfg, recipient, subject, body); err != nil {
			s.logger.Error("send status page confirm mail failed", "error", err)
		}
	}(email)

	s.statusPageRedirect(w, r, slug, "notice", "status_page.subscribe.check_email")
}

func parseStatusPageMonitorIDs(values []string) []int64 {
	out := make([]int64, 0, len(values))
	seen := make(map[int64]struct{}, len(values))
	for _, raw := range values {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// handleStatusPageSubscribeConfirm completes double-opt-in.
func (s *Server) handleStatusPageSubscribeConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := tenantSlugFromRequest(r)
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	_, enabled, err := s.loadEnabledStatusPageSettings(r)
	if err != nil || !enabled {
		http.NotFound(w, r)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if _, err := appStore.ConfirmStatusPageSubscription(r.Context(), token); err != nil {
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.confirm_failed")
		return
	}
	s.statusPageRedirect(w, r, slug, "notice", "status_page.subscribe.confirmed")
}

// handleStatusPageUnsubscribe removes a subscription via emailed link.
func (s *Server) handleStatusPageUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := tenantSlugFromRequest(r)
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "status page unavailable", http.StatusInternalServerError)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		token = strings.TrimSpace(r.FormValue("token"))
	}
	if err := appStore.UnsubscribeStatusPageSubscription(r.Context(), token); err != nil {
		s.statusPageRedirect(w, r, slug, "error", "status_page.subscribe.unsubscribe_failed")
		return
	}
	s.statusPageRedirect(w, r, slug, "notice", "status_page.subscribe.unsubscribed")
}

// resolveStatusPageFlash maps query keys like status_page.subscribe.check_email to translated text.
func resolveStatusPageFlash(tr map[string]string, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "status_page.") || strings.HasPrefix(raw, "email.") {
		return statusPageTr(tr, raw, raw)
	}
	return raw
}
