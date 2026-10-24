package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	webpushnotify "goup/internal/notify/webpush"
	store "goup/internal/store/sqlite"
	"net/http"
	"strings"
	"time"
)

// handlePushTest sends a test notification to all of the caller's devices (1 per 10 s per user).
func (s *Server) handlePushTest(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := s.pushUser(w, r, http.MethodPost)
	if !ok {
		return
	}
	if !s.allowPushTest(tenantID, userID, time.Now()) {
		w.Header().Set("Retry-After", fmt.Sprint(int(pushTestCooldown.Seconds())))
		writePushError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	subs, err := s.controlStore.ListUserPushSubscriptions(ctx, tenantID, userID)
	if err != nil {
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	if len(subs) == 0 {
		writePushError(w, http.StatusNotFound, "no_devices")
		return
	}
	language := "en"
	if profile, err := s.controlStore.GetTenantUser(ctx, tenantID, userID); err == nil {
		language = webpushnotify.NormalizeLanguage(profile.PreferredLanguage)
	}
	raw, _ := json.Marshal(webpushnotify.BuildTestPayload(language, s.tenantAppBase(r)+"settings/profile"))
	results := s.pushSender().Deliver(ctx, subs,
		func(store.PushSubscription) []byte { return raw },
		func(store.PushSubscription) webpushnotify.SendOptions {
			return webpushnotify.SendOptions{TTL: 600, Urgency: webpushnotify.UrgencyHigh}
		})
	sent, failed := 0, 0
	for _, res := range results {
		if res.Err != nil {
			failed++
			s.logger.Warn("push: test delivery failed", "subscription_id", res.Subscription.ID, "gone", res.Gone, "error", res.Err)
		} else {
			sent++
		}
	}
	status := http.StatusOK
	if sent == 0 {
		status = http.StatusBadGateway
	}
	writePushJSON(w, status, map[string]int{"sent": sent, "failed": failed})
}

// allowPushTest allows one test push per user every pushTestCooldown.
func (s *Server) allowPushTest(tenantID, userID int64, now time.Time) bool {
	key := fmt.Sprintf("%d:%d", tenantID, userID)
	s.notifierTestMu.Lock()
	defer s.notifierTestMu.Unlock()
	if s.pushTestLast == nil {
		s.pushTestLast = make(map[string]time.Time)
	}
	if last, ok := s.pushTestLast[key]; ok && now.Sub(last) < pushTestCooldown {
		return false
	}
	s.pushTestLast[key] = now
	if len(s.pushTestLast) > 4096 {
		for k, v := range s.pushTestLast {
			if now.Sub(v) > pushTestCooldown {
				delete(s.pushTestLast, k)
			}
		}
	}
	return true
}

// deviceLabelFromUserAgent produces a short human label such as "iPhone · Safari".
func deviceLabelFromUserAgent(ua string) string {
	lower := strings.ToLower(ua)
	device := "Browser"
	switch {
	case strings.Contains(lower, "iphone"):
		device = "iPhone"
	case strings.Contains(lower, "ipad"):
		device = "iPad"
	case strings.Contains(lower, "android"):
		device = "Android"
	case strings.Contains(lower, "macintosh"), strings.Contains(lower, "mac os"):
		device = "Mac"
	case strings.Contains(lower, "windows"):
		device = "Windows"
	case strings.Contains(lower, "linux"):
		device = "Linux"
	}
	browser := ""
	switch {
	case strings.Contains(lower, "edg/"), strings.Contains(lower, "edga/"), strings.Contains(lower, "edgios/"):
		browser = "Edge"
	case strings.Contains(lower, "firefox/"), strings.Contains(lower, "fxios/"):
		browser = "Firefox"
	case strings.Contains(lower, "chrome/"), strings.Contains(lower, "crios/"):
		browser = "Chrome"
	case strings.Contains(lower, "safari/"):
		browser = "Safari"
	}
	if browser == "" {
		return device
	}
	return device + " · " + browser
}
