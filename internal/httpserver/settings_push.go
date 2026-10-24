package httpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	webpushnotify "goup/internal/notify/webpush"
	store "goup/internal/store/sqlite"
	"net/http"
	"strings"
	"time"
)

const (
	pushTestCooldown     = 10 * time.Second
	pushRequestBodyLimit = 16 << 10
)

// pushSender lazily creates the shared Web Push sender (VAPID keys are loaded on first use).
func (s *Server) pushSender() *webpushnotify.Sender {
	s.pushOnce.Do(func() {
		if s.pushSenderInst == nil {
			s.pushSenderInst = webpushnotify.NewSender(s.controlStore, s.cfg.BaseURL)
		}
	})
	return s.pushSenderInst
}

type pushDeviceView struct {
	ID          int64
	Label       string
	Endpoint    string
	Created     string
	LastSuccess string
	LastError   string
	Down        bool
	Recovery    bool
	Degraded    bool
	Reminder    bool
}

func pushDeviceViews(items []store.PushSubscription) []pushDeviceView {
	views := make([]pushDeviceView, 0, len(items))
	for _, it := range items {
		v := pushDeviceView{
			ID:        it.ID,
			Label:     it.DeviceLabel,
			Endpoint:  it.Endpoint,
			Created:   it.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			LastError: it.LastError,
			Down:      it.NotifyDown, Recovery: it.NotifyRecovery, Degraded: it.NotifyDegraded, Reminder: it.NotifyReminder,
		}
		if it.LastSuccessAt != nil {
			v.LastSuccess = it.LastSuccessAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		views = append(views, v)
	}
	return views
}

func writePushJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writePushError(w http.ResponseWriter, status int, code string) {
	writePushJSON(w, status, map[string]string{"error": code})
}

// pushUser returns the signed-in user or writes a 401.
func (s *Server) pushUser(w http.ResponseWriter, r *http.Request, method string) (tenantID, userID int64, ok bool) {
	if r.Method != method {
		writePushError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return 0, 0, false
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 || user.UserID <= 0 {
		writePushError(w, http.StatusUnauthorized, "unauthorized")
		return 0, 0, false
	}
	return user.TenantID, user.UserID, true
}

func decodePushJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, pushRequestBodyLimit)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writePushError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

// handlePushKey returns the VAPID application server key for pushManager.subscribe.
func (s *Server) handlePushKey(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.pushUser(w, r, http.MethodGet); !ok {
		return
	}
	key, err := s.pushSender().PublicKey(r.Context())
	if err != nil {
		s.logger.Error("push: load vapid key failed", "error", err)
		writePushError(w, http.StatusInternalServerError, "key_unavailable")
		return
	}
	writePushJSON(w, http.StatusOK, map[string]string{"publicKey": key})
}

type pushPrefsJSON struct {
	Down     *bool `json:"down"`
	Recovery *bool `json:"recovery"`
	Degraded *bool `json:"degraded"`
	Reminder *bool `json:"reminder"`
}

func (p pushPrefsJSON) apply(base store.PushPrefs) store.PushPrefs {
	if p.Down != nil {
		base.Down = *p.Down
	}
	if p.Recovery != nil {
		base.Recovery = *p.Recovery
	}
	if p.Degraded != nil {
		base.Degraded = *p.Degraded
	}
	if p.Reminder != nil {
		base.Reminder = *p.Reminder
	}
	return base
}

type pushSubscribeRequest struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	// OldEndpoint is set by the service worker after a pushsubscriptionchange; the old row's
	// preferences carry over and it is removed.
	OldEndpoint string         `json:"oldEndpoint"`
	Prefs       *pushPrefsJSON `json:"prefs"`
}

// handlePushSubscribe registers (or refreshes) a device for the signed-in user.
func (s *Server) handlePushSubscribe(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := s.pushUser(w, r, http.MethodPost)
	if !ok {
		return
	}
	var req pushSubscribeRequest
	if !decodePushJSON(w, r, &req) {
		return
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	if _, err := webpushnotify.ValidateEndpoint(endpoint); err != nil {
		writePushError(w, http.StatusBadRequest, "invalid_endpoint")
		return
	}
	p256dh, auth, err := webpushnotify.NormalizeKeys(req.Keys.P256dh, req.Keys.Auth)
	if err != nil {
		writePushError(w, http.StatusBadRequest, "invalid_keys")
		return
	}

	ctx := r.Context()
	prefs := store.DefaultPushPrefs()
	// Inherit preferences from the device this subscription replaces (own rows only), else
	// from an existing row for the same endpoint.
	existing, err := s.controlStore.ListUserPushSubscriptions(ctx, tenantID, userID)
	if err != nil {
		s.logger.Error("push: list subscriptions failed", "error", err)
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	oldEndpoint := strings.TrimSpace(req.OldEndpoint)
	for _, e := range existing {
		if e.Endpoint == endpoint || (oldEndpoint != "" && e.Endpoint == oldEndpoint) {
			prefs = store.PushPrefs{Down: e.NotifyDown, Recovery: e.NotifyRecovery, Degraded: e.NotifyDegraded, Reminder: e.NotifyReminder}
			break
		}
	}
	if req.Prefs != nil {
		prefs = req.Prefs.apply(prefs)
	}

	ua := strings.TrimSpace(r.UserAgent())
	if len(ua) > 300 {
		ua = ua[:300]
	}
	sub, err := s.controlStore.UpsertPushSubscription(ctx, store.PushSubscription{
		TenantID: tenantID, UserID: userID, Endpoint: endpoint, P256dh: p256dh, Auth: auth,
		UserAgent: ua, DeviceLabel: deviceLabelFromUserAgent(ua),
		ReplacesEndpoint: oldEndpoint,
		NotifyDown:       prefs.Down, NotifyRecovery: prefs.Recovery, NotifyDegraded: prefs.Degraded, NotifyReminder: prefs.Reminder,
	})
	if err != nil {
		if errors.Is(err, store.ErrPushSubscriptionLimit) {
			writePushError(w, http.StatusConflict, "limit_reached")
			return
		}
		s.logger.Error("push: save subscription failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.writeAudit(r, "tenant.push.subscribe", "tenant", tenantID, fmt.Sprintf("user_id=%d subscription_id=%d", userID, sub.ID))
	writePushJSON(w, http.StatusOK, map[string]any{"ok": true, "id": sub.ID, "label": sub.DeviceLabel})
}

// handlePushUnsubscribe removes one of the caller's devices by endpoint or id. Other users'
// subscriptions are never touched; unknown or foreign entries answer the same 404.
func (s *Server) handlePushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := s.pushUser(w, r, http.MethodPost)
	if !ok {
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
		ID       int64  `json:"id"`
	}
	if !decodePushJSON(w, r, &req) {
		return
	}
	var (
		removed bool
		err     error
	)
	switch {
	case strings.TrimSpace(req.Endpoint) != "":
		removed, err = s.controlStore.DeleteUserPushSubscriptionByEndpoint(r.Context(), tenantID, userID, req.Endpoint)
	case req.ID > 0:
		removed, err = s.controlStore.DeleteUserPushSubscription(r.Context(), tenantID, userID, req.ID)
	default:
		writePushError(w, http.StatusBadRequest, "endpoint_required")
		return
	}
	if err != nil {
		s.logger.Error("push: delete subscription failed", "error", err)
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !removed {
		writePushError(w, http.StatusNotFound, "not_found")
		return
	}
	s.writeAudit(r, "tenant.push.unsubscribe", "tenant", tenantID, fmt.Sprintf("user_id=%d", userID))
	writePushJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePushPrefs updates the event categories of one of the caller's devices.
func (s *Server) handlePushPrefs(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := s.pushUser(w, r, http.MethodPost)
	if !ok {
		return
	}
	var req struct {
		ID int64 `json:"id"`
		pushPrefsJSON
	}
	if !decodePushJSON(w, r, &req) {
		return
	}
	if req.ID <= 0 {
		writePushError(w, http.StatusBadRequest, "id_required")
		return
	}
	// Missing fields keep their stored value.
	prefs := store.DefaultPushPrefs()
	items, err := s.controlStore.ListUserPushSubscriptions(r.Context(), tenantID, userID)
	if err != nil {
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	found := false
	for _, it := range items {
		if it.ID == req.ID {
			prefs = store.PushPrefs{Down: it.NotifyDown, Recovery: it.NotifyRecovery, Degraded: it.NotifyDegraded, Reminder: it.NotifyReminder}
			found = true
		}
	}
	if !found {
		writePushError(w, http.StatusNotFound, "not_found")
		return
	}
	prefs = req.pushPrefsJSON.apply(prefs)
	if _, err := s.controlStore.UpdatePushSubscriptionPrefs(r.Context(), tenantID, userID, req.ID, prefs); err != nil {
		writePushError(w, http.StatusInternalServerError, "internal")
		return
	}
	writePushJSON(w, http.StatusOK, map[string]any{"ok": true})
}
