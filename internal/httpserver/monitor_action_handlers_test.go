package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/web"
)

func TestDashboardActionRedirect(t *testing.T) {
	catalog, err := loadTranslationCatalog(web.FS, "i18n")
	if err != nil {
		t.Fatalf("load translations: %v", err)
	}
	s := &Server{i18n: catalog, sessions: auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false)}
	target := "/barner/?error=" + "Monitor+wurde+nicht+gefunden"

	formReq := httptest.NewRequest(http.MethodPost, "/barner/monitors/delete", nil)
	formRec := httptest.NewRecorder()
	s.dashboardActionRedirect(formRec, formReq, target)
	if formRec.Code != http.StatusSeeOther || formRec.Header().Get("Location") != target {
		t.Fatalf("form post should redirect, got %d %q", formRec.Code, formRec.Header().Get("Location"))
	}

	fetchReq := httptest.NewRequest(http.MethodPost, "/barner/monitors/delete", nil)
	fetchReq.Header.Set("Accept", "application/json")
	fetchReq.Header.Set("Accept-Language", "en")
	fetchRec := httptest.NewRecorder()
	s.dashboardActionRedirect(fetchRec, fetchReq, target)
	if fetchRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for failed fetch action, got %d", fetchRec.Code)
	}
	var payload struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(fetchRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if payload.OK || payload.Error != "Monitor not found" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestBulkMonitorAction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	appStore, err := store.Open(ctx, filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer appStore.Close()
	catalog, err := loadTranslationCatalog(web.FS, "i18n")
	if err != nil {
		t.Fatalf("load translations: %v", err)
	}
	s := &Server{
		store:        appStore,
		controlStore: cp,
		i18n:         catalog,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions:     auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}

	ids := make([]string, 0, 2)
	for _, name := range []string{"a", "b"} {
		id, err := appStore.CreateMonitor(ctx, store.CreateMonitorParams{
			Name: name, Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
		})
		if err != nil {
			t.Fatalf("create monitor: %v", err)
		}
		ids = append(ids, strconv.FormatInt(id, 10))
	}

	post := func(action string, ids ...string) (int, map[string]any) {
		form := url.Values{"action": {action}, "id": ids}
		req := httptest.NewRequest(http.MethodPost, "/monitors/bulk", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", "en")
		rec := httptest.NewRecorder()
		s.handleBulkMonitorAction(rec, req)
		var payload map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &payload)
		return rec.Code, payload
	}
	snapshots := func() []monitor.Snapshot {
		items, err := appStore.ListMonitorSnapshots(ctx)
		if err != nil {
			t.Fatalf("list snapshots: %v", err)
		}
		return items
	}

	if code, payload := post("mute_8h", ids...); code != http.StatusOK || payload["notice"] != "2 monitor(s) updated" {
		t.Fatalf("mute: %d %v", code, payload)
	}
	for _, item := range snapshots() {
		if !item.Monitor.IsMuted(time.Now().Add(7 * time.Hour)) {
			t.Fatalf("monitor %d should be muted for 8h", item.Monitor.ID)
		}
	}
	if code, _ := post("pause", ids[0]); code != http.StatusOK {
		t.Fatalf("pause failed: %d", code)
	}
	if code, payload := post("explode", ids...); code != http.StatusUnprocessableEntity || payload["error"] != "Unknown action" {
		t.Fatalf("unknown action: %d %v", code, payload)
	}
	if code, payload := post("pause"); code != http.StatusUnprocessableEntity || payload["error"] != "No monitors selected" {
		t.Fatalf("empty selection: %d %v", code, payload)
	}
	if code, _ := post("delete", ids[1]); code != http.StatusOK {
		t.Fatalf("delete failed: %d", code)
	}
	remaining := snapshots()
	if len(remaining) != 1 || remaining[0].Monitor.Enabled {
		t.Fatalf("expected one paused monitor left, got %+v", remaining)
	}
}
