package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestAPIV1AuthScopesAndCRUD(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()

	readPlain, _, err := env.s.controlStore.CreateAPIToken(ctx, env.tenantID, "read", store.APITokenScopeMonitorsRead, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	writePlain, _, err := env.s.controlStore.CreateAPIToken(ctx, env.tenantID, "write", store.APITokenScopeMonitorsWrite, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	metricsPlain, _, err := env.s.controlStore.CreateAPIToken(ctx, env.tenantID, "metrics", store.APITokenScopeMetrics, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, path, token string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var reader *bytes.Reader
		if body != nil {
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(payload)
		} else {
			reader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, reader)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		env.s.handleRoot(rec, req)
		return rec
	}

	if rec := do(http.MethodGet, "/acme/api/v1/monitors", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/acme/api/v1/monitors", metricsPlain, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics scope must not read monitors: %d", rec.Code)
	}
	rec := do(http.MethodGet, "/acme/api/v1/monitors", readPlain, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read list: %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Monitors []apiMonitorDTO `json:"monitors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Monitors) < 2 {
		t.Fatalf("expected seeded monitors, got %d", len(listed.Monitors))
	}

	createBody := monitorExportRecord{
		Name: "API Created", Kind: string(monitor.KindTCP), Target: "127.0.0.1:9",
		IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true, TLSMode: string(monitor.TLSModeNone),
		ExecutorKind: "local", ConfirmAfter: 1,
	}
	if rec := do(http.MethodPost, "/acme/api/v1/monitors", readPlain, createBody); rec.Code != http.StatusUnauthorized {
		t.Fatalf("read token must not create: %d", rec.Code)
	}
	rec = do(http.MethodPost, "/acme/api/v1/monitors", writePlain, createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created apiMonitorDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID <= 0 || created.Name != "API Created" {
		t.Fatalf("created dto: %+v", created)
	}

	path := "/acme/api/v1/monitors/" + strconv.FormatInt(created.ID, 10)
	rec = do(http.MethodGet, path, readPlain, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	createBody.Name = "API Updated"
	rec = do(http.MethodPut, path, writePlain, createBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "API Updated") {
		t.Fatalf("update body: %s", rec.Body.String())
	}

	if err := env.st.RecordMonitorState(ctx, created.ID, monitor.StatusDown, "boom", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec = do(http.MethodGet, path+"/incidents", readPlain, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cause":"boom"`) {
		t.Fatalf("incidents: %d %s", rec.Code, rec.Body.String())
	}
	if err := env.st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: created.ID, CheckedAt: time.Now().UTC(), Status: monitor.StatusUp, Latency: 12 * time.Millisecond, Message: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	rec = do(http.MethodGet, path+"/results?limit=5", readPlain, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"up"`) {
		t.Fatalf("results: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(http.MethodDelete, path, writePlain, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, path, readPlain, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", rec.Code)
	}
}
