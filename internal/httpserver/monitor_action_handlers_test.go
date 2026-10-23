package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"goup/internal/auth"
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
