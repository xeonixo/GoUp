package httpserver

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithRequestIDGeneratesAndEchoes(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var gotFromContext string
	handler := s.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFromContext = requestIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	id := rec.Header().Get("X-Request-ID")
	if id == "" || !strings.Contains(id, "-") {
		t.Fatalf("generated X-Request-ID = %q", id)
	}
	if gotFromContext != id {
		t.Fatalf("context id = %q, header = %q", gotFromContext, id)
	}
}

func TestWithRequestIDAcceptsIncoming(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := s.withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestIDFromContext(r.Context()); got != "client-req-1" {
			t.Fatalf("context id = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "client-req-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "client-req-1" {
		t.Fatalf("echo = %q", rec.Header().Get("X-Request-ID"))
	}
}

func TestSanitizeRequestID(t *testing.T) {
	if got := sanitizeRequestID("  ok-id_1  "); got != "ok-id_1" {
		t.Fatalf("trim = %q", got)
	}
	if got := sanitizeRequestID("bad\nid"); got != "" {
		t.Fatalf("control chars must be rejected, got %q", got)
	}
	if got := sanitizeRequestID(strings.Repeat("a", 129)); got != "" {
		t.Fatalf("overlong must be rejected")
	}
}

func TestLoggingIncludesRequestID(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	handler := s.withRequestID(s.logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "log-req-42")
	req.RemoteAddr = "127.0.0.1:9"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !strings.Contains(buf.String(), "request_id=log-req-42") {
		t.Fatalf("log missing request_id: %s", buf.String())
	}
}
