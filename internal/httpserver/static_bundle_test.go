package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"goup/web"
)

func TestStylesheetBundle(t *testing.T) {
	css := string(stylesheetBundle())
	if css == "" {
		t.Fatal("stylesheet bundle is empty")
	}
	// Markers from the first (tokens) and last (PWA / status page) source file.
	first, last := "--bg: #0b1020;", ".table-actions {"
	for _, want := range []string{first, last} {
		if !strings.Contains(css, want) {
			t.Errorf("bundle lacks marker %q", want)
		}
	}
	if strings.Index(css, first) > strings.Index(css, last) {
		t.Error("bundle is not in source order")
	}
	if _, err := web.FS.ReadFile("static/style.css"); err == nil {
		t.Error("static/style.css should only exist as a generated bundle")
	}
}

func TestStaticStylesheetServedAsBundle(t *testing.T) {
	h := staticFileHandler(os.DirFS("../../web/static"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/style.css?v="+assetVersion(), nil))
	if rec.Code != http.StatusOK || rec.Body.String() != string(stylesheetBundle()) {
		t.Fatalf("status = %d, body matches bundle = %v", rec.Code, rec.Body.String() == string(stylesheetBundle()))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("cache-control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestStaticETagRevalidation(t *testing.T) {
	h := staticFileHandler(os.DirFS("../../web/static"))
	for _, p := range []string{"/theme.js", "/style.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		tag := rec.Header().Get("ETag")
		if rec.Code != http.StatusOK || !strings.HasPrefix(tag, `"`) {
			t.Fatalf("%s: status %d etag %q", p, rec.Code, tag)
		}
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("If-None-Match", tag)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Errorf("%s: conditional status = %d, body %d bytes", p, rec.Code, rec.Body.Len())
		}
		req.Header.Set("If-None-Match", `"stale"`)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: stale etag status = %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing.js", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("ETag") != "" {
		t.Errorf("missing file: status %d etag %q", rec.Code, rec.Header().Get("ETag"))
	}
}
