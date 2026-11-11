package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildPrometheusQueryURL(t *testing.T) {
	got, err := buildPrometheusQueryURL("http://prom.example:9090", "up")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "/api/v1/query?") || !strings.Contains(got, "query=up") {
		t.Fatalf("unexpected URL %q", got)
	}

	got, err = buildPrometheusQueryURL("http://prom.example:9090/api/v1/query?query=old", "up{job=\"api\"}")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "query=up") || strings.Contains(got, "query=old") {
		t.Fatalf("expected query override, got %q", got)
	}

	if _, err := buildPrometheusQueryURL("http://prom.example:9090", ""); err == nil {
		t.Fatal("expected missing query error")
	}
}

func TestPrometheusCheckerVectorThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("query"); got != `up{job="api"}` {
			t.Errorf("query=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"job":"api"},"value":[1,"1"]}]}}`))
	}))
	defer srv.Close()

	ok := (PrometheusChecker{}).Check(context.Background(), Monitor{
		ID:                1,
		Kind:              KindPrometheus,
		Target:            srv.URL,
		Timeout:           2 * time.Second,
		TLSMode:           TLSModeNone,
		PromQuery:         `up{job="api"}`,
		PromExpectedValue: "1",
		PromComparison:    "eq",
	})
	if ok.Status != StatusUp {
		t.Fatalf("expected up, got %s %q", ok.Status, ok.Message)
	}

	fail := (PrometheusChecker{}).Check(context.Background(), Monitor{
		ID:                1,
		Kind:              KindPrometheus,
		Target:            srv.URL,
		Timeout:           2 * time.Second,
		TLSMode:           TLSModeNone,
		PromQuery:         `up{job="api"}`,
		PromExpectedValue: "0",
		PromComparison:    "eq",
	})
	if fail.Status != StatusDown || !strings.Contains(fail.Message, "not eq") {
		t.Fatalf("expected threshold failure, got %s %q", fail.Status, fail.Message)
	}
}

func TestPrometheusCheckerScalarAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("query") {
		case "scalar_ok":
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"scalar","result":[1,"42.5"]}}`))
		case "empty":
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"invalid query"}`))
		}
	}))
	defer srv.Close()

	ok := (PrometheusChecker{}).Check(context.Background(), Monitor{
		Kind: KindPrometheus, Target: srv.URL, Timeout: time.Second, TLSMode: TLSModeNone,
		PromQuery: "scalar_ok", PromExpectedValue: "40", PromComparison: "gt",
	})
	if ok.Status != StatusUp {
		t.Fatalf("scalar: %s %q", ok.Status, ok.Message)
	}

	empty := (PrometheusChecker{}).Check(context.Background(), Monitor{
		Kind: KindPrometheus, Target: srv.URL, Timeout: time.Second, TLSMode: TLSModeNone,
		PromQuery: "empty", PromExpectedValue: "1", PromComparison: "eq",
	})
	if empty.Status != StatusDown || !strings.Contains(empty.Message, "empty") {
		t.Fatalf("empty: %s %q", empty.Status, empty.Message)
	}

	apiErr := (PrometheusChecker{}).Check(context.Background(), Monitor{
		Kind: KindPrometheus, Target: srv.URL, Timeout: time.Second, TLSMode: TLSModeNone,
		PromQuery: "boom", PromExpectedValue: "1", PromComparison: "eq",
	})
	if apiErr.Status != StatusDown || !strings.Contains(apiErr.Message, "bad_data") {
		t.Fatalf("api error: %s %q", apiErr.Status, apiErr.Message)
	}
}

func TestNormalizePromComparison(t *testing.T) {
	if got := NormalizePromComparison(""); got != PromComparisonEQ {
		t.Fatalf("default = %q", got)
	}
	if got := NormalizePromComparison(">="); got != PromComparisonGTE {
		t.Fatalf("gte = %q", got)
	}
	if IsValidPromComparison("nope") {
		t.Fatal("expected invalid")
	}
}
