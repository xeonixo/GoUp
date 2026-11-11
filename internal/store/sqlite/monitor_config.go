package sqlite

import (
	"encoding/json"
	"goup/internal/monitor"
	"strings"
)

// monitorConfigJSON holds optional kind-specific settings in monitors.config_json.
type monitorConfigJSON struct {
	HTTPMethod        string `json:"http_method,omitempty"`
	RequestHeaders    string `json:"request_headers,omitempty"`
	RequestBody       string `json:"request_body,omitempty"`
	JSONPath          string `json:"json_path,omitempty"`
	JSONPathExpected  string `json:"json_path_expected,omitempty"`
	CheckMode         string `json:"check_mode,omitempty"`
	Query             string `json:"query,omitempty"`
	ExpectedValue     string `json:"expected_value,omitempty"`
	Comparison        string `json:"comparison,omitempty"`
	Service           string `json:"service,omitempty"`
}

func encodeMonitorConfigJSON(params CreateMonitorParams) string {
	cfg := monitorConfigJSON{}
	switch params.Kind {
	case monitor.KindHTTPS:
		if method := monitor.NormalizeHTTPSMethod(params.HTTPMethod); method != "" && method != "GET" {
			cfg.HTTPMethod = method
		}
		cfg.RequestHeaders = strings.TrimSpace(params.RequestHeaders)
		cfg.RequestBody = params.RequestBody
		cfg.JSONPath = strings.TrimSpace(params.JSONPath)
		cfg.JSONPathExpected = strings.TrimSpace(params.JSONPathExpected)
		if mode := monitor.NormalizeHTTPSCheckMode(params.CheckMode); mode == monitor.CheckModeTLS {
			cfg.CheckMode = mode
		}
	case monitor.KindPrometheus:
		cfg.Query = strings.TrimSpace(params.PromQuery)
		cfg.ExpectedValue = strings.TrimSpace(params.PromExpectedValue)
		if cmp := monitor.NormalizePromComparison(params.PromComparison); cmp != "" && cmp != monitor.PromComparisonEQ {
			cfg.Comparison = cmp
		}
	case monitor.KindGRPC:
		cfg.Service = strings.TrimSpace(params.GRPCService)
	}
	if cfg.HTTPMethod == "" && cfg.RequestHeaders == "" && cfg.RequestBody == "" &&
		cfg.JSONPath == "" && cfg.JSONPathExpected == "" && cfg.CheckMode == "" &&
		cfg.Query == "" && cfg.ExpectedValue == "" && cfg.Comparison == "" && cfg.Service == "" {
		return "{}"
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func applyMonitorConfigJSON(item *monitor.Monitor, raw string) {
	if item == nil {
		return
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return
	}
	var cfg monitorConfigJSON
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return
	}
	item.HTTPMethod = strings.TrimSpace(cfg.HTTPMethod)
	item.RequestHeaders = strings.TrimSpace(cfg.RequestHeaders)
	item.RequestBody = cfg.RequestBody
	item.JSONPath = strings.TrimSpace(cfg.JSONPath)
	item.JSONPathExpected = strings.TrimSpace(cfg.JSONPathExpected)
	item.CheckMode = monitor.NormalizeHTTPSCheckMode(cfg.CheckMode)
	item.PromQuery = strings.TrimSpace(cfg.Query)
	item.PromExpectedValue = strings.TrimSpace(cfg.ExpectedValue)
	item.PromComparison = monitor.NormalizePromComparison(cfg.Comparison)
	item.GRPCService = strings.TrimSpace(cfg.Service)
}
