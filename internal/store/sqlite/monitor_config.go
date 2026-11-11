package sqlite

import (
	"encoding/json"
	"goup/internal/monitor"
	"strings"
)

// monitorConfigJSON holds optional HTTPS assertion settings in monitors.config_json.
type monitorConfigJSON struct {
	HTTPMethod       string `json:"http_method,omitempty"`
	RequestHeaders   string `json:"request_headers,omitempty"`
	RequestBody      string `json:"request_body,omitempty"`
	JSONPath         string `json:"json_path,omitempty"`
	JSONPathExpected string `json:"json_path_expected,omitempty"`
	CheckMode        string `json:"check_mode,omitempty"`
}

func encodeMonitorConfigJSON(params CreateMonitorParams) string {
	cfg := monitorConfigJSON{}
	if params.Kind == monitor.KindHTTPS {
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
	}
	if cfg.HTTPMethod == "" && cfg.RequestHeaders == "" && cfg.RequestBody == "" &&
		cfg.JSONPath == "" && cfg.JSONPathExpected == "" && cfg.CheckMode == "" {
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
}
