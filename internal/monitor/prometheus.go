package monitor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxPrometheusBodyBytes = 1024 * 1024

// PromComparison values for prometheus threshold assertions.
const (
	PromComparisonEQ  = "eq"
	PromComparisonNE  = "ne"
	PromComparisonGT  = "gt"
	PromComparisonGTE = "gte"
	PromComparisonLT  = "lt"
	PromComparisonLTE = "lte"
)

// PrometheusChecker queries Prometheus' instant-query HTTP API and asserts the
// returned scalar/vector sample against a threshold from config_json.
type PrometheusChecker struct{}

type prometheusAPIResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type prometheusVectorSample struct {
	Value []any `json:"value"`
}

func (c PrometheusChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	queryURL, err := buildPrometheusQueryURL(item.Target, item.PromQuery)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	comparison := NormalizePromComparison(item.PromComparison)
	if comparison == "" {
		result.Message = fmt.Sprintf("unsupported prometheus comparison %q", strings.TrimSpace(item.PromComparison))
		return result
	}

	securityMode, verifyCertificate, _ := ParseHTTPSTLSMode(item.TLSMode)
	if schemeErr := validateHTTPSMonitorScheme(queryURL, securityMode); schemeErr != nil {
		// Prometheus base URLs may be http or https; re-validate against the
		// final request URL after query construction.
		result.Message = schemeErr.Error()
		return result
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !verifyCertificate,
	}
	dialer := newMonitorDialer(item.Timeout)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	client := &http.Client{
		Timeout:   item.Timeout,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		result.Message = fmt.Sprintf("invalid prometheus query URL: %v", err)
		return result
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("prometheus query failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatusCode = &resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPrometheusBodyBytes))
	if err != nil {
		result.Message = fmt.Sprintf("prometheus response read failed: %v", err)
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Message = fmt.Sprintf("prometheus HTTP %d", resp.StatusCode)
		return result
	}

	var apiResp prometheusAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		result.Message = fmt.Sprintf("prometheus response is not JSON: %v", err)
		return result
	}
	if !strings.EqualFold(strings.TrimSpace(apiResp.Status), "success") {
		msg := strings.TrimSpace(apiResp.Error)
		if msg == "" {
			msg = "query failed"
		}
		if apiResp.ErrorType != "" {
			result.Message = fmt.Sprintf("prometheus %s: %s", apiResp.ErrorType, msg)
		} else {
			result.Message = fmt.Sprintf("prometheus error: %s", msg)
		}
		return result
	}

	value, err := extractPrometheusSample(apiResp.Data.ResultType, apiResp.Data.Result)
	if err != nil {
		result.Message = err.Error()
		return result
	}

	expectedRaw := strings.TrimSpace(item.PromExpectedValue)
	if expectedRaw == "" {
		result.Status = StatusUp
		result.Message = fmt.Sprintf("prometheus %s=%g in %s", apiResp.Data.ResultType, value, formatLatency(result.Latency))
		return result
	}
	expected, err := strconv.ParseFloat(expectedRaw, 64)
	if err != nil {
		result.Message = fmt.Sprintf("invalid expected_value %q", expectedRaw)
		return result
	}
	if !comparePrometheusValue(value, expected, comparison) {
		result.Message = fmt.Sprintf("prometheus value %g not %s %g", value, comparison, expected)
		return result
	}

	result.Status = StatusUp
	result.Message = fmt.Sprintf("prometheus %g %s %g in %s", value, comparison, expected, formatLatency(result.Latency))
	return result
}

// NormalizePromComparison returns a canonical comparison operator, or "" when unsupported.
func NormalizePromComparison(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", PromComparisonEQ, "==", "=":
		return PromComparisonEQ
	case PromComparisonNE, "!=", "<>":
		return PromComparisonNE
	case PromComparisonGT, ">":
		return PromComparisonGT
	case PromComparisonGTE, ">=":
		return PromComparisonGTE
	case PromComparisonLT, "<":
		return PromComparisonLT
	case PromComparisonLTE, "<=":
		return PromComparisonLTE
	default:
		return ""
	}
}

// IsValidPromComparison reports whether raw is a supported comparison operator.
func IsValidPromComparison(raw string) bool {
	return NormalizePromComparison(raw) != ""
}

func buildPrometheusQueryURL(rawTarget, query string) (string, error) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return "", fmt.Errorf("prometheus target is required")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || parsed.Host == "" {
		return "", fmt.Errorf("prometheus target must be a valid http(s) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("prometheus target must use http or https")
	}

	query = strings.TrimSpace(query)
	if query == "" {
		query = strings.TrimSpace(parsed.Query().Get("query"))
	}
	if query == "" {
		return "", fmt.Errorf("prometheus query is required")
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	switch {
	case strings.HasSuffix(path, "/api/v1/query"):
		// keep as-is
	case path == "" || path == "/":
		parsed.Path = "/api/v1/query"
	default:
		parsed.Path = path + "/api/v1/query"
	}

	values := parsed.Query()
	values.Set("query", query)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func extractPrometheusSample(resultType string, raw json.RawMessage) (float64, error) {
	resultType = strings.ToLower(strings.TrimSpace(resultType))
	switch resultType {
	case "scalar", "string":
		var pair []any
		if err := json.Unmarshal(raw, &pair); err != nil {
			return 0, fmt.Errorf("prometheus scalar decode failed: %v", err)
		}
		return prometheusPairValue(pair)
	case "vector":
		var samples []prometheusVectorSample
		if err := json.Unmarshal(raw, &samples); err != nil {
			return 0, fmt.Errorf("prometheus vector decode failed: %v", err)
		}
		if len(samples) == 0 {
			return 0, fmt.Errorf("prometheus vector result is empty")
		}
		return prometheusPairValue(samples[0].Value)
	case "matrix":
		return 0, fmt.Errorf("prometheus matrix results are not supported; use an instant query")
	default:
		return 0, fmt.Errorf("unsupported prometheus result type %q", resultType)
	}
}

func prometheusPairValue(pair []any) (float64, error) {
	if len(pair) < 2 {
		return 0, fmt.Errorf("prometheus sample missing value")
	}
	switch v := pair[1].(type) {
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, fmt.Errorf("prometheus sample is not numeric: %q", v)
		}
		return parsed, nil
	case float64:
		return v, nil
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, fmt.Errorf("prometheus sample is not numeric: %v", err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("prometheus sample has unexpected type %T", pair[1])
	}
}

func comparePrometheusValue(got, expected float64, comparison string) bool {
	switch NormalizePromComparison(comparison) {
	case PromComparisonEQ:
		return got == expected
	case PromComparisonNE:
		return got != expected
	case PromComparisonGT:
		return got > expected
	case PromComparisonGTE:
		return got >= expected
	case PromComparisonLT:
		return got < expected
	case PromComparisonLTE:
		return got <= expected
	default:
		return false
	}
}
