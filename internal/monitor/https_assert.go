package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	// CheckModeHTTP runs the full HTTPS content check (status, keywords, JSONPath).
	CheckModeHTTP = "http"
	// CheckModeTLS skips HTTP content assertions and only validates the TLS certificate.
	CheckModeTLS = "tls"
)

// NormalizeHTTPSCheckMode returns CheckModeHTTP or CheckModeTLS.
func NormalizeHTTPSCheckMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case CheckModeTLS:
		return CheckModeTLS
	default:
		return CheckModeHTTP
	}
}

// NormalizeHTTPSMethod returns a supported HTTP method, defaulting to GET.
func NormalizeHTTPSMethod(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case http.MethodPost:
		return http.MethodPost
	case http.MethodPut:
		return http.MethodPut
	case http.MethodHead:
		return http.MethodHead
	case http.MethodPatch:
		return http.MethodPatch
	case http.MethodDelete:
		return http.MethodDelete
	case http.MethodGet, "":
		return http.MethodGet
	default:
		return ""
	}
}

// ParseHTTPRequestHeaders accepts a JSON object map or multiline Name: value / Name=value lines.
func ParseHTTPRequestHeaders(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "{") {
		var asMap map[string]string
		if err := json.Unmarshal([]byte(raw), &asMap); err != nil {
			return nil, fmt.Errorf("invalid request headers JSON: %w", err)
		}
		out := make(map[string]string, len(asMap))
		for key, value := range asMap {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			out[key] = value
		}
		return out, nil
	}

	out := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			name, value, ok = strings.Cut(line, "=")
		}
		if !ok {
			return nil, fmt.Errorf("invalid request header line %q (expected Name: value)", line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("invalid request header line %q (empty name)", line)
		}
		out[name] = value
	}
	return out, nil
}

// ValidateSimpleJSONPath reports whether path uses the supported JSONPath subset.
func ValidateSimpleJSONPath(path string) error {
	_, err := splitJSONPath(strings.TrimSpace(path))
	return err
}

// EvalSimpleJSONPath walks a decoded JSON value with a tiny subset of JSONPath:
// leading "$." / "$[" optional, dotted keys, and [index] segments.
func EvalSimpleJSONPath(root any, path string) (any, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("json path is empty")
	}
	segments, err := splitJSONPath(path)
	if err != nil {
		return nil, err
	}
	current := root
	for _, segment := range segments {
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[segment.key]
			if !ok {
				return nil, fmt.Errorf("path not found: missing key %q", segment.key)
			}
			current = next
		case []any:
			if !segment.indexOK {
				return nil, fmt.Errorf("path not found: expected array index, got key %q", segment.key)
			}
			if segment.index < 0 || segment.index >= len(typed) {
				return nil, fmt.Errorf("path not found: array index %d out of range", segment.index)
			}
			current = typed[segment.index]
		default:
			return nil, fmt.Errorf("path not found: cannot traverse %T", current)
		}
	}
	return current, nil
}

type jsonPathSegment struct {
	key     string
	index   int
	indexOK bool
}

func splitJSONPath(path string) ([]jsonPathSegment, error) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$")
	if path == "" {
		return nil, fmt.Errorf("json path must select a value (e.g. $.status)")
	}

	segments := make([]jsonPathSegment, 0, 4)
	i := 0
	for i < len(path) {
		switch path[i] {
		case '.':
			i++
			if i >= len(path) {
				return nil, fmt.Errorf("invalid json path: trailing dot")
			}
			start := i
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				i++
			}
			key := path[start:i]
			if key == "" {
				return nil, fmt.Errorf("invalid json path: empty key")
			}
			if idx, err := strconv.Atoi(key); err == nil {
				segments = append(segments, jsonPathSegment{index: idx, indexOK: true})
			} else {
				segments = append(segments, jsonPathSegment{key: key})
			}
		case '[':
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("invalid json path: missing ']'")
			}
			inner := strings.TrimSpace(path[i+1 : i+end])
			if strings.HasPrefix(inner, "\"") && strings.HasSuffix(inner, "\"") && len(inner) >= 2 {
				segments = append(segments, jsonPathSegment{key: inner[1 : len(inner)-1]})
			} else {
				idx, err := strconv.Atoi(inner)
				if err != nil {
					return nil, fmt.Errorf("invalid json path index %q", inner)
				}
				segments = append(segments, jsonPathSegment{index: idx, indexOK: true})
			}
			i += end + 1
		default:
			// Allow bare "status" or "data.items" without a leading $.
			start := i
			for i < len(path) && path[i] != '.' && path[i] != '[' {
				i++
			}
			key := path[start:i]
			if key == "" {
				return nil, fmt.Errorf("invalid json path")
			}
			if idx, err := strconv.Atoi(key); err == nil {
				segments = append(segments, jsonPathSegment{index: idx, indexOK: true})
			} else {
				segments = append(segments, jsonPathSegment{key: key})
			}
		}
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("json path must select a value (e.g. $.status)")
	}
	return segments, nil
}

func matchJSONPathExpected(got any, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return got != nil
	}
	if got == nil {
		return strings.EqualFold(expected, "null")
	}
	switch value := got.(type) {
	case string:
		return value == expected
	case bool:
		return strconv.FormatBool(value) == expected || strings.EqualFold(strconv.FormatBool(value), expected)
	case float64:
		if parsed, err := strconv.ParseFloat(expected, 64); err == nil {
			return parsed == value
		}
		return formatJSONScalar(value) == expected
	case json.Number:
		return value.String() == expected
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value) == expected
		}
		if string(encoded) == expected {
			return true
		}
		// Allow expected without surrounding quotes for simple scalars already handled above.
		return strings.TrimSpace(string(encoded)) == expected
	}
}

func formatJSONScalar(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func formatJSONPathValue(value any) string {
	if value == nil {
		return "null"
	}
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return formatJSONScalar(typed)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(encoded)
	}
}
