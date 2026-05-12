package httpserver

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	expected, err := url.Parse(s.cfg.BaseURL)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return next
	}
	expectedScheme := strings.ToLower(strings.TrimSpace(expected.Scheme))
	expectedHost := strings.ToLower(strings.TrimSpace(expected.Hostname()))
	expectedPort := strings.TrimSpace(expected.Port())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/node/") {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}

		allowedOrigins := make(map[string]struct{})
		for _, origin := range buildAllowedOrigins(expectedScheme, expectedHost, expectedPort, r) {
			allowedOrigins[origin] = struct{}{}
		}

		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			normalizedOrigin := normalizeOrigin(origin)
			if normalizedOrigin == "" {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedOrigin]; !ok {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
			normalizedRefererOrigin := normalizeRefererOrigin(referer)
			if normalizedRefererOrigin == "" {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedRefererOrigin]; !ok {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Neither Origin nor Referer present on a mutating request: reject.
		// Legitimate browser-initiated form submissions always include at least one.
		// Non-browser API clients should supply Origin.
		http.Error(w, "origin or referer required", http.StatusForbidden)
	})
}

func buildAllowedOrigins(expectedScheme, expectedHost, expectedPort string, r *http.Request) []string {
	origins := make(map[string]struct{})
	addOriginCandidate(origins, expectedScheme, expectedHost, expectedPort)

	requestScheme := expectedScheme
	if strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")) != "" {
		requestScheme = strings.ToLower(strings.TrimSpace(strings.Split(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), ",")[0]))
	}
	requestHost := strings.ToLower(strings.TrimSpace(r.Host))
	if requestHost != "" {
		hostname := requestHost
		port := ""
		if strings.Contains(requestHost, ":") {
			if parsedHost, parsedPort, err := net.SplitHostPort(requestHost); err == nil {
				hostname = strings.ToLower(strings.TrimSpace(parsedHost))
				port = strings.TrimSpace(parsedPort)
			}
		}
		addOriginCandidate(origins, requestScheme, hostname, port)
	}

	for _, host := range []string{expectedHost, strings.ToLower(strings.TrimSpace(r.URL.Hostname()))} {
		if host == "" {
			continue
		}
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			for _, alt := range []string{"localhost", "127.0.0.1", "[::1]"} {
				addOriginCandidate(origins, expectedScheme, alt, expectedPort)
			}
		}
	}

	result := make([]string, 0, len(origins))
	for value := range origins {
		result = append(result, value)
	}
	return result
}

func addOriginCandidate(set map[string]struct{}, scheme, host, port string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "http"
	}
	port = strings.TrimSpace(port)
	if port != "" {
		set[scheme+"://"+strings.ToLower(host)+":"+port] = struct{}{}
		return
	}
	set[scheme+"://"+strings.ToLower(host)] = struct{}{}
}

func normalizeOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}

func normalizeRefererOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}
