package httpserver

import (
	"net/http"
	"strings"
)

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Clickjacking protection
		h.Set("X-Frame-Options", "DENY")
		// MIME-type sniffing protection
		h.Set("X-Content-Type-Options", "nosniff")
		// Referrer leakage: only send origin on cross-origin requests
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Disable browser features not needed
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		// Content Security Policy: only same-origin assets, including locally served icon cache/uploads
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		// HSTS: only set when using HTTPS
		if s.requestIsHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Authenticated pages and API-ish responses must not be stored by
		// browsers or intermediaries. Static assets and handlers that set their
		// own Cache-Control (e.g. embedded favicons, icons) are unaffected.
		if !isStaticAssetPath(r.URL.Path) {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func isStaticAssetPath(path string) bool {
	for _, prefix := range []string{"/static/", "/assets/", "/favicon/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

const (
	defaultMaxRequestBodyBytes = 1 << 20
	groupIconRequestBodyBytes  = groupIconUploadMaxBytes + (1 << 20)
	importRequestBodyBytes     = 5 << 20
)

// maxBodyBytesForPath returns the request body limit for a path. Only the
// upload/import routes may exceed the 1 MiB default.
func maxBodyBytesForPath(path string) int64 {
	switch {
	case isHeartbeatPath(path):
		return heartbeatBodyLimit
	case strings.HasSuffix(path, "/monitors/import/preview"), strings.HasSuffix(path, "/monitors/import/confirm"):
		return importRequestBodyBytes
	case strings.HasSuffix(path, "/groups/save"):
		return groupIconRequestBodyBytes
	}
	return defaultMaxRequestBodyBytes
}

// limitRequestBody bounds request bodies globally so that no handler can be
// forced to buffer unbounded input.
func (s *Server) limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytesForPath(r.URL.Path))
		}
		next.ServeHTTP(w, r)
	})
}
