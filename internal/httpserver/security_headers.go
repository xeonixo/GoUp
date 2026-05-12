package httpserver

import (
	"net/http"
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
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
