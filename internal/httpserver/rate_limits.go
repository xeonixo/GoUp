package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func (s *Server) clientIP(r *http.Request) string {
	// Only use RemoteAddr. X-Forwarded-For is trivially spoofable by clients
	// and must not be trusted for security decisions unless the server is behind
	// a trusted reverse proxy that strips/overwrites the header.
	clientIP := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(clientIP); err == nil && host != "" {
		clientIP = host
	}
	if clientIP == "" {
		clientIP = "unknown"
	}
	return clientIP
}

func (s *Server) localLoginKey(r *http.Request, tenantID int64, loginName string) string {
	return fmt.Sprintf("%d|%s|%s", tenantID, strings.ToLower(strings.TrimSpace(loginName)), s.clientIP(r))
}

func (s *Server) localLoginAllowed(key string, now time.Time) (bool, time.Duration) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt, ok := s.localLoginAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > localLoginWindow {
		delete(s.localLoginAttempts, key)
	}
	return true, 0
}

func (s *Server) registerLocalLoginFailure(key string, now time.Time) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt := s.localLoginAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > localLoginWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.localLoginAttempts[key] = attempt
		return
	}

	attempt.Failures++
	if attempt.Failures >= localLoginMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(localLoginLockout)
	}
	s.localLoginAttempts[key] = attempt
}

func (s *Server) clearLocalLoginAttempts(key string) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()
	delete(s.localLoginAttempts, key)
}

func (s *Server) adminAccessKey(r *http.Request) string {
	return "admin|" + s.clientIP(r)
}

func (s *Server) adminAccessAllowed(key string, now time.Time) (bool, time.Duration) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt, ok := s.adminAccessAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > adminAccessWindow {
		delete(s.adminAccessAttempts, key)
	}
	return true, 0
}

func (s *Server) registerAdminAccessFailure(key string, now time.Time) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt := s.adminAccessAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > adminAccessWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.adminAccessAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= adminAccessMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(adminAccessLockout)
	}
	s.adminAccessAttempts[key] = attempt
}

func (s *Server) clearAdminAccessAttempts(key string) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	delete(s.adminAccessAttempts, key)
}

func (s *Server) bootstrapAttemptKey(r *http.Request, nodeID string) string {
	return "node-bootstrap|" + strings.ToLower(strings.TrimSpace(nodeID)) + "|" + s.clientIP(r)
}

func (s *Server) bootstrapAllowed(key string, now time.Time) (bool, time.Duration) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt, ok := s.bootstrapAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > bootstrapWindow {
		delete(s.bootstrapAttempts, key)
	}
	return true, 0
}

func (s *Server) registerBootstrapFailure(key string, now time.Time) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt := s.bootstrapAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > bootstrapWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.bootstrapAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= bootstrapMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(bootstrapLockout)
	}
	s.bootstrapAttempts[key] = attempt
}

func (s *Server) clearBootstrapAttempts(key string) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	delete(s.bootstrapAttempts, key)
}
