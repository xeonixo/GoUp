package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const securityStateSweepInterval = 5 * time.Minute

func (s *Server) runSecurityStateSweeper(ctx context.Context) {
	ticker := time.NewTicker(securityStateSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			s.sweepLocalLoginAttempts(now)
			s.sweepAdminAccessAttempts(now)
			s.sweepBootstrapAttempts(now)
			s.sweepUsedPasswordResetTokens(now)
		}
	}
}

func (s *Server) sweepLocalLoginAttempts(now time.Time) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()
	for key, attempt := range s.localLoginAttempts {
		if !keepAttempt(attempt, now, localLoginWindow) {
			delete(s.localLoginAttempts, key)
		}
	}
}

func (s *Server) sweepAdminAccessAttempts(now time.Time) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	for key, attempt := range s.adminAccessAttempts {
		if !keepAttempt(attempt, now, adminAccessWindow) {
			delete(s.adminAccessAttempts, key)
		}
	}
}

func (s *Server) sweepBootstrapAttempts(now time.Time) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	for key, attempt := range s.bootstrapAttempts {
		if !keepAttempt(attempt, now, bootstrapWindow) {
			delete(s.bootstrapAttempts, key)
		}
	}
}

func keepAttempt(attempt localLoginAttempt, now time.Time, window time.Duration) bool {
	if !attempt.LockedUntil.IsZero() && now.Before(attempt.LockedUntil) {
		return true
	}
	if attempt.WindowStart.IsZero() {
		return false
	}
	return now.Sub(attempt.WindowStart) <= window
}

func (s *Server) passwordResetTokenUsed(token string) bool {
	digest := passwordResetTokenDigest(token)
	s.passwordResetMu.Lock()
	defer s.passwordResetMu.Unlock()
	expiresAt, ok := s.usedResetTokens[digest]
	if !ok {
		return false
	}
	if time.Now().UTC().After(expiresAt) {
		delete(s.usedResetTokens, digest)
		return false
	}
	return true
}

func (s *Server) markPasswordResetTokenUsed(token string, expiresAt time.Time) {
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(passwordResetTTL)
	}
	digest := passwordResetTokenDigest(token)
	s.passwordResetMu.Lock()
	s.usedResetTokens[digest] = expiresAt.UTC()
	s.passwordResetMu.Unlock()
}

func (s *Server) sweepUsedPasswordResetTokens(now time.Time) {
	s.passwordResetMu.Lock()
	defer s.passwordResetMu.Unlock()
	for digest, expiresAt := range s.usedResetTokens {
		if now.After(expiresAt) {
			delete(s.usedResetTokens, digest)
		}
	}
}

func passwordResetTokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
