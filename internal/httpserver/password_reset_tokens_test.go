package httpserver

import (
	"strings"
	"testing"
	"time"

	"goup/internal/config"
)

func TestPasswordResetTokenRoundTrip(t *testing.T) {
	s := &Server{cfg: config.Config{SessionKey: strings.Repeat("k", 32)}}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	token, err := s.signPasswordResetToken(42, 99, expiresAt)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	tenantID, userID, parsedExpiresAt, err := s.parsePasswordResetToken(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if tenantID != 42 || userID != 99 {
		t.Fatalf("unexpected token values: tenant=%d user=%d", tenantID, userID)
	}
	if parsedExpiresAt.Unix() != expiresAt.Unix() {
		t.Fatalf("expiry mismatch: got=%v want=%v", parsedExpiresAt, expiresAt)
	}
}

func TestPasswordResetTokenTamperDetected(t *testing.T) {
	s := &Server{cfg: config.Config{SessionKey: strings.Repeat("k", 32)}}
	token, err := s.signPasswordResetToken(1, 2, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	token = token + "x"
	if _, _, _, err := s.parsePasswordResetToken(token); err == nil {
		t.Fatalf("expected parse failure for tampered token")
	}
}

func TestPasswordResetTokenReplayState(t *testing.T) {
	s := &Server{usedResetTokens: make(map[string]time.Time)}
	token := "abc"
	if s.passwordResetTokenUsed(token) {
		t.Fatalf("token should not be used initially")
	}

	s.markPasswordResetTokenUsed(token, time.Now().UTC().Add(2*time.Minute))
	if !s.passwordResetTokenUsed(token) {
		t.Fatalf("token should be marked as used")
	}

	s.markPasswordResetTokenUsed("expired", time.Now().UTC().Add(-1*time.Minute))
	if s.passwordResetTokenUsed("expired") {
		t.Fatalf("expired token should be cleaned up on access")
	}
}

func TestKeepAttempt(t *testing.T) {
	now := time.Now().UTC()
	if keepAttempt(localLoginAttempt{}, now, time.Minute) {
		t.Fatalf("empty attempt should not be retained")
	}
	if !keepAttempt(localLoginAttempt{LockedUntil: now.Add(time.Minute)}, now, time.Minute) {
		t.Fatalf("locked attempt should be retained")
	}
	if keepAttempt(localLoginAttempt{WindowStart: now.Add(-2 * time.Minute)}, now, time.Minute) {
		t.Fatalf("expired window should not be retained")
	}
}
