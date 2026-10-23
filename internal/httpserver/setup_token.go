package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// currentSetupToken returns the token required for the initial control-plane
// admin setup: GOUP_SETUP_TOKEN when configured, otherwise a random token that
// is generated once per process.
func (s *Server) currentSetupToken() string {
	s.setupTokenMu.Lock()
	defer s.setupTokenMu.Unlock()
	if token := strings.TrimSpace(s.cfg.SetupToken); token != "" {
		return token
	}
	if s.setupToken == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			// Never fall back to a guessable token; an unusable token blocks setup.
			s.setupToken = "unavailable-" + hex.EncodeToString(raw)
		} else {
			s.setupToken = hex.EncodeToString(raw)
		}
	}
	return s.setupToken
}

// verifySetupToken compares in constant time.
func (s *Server) verifySetupToken(provided string) bool {
	expected := sha256.Sum256([]byte(s.currentSetupToken()))
	got := sha256.Sum256([]byte(strings.TrimSpace(provided)))
	return subtle.ConstantTimeCompare(expected[:], got[:]) == 1
}

// announceSetupToken logs the setup token prominently when the control plane
// still has to be set up and no token was configured via the environment.
func (s *Server) announceSetupToken(ctx context.Context) {
	if s.controlStore == nil || s.logger == nil {
		return
	}
	required, err := s.controlStore.IsSetupRequired(ctx)
	if err != nil || !required {
		return
	}
	if strings.TrimSpace(s.cfg.SetupToken) != "" {
		s.logger.Warn("control-plane setup is pending: open /admin/setup and enter the value of GOUP_SETUP_TOKEN")
		return
	}
	token := s.currentSetupToken()
	s.logger.Warn("==================================================================")
	s.logger.Warn("CONTROL-PLANE SETUP PENDING - enter this one-time setup token at /admin/setup", "setup_token", token)
	s.logger.Warn("(set GOUP_SETUP_TOKEN to choose a fixed token; the token changes on every restart)")
	s.logger.Warn("==================================================================")
}
