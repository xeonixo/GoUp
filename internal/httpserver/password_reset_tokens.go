package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (s *Server) passwordResetEnabled(ctx context.Context) bool {
	smtpCfg, err := s.controlStore.GetGlobalSMTPSettings(ctx)
	if err != nil {
		return false
	}
	return strings.TrimSpace(smtpCfg.Host) != "" && strings.TrimSpace(smtpCfg.FromEmail) != "" && smtpCfg.PasswordConfigured
}

func (s *Server) signPasswordResetToken(tenantID, userID int64, expiresAt time.Time) (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%d:%d:%d:%s", tenantID, userID, expiresAt.UTC().Unix(), hex.EncodeToString(nonce))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))

	h := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = h.Write([]byte(payloadEncoded))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return payloadEncoded + "." + signature, nil
}

func (s *Server) parsePasswordResetToken(token string) (tenantID, userID int64, expiresAt time.Time, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token")
	}
	payloadEncoded := parts[0]
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token signature")
	}

	h := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = h.Write([]byte(payloadEncoded))
	expectedSig := h.Sum(nil)
	if !hmac.Equal(providedSig, expectedSig) {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token payload")
	}
	fields := strings.Split(string(payloadBytes), ":")
	if len(fields) < 3 {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token payload")
	}

	tenantID, err = strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token tenant")
	}
	userID, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token user")
	}
	expUnix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token expiration")
	}
	expiresAt = time.Unix(expUnix, 0).UTC()
	if time.Now().UTC().After(expiresAt) {
		return 0, 0, time.Time{}, fmt.Errorf("token expired")
	}

	return tenantID, userID, expiresAt, nil
}
