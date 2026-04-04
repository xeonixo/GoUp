package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30
)

// TOTPGenerateSecret returns a new random 20-byte secret encoded as base32 (no padding).
func TOTPGenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPValidate returns true if code matches the current TOTP counter ±1 window.
func TOTPValidate(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	t := time.Now().Unix() / totpPeriod
	for _, delta := range []int64{-1, 0, 1} {
		if totpGenerate(secret, t+delta) == code {
			return true
		}
	}
	return false
}

// TOTPOtpAuthURL returns the standard otpauth:// URI for use in authenticator apps.
func TOTPOtpAuthURL(issuer, account, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		url.PathEscape(issuer),
		url.PathEscape(account),
		url.QueryEscape(secret),
		url.QueryEscape(issuer),
		totpDigits,
		totpPeriod,
	)
}

func totpGenerate(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	h := hmac.New(sha1.New, key) //nolint:gosec // RFC 6238
	_, _ = h.Write(msg)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := int64(sum[offset]&0x7f)<<24 |
		int64(sum[offset+1]&0xff)<<16 |
		int64(sum[offset+2]&0xff)<<8 |
		int64(sum[offset+3]&0xff)
	code = code % int64(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, code)
}
