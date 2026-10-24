package sqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ConfigureSecretKey sets the encryption key used to store control-plane secrets.
func (s *ControlPlaneStore) ConfigureSecretKey(key string) error {
	return s.ConfigureSecretKeys(key)
}

// ConfigureSecretKeys sets the primary encryption key and optional legacy
// fallback keys used only when reading previously stored secrets.
func (s *ControlPlaneStore) ConfigureSecretKeys(primary string, fallbacks ...string) error {
	derived, err := deriveControlPlaneSecretKey(primary)
	if err != nil {
		return err
	}
	s.secretKey = derived
	s.secretFallbackKeys = s.secretFallbackKeys[:0]
	for _, fallback := range fallbacks {
		fallbackKey, err := deriveControlPlaneSecretKey(fallback)
		if err != nil {
			return err
		}
		if secretKeysEqual(derived, fallbackKey) {
			continue
		}
		duplicate := false
		for _, existing := range s.secretFallbackKeys {
			if secretKeysEqual(existing, fallbackKey) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			s.secretFallbackKeys = append(s.secretFallbackKeys, fallbackKey)
		}
	}
	return nil
}

func deriveControlPlaneSecretKey(key string) ([]byte, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("secret key must not be empty")
	}
	return pbkdf2.Key([]byte(key), []byte("goup/control-plane/secret-key/v2"), 120000, 32, sha256.New), nil
}

func secretKeysEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func encryptProviderSecret(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, sealed...)
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func decryptProviderSecret(key []byte, ciphertext string) (string, error) {
	payload, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := payload[:nonceSize]
	data := payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *ControlPlaneStore) decryptSecret(ciphertext string) (string, error) {
	if len(s.secretKey) == 0 {
		return "", fmt.Errorf("secret key is not configured")
	}
	plaintext, err := decryptProviderSecret(s.secretKey, ciphertext)
	if err == nil {
		return plaintext, nil
	}
	for _, fallbackKey := range s.secretFallbackKeys {
		plaintext, fallbackErr := decryptProviderSecret(fallbackKey, ciphertext)
		if fallbackErr == nil {
			return plaintext, nil
		}
	}
	return "", err
}
