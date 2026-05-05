package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type webhookPayload struct {
	EventType  string `json:"event_type"`
	TenantID   int64  `json:"tenant_id"`
	EndpointID int64  `json:"endpoint_id"`
	OccurredAt string `json:"occurred_at"`
	Monitor    struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Group  string `json:"group"`
	} `json:"monitor"`
	Transition struct {
		Previous     string `json:"previous"`
		Current      string `json:"current"`
		CheckedAt    string `json:"checked_at"`
		ResultDetail string `json:"result_detail"`
	} `json:"transition"`
}

func main() {
	secret := strings.TrimSpace(os.Getenv("WEBHOOK_SECRET"))
	if secret == "" {
		log.Fatal("WEBHOOK_SECRET is required")
	}

	addr := strings.TrimSpace(os.Getenv("WEBHOOK_ADDR"))
	if addr == "" {
		addr = ":8090"
	}

	path := strings.TrimSpace(os.Getenv("WEBHOOK_PATH"))
	if path == "" {
		path = "/webhook"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	maxSkewSeconds := 300
	if raw := strings.TrimSpace(os.Getenv("WEBHOOK_MAX_SKEW_SECONDS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			maxSkewSeconds = v
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB
		if err != nil {
			http.Error(w, "unable to read body", http.StatusBadRequest)
			return
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-GoUp-Timestamp"))
		signature := strings.TrimSpace(r.Header.Get("X-GoUp-Signature"))
		eventHeader := strings.TrimSpace(r.Header.Get("X-GoUp-Event"))

		if err := verifyTimestamp(timestamp, time.Duration(maxSkewSeconds)*time.Second); err != nil {
			http.Error(w, "invalid timestamp: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if err := verifySignature(secret, timestamp, body, signature); err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		var payload webhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}

		log.Printf(
			"webhook ok event=%s tenant=%d endpoint=%d monitor=%q kind=%s target=%q transition=%s->%s detail=%q",
			coalesce(payload.EventType, eventHeader),
			payload.TenantID,
			payload.EndpointID,
			payload.Monitor.Name,
			payload.Monitor.Kind,
			payload.Monitor.Target,
			payload.Transition.Previous,
			payload.Transition.Current,
			payload.Transition.ResultDetail,
		)

		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("listening addr=%s path=%s", addr, path)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func verifyTimestamp(timestamp string, maxSkew time.Duration) error {
	if strings.TrimSpace(timestamp) == "" {
		return errors.New("missing X-GoUp-Timestamp")
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return err
	}
	if maxSkew <= 0 {
		return nil
	}
	delta := time.Since(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return fmt.Errorf("outside allowed skew window")
	}
	return nil
}

func verifySignature(secret, timestamp string, body []byte, got string) error {
	if secret == "" {
		return errors.New("missing secret")
	}
	if !strings.HasPrefix(got, "v1=") {
		return errors.New("missing v1= prefix")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := "v1=" + hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(strings.TrimSpace(got)), []byte(expected)) {
		return errors.New("signature mismatch")
	}
	return nil
}

func coalesce(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return strings.TrimSpace(fallback)
}
