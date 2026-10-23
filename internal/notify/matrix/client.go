package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goup/internal/netguard"
)

type Client struct {
	httpClient    *http.Client
	homeserverURL string
	accessToken   string
	roomID        string
}

// newGuardedHTTPClient returns an SSRF-guarded client: connections to private,
// loopback and metadata addresses are refused unless
// GOUP_ALLOW_PRIVATE_INTEGRATIONS=true (metadata addresses are always refused).
// Redirects are not followed.
func newGuardedHTTPClient() *http.Client {
	return netguard.NewHTTPClient(netguard.Options{
		Timeout:      10 * time.Second,
		AllowPrivate: netguard.AllowPrivateIntegrationsFromEnv(),
		UseEnvProxy:  true,
	})
}

func New(homeserverURL, accessToken, roomID string) *Client {
	return &Client{
		httpClient:    newGuardedHTTPClient(),
		homeserverURL: strings.TrimRight(homeserverURL, "/"),
		accessToken:   accessToken,
		roomID:        roomID,
	}
}

func (c *Client) Enabled() bool {
	return c.homeserverURL != "" && c.accessToken != "" && c.roomID != ""
}

func (c *Client) SendMessage(ctx context.Context, body string) error {
	if !c.Enabled() {
		return errors.New("matrix client is not configured")
	}

	if _, err := netguard.ValidateURL(c.homeserverURL, netguard.AllowPrivateIntegrationsFromEnv()); err != nil {
		return fmt.Errorf("matrix homeserver url rejected: %w", err)
	}

	payload, err := json.Marshal(map[string]string{
		"msgtype": "m.text",
		"body":    body,
	})
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/_matrix/client/v3/rooms/%s/send/m.room.message/%d", c.homeserverURL, url.PathEscape(c.roomID), time.Now().UnixNano())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("matrix send failed with status %s", resp.Status)
	}

	return nil
}
