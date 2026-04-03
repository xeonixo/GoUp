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

	"goup/internal/config"
)

type Client struct {
	httpClient    *http.Client
	homeserverURL string
	accessToken   string
	roomID        string
}

func New(cfg config.MatrixConfig) *Client {
	return &Client{
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		homeserverURL: strings.TrimRight(cfg.HomeserverURL, "/"),
		accessToken:   cfg.AccessToken,
		roomID:        cfg.RoomID,
	}
}

func (c *Client) Enabled() bool {
	return c.homeserverURL != "" && c.accessToken != "" && c.roomID != ""
}

func (c *Client) SendMessage(ctx context.Context, body string) error {
	if !c.Enabled() {
		return errors.New("matrix client is not configured")
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
