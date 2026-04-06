package matrix

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type Notifier struct {
	client       *Client
	controlStore *store.ControlPlaneStore
	tenantID     int64
	endpointID   int64
}

func NewNotifier(client *Client, endpointID int64) *Notifier {
	return &Notifier{client: client, endpointID: endpointID}
}

func NewTenantNotifier(controlStore *store.ControlPlaneStore, endpointID int64, tenantID int64) *Notifier {
	return &Notifier{controlStore: controlStore, endpointID: endpointID, tenantID: tenantID}
}

func (n *Notifier) Enabled() bool {
	if n == nil || n.endpointID <= 0 {
		return false
	}
	if n.controlStore != nil && n.tenantID > 0 {
		return true
	}
	return n.client != nil
}

func (n *Notifier) EndpointID() int64 {
	if n == nil {
		return 0
	}
	return n.endpointID
}

func (n *Notifier) EventType() string {
	return "status_transition"
}

func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}

	message := formatTransitionMessage(transition)

	if n.controlStore != nil && n.tenantID > 0 {
		targets, err := n.controlStore.ListTenantMatrixNotificationTargets(ctx, n.tenantID)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return monitor.ErrNoRecipients
		}

		var sendErrors []string
		for _, target := range targets {
			client := &Client{
				homeserverURL: strings.TrimSpace(target.HomeserverURL),
				accessToken:   strings.TrimSpace(target.AccessToken),
				roomID:        strings.TrimSpace(target.RoomID),
				httpClient:    &http.Client{Timeout: 10 * time.Second},
			}
			if !client.Enabled() {
				continue
			}
			if err := client.SendMessage(ctx, message); err != nil {
				sendErrors = append(sendErrors, fmt.Sprintf("user_id=%d: %v", target.UserID, err))
			}
		}
		if len(sendErrors) > 0 {
			return fmt.Errorf("matrix delivery failed: %s", strings.Join(sendErrors, "; "))
		}
		return nil
	}

	if n.client == nil {
		return fmt.Errorf("matrix client is not initialized")
	}
	return n.client.SendMessage(ctx, message)
}

func formatTransitionMessage(transition monitor.Transition) string {
	headline := fmt.Sprintf("%s %s: %s → %s", statusEmoji(transition.Current), transition.Monitor.Name, strings.ToUpper(string(transition.Previous)), strings.ToUpper(string(transition.Current)))
	detail := fmt.Sprintf("Kind: %s\nTarget: %s\nZeit: %s\nDetails: %s", strings.ToUpper(string(transition.Monitor.Kind)), transition.Monitor.Target, transition.CheckedAt.Local().Format(time.RFC3339), transition.ResultDetail)
	return headline + "\n" + detail
}

func statusEmoji(status monitor.Status) string {
	switch status {
	case monitor.StatusUp:
		return "✅"
	case monitor.StatusDegraded:
		return "⚠️"
	default:
		return "❌"
	}
}
