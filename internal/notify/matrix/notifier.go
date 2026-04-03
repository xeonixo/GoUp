package matrix

import (
	"context"
	"fmt"
	"strings"
	"time"

	"goup/internal/monitor"
)

type Notifier struct {
	client     *Client
	endpointID int64
}

func NewNotifier(client *Client, endpointID int64) *Notifier {
	return &Notifier{client: client, endpointID: endpointID}
}

func (n *Notifier) Enabled() bool {
	return n != nil && n.endpointID > 0
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
	if n.client == nil {
		return fmt.Errorf("matrix client is not initialized")
	}

	headline := fmt.Sprintf("%s %s: %s → %s", statusEmoji(transition.Current), transition.Monitor.Name, strings.ToUpper(string(transition.Previous)), strings.ToUpper(string(transition.Current)))
	detail := fmt.Sprintf("Kind: %s\nTarget: %s\nZeit: %s\nDetails: %s", strings.ToUpper(string(transition.Monitor.Kind)), transition.Monitor.Target, transition.CheckedAt.Local().Format(time.RFC3339), transition.ResultDetail)

	return n.client.SendMessage(ctx, headline+"\n"+detail)
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
