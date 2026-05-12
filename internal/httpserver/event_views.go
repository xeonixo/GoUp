package httpserver

import (
	"strconv"
	"strings"
	"time"

	store "goup/internal/store/sqlite"
)

type notificationEventView struct {
	ID             int64
	When           string
	WhenRaw        string
	Monitor        string
	EventType      string
	Endpoint       string
	Result         string
	Error          string
	DeliveredAt    string
	DeliveredAtRaw string
}

type monitorStateEventView struct {
	ID        int64
	When      string
	WhenRaw   string
	Group     string
	Monitor   string
	From      string
	FromClass string
	To        string
	ToClass   string
	Message   string
}

func buildNotificationEventViews(items []store.NotificationEvent) []notificationEventView {
	views := make([]notificationEventView, 0, len(items))
	for _, item := range items {
		view := notificationEventView{
			ID:        item.ID,
			When:      item.CreatedAt.UTC().Format(time.RFC3339),
			WhenRaw:   item.CreatedAt.UTC().Format(time.RFC3339),
			Monitor:   item.MonitorName,
			EventType: strings.ToUpper(strings.TrimSpace(item.EventType)),
			Endpoint:  item.Endpoint,
			Result:    "FAILED",
			Error:     item.Error,
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Endpoint == "" {
			view.Endpoint = strconv.FormatInt(item.EndpointID, 10)
		}
		if item.DeliveredAt != nil {
			view.Result = "DELIVERED"
			view.DeliveredAt = item.DeliveredAt.UTC().Format(time.RFC3339)
			view.DeliveredAtRaw = item.DeliveredAt.UTC().Format(time.RFC3339)
		}
		if strings.TrimSpace(view.Error) == "" {
			view.Error = "—"
		}
		views = append(views, view)
	}
	return views
}

func buildMonitorStateEventViews(items []store.MonitorStateEvent) []monitorStateEventView {
	views := make([]monitorStateEventView, 0, len(items))
	for _, item := range items {
		view := monitorStateEventView{
			ID:      item.ID,
			When:    item.CheckedAt.UTC().Format(time.RFC3339),
			WhenRaw: item.CheckedAt.UTC().Format(time.RFC3339),
			Group:   item.GroupName,
			Monitor: item.MonitorName,
			From:    strings.ToUpper(strings.TrimSpace(item.FromStatus)),
			To:      strings.ToUpper(strings.TrimSpace(item.ToStatus)),
			Message: strings.TrimSpace(item.Message),
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Message == "" {
			view.Message = "—"
		}
		if view.From == "" {
			view.From = "UNKNOWN"
		}
		if view.To == "" {
			view.To = "UNKNOWN"
		}
		view.FromClass = "status-" + view.From
		view.ToClass = "status-" + view.To
		views = append(views, view)
	}
	return views
}
