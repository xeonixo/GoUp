package httpserver

import (
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"strconv"
	"strings"
	"time"
)

type monitorGroupView struct {
	Title       string
	Subtitle    string
	EmptyText   string
	AccentClass string
	Monitors    []monitorView
	Services    []monitorServiceGroupView
	Count       int
	ServiceHint string
}

type monitorServiceGroupView struct {
	Title       string
	Subtitle    string
	StatusLabel string
	StatusClass string
	StatusInfo  string
	TrendLabel  string
	UptimeLabel string
	TrendPoints []trendPointView
	IconSlug    string
	IconURL     string
	Monitors    []monitorView
	Open        bool
	CanMoveUp   bool
	CanMoveDown bool
}

type monitorView struct {
	ID                   int64
	Name                 string
	Group                string
	SortOrder            int
	CanMoveUp            bool
	CanMoveDown          bool
	KindValue            string
	Kind                 string
	TLSMode              string
	TLSModeValue         string
	Target               string
	TargetLabel          string
	Interval             string
	IntervalSeconds      int
	Timeout              string
	TimeoutSeconds       int
	Enabled              bool
	ExecutorKind         string
	ExecutorRef          string
	ExecutorValue        string
	ExecutorLabel        string
	NotifyOnRecovery     bool
	RetryCount           int
	RetryIntervalSeconds int
	ExpectedStatus       string
	ExpectedText         string
	TrendLabel           string
	StatusLabel          string
	StatusClass          string
	StatusSummary        string
	LastCheckedAt        string
	LastCheckedAtRaw     string
	LastStatus           string
	LastMessage          string
	LastLatency          string
	TrendPoints          []trendPointView
	UptimeLabel          string
	HTTPStatusCode       string
	TLSDaysRemaining     string
	TLSNotAfter          string
	TLSNotAfterRaw       string
}

func buildMonitorViews(items []monitor.Snapshot, rollups []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange, remoteNodeNames map[string]string) []monitorView {
	rollupsByMonitor := groupRollupsByMonitor(rollups)
	views := make([]monitorView, 0, len(items))
	for _, item := range items {
		kindLabel := monitorKindLabel(item.Monitor.Kind)
		tlsLabel := monitorTLSModeLabel(item.Monitor)
		if item.Monitor.Kind == monitor.KindHTTPS {
			kindLabel = monitorHTTPKindLabel(item.Monitor.Target, item.Monitor.TLSMode)
			tlsLabel = ""
		}

		view := monitorView{
			ID:                   item.Monitor.ID,
			Name:                 item.Monitor.Name,
			Group:                effectiveMonitorGroup(strings.TrimSpace(item.Monitor.Group), item.Monitor.Name, item.Monitor.Target),
			SortOrder:            item.Monitor.SortOrder,
			ExecutorKind:         strings.TrimSpace(item.Monitor.ExecutorKind),
			ExecutorRef:          strings.TrimSpace(item.Monitor.ExecutorRef),
			KindValue:            string(item.Monitor.Kind),
			Kind:                 kindLabel,
			TLSMode:              tlsLabel,
			TLSModeValue:         string(item.Monitor.TLSMode),
			Target:               item.Monitor.Target,
			TargetLabel:          monitorTargetLabel(item.Monitor),
			Interval:             item.Monitor.Interval.String(),
			IntervalSeconds:      int(item.Monitor.Interval / time.Second),
			Timeout:              item.Monitor.Timeout.String(),
			TimeoutSeconds:       int(item.Monitor.Timeout / time.Second),
			Enabled:              item.Monitor.Enabled,
			NotifyOnRecovery:     item.Monitor.NotifyOnRecovery,
			RetryCount:           item.Monitor.RetryCount,
			RetryIntervalSeconds: int(item.Monitor.RetryInterval / time.Second),
			TrendLabel:           selectedTrend.Label,
			TrendPoints:          buildTrendPoints(rollupsByMonitor[item.Monitor.ID], now, selectedTrend),
		}
		if view.ExecutorKind == "" {
			view.ExecutorKind = "local"
		}
		if view.ExecutorKind == "remote" && view.ExecutorRef != "" {
			view.ExecutorValue = "remote:" + view.ExecutorRef
			view.ExecutorLabel = "Remote: " + view.ExecutorRef
			if remoteNodeNames != nil {
				if remoteName := strings.TrimSpace(remoteNodeNames[view.ExecutorRef]); remoteName != "" {
					view.ExecutorLabel = "Remote: " + remoteName + " (" + view.ExecutorRef + ")"
				}
			}
		} else {
			view.ExecutorKind = "local"
			view.ExecutorRef = ""
			view.ExecutorValue = "local"
			view.ExecutorLabel = "Control-Plane (lokal)"
		}
		view.UptimeLabel = summarizeTrend(view.TrendPoints, selectedTrend)
		view.StatusLabel = "UNKNOWN"
		view.StatusClass = "status-UNKNOWN"
		view.StatusSummary = "No successful check yet"
		if item.Monitor.ExpectedStatusCode != nil {
			view.ExpectedStatus = strconv.Itoa(*item.Monitor.ExpectedStatusCode)
		}
		view.ExpectedText = strings.TrimSpace(item.Monitor.ExpectedText)
		if item.LastResult != nil {
			view.LastCheckedAt = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastCheckedAtRaw = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastStatus = strings.ToUpper(string(item.LastResult.Status))
			view.StatusLabel = view.LastStatus
			view.StatusClass = "status-" + view.LastStatus
			view.StatusSummary = item.LastResult.Message
			view.LastMessage = item.LastResult.Message
			view.LastLatency = formatLatencyLabel(item.LastResult.Latency)
			if isTimeoutMessage(item.LastResult.Message) {
				view.LastLatency = ""
			}
			if item.Monitor.Kind == monitor.KindICMP {
				if dualLatency := icmpDualStackLatencyLabel(item.LastResult.Message); dualLatency != "" {
					view.LastLatency = dualLatency
				}
			}
			if item.LastResult.HTTPStatusCode != nil {
				view.HTTPStatusCode = strconv.Itoa(*item.LastResult.HTTPStatusCode)
			}
			if item.LastResult.TLSDaysRemaining != nil {
				view.TLSDaysRemaining = strconv.Itoa(*item.LastResult.TLSDaysRemaining) + " Tage"
			}
			if item.LastResult.TLSNotAfter != nil {
				view.TLSNotAfter = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
				view.TLSNotAfterRaw = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
			}
		}
		if !item.Monitor.Enabled {
			view.StatusLabel = "PAUSED"
			view.StatusClass = "status-PAUSED"
			view.StatusSummary = "Monitor is paused"
		}
		views = append(views, view)
	}
	return views
}
