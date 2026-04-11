package monitor

import "time"

// NotificationRetryParams holds all data needed to enqueue a persistent retry.
type NotificationRetryParams struct {
	MonitorID      int64
	EndpointID     int64
	EventType      string
	Transition     Transition
	MaxAttempts    int
	NextAttemptAt  time.Time
}

// NotificationRetry represents a pending or completed retry row from the store.
type NotificationRetry struct {
	ID           int64
	EndpointID   int64
	EventType    string
	Transition   Transition
	AttemptCount int
	MaxAttempts  int
	NextAttemptAt time.Time
}
