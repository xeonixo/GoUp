package monitor

import (
	"context"
	"time"
)

// RetryQueueStats describes the pending notification retry queue.
type RetryQueueStats struct {
	Pending int
	// OldestAttemptAt is the earliest scheduled attempt among pending retries (nil when empty).
	OldestAttemptAt *time.Time
}

// retryQueueStatsStore is implemented by stores that can report on the retry queue.
type retryQueueStatsStore interface {
	NotificationRetryQueueStats(ctx context.Context) (int, *time.Time, error)
}

// RetryQueueStats reports the number of pending notification retries and the oldest scheduled one.
// Stores without queue statistics yield an empty result.
func (d *Dispatcher) RetryQueueStats(ctx context.Context) (RetryQueueStats, error) {
	source, ok := d.store.(retryQueueStatsStore)
	if !ok {
		return RetryQueueStats{}, nil
	}
	pending, oldest, err := source.NotificationRetryQueueStats(ctx)
	if err != nil {
		return RetryQueueStats{}, err
	}
	return RetryQueueStats{Pending: pending, OldestAttemptAt: oldest}, nil
}
