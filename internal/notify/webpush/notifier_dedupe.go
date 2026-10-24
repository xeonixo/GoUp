package webpush

import (
	"strconv"
	"sync"
	"time"
)

var (
	dedupeMu   sync.Mutex
	dedupeSeen = map[string]time.Time{}
)

func dedupeID(subID int64, key string) string { return strconv.FormatInt(subID, 10) + "|" + key }

func deliveredRecently(subID int64, key string) bool {
	dedupeMu.Lock()
	defer dedupeMu.Unlock()
	at, ok := dedupeSeen[dedupeID(subID, key)]
	return ok && time.Since(at) < dedupeTTL
}

func markDelivered(subID int64, key string) {
	dedupeMu.Lock()
	defer dedupeMu.Unlock()
	now := time.Now()
	dedupeSeen[dedupeID(subID, key)] = now
	if len(dedupeSeen) > 2048 {
		for k, at := range dedupeSeen {
			if now.Sub(at) > dedupeTTL {
				delete(dedupeSeen, k)
			}
		}
	}
}
