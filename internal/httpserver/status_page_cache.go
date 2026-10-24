package httpserver

import (
	"strconv"
	"sync"
	"time"
)

type statusPageCacheEntry struct {
	body      []byte // nil means "status page disabled"
	expiresAt time.Time
}

// statusPageCache keeps the rendered page per tenant and language for statusPageCacheTTL.
type statusPageCache struct {
	mu      sync.Mutex
	entries map[string]statusPageCacheEntry
}

func statusPageCacheKey(tenantID int64, lang string) string {
	return lang + "|" + strconv.FormatInt(tenantID, 10)
}

func (c *statusPageCache) get(key string, now time.Time) (statusPageCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || !now.Before(entry.expiresAt) {
		return statusPageCacheEntry{}, false
	}
	return entry, true
}

func (c *statusPageCache) put(key string, entry statusPageCacheEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]statusPageCacheEntry)
	}
	for k, v := range c.entries {
		if !now.Before(v.expiresAt) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = entry
}

func (c *statusPageCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
}
