package httpserver

import (
	"context"
	"time"

	store "goup/internal/store/sqlite"
)

const rateLimitPersistTimeout = 2 * time.Second

func (s *Server) loadPersistedRateLimitAttempts(ctx context.Context) {
	if s.controlStore == nil {
		return
	}
	items, err := s.controlStore.ListRateLimitAttempts(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("load persisted rate limit attempts failed", "error", err)
		}
		return
	}
	now := time.Now().UTC()
	expiredKeys := make([]string, 0)
	for _, item := range items {
		attempt := localLoginAttempt{
			Failures:    item.Failures,
			WindowStart: item.WindowStart,
			LockedUntil: item.LockedUntil,
		}
		switch item.Kind {
		case store.RateLimitKindLocalLogin:
			if keepAttempt(attempt, now, localLoginWindow) {
				s.localLoginAttempts[item.Key] = attempt
			} else {
				expiredKeys = append(expiredKeys, item.Key)
			}
		case store.RateLimitKindAdminAccess:
			if keepAttempt(attempt, now, adminAccessWindow) {
				s.adminAccessAttempts[item.Key] = attempt
			} else {
				expiredKeys = append(expiredKeys, item.Key)
			}
		case store.RateLimitKindBootstrap:
			if keepAttempt(attempt, now, bootstrapWindow) {
				s.bootstrapAttempts[item.Key] = attempt
			} else {
				expiredKeys = append(expiredKeys, item.Key)
			}
		default:
			expiredKeys = append(expiredKeys, item.Key)
		}
	}
	if len(expiredKeys) == 0 {
		return
	}
	deleteCtx, cancel := context.WithTimeout(context.Background(), rateLimitPersistTimeout)
	defer cancel()
	if err := s.controlStore.DeleteRateLimitAttempts(deleteCtx, expiredKeys); err != nil && s.logger != nil {
		s.logger.Warn("prune expired rate limit attempts on load failed", "error", err)
	}
}

func (s *Server) persistRateLimitAttempt(kind, key string, attempt localLoginAttempt) {
	if s.controlStore == nil || key == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateLimitPersistTimeout)
	defer cancel()
	err := s.controlStore.UpsertRateLimitAttempt(ctx, store.RateLimitAttempt{
		Key:         key,
		Kind:        kind,
		Failures:    attempt.Failures,
		WindowStart: attempt.WindowStart,
		LockedUntil: attempt.LockedUntil,
	})
	if err != nil && s.logger != nil {
		s.logger.Warn("persist rate limit attempt failed", "kind", kind, "key", key, "error", err)
	}
}

func (s *Server) deletePersistedRateLimitAttempt(key string) {
	if s.controlStore == nil || key == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateLimitPersistTimeout)
	defer cancel()
	if err := s.controlStore.DeleteRateLimitAttempt(ctx, key); err != nil && s.logger != nil {
		s.logger.Warn("delete persisted rate limit attempt failed", "key", key, "error", err)
	}
}

func (s *Server) deletePersistedRateLimitAttempts(keys []string) {
	if s.controlStore == nil || len(keys) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateLimitPersistTimeout)
	defer cancel()
	if err := s.controlStore.DeleteRateLimitAttempts(ctx, keys); err != nil && s.logger != nil {
		s.logger.Warn("delete persisted rate limit attempts failed", "count", len(keys), "error", err)
	}
}

func (s *Server) prunePersistedRateLimitAttempts(now time.Time) {
	if s.controlStore == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rateLimitPersistTimeout)
	defer cancel()
	_, err := s.controlStore.PruneRateLimitAttempts(ctx, now, map[string]time.Duration{
		store.RateLimitKindLocalLogin:  localLoginWindow,
		store.RateLimitKindAdminAccess: adminAccessWindow,
		store.RateLimitKindBootstrap:   bootstrapWindow,
	})
	if err != nil && s.logger != nil {
		s.logger.Warn("prune persisted rate limit attempts failed", "error", err)
	}
}
