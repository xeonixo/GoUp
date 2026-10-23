package notify

import (
	"context"
	"path/filepath"
	"testing"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestBuildReturnsCompleteNotifierSet(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	appStore, err := store.Open(ctx, filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer appStore.Close()

	for _, admin := range []bool{false, true} {
		notifiers, err := Build(ctx, cp, appStore, Options{TenantID: 1, TenantSlug: "acme", BaseURL: "https://goup.example", AdminOnly: admin})
		if err != nil {
			t.Fatalf("build (admin=%v): %v", admin, err)
		}
		if len(notifiers) != 4 {
			t.Fatalf("got %d notifiers, want matrix, email, webpush and webhook", len(notifiers))
		}
		fanouts := 0
		for _, n := range notifiers {
			if !n.Enabled() {
				t.Fatalf("notifier %s is disabled", n.EventType())
			}
			if _, ok := n.(monitor.FanoutNotifier); ok {
				fanouts++
			}
		}
		if fanouts != 1 {
			t.Fatalf("expected the webhook notifier to be part of the set, fanouts=%d", fanouts)
		}
	}
}
