package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusPageSubscriptionDoubleOptIn(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Shop", Kind: "tcp", Target: "10.9.8.7:443", Interval: time.Minute, Timeout: time.Second,
		Enabled: true, TLSMode: "none", ConfirmAfter: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveStatusPageSettings(ctx, StatusPageSettings{Enabled: true}, []StatusPageMonitor{{MonitorID: id, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}

	confirm, err := st.UpsertPendingStatusPageSubscription(ctx, "Visitor@Example.com", "de", []int64{id})
	if err != nil || confirm == "" {
		t.Fatalf("pending: token=%q err=%v", confirm, err)
	}
	subs, err := st.ListConfirmedStatusPageSubscribersForMonitor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("confirmed before opt-in: %d", len(subs))
	}

	unsub, err := st.ConfirmStatusPageSubscription(ctx, confirm)
	if err != nil || unsub == "" {
		t.Fatalf("confirm: unsub=%q err=%v", unsub, err)
	}
	subs, err = st.ListConfirmedStatusPageSubscribersForMonitor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].Email != "Visitor@Example.com" || subs[0].Language != "de" {
		t.Fatalf("subs = %+v", subs)
	}
	if name, ok, err := st.StatusPageDisplayNameForMonitor(ctx, id); err != nil || !ok || name != "Online Shop" {
		t.Fatalf("display name = %q ok=%v err=%v", name, ok, err)
	}

	// Re-subscribe while confirmed updates monitors without a new confirm mail.
	again, err := st.UpsertPendingStatusPageSubscription(ctx, "visitor@example.com", "en", nil)
	if err != nil || again != "" {
		t.Fatalf("already confirmed upsert: token=%q err=%v", again, err)
	}

	if err := st.UnsubscribeStatusPageSubscription(ctx, unsub); err != nil {
		t.Fatal(err)
	}
	subs, err = st.ListConfirmedStatusPageSubscribersForMonitor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Fatalf("after unsubscribe: %d", len(subs))
	}
}

func TestStatusPageSubscriptionConfirmExpiry(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "API", Kind: "tcp", Target: "10.1.1.1:443", Interval: time.Minute, Timeout: time.Second,
		Enabled: true, TLSMode: "none", ConfirmAfter: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveStatusPageSettings(ctx, StatusPageSettings{Enabled: true}, []StatusPageMonitor{{MonitorID: id}}); err != nil {
		t.Fatal(err)
	}
	token, err := st.UpsertPendingStatusPageSubscription(ctx, "a@b.co", "en", []int64{id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
UPDATE status_page_subscriptions SET confirm_sent_at = ? WHERE email_normalized = ?
`, time.Now().UTC().Add(-statusPageConfirmTokenTTL-time.Minute), "a@b.co"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConfirmStatusPageSubscription(ctx, token); err == nil {
		t.Fatal("expected expired confirm to fail")
	}
}
