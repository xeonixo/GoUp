package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/monitor"
)

func openHeartbeatTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func heartbeatParams(name string) CreateMonitorParams {
	return CreateMonitorParams{Name: name, Kind: monitor.KindHeartbeat, Interval: 24 * time.Hour, Timeout: 5 * time.Minute, Enabled: true}
}

func TestHeartbeatMonitorTokenGeneratedAndUnique(t *testing.T) {
	ctx := context.Background()
	st := openHeartbeatTestStore(t)

	first, err := st.CreateMonitor(ctx, heartbeatParams("one"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := st.CreateMonitor(ctx, heartbeatParams("two"))
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	a, _ := st.GetMonitorSnapshot(ctx, first)
	b, _ := st.GetMonitorSnapshot(ctx, second)
	if len(a.Monitor.HeartbeatToken) != 43 || a.Monitor.HeartbeatToken == b.Monitor.HeartbeatToken {
		t.Fatalf("tokens must be 43 chars and unique: %q %q", a.Monitor.HeartbeatToken, b.Monitor.HeartbeatToken)
	}
	if a.Monitor.Target != HeartbeatTarget || a.Monitor.ExecutorKind != "local" || a.Monitor.TLSMode != monitor.TLSModeNone {
		t.Fatalf("heartbeat fields not normalized: %+v", a.Monitor)
	}

	// The unique index rejects a duplicate token; empty tokens of other kinds do not collide.
	if _, err := st.db.ExecContext(ctx, `UPDATE monitors SET heartbeat_token = ? WHERE id = ?`, a.Monitor.HeartbeatToken, second); err == nil {
		t.Fatalf("duplicate token must be rejected")
	}
	for _, name := range []string{"x", "y"} {
		if _, err := st.CreateMonitor(ctx, CreateMonitorParams{Name: name, Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, TLSMode: monitor.TLSModeNone}); err != nil {
			t.Fatalf("create tcp monitor: %v", err)
		}
	}

	found, err := st.GetMonitorSnapshotByHeartbeatToken(ctx, a.Monitor.HeartbeatToken)
	if err != nil || found.Monitor.ID != first {
		t.Fatalf("lookup by token: %+v err=%v", found.Monitor, err)
	}
	for _, token := range []string{"", "nope"} {
		if _, err := st.GetMonitorSnapshotByHeartbeatToken(ctx, token); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("token %q: err = %v, want ErrNoRows", token, err)
		}
	}
}

func TestHeartbeatRecordAndRegenerate(t *testing.T) {
	ctx := context.Background()
	st := openHeartbeatTestStore(t)
	id, err := st.CreateMonitor(ctx, heartbeatParams("job"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetMonitorSnapshot(ctx, id)
	if before.Monitor.LastHeartbeatAt != nil || before.Monitor.LastHeartbeatFailed {
		t.Fatalf("new monitor must have no heartbeat: %+v", before.Monitor)
	}

	at := time.Now().UTC().Truncate(time.Second)
	if err := st.RecordHeartbeat(ctx, id, at, false); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetMonitorSnapshot(ctx, id)
	if after.Monitor.LastHeartbeatAt == nil || !after.Monitor.LastHeartbeatAt.Equal(at) || !after.Monitor.LastHeartbeatFailed {
		t.Fatalf("heartbeat not stored: %+v", after.Monitor)
	}

	token, err := st.RegenerateHeartbeatToken(ctx, id)
	if err != nil || token == before.Monitor.HeartbeatToken {
		t.Fatalf("regenerate: %q err=%v", token, err)
	}
	if _, err := st.GetMonitorSnapshotByHeartbeatToken(ctx, before.Monitor.HeartbeatToken); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old token must stop working, err=%v", err)
	}
	if _, err := st.GetMonitorSnapshotByHeartbeatToken(ctx, token); err != nil {
		t.Fatalf("new token must work: %v", err)
	}

	tcp, _ := st.CreateMonitor(ctx, CreateMonitorParams{Name: "t", Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, TLSMode: monitor.TLSModeNone})
	if _, err := st.RegenerateHeartbeatToken(ctx, tcp); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("non-heartbeat monitor: err = %v", err)
	}
}

func TestHeartbeatUpdateKeepsOrClearsToken(t *testing.T) {
	ctx := context.Background()
	st := openHeartbeatTestStore(t)
	id, _ := st.CreateMonitor(ctx, heartbeatParams("job"))
	orig, _ := st.GetMonitorSnapshot(ctx, id)

	params := heartbeatParams("job renamed")
	params.Interval = time.Hour
	if err := st.UpdateMonitor(ctx, UpdateMonitorParams{ID: id, CreateMonitorParams: params}); err != nil {
		t.Fatal(err)
	}
	kept, _ := st.GetMonitorSnapshot(ctx, id)
	if kept.Monitor.HeartbeatToken != orig.Monitor.HeartbeatToken || kept.Monitor.Interval != time.Hour {
		t.Fatalf("update must keep the token: %+v", kept.Monitor)
	}

	tcp := CreateMonitorParams{Name: "job", Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, TLSMode: monitor.TLSModeNone, Enabled: true}
	if err := st.UpdateMonitor(ctx, UpdateMonitorParams{ID: id, CreateMonitorParams: tcp}); err != nil {
		t.Fatal(err)
	}
	if cleared, _ := st.GetMonitorSnapshot(ctx, id); cleared.Monitor.HeartbeatToken != "" {
		t.Fatalf("switching away from heartbeat must clear the token")
	}

	// Switching an existing monitor to heartbeat issues a token.
	if err := st.UpdateMonitor(ctx, UpdateMonitorParams{ID: id, CreateMonitorParams: heartbeatParams("job")}); err != nil {
		t.Fatal(err)
	}
	if issued, _ := st.GetMonitorSnapshot(ctx, id); len(issued.Monitor.HeartbeatToken) != 43 {
		t.Fatalf("switching to heartbeat must issue a token")
	}
}

func TestHeartbeatValidation(t *testing.T) {
	ctx := context.Background()
	st := openHeartbeatTestStore(t)

	short := heartbeatParams("short")
	short.Interval = 30 * time.Second
	if _, err := st.CreateMonitor(ctx, short); err == nil {
		t.Fatalf("period below 60s must be rejected")
	}
	negative := heartbeatParams("neg")
	negative.Timeout = -time.Second
	if _, err := st.CreateMonitor(ctx, negative); err == nil {
		t.Fatalf("negative grace must be rejected")
	}
	noGrace := heartbeatParams("zero")
	noGrace.Timeout = 0
	if _, err := st.CreateMonitor(ctx, noGrace); err != nil {
		t.Fatalf("zero grace must be allowed: %v", err)
	}
	remote := heartbeatParams("remote")
	remote.ExecutorKind, remote.ExecutorRef = "remote", "node-1"
	id, err := st.CreateMonitor(ctx, remote)
	if err != nil {
		t.Fatalf("executor is forced to local: %v", err)
	}
	if snap, _ := st.GetMonitorSnapshot(ctx, id); snap.Monitor.ExecutorKind != "local" {
		t.Fatalf("executor = %q", snap.Monitor.ExecutorKind)
	}
	if err := st.UpdateMonitorTarget(ctx, id, "https://example.com"); err == nil {
		t.Fatalf("heartbeat monitors have no editable target")
	}
}

func TestHeartbeatSlugReserved(t *testing.T) {
	if !IsReservedTenantSlug("hb") || !IsReservedTenantSlug("HB") {
		t.Fatalf("hb must be a reserved tenant slug")
	}
}
