package webpush

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type pushRequest struct {
	Path    string
	Headers http.Header
	Body    []byte
}

type pushServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []pushRequest
	status   map[string]int
}

func newPushServer(t *testing.T) *pushServer {
	t.Helper()
	ps := &pushServer{status: map[string]int{}}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ps.mu.Lock()
		ps.requests = append(ps.requests, pushRequest{Path: r.URL.Path, Headers: r.Header.Clone(), Body: body})
		code := ps.status[r.URL.Path]
		ps.mu.Unlock()
		if code == 0 {
			code = http.StatusCreated
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(ps.Close)
	return ps
}

func (p *pushServer) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.requests {
		if r.Path == path {
			n++
		}
	}
	return n
}

type device struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newDevice(t *testing.T) (device, string, string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return device{priv: priv, auth: auth},
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(auth)
}

// decrypt reverses RFC 8291 (aes128gcm) for a single-record message.
func (d device) decrypt(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) < 21 {
		t.Fatalf("body too short: %d", len(body))
	}
	salt := body[:16]
	idLen := int(body[20])
	asPub := body[21 : 21+idLen]
	ciphertext := body[21+idLen:]
	_ = binary.BigEndian.Uint32(body[16:20])

	remote, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatalf("server public key: %v", err)
	}
	secret, err := d.priv.ECDH(remote)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("WebPush: info\x00"), d.priv.PublicKey().Bytes()...)
	info = append(info, asPub...)
	read := func(h io.Reader, n int) []byte {
		out := make([]byte, n)
		if _, err := io.ReadFull(h, out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ikm := read(hkdf.New(sha256.New, secret, d.auth, info), 32)
	cek := read(hkdf.New(sha256.New, ikm, salt, []byte("Content-Encoding: aes128gcm\x00")), 16)
	nonce := read(hkdf.New(sha256.New, ikm, salt, []byte("Content-Encoding: nonce\x00")), 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	end := len(plain)
	for end > 0 && plain[end-1] == 0 {
		end--
	}
	if end == 0 || plain[end-1] != 0x02 {
		t.Fatalf("missing padding delimiter")
	}
	return plain[:end-1]
}

type fakeState struct{ down int }

func (f fakeState) ListMonitorSnapshots(context.Context) ([]monitor.Snapshot, error) {
	var out []monitor.Snapshot
	for i := 0; i < f.down; i++ {
		out = append(out, monitor.Snapshot{
			Monitor:    monitor.Monitor{ID: int64(100 + i), Enabled: true},
			LastResult: &monitor.Result{Status: monitor.StatusDown},
		})
	}
	out = append(out, monitor.Snapshot{Monitor: monitor.Monitor{ID: 1, Enabled: true}, LastResult: &monitor.Result{Status: monitor.StatusUp}})
	return out, nil
}

func (f fakeState) ListMonitorIncidents(context.Context, int64, int) ([]store.MonitorIncident, error) {
	return []store.MonitorIncident{{StartedAt: time.Now().Add(-12 * time.Minute)}}, nil
}

type env struct {
	cp       *store.ControlPlaneStore
	tenant   store.Tenant
	user     store.LocalUser
	sender   *Sender
	server   *pushServer
	notifier *Notifier
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	if err := cp.ConfigureSecretKey("test-secret-key-for-webpush-tests"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "ops", "password-123456", "ops@example.com", "Ops", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.UpdateUserProfileForTenant(ctx, tenant.ID, user.UserID, "ops@example.com", "Ops", "de"); err != nil {
		t.Fatal(err)
	}
	srv := newPushServer(t)
	sender := NewSender(cp, "https://goup.example")
	sender.client = srv.Client()
	sender.checkEndpoint = func(string) error { return nil }
	return &env{
		cp: cp, tenant: tenant, user: user, sender: sender, server: srv,
		notifier: NewTenantNotifier(sender, cp, fakeState{down: 1}, 5, tenant.ID, "acme"),
	}
}

func (e *env) addDevice(t *testing.T, path string) (device, store.PushSubscription) {
	t.Helper()
	dev, p256dh, auth := newDevice(t)
	sub, err := e.cp.UpsertPushSubscription(context.Background(), store.PushSubscription{
		TenantID: e.tenant.ID, UserID: e.user.UserID, Endpoint: e.server.URL + path, P256dh: p256dh, Auth: auth,
		NotifyDown: true, NotifyRecovery: true, NotifyDegraded: true, NotifyReminder: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dev, sub
}

var transitionSeq atomic.Int64

// transition shifts the check time so every call is a distinct event; the retry de-duplication
// is process-wide and subscription ids repeat across the per-test databases.
func transition(prev, cur monitor.Status, at time.Time) monitor.Transition {
	at = at.Add(time.Duration(transitionSeq.Add(1)) * time.Second)
	return monitor.Transition{
		Monitor:  monitor.Monitor{ID: 7, Name: "Web", Enabled: true},
		Previous: prev, Current: cur, CheckedAt: at, ResultDetail: "connection refused",
	}
}

func TestNotifyDownSendsEncryptedHighUrgencyPush(t *testing.T) {
	e := newEnv(t)
	dev, _ := e.addDevice(t, "/down")

	if err := e.notifier.Notify(context.Background(), transition(monitor.StatusUp, monitor.StatusDown, time.Now())); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if len(e.server.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(e.server.requests))
	}
	req := e.server.requests[0]
	if got := req.Headers.Get("TTL"); got != "86400" {
		t.Errorf("TTL = %q", got)
	}
	if got := req.Headers.Get("Urgency"); got != "high" {
		t.Errorf("Urgency = %q", got)
	}
	if got := req.Headers.Get("Content-Encoding"); got != "aes128gcm" {
		t.Errorf("Content-Encoding = %q", got)
	}
	_, pub, _ := e.cp.GetOrCreateVAPIDKeys(context.Background())
	auth := req.Headers.Get("Authorization")
	if !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+pub) {
		t.Errorf("Authorization = %q", auth)
	}

	var p Payload
	if err := json.Unmarshal(dev.decrypt(t, req.Body), &p); err != nil {
		t.Fatal(err)
	}
	if p.Title != "🔴 Web ist DOWN" || p.URL != "/acme/monitors/7" || p.Tag != MonitorTag(e.tenant.ID, 7) {
		t.Errorf("payload = %#v", p)
	}
	if !strings.Contains(p.Body, "connection refused") {
		t.Errorf("body = %q", p.Body)
	}
	if p.BadgeCount == nil || *p.BadgeCount != 1 {
		t.Errorf("badge = %v, want 1", p.BadgeCount)
	}
}

func TestNotifyRecoveryNormalUrgencyWithDowntimeAndCategoryFilter(t *testing.T) {
	e := newEnv(t)
	dev, sub := e.addDevice(t, "/rec")

	if err := e.notifier.Notify(context.Background(), transition(monitor.StatusDown, monitor.StatusUp, time.Now())); err != nil {
		t.Fatal(err)
	}
	req := e.server.requests[0]
	if got := req.Headers.Get("Urgency"); got != "normal" {
		t.Errorf("Urgency = %q", got)
	}
	var p Payload
	_ = json.Unmarshal(dev.decrypt(t, req.Body), &p)
	if p.Title != "🟢 Web ist wieder UP" || !strings.Contains(p.Body, "12 min") {
		t.Errorf("payload = %#v", p)
	}

	// Recovery disabled on the device: nothing is sent.
	if _, err := e.cp.UpdatePushSubscriptionPrefs(context.Background(), e.tenant.ID, e.user.UserID, sub.ID, store.PushPrefs{Down: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.notifier.Notify(context.Background(), transition(monitor.StatusDown, monitor.StatusUp, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if len(e.server.requests) != 1 {
		t.Fatalf("filtered category was still sent (%d requests)", len(e.server.requests))
	}
}

func TestNotifyGoneSubscriptionIsDeleted(t *testing.T) {
	e := newEnv(t)
	e.addDevice(t, "/gone")
	e.server.status["/gone"] = http.StatusGone

	if err := e.notifier.Notify(context.Background(), transition(monitor.StatusUp, monitor.StatusDown, time.Now())); err != nil {
		t.Fatalf("a 410 is not a retryable error: %v", err)
	}
	subs, _ := e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.user.UserID)
	if len(subs) != 0 {
		t.Fatalf("expired subscription not deleted: %#v", subs)
	}
}

func TestNotifyRetryOnlyResendsToFailedDevices(t *testing.T) {
	e := newEnv(t)
	e.addDevice(t, "/ok")
	_, bad := e.addDevice(t, "/bad")
	e.server.status["/bad"] = http.StatusInternalServerError
	tr := transition(monitor.StatusUp, monitor.StatusDown, time.Now())

	if err := e.notifier.Notify(context.Background(), tr); err == nil {
		t.Fatal("expected an error so the retry queue retries the failed device")
	}
	e.server.status["/bad"] = http.StatusCreated
	if err := e.notifier.Notify(context.Background(), tr); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if e.server.count("/ok") != 1 {
		t.Errorf("successful device received %d pushes, want exactly 1", e.server.count("/ok"))
	}
	if e.server.count("/bad") != 2 {
		t.Errorf("failed device received %d attempts, want 2", e.server.count("/bad"))
	}
	subs, _ := e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.user.UserID)
	for _, s := range subs {
		if s.ID == bad.ID && (s.LastSuccessAt == nil || s.LastError != "") {
			t.Errorf("retry success not recorded: %#v", s)
		}
	}
}

func TestNotifyWithoutDevicesReportsNoRecipients(t *testing.T) {
	e := newEnv(t)
	err := e.notifier.Notify(context.Background(), transition(monitor.StatusUp, monitor.StatusDown, time.Now()))
	if !errors.Is(err, monitor.ErrNoRecipients) {
		t.Fatalf("err = %v, want ErrNoRecipients", err)
	}
}

func TestValidateEndpoint(t *testing.T) {
	valid := []string{
		"https://web.push.apple.com/QAbc",
		"https://fcm.googleapis.com/fcm/send/abc",
		"https://updates.push.services.mozilla.com/wpush/v2/abc",
		"https://wns2-par02p.notify.windows.com/w/?token=x",
	}
	for _, u := range valid {
		if _, err := ValidateEndpoint(u); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	invalid := []string{
		"http://web.push.apple.com/x",
		"https://evil.example.com/x",
		"https://push.apple.com.evil.example/x",
		"https://notpush.apple.com.attacker.io/",
		"https://127.0.0.1/x",
		"https://localhost/x",
		"https://user:pw@web.push.apple.com/x",
		"https://web.push.apple.com:8443/x",
		"https://169.254.169.254/latest",
		"",
	}
	for _, u := range invalid {
		if _, err := ValidateEndpoint(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestNormalizeKeys(t *testing.T) {
	_, p, a := newDevice(t)
	if _, _, err := NormalizeKeys(p, a); err != nil {
		t.Fatalf("valid keys rejected: %v", err)
	}
	if _, _, err := NormalizeKeys("AAAA", a); err == nil {
		t.Error("short p256dh accepted")
	}
	if _, _, err := NormalizeKeys(p, "AAAA"); err == nil {
		t.Error("short auth accepted")
	}
}

func TestCategoryOf(t *testing.T) {
	cases := map[monitor.Status]Category{
		monitor.StatusDown: CategoryDown, monitor.StatusUp: CategoryRecovery,
		monitor.StatusDegraded: CategoryDegraded, monitor.StatusUnknown: CategoryDegraded,
	}
	for status, want := range cases {
		if got := CategoryOf(monitor.Transition{Current: status}); got != want {
			t.Errorf("CategoryOf(%s) = %s, want %s", status, got, want)
		}
	}
}

func TestReminderCategoryAndPayload(t *testing.T) {
	tr := monitor.Transition{
		Monitor:  monitor.Monitor{ID: 4, Name: "API"},
		Previous: monitor.StatusDown, Current: monitor.StatusDown,
		Reminder: true, OutageDuration: 135 * time.Minute,
	}
	if got := CategoryOf(tr); got != CategoryReminder {
		t.Fatalf("category = %s, want reminder", got)
	}
	if !Wants(store.PushSubscription{NotifyReminder: true}, CategoryOf(tr)) || Wants(store.PushSubscription{NotifyDown: true}, CategoryOf(tr)) {
		t.Fatal("reminders must follow the reminder preference only")
	}
	p := BuildPayload(tr, 1, "acme", "en", nil, 0, 0)
	if !strings.Contains(p.Title, "still DOWN") || !strings.Contains(p.Body, "2 h 15 min") {
		t.Fatalf("payload = %+v", p)
	}
	de := BuildPayload(tr, 1, "acme", "de", nil, 0, 0)
	if !strings.Contains(de.Title, "weiterhin DOWN") || !strings.Contains(de.Body, "2 h 15 min") {
		t.Fatalf("german payload = %+v", de)
	}
}
