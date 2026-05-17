package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPDualStackDegradesWhenOnlyIPv4Answers(t *testing.T) {
	target, closeServer := startIPv4BannerServer(t, "220 localhost ESMTP\r\n")
	defer closeServer()

	result := SMTPChecker{}.Check(context.Background(), Monitor{
		ID:      1,
		Target:  target,
		TLSMode: TLSModeNone,
		Timeout: 200 * time.Millisecond,
	})

	if result.Status != StatusDegraded {
		t.Fatalf("status = %q, want %q; message=%q", result.Status, StatusDegraded, result.Message)
	}
	if !strings.Contains(result.Message, "SMTP dual stack degraded") {
		t.Fatalf("message = %q, want SMTP dual stack degraded details", result.Message)
	}
	if !strings.Contains(result.Message, "IPv4") || !strings.Contains(result.Message, "IPv6") {
		t.Fatalf("message = %q, want both address families", result.Message)
	}
}

func TestIMAPDualStackDegradesWhenOnlyIPv4Answers(t *testing.T) {
	target, closeServer := startIPv4BannerServer(t, "* OK localhost IMAP4rev1\r\n")
	defer closeServer()

	result := IMAPChecker{}.Check(context.Background(), Monitor{
		ID:      1,
		Target:  target,
		TLSMode: TLSModeNone,
		Timeout: 200 * time.Millisecond,
	})

	if result.Status != StatusDegraded {
		t.Fatalf("status = %q, want %q; message=%q", result.Status, StatusDegraded, result.Message)
	}
	if !strings.Contains(result.Message, "IMAP dual stack degraded") {
		t.Fatalf("message = %q, want IMAP dual stack degraded details", result.Message)
	}
	if !strings.Contains(result.Message, "IPv4") || !strings.Contains(result.Message, "IPv6") {
		t.Fatalf("message = %q, want both address families", result.Message)
	}
}

func TestMailTargetUsesHostname(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "hostname", target: "localhost:25", want: true},
		{name: "ipv4", target: "127.0.0.1:25", want: false},
		{name: "ipv6", target: "[::1]:25", want: false},
		{name: "invalid", target: "localhost", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mailTargetUsesHostname(tt.target); got != tt.want {
				t.Fatalf("mailTargetUsesHostname(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func startIPv4BannerServer(t *testing.T, banner string) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(banner))
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("split listener address: %v", err)
	}

	closeServer := func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("server did not stop")
		}
	}

	return fmt.Sprintf("localhost:%s", port), closeServer
}
