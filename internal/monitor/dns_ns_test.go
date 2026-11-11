package monitor

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestDNSParentName(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com", "com"},
		{"www.example.com", "example.com"},
		{"com", "."},
		{".example.com.", "com"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := dnsParentName(tt.host); got != tt.want {
			t.Fatalf("dnsParentName(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func startNSTestServer(t *testing.T, handler mdns.HandlerFunc) (addr string, shutdown func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &mdns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = server.Shutdown() }
}

func TestLookupDNSNSPreferredServerRequiresAuthoritativeBit(t *testing.T) {
	addr, stop := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		// Simulate a recursive resolver: RD=false still returns a cached Answer without AA.
		msg.Authoritative = false
		if len(r.Question) > 0 && r.Question[0].Qtype == mdns.TypeNS {
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 86400},
				Ns:  "ns-cached.example.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stop()

	parentAddr, stopParent := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == mdns.TypeNS && !r.RecursionDesired {
			msg.Ns = append(msg.Ns, &mdns.NS{
				Hdr: mdns.RR_Header{Name: "shop.example.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns-live.example.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stopParent()

	origParent := lookupParentAuthoritativeServersFn
	lookupParentAuthoritativeServersFn = func(context.Context, string, string, time.Duration) ([]string, []string, error) {
		return []string{parentAddr}, nil, nil
	}
	defer func() { lookupParentAuthoritativeServersFn = origParent }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := lookupDNSNS(ctx, "shop.example", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("lookupDNSNS: %v", err)
	}
	if len(records) != 1 || records[0] != "ns-live.example" {
		t.Fatalf("records = %v, want parent authoritative NS (not cached recursive Answer)", records)
	}
}

func TestLookupDNSNSUsesParentAuthoritativeServers(t *testing.T) {
	addr, stop := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		if len(r.Question) == 0 {
			_ = w.WriteMsg(msg)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(strings.Trim(q.Name, "."))
		if q.Qtype == mdns.TypeNS && name == "example.com" {
			if r.RecursionDesired {
				msg.Answer = append(msg.Answer, &mdns.NS{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 86400},
					Ns:  "ns-stale.example.net.",
				})
			} else {
				msg.Ns = append(msg.Ns, &mdns.NS{
					Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
					Ns:  "ns-fresh.example.net.",
				})
			}
		}
		_ = w.WriteMsg(msg)
	})
	defer stop()

	origParent := lookupParentAuthoritativeServersFn
	lookupParentAuthoritativeServersFn = func(context.Context, string, string, time.Duration) ([]string, []string, error) {
		return []string{addr}, nil, nil
	}
	defer func() { lookupParentAuthoritativeServersFn = origParent }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty preferred server forces the parent-authoritative path.
	records, err := lookupDNSNS(ctx, "example.com", "", 2*time.Second)
	if err != nil {
		t.Fatalf("lookupDNSNS: %v", err)
	}
	if len(records) != 1 || records[0] != "ns-fresh.example.net" {
		t.Fatalf("records = %v, want authoritative fresh NS from parent", records)
	}
}

func TestDNSCheckerNSExpectedKeywordsAgainstFreshAnswer(t *testing.T) {
	addr, stop := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == mdns.TypeNS && !r.RecursionDesired {
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns1.new-provider.net.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stop()

	result := DNSChecker{}.Check(context.Background(), Monitor{
		ID:           7,
		Kind:         KindDNS,
		Target:       ComposeDNSTarget("example.org", DNSRecordTypeNS, addr),
		Timeout:      2 * time.Second,
		ExpectedText: "old-provider.net",
	})
	if result.Status != StatusDown {
		t.Fatalf("status = %s (%s), want down when expected old NS missing", result.Status, result.Message)
	}
	if !strings.Contains(result.Message, "ns1.new-provider.net") {
		t.Fatalf("message should include fresh NS, got %q", result.Message)
	}
}
