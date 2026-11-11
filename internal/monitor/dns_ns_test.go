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

func TestLookupDNSNSPrefersRDFalseOverStaleRecursive(t *testing.T) {
	addr, stop := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = !r.RecursionDesired
		if len(r.Question) == 0 {
			_ = w.WriteMsg(msg)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(strings.Trim(q.Name, "."))
		if q.Qtype != mdns.TypeNS || name != "shop.example" {
			_ = w.WriteMsg(msg)
			return
		}
		ns := "ns-stale.example."
		section := &msg.Answer
		if !r.RecursionDesired {
			ns = "ns-live.example."
			section = &msg.Ns
		}
		*section = append(*section, &mdns.NS{
			Hdr: mdns.RR_Header{Name: "shop.example.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
			Ns:  ns,
		})
		_ = w.WriteMsg(msg)
	})
	defer stop()

	origResolvers := dnsResolverServersFn
	dnsResolverServersFn = func(preferred string) []string {
		normalized, err := NormalizeDNSServer(preferred)
		if err != nil || normalized == "" {
			t.Fatalf("preferred resolver: %v", err)
		}
		return []string{normalized}
	}
	defer func() { dnsResolverServersFn = origResolvers }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := lookupDNSNS(ctx, "shop.example", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("lookupDNSNS: %v", err)
	}
	if len(records) != 1 || records[0] != "ns-live.example" {
		t.Fatalf("records = %v, want ns-live.example from RD=false referral/answer", records)
	}
}

func TestLookupDNSNSParentServersQueriedInParallelWithShortTimeout(t *testing.T) {
	// Use a non-delegated test name so CI system resolvers cannot answer first.
	const host = "shop.example.test"

	parentAddr, stopParent := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		if len(r.Question) > 0 && r.Question[0].Qtype == mdns.TypeNS && !r.RecursionDesired {
			msg.Ns = append(msg.Ns, &mdns.NS{
				Hdr: mdns.RR_Header{Name: host + ".", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns-fresh.example.net.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stopParent()

	// Resolver returns no RD=false records, but answers parent NS recursively.
	resolverAddr, stopResolver := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(msg)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(strings.Trim(q.Name, "."))
		switch {
		case q.Qtype == mdns.TypeNS && name == "example.test" && r.RecursionDesired:
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: "example.test.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns.test-parent.",
			})
		case q.Qtype == mdns.TypeNS && name == host && r.RecursionDesired:
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: host + ".", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 86400},
				Ns:  "ns-stale.example.net.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stopResolver()

	origResolve := resolveDNSHostPortsFn
	resolveDNSHostPortsFn = func(context.Context, string, time.Duration) []string {
		return []string{parentAddr}
	}
	defer func() { resolveDNSHostPortsFn = origResolve }()

	origResolvers := dnsResolverServersFn
	dnsResolverServersFn = func(preferred string) []string {
		normalized, err := NormalizeDNSServer(preferred)
		if err != nil || normalized == "" {
			t.Fatalf("preferred resolver: %v", err)
		}
		return []string{normalized}
	}
	defer func() { dnsResolverServersFn = origResolvers }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	records, err := lookupDNSNS(ctx, host, resolverAddr, 3*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("lookupDNSNS: %v", err)
	}
	if len(records) != 1 || records[0] != "ns-fresh.example.net" {
		t.Fatalf("records = %v, want fresh parent-authoritative NS", records)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("lookup took %s, likely sequential timeouts instead of short parallel attempts", elapsed)
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

	origResolvers := dnsResolverServersFn
	dnsResolverServersFn = func(preferred string) []string {
		normalized, err := NormalizeDNSServer(preferred)
		if err != nil || normalized == "" {
			t.Fatalf("preferred resolver: %v", err)
		}
		return []string{normalized}
	}
	defer func() { dnsResolverServersFn = origResolvers }()

	result := DNSChecker{}.Check(context.Background(), Monitor{
		ID:           7,
		Kind:         KindDNS,
		Target:       ComposeDNSTarget("shop.example.test", DNSRecordTypeNS, addr),
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

func TestLookupDNSNSDoesNotHangOnUnreachableParent(t *testing.T) {
	const host = "shop.example.test"

	resolverAddr, stopResolver := startNSTestServer(t, func(w mdns.ResponseWriter, r *mdns.Msg) {
		msg := new(mdns.Msg)
		msg.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(msg)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(strings.Trim(q.Name, "."))
		if q.Qtype == mdns.TypeNS && name == "example.test" && r.RecursionDesired {
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: "example.test.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns.blocked-parent.",
			})
		}
		if q.Qtype == mdns.TypeNS && name == host && r.RecursionDesired {
			msg.Answer = append(msg.Answer, &mdns.NS{
				Hdr: mdns.RR_Header{Name: host + ".", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 60},
				Ns:  "ns-recursive.example.net.",
			})
		}
		_ = w.WriteMsg(msg)
	})
	defer stopResolver()

	origResolve := resolveDNSHostPortsFn
	resolveDNSHostPortsFn = func(context.Context, string, time.Duration) []string {
		// Blackhole address: exchange should time out quickly per attempt.
		return []string{"127.0.0.1:1"}
	}
	defer func() { resolveDNSHostPortsFn = origResolve }()

	origResolvers := dnsResolverServersFn
	dnsResolverServersFn = func(preferred string) []string {
		normalized, err := NormalizeDNSServer(preferred)
		if err != nil || normalized == "" {
			t.Fatalf("preferred resolver: %v", err)
		}
		return []string{normalized}
	}
	defer func() { dnsResolverServersFn = origResolvers }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	records, err := lookupDNSNS(ctx, host, resolverAddr, 3*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("lookupDNSNS fallback failed: %v", err)
	}
	if len(records) != 1 || records[0] != "ns-recursive.example.net" {
		t.Fatalf("records = %v, want recursive fallback", records)
	}
	if elapsed > 3500*time.Millisecond {
		t.Fatalf("blocked parent path hung too long: %s", elapsed)
	}
}
