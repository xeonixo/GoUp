package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestDoHWireFormatMatchesRFC8484Example(t *testing.T) {
	query, err := buildSDNSQuery("example.com", mdns.TypeA, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got := encodeDoHParameter(wire)
	const want = "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
	if got != want {
		t.Fatalf("dns parameter = %s, want %s (wire %x)", got, want, wire)
	}
	if strings.Contains(got, "=") {
		t.Fatalf("dns parameter must not use base64 padding: %s", got)
	}
}

func TestSDNSModeRoundTrip(t *testing.T) {
	cases := []struct {
		transport SDNSTransport
		method    SDNSMethod
		verify    bool
		family    TCPAddressFamily
		stored    TLSMode
	}{
		{SDNSTransportDoH, SDNSMethodPOST, true, TCPAddressFamilyDual, "doh"},
		{SDNSTransportDoH, SDNSMethodGET, true, TCPAddressFamilyIPv6, "doh_get_ipv6"},
		{SDNSTransportDoH, SDNSMethodPOST, false, TCPAddressFamilyIPv4, "doh_insecure_ipv4"},
		{SDNSTransportDoT, SDNSMethodPOST, true, TCPAddressFamilyDual, "dot"},
		{SDNSTransportDoT, SDNSMethodGET, false, TCPAddressFamilyIPv6, "dot_insecure_ipv6"},
		{SDNSTransportDoQ, SDNSMethodPOST, true, TCPAddressFamilyIPv4, "doq_ipv4"},
		{SDNSTransportDoH3, SDNSMethodGET, false, TCPAddressFamilyDual, "doh3_get_insecure"},
	}
	for _, tc := range cases {
		got := ComposeSDNSMode(tc.transport, tc.method, tc.verify, tc.family)
		if got != tc.stored {
			t.Fatalf("compose = %s, want %s", got, tc.stored)
		}
		if !IsValidSDNSMode(got) {
			t.Fatalf("%s should be valid", got)
		}
		parsed := ParseSDNSMode(got)
		if parsed.Transport != tc.transport || parsed.Verify != tc.verify || parsed.Family != tc.family {
			t.Fatalf("parse %+v", parsed)
		}
		wantMethod := tc.method
		if !tc.transport.UsesHTTP() {
			wantMethod = SDNSMethodPOST
		}
		if parsed.Method != NormalizeSDNSMethod(string(wantMethod)) {
			t.Fatalf("method = %s, want %s", parsed.Method, wantMethod)
		}
	}
	if IsValidSDNSMode("") || IsValidSDNSMode("starttls") {
		t.Fatal("empty and unrelated modes must be rejected")
	}
}

func TestNormalizeSDNSTargetKeepsClientID(t *testing.T) {
	got, err := NormalizeSDNSTarget("example.com|a|https://dns.example/dns-query/client-id?dns=old&x=1|", SDNSTransportDoH)
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.com|a|https://dns.example/dns-query/client-id?x=1" {
		t.Fatalf("normalized = %s", got)
	}
	plain, err := NormalizeSDNSTarget("example.com|mixed|https://dns.example", SDNSTransportDoH3)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "example.com|mixed|https://dns.example/dns-query" {
		t.Fatalf("default path = %s", plain)
	}
	if _, err := NormalizeSDNSTarget("example.com|a|http://dns.example/dns-query", SDNSTransportDoH); err == nil {
		t.Fatal("http endpoint should be rejected")
	}
	dot, err := NormalizeSDNSTarget("example.com|aaaa|dns.google|dns.google", SDNSTransportDoT)
	if err != nil {
		t.Fatal(err)
	}
	if dot != "example.com|aaaa|dns.google:853|dns.google" {
		t.Fatalf("dot = %s", dot)
	}
	v6, err := NormalizeSDNSTarget("example.com|a|2001:db8::53", SDNSTransportDoQ)
	if err != nil {
		t.Fatal(err)
	}
	if v6 != "example.com|a|[2001:db8::53]:853" {
		t.Fatalf("doq v6 = %s", v6)
	}
}

func TestSDNSDialNetwork(t *testing.T) {
	network, err := sdnsDialNetwork("127.0.0.1", TCPAddressFamilyDual, false)
	if err != nil || network != "tcp4" {
		t.Fatalf("v4 literal = %s %v", network, err)
	}
	if _, err := sdnsDialNetwork("127.0.0.1", TCPAddressFamilyIPv6, false); err == nil {
		t.Fatal("ipv6 family on an ipv4 address should fail")
	}
	network, err = sdnsDialNetwork("dns.example", TCPAddressFamilyIPv6, true)
	if err != nil || network != "udp6" {
		t.Fatalf("hostname ipv6 udp = %s %v", network, err)
	}
}

func TestAggregateSDNSDualStack(t *testing.T) {
	up := func(message string, records ...string) sdnsAttempt {
		return sdnsAttempt{result: Result{Status: StatusUp, Latency: 10 * time.Millisecond, Message: message}, records: records}
	}
	down := sdnsAttempt{result: Result{Status: StatusDown, Message: "connection refused"}}
	both := aggregateSDNSDualStack(1, time.Now(), time.Now(), ParseSDNSMode("doh"), up("ok", "192.0.2.1"), up("ok", "192.0.2.1"))
	if both.Status != StatusUp || !strings.Contains(both.Message, "DoH POST dual stack ok") || !strings.Contains(both.Message, "192.0.2.1") {
		t.Fatalf("both up: %+v", both)
	}
	one := aggregateSDNSDualStack(1, time.Now(), time.Now(), ParseSDNSMode("dot"), up("ok", "192.0.2.1"), down)
	if one.Status != StatusDegraded || !strings.Contains(one.Message, "DoT dual stack degraded") {
		t.Fatalf("one up: %+v", one)
	}
	none := aggregateSDNSDualStack(1, time.Now(), time.Now(), ParseSDNSMode("doq"), down, down)
	if none.Status != StatusDown || !strings.Contains(none.Message, "DoQ dual stack failed") {
		t.Fatalf("none up: %+v", none)
	}
}

func TestDoHPostAndGetAgainstLocalResolver(t *testing.T) {
	var postBody []byte
	var getParam string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query/client-1" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Accept") != dnsMessageMediaType {
			http.Error(w, "missing accept", http.StatusBadRequest)
			return
		}
		var wire []byte
		switch r.Method {
		case http.MethodPost:
			if r.Header.Get("Content-Type") != dnsMessageMediaType {
				http.Error(w, "missing content type", http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(r.Body)
			postBody = append([]byte(nil), body...)
			wire = body
		case http.MethodGet:
			getParam = r.URL.Query().Get("dns")
			decoded, err := base64.RawURLEncoding.DecodeString(getParam)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			wire = decoded
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", dnsMessageMediaType)
		_, _ = w.Write(sdnsTestReply(t, wire, "192.0.2.10"))
	}))
	defer server.Close()

	endpoint := server.URL + "/dns-query/client-1"
	post := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 7, Kind: KindSDNS, Timeout: 3 * time.Second,
		Target:  "example.com|a|" + endpoint,
		TLSMode: "doh_insecure",
	})
	if post.Status != StatusUp {
		t.Fatalf("POST status %s: %s", post.Status, post.Message)
	}
	if !strings.Contains(post.Message, "192.0.2.10") || !strings.Contains(post.Message, "client-1") {
		t.Fatalf("POST message = %s", post.Message)
	}
	if post.HTTPStatusCode == nil || *post.HTTPStatusCode != 200 {
		t.Fatalf("POST http status = %v", post.HTTPStatusCode)
	}
	if post.TLSValid == nil || !*post.TLSValid || post.TLSDaysRemaining == nil {
		t.Fatalf("POST should record the resolver certificate: %+v", post)
	}
	wantParam := "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
	if encodeDoHParameter(postBody) != wantParam {
		t.Fatalf("POST body parameter = %s, want %s", encodeDoHParameter(postBody), wantParam)
	}

	get := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 8, Kind: KindSDNS, Timeout: 3 * time.Second,
		Target:       "example.com|a|" + endpoint,
		TLSMode:      "doh_get_insecure",
		ExpectedText: "192.0.2.10",
	})
	if get.Status != StatusUp {
		t.Fatalf("GET status %s: %s", get.Status, get.Message)
	}
	if getParam != wantParam {
		t.Fatalf("GET dns parameter = %s, want %s", getParam, wantParam)
	}

	missing := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 9, Kind: KindSDNS, Timeout: 3 * time.Second,
		Target: "example.com|a|" + endpoint, TLSMode: "doh_insecure", ExpectedText: "203.0.113.5",
	})
	if missing.Status != StatusDown || !strings.Contains(missing.Message, "203.0.113.5") {
		t.Fatalf("keyword miss = %+v", missing)
	}
}

func TestDoHRejectsRedirectAndWrongType(t *testing.T) {
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/elsewhere", http.StatusFound)
	}))
	defer redirect.Close()
	result := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 1, Timeout: 3 * time.Second, TLSMode: "doh_insecure",
		Target: "example.com|a|" + redirect.URL + "/dns-query",
	})
	if result.Status != StatusDown || !strings.Contains(strings.ToLower(result.Message), "redirect") {
		t.Fatalf("redirect result = %+v", result)
	}

	html := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer html.Close()
	result = SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 1, Timeout: 3 * time.Second, TLSMode: "doh_insecure",
		Target: "example.com|a|" + html.URL + "/dns-query",
	})
	if result.Status != StatusDown || !strings.Contains(result.Message, "content type") {
		t.Fatalf("html result = %+v", result)
	}
}

func TestDoTAgainstLocalResolver(t *testing.T) {
	cert := sdnsTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serveDoT(listener)

	result := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 3, Timeout: 3 * time.Second, TLSMode: "dot_insecure",
		Target: "example.com|a|" + listener.Addr().String(),
	})
	if result.Status != StatusUp || !strings.Contains(result.Message, "192.0.2.20") {
		t.Fatalf("DoT result = %+v", result)
	}
	if result.TLSDaysRemaining == nil {
		t.Fatal("DoT should record certificate lifetime")
	}

	mismatch := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 3, Timeout: 3 * time.Second, TLSMode: "dot_insecure_ipv6",
		Target: "example.com|a|" + listener.Addr().String(),
	})
	if mismatch.Status != StatusDown || !strings.Contains(mismatch.Message, "IPv6") {
		t.Fatalf("family mismatch = %+v", mismatch)
	}
}

func TestDoQAgainstLocalResolver(t *testing.T) {
	cert := sdnsTestCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go serveDoQ(listener)

	result := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 4, Timeout: 3 * time.Second, TLSMode: "doq_insecure",
		Target: "example.com|txt|" + listener.Addr().String(),
	})
	if result.Status != StatusUp || !strings.Contains(result.Message, "hello-doq") {
		t.Fatalf("DoQ result = %+v", result)
	}
}

func TestDoH3AgainstLocalResolver(t *testing.T) {
	cert := sdnsTestCertificate(t)
	packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/dns-query/client-h3" {
				http.NotFound(w, r)
				return
			}
			var wire []byte
			if r.Method == http.MethodGet {
				decoded, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				wire = decoded
			} else {
				wire, _ = io.ReadAll(io.LimitReader(r.Body, sdnsMaxMessageBytes))
			}
			w.Header().Set("Content-Type", dnsMessageMediaType)
			_, _ = w.Write(sdnsTestReply(t, wire, "192.0.2.30"))
		}),
	}
	defer server.Close()
	defer packet.Close()
	go func() { _ = server.Serve(packet) }()

	endpoint := "https://" + packet.LocalAddr().String() + "/dns-query/client-h3"
	result := SDNSChecker{}.Check(t.Context(), Monitor{
		ID: 5, Timeout: 3 * time.Second, TLSMode: "doh3_insecure",
		Target: "example.com|a|" + endpoint,
	})
	if result.Status != StatusUp || !strings.Contains(result.Message, "192.0.2.30") || !strings.Contains(result.Message, "client-h3") {
		t.Fatalf("DoH3 result = %+v", result)
	}
}

func serveDoT(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			raw, err := readDNSFrame(conn)
			if err != nil {
				return
			}
			_ = writeDNSFrame(conn, sdnsTestReply(nil, raw, "192.0.2.20"))
		}(conn)
	}
}

func serveDoQ(listener *quic.Listener) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go func(conn *quic.Conn) {
			defer conn.CloseWithError(quic.ApplicationErrorCode(0), "done")
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			raw, err := readDNSFrame(stream)
			if err != nil {
				_ = stream.Close()
				return
			}
			if err := writeDNSFrame(stream, sdnsTestReply(nil, raw, "")); err != nil {
				_ = stream.Close()
				return
			}
			_ = stream.Close()
			// Keep the connection until the client finishes reading the response.
			// Closing immediately aborts the stream with an application error.
			select {
			case <-conn.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}(conn)
	}
}

func sdnsTestReply(t *testing.T, wire []byte, ipv4 string) []byte {
	request := new(mdns.Msg)
	if err := request.Unpack(wire); err != nil {
		if t != nil {
			t.Errorf("server unpack: %v", err)
		}
		return nil
	}
	response := new(mdns.Msg)
	response.SetReply(request)
	if len(request.Question) == 0 {
		return mustPack(response)
	}
	question := request.Question[0]
	header := mdns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: mdns.ClassINET, Ttl: 60}
	switch question.Qtype {
	case mdns.TypeA:
		response.Answer = []mdns.RR{&mdns.A{Hdr: header, A: net.ParseIP(ipv4)}}
	case mdns.TypeAAAA:
		response.Answer = []mdns.RR{&mdns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::10")}}
	case mdns.TypeTXT:
		response.Answer = []mdns.RR{&mdns.TXT{Hdr: header, Txt: []string{"hello-doq"}}}
	default:
		response.Rcode = mdns.RcodeNameError
	}
	return mustPack(response)
}

func mustPack(msg *mdns.Msg) []byte {
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	return packed
}

func sdnsTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"sdns.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
