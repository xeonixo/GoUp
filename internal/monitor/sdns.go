package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// SDNSChecker resolves a name through an encrypted DNS transport:
// DNS over HTTPS (GET and POST), DNS over TLS, DNS over QUIC, or DNS over HTTP/3.
type SDNSChecker struct{}

type sdnsAttempt struct {
	result  Result
	records []string
}

type sdnsSession interface {
	Exchange(ctx context.Context, query *mdns.Msg) (*mdns.Msg, error)
	HTTPStatus() *int
	TLS() *tls.ConnectionState
	Close()
}

func openSDNSSession(ctx context.Context, item Monitor, target SDNSTarget, settings sdnsSettings, network string) (sdnsSession, error) {
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	switch settings.Transport {
	case SDNSTransportDoT:
		return openDoTSession(ctx, target, settings, network, timeout)
	case SDNSTransportDoQ:
		return openDoQSession(ctx, target, settings, network, timeout)
	case SDNSTransportDoH3:
		return openDoH3Session(ctx, target, settings, network, timeout)
	default:
		return openDoHSession(ctx, target, settings, network, timeout)
	}
}

func (c SDNSChecker) Check(ctx context.Context, item Monitor) Result {
	started := time.Now()
	checkedAt := started.UTC()
	down := func(message string) Result {
		return Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt,
			Status:    StatusDown,
			Latency:   time.Since(started),
			Message:   message,
		}
	}

	settings := ParseSDNSMode(item.TLSMode)
	if !IsValidSDNSMode(item.TLSMode) {
		return down("invalid secure DNS transport")
	}
	normalized, err := NormalizeSDNSTarget(item.Target, settings.Transport)
	if err != nil {
		return down(err.Error())
	}
	target := ParseSDNSTarget(normalized)
	host := SDNSEndpointHost(settings.Transport, target.Endpoint)
	if host == "" {
		return down("secure DNS resolver is missing a host")
	}

	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// A hostname on dual-stack is checked on IPv4 and IPv6 independently, in parallel,
	// the same way HTTPS does: both up, one up (degraded), or both down.
	// A literal address uses only that address.
	if settings.Family == TCPAddressFamilyDual && net.ParseIP(host) == nil {
		n4, n6 := "tcp4", "tcp6"
		if settings.Transport.UsesUDP() {
			n4, n6 = "udp4", "udp6"
		}
		var v4, v6 sdnsAttempt
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			v4 = c.checkNetwork(checkCtx, item, target, settings, n4, checkedAt)
		}()
		go func() {
			defer wg.Done()
			v6 = c.checkNetwork(checkCtx, item, target, settings, n6, checkedAt)
		}()
		wg.Wait()
		return aggregateSDNSDualStack(item.ID, checkedAt, started, settings, v4, v6)
	}

	network, err := sdnsDialNetwork(host, settings.Family, settings.Transport.UsesUDP())
	if err != nil {
		return down(err.Error())
	}
	return c.checkNetwork(checkCtx, item, target, settings, network, checkedAt).result
}

func (c SDNSChecker) checkNetwork(ctx context.Context, item Monitor, target SDNSTarget, settings sdnsSettings, network string, checkedAt time.Time) sdnsAttempt {
	started := time.Now()
	attempt := sdnsAttempt{result: Result{MonitorID: item.ID, CheckedAt: checkedAt, Status: StatusDown}}
	fail := func(err error) sdnsAttempt {
		attempt.result.Latency = time.Since(started)
		attempt.result.Message = fmt.Sprintf("%s via %s failed: %v", sdnsTransportPhrase(settings), target.Endpoint, err)
		return attempt
	}

	session, err := openSDNSSession(ctx, item, target, settings, network)
	if err != nil {
		return fail(err)
	}
	defer session.Close()

	qtypes := sdnsQtypes(target.RecordType)
	mixed := len(qtypes) > 1
	records := make([]string, 0, 4)
	for _, qtype := range qtypes {
		query, buildErr := buildSDNSQuery(target.Name, qtype, sdnsQueryID(settings.Transport, qtype))
		if buildErr != nil {
			return fail(buildErr)
		}
		response, exchangeErr := session.Exchange(ctx, query)
		if exchangeErr != nil {
			return fail(exchangeErr)
		}
		formatted, interpretErr := interpretSDNSResponse(response, qtype)
		if interpretErr != nil {
			return fail(interpretErr)
		}
		if len(formatted) == 0 {
			if mixed {
				return fail(fmt.Errorf("missing %s record", sdnsRecordTypeName(qtype)))
			}
			return fail(fmt.Errorf("no %s records", sdnsRecordTypeName(qtype)))
		}
		records = append(records, formatted...)
	}

	attempt.records = records
	attempt.result.Latency = time.Since(started)
	if status := session.HTTPStatus(); status != nil {
		code := *status
		attempt.result.HTTPStatusCode = &code
	}
	if state := session.TLS(); state != nil {
		applyTLSMetadata(&attempt.result, *state)
	}

	label := dnsRecordTypeLabel(target.RecordType)
	message := fmt.Sprintf("%s resolved %s: %s via %s", sdnsTransportPhrase(settings), label, strings.Join(records, ", "), target.Endpoint)
	if target.SNI != "" {
		message += fmt.Sprintf(" (SNI %s)", target.SNI)
	}
	if attempt.result.HTTPStatusCode != nil {
		message += fmt.Sprintf(" (HTTP %d)", *attempt.result.HTTPStatusCode)
	}

	keywords := parseExpectedDNSKeywords(item.ExpectedText)
	if len(keywords) > 0 {
		joined := strings.ToLower(strings.Join(records, " | "))
		missing := make([]string, 0)
		for _, keyword := range keywords {
			if !strings.Contains(joined, keyword) {
				missing = append(missing, keyword)
			}
		}
		if len(missing) > 0 {
			attempt.result.Status = StatusDown
			attempt.result.Message = fmt.Sprintf("%s resolved but missing expected keyword(s) %q in: %s", sdnsTransportPhrase(settings), strings.Join(missing, ", "), strings.Join(records, ", "))
			return attempt
		}
	}

	status := StatusUp
	if attempt.result.TLSDaysRemaining != nil {
		status, message = finalizeTLSResult(&attempt.result, message, item.EffectiveCertWarningDays())
		if !settings.Verify && status == StatusUp {
			if state := session.TLS(); state != nil && len(state.PeerCertificates) > 0 {
				leaf := state.PeerCertificates[0]
				if leaf.CheckSignatureFrom(leaf) == nil && attempt.result.TLSDaysRemaining != nil {
					message = fmt.Sprintf("%s (self-signed cert, expires in %d days)", message, *attempt.result.TLSDaysRemaining)
				}
			}
		}
	}
	attempt.result.Status = status
	attempt.result.Message = message
	return attempt
}

func aggregateSDNSDualStack(monitorID int64, checkedAt time.Time, started time.Time, settings sdnsSettings, v4 sdnsAttempt, v6 sdnsAttempt) Result {
	result := Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown}
	v4Label := formatAttemptLabel("IPv4", v4.result)
	v6Label := formatAttemptLabel("IPv6", v6.result)
	v4Up := v4.result.Status == StatusUp || v4.result.Status == StatusDegraded
	v6Up := v6.result.Status == StatusUp || v6.result.Status == StatusDegraded
	phrase := sdnsTransportPhrase(settings)

	switch {
	case v4Up && v6Up:
		result.Status = StatusUp
		if v4.result.Status == StatusDegraded || v6.result.Status == StatusDegraded {
			result.Status = StatusDegraded
		}
		result.Latency = (v4.result.Latency + v6.result.Latency) / 2
		adoptHTTPAttemptMetadata(&result, v4.result)
		if result.TLSValid == nil {
			adoptHTTPAttemptMetadata(&result, v6.result)
		}
		state := "ok"
		if result.Status == StatusDegraded {
			state = "degraded"
		}
		result.Message = phrase + " dual stack " + state + " · " + v4Label + " · " + v6Label + sdnsDualRecordSuffix(v4, v6)
	case v4Up || v6Up:
		result.Status = StatusDegraded
		winner := v6
		if v4Up {
			winner = v4
		}
		result.Latency = winner.result.Latency
		adoptHTTPAttemptMetadata(&result, winner.result)
		result.Message = phrase + " dual stack degraded · " + v4Label + " · " + v6Label + sdnsDualRecordSuffix(winner, sdnsAttempt{})
	default:
		result.Status = StatusDown
		result.Latency = time.Since(started)
		result.Message = phrase + " dual stack failed · " + v4Label + " · " + v6Label
	}
	return result
}

func sdnsDualRecordSuffix(primary sdnsAttempt, secondary sdnsAttempt) string {
	if len(primary.records) == 0 && len(secondary.records) == 0 {
		return ""
	}
	if len(secondary.records) == 0 || sameSDNSRecords(primary.records, secondary.records) {
		if len(primary.records) == 0 {
			return ""
		}
		return " · " + strings.Join(primary.records, ", ")
	}
	return " · IPv4 " + strings.Join(primary.records, ", ") + " · IPv6 " + strings.Join(secondary.records, ", ")
}

func sameSDNSRecords(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sdnsTransportPhrase(settings sdnsSettings) string {
	if settings.Transport.UsesHTTP() {
		if settings.Method == SDNSMethodGET {
			return settings.Transport.Label() + " GET"
		}
		return settings.Transport.Label() + " POST"
	}
	return settings.Transport.Label()
}

// verifyCertificateIP checks the peer certificate against an IP SAN.
// QUIC and HTTP/3 fill ServerName with the IP string, which makes the default
// verifier look for a DNS name instead of an IP address.
func verifyCertificateIP(ip net.IP) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	want := ip.String()
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("tls: no peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			cert, parseErr := x509.ParseCertificate(raw)
			if parseErr != nil {
				return parseErr
			}
			intermediates.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates}); err != nil {
			return err
		}
		return leaf.VerifyHostname(want)
	}
}

func sdnsTLSConfig(connectHost, sni string, verify bool, nextProtos []string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: nextProtos,
	}
	name := strings.TrimSpace(sni)
	if name == "" {
		name = strings.Trim(strings.TrimSpace(connectHost), "[]")
	}
	if name != "" && net.ParseIP(name) == nil {
		cfg.ServerName = name
		cfg.InsecureSkipVerify = !verify
		return cfg
	}
	if !verify {
		cfg.InsecureSkipVerify = true
		return cfg
	}
	ip := net.ParseIP(name)
	if ip == nil {
		return cfg
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = verifyCertificateIP(ip)
	return cfg
}
