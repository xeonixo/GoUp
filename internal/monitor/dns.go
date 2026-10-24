package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSChecker resolves a hostname using the configured resolver and optionally
// checks that a specific value appears in the results.
type DNSChecker struct{}

type dnsLookupResult struct {
	records []string
	hasIPv4 bool
	hasIPv6 bool
}

func (c DNSChecker) Check(ctx context.Context, item Monitor) Result {
	start := time.Now()
	target := ParseDNSTarget(item.Target)
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := net.DefaultResolver
	if normalizedServer, err := NormalizeDNSServer(target.Server); err == nil && normalizedServer != "" {
		dialer := &net.Dialer{Timeout: timeout}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, normalizedServer)
			},
		}
	}

	lookupResult, err := lookupDNSAddresses(resolveCtx, resolver, target)
	latency := time.Since(start)
	if err != nil {
		resolverLabel := "system resolver"
		if target.Server != "" {
			resolverLabel = target.Server
		}
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("DNS lookup (%s via %s) failed: %v", dnsRecordTypeLabel(target.RecordType), resolverLabel, err),
		}
	}

	if len(lookupResult.records) == 0 {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("DNS lookup (%s) returned no records", dnsRecordTypeLabel(target.RecordType)),
		}
	}

	keywords := parseExpectedDNSKeywords(item.ExpectedText)
	if len(keywords) > 0 {
		joined := strings.ToLower(strings.Join(lookupResult.records, " | "))
		missing := make([]string, 0, len(keywords))
		for _, keyword := range keywords {
			if !strings.Contains(joined, keyword) {
				missing = append(missing, keyword)
			}
		}
		if len(missing) > 0 {
			return Result{
				MonitorID: item.ID,
				CheckedAt: time.Now().UTC(),
				Status:    StatusDown,
				Latency:   latency,
				Message:   fmt.Sprintf("DNS resolved but missing expected keyword(s) %q in: %s", strings.Join(missing, ", "), strings.Join(lookupResult.records, ", ")),
			}
		}
	}

	message := fmt.Sprintf("Resolved %s: %s", dnsRecordTypeLabel(target.RecordType), strings.Join(lookupResult.records, ", "))
	if target.Server != "" {
		message += fmt.Sprintf(" via %s", target.Server)
	}

	return Result{
		MonitorID: item.ID,
		CheckedAt: time.Now().UTC(),
		Status:    StatusUp,
		Latency:   latency,
		Message:   message,
	}
}

func lookupDNSAddresses(ctx context.Context, resolver *net.Resolver, target DNSTarget) (dnsLookupResult, error) {
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return dnsLookupResult{}, fmt.Errorf("missing hostname")
	}
	switch NormalizeDNSRecordType(string(target.RecordType)) {
	case DNSRecordTypeA:
		records, err := lookupDNSAddressesByNetwork(ctx, resolver, host, "ip4")
		return dnsLookupResult{records: records, hasIPv4: len(records) > 0}, err
	case DNSRecordTypeAAAA:
		records, err := lookupDNSAddressesByNetwork(ctx, resolver, host, "ip6")
		return dnsLookupResult{records: records, hasIPv6: len(records) > 0}, err
	case DNSRecordTypeCNAME:
		records, err := lookupDNSCNAME(ctx, resolver, host)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeMX:
		records, err := lookupDNSMX(ctx, resolver, host)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeTXT:
		records, err := lookupDNSTXT(ctx, resolver, host)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeNS:
		records, err := lookupDNSNS(ctx, resolver, host)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeSRV:
		records, err := lookupDNSSRV(ctx, resolver, host)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeCAA:
		records, err := lookupDNSCAA(ctx, host, target.Server, 10*time.Second)
		return dnsLookupResult{records: records}, err
	case DNSRecordTypeSOA:
		records, err := lookupDNSSOA(ctx, host, target.Server, 10*time.Second)
		return dnsLookupResult{records: records}, err
	default:
		ipv4, err4 := lookupDNSAddressesByNetwork(ctx, resolver, host, "ip4")
		ipv6, err6 := lookupDNSAddressesByNetwork(ctx, resolver, host, "ip6")
		hasIPv4 := len(ipv4) > 0
		hasIPv6 := len(ipv6) > 0
		if !hasIPv4 && !hasIPv6 {
			if err4 != nil {
				return dnsLookupResult{}, err4
			}
			if err6 != nil {
				return dnsLookupResult{}, err6
			}
			return dnsLookupResult{}, nil
		}
		if !hasIPv4 {
			return dnsLookupResult{}, fmt.Errorf("missing A record")
		}
		if !hasIPv6 {
			return dnsLookupResult{}, fmt.Errorf("missing AAAA record")
		}
		return dnsLookupResult{records: append(ipv4, ipv6...), hasIPv4: hasIPv4, hasIPv6: hasIPv6}, nil
	}
}

func parseExpectedDNSKeywords(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	keywords := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		keyword := strings.ToLower(strings.TrimSpace(part))
		if keyword == "" {
			continue
		}
		if _, ok := seen[keyword]; ok {
			continue
		}
		seen[keyword] = struct{}{}
		keywords = append(keywords, keyword)
	}
	return keywords
}

func dnsRecordTypeLabel(recordType DNSRecordType) string {
	switch NormalizeDNSRecordType(string(recordType)) {
	case DNSRecordTypeA:
		return "A"
	case DNSRecordTypeAAAA:
		return "AAAA"
	case DNSRecordTypeCNAME:
		return "CNAME"
	case DNSRecordTypeMX:
		return "MX"
	case DNSRecordTypeTXT:
		return "TXT"
	case DNSRecordTypeNS:
		return "NS"
	case DNSRecordTypeSRV:
		return "SRV"
	case DNSRecordTypeCAA:
		return "CAA"
	case DNSRecordTypeSOA:
		return "SOA"
	default:
		return "A+AAAA"
	}
}
