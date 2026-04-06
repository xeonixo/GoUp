package monitor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
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

func lookupDNSCNAME(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	value, err := resolver.LookupCNAME(ctx, host)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(strings.TrimSuffix(value, "."))
	if trimmed == "" {
		return nil, nil
	}
	return []string{trimmed}, nil
}

func lookupDNSMX(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	records, err := resolver.LookupMX(ctx, host)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	for _, record := range records {
		mxHost := strings.TrimSpace(strings.TrimSuffix(record.Host, "."))
		if mxHost == "" {
			continue
		}
		results = append(results, fmt.Sprintf("%d %s", record.Pref, mxHost))
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSTXT(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	records, err := resolver.LookupTXT(ctx, host)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		trimmed := strings.TrimSpace(record)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		results = append(results, trimmed)
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSNS(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	records, err := resolver.LookupNS(ctx, host)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		trimmed := strings.TrimSpace(strings.TrimSuffix(record.Host, "."))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		results = append(results, trimmed)
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSSRV(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	service, proto, name := parseSRVHost(host)
	_, records, err := resolver.LookupSRV(ctx, service, proto, name)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	for _, record := range records {
		target := strings.TrimSpace(strings.TrimSuffix(record.Target, "."))
		if target == "" {
			continue
		}
		results = append(results, fmt.Sprintf("%d %d %d %s", record.Priority, record.Weight, record.Port, target))
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSCAA(ctx context.Context, host string, preferredServer string, timeout time.Duration) ([]string, error) {
	records, err := lookupDNSRawRR(ctx, host, mdns.TypeCAA, preferredServer, timeout)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	for _, record := range records {
		caa, ok := record.(*mdns.CAA)
		if !ok {
			continue
		}
		results = append(results, fmt.Sprintf("%d %s %s", caa.Flag, strings.TrimSpace(caa.Tag), strings.TrimSpace(caa.Value)))
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSSOA(ctx context.Context, host string, preferredServer string, timeout time.Duration) ([]string, error) {
	records, err := lookupDNSRawRR(ctx, host, mdns.TypeSOA, preferredServer, timeout)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(records))
	for _, record := range records {
		soa, ok := record.(*mdns.SOA)
		if !ok {
			continue
		}
		ns := strings.TrimSpace(strings.TrimSuffix(soa.Ns, "."))
		mbox := strings.TrimSpace(strings.TrimSuffix(soa.Mbox, "."))
		results = append(results, fmt.Sprintf("%s %s %d %d %d %d %d", ns, mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl))
	}
	sort.Strings(results)
	return results, nil
}

func lookupDNSRawRR(ctx context.Context, host string, qtype uint16, preferredServer string, timeout time.Duration) ([]mdns.RR, error) {
	servers := make([]string, 0, 3)
	if normalizedServer, err := NormalizeDNSServer(preferredServer); err == nil && normalizedServer != "" {
		servers = append(servers, normalizedServer)
	} else {
		if cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
			for _, srv := range cfg.Servers {
				port := cfg.Port
				if strings.TrimSpace(port) == "" {
					port = "53"
				}
				hostPort, joinErr := NormalizeDNSServer(net.JoinHostPort(strings.TrimSpace(srv), port))
				if joinErr == nil && hostPort != "" {
					servers = append(servers, hostPort)
				}
			}
		}
	}
	if len(servers) == 0 {
		servers = append(servers, "1.1.1.1:53")
	}

	question := new(mdns.Msg)
	question.SetQuestion(mdns.Fqdn(strings.TrimSpace(host)), qtype)
	question.RecursionDesired = true
	client := &mdns.Client{Net: "udp", Timeout: timeout}

	var lastErr error
	for _, server := range servers {
		response, _, err := client.ExchangeContext(ctx, question, server)
		if err != nil {
			lastErr = err
			continue
		}
		if response == nil {
			continue
		}
		if response.Rcode != mdns.RcodeSuccess && response.Rcode != mdns.RcodeNameError {
			lastErr = fmt.Errorf("dns rcode %s", mdns.RcodeToString[response.Rcode])
			continue
		}
		matches := make([]mdns.RR, 0, len(response.Answer))
		for _, answer := range response.Answer {
			if answer == nil || answer.Header() == nil {
				continue
			}
			if answer.Header().Rrtype == qtype {
				matches = append(matches, answer)
			}
		}
		return matches, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func parseSRVHost(raw string) (service string, proto string, name string) {
	trimmed := strings.Trim(strings.TrimSpace(raw), ".")
	if trimmed == "" {
		return "", "", ""
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) >= 3 && strings.HasPrefix(parts[0], "_") && strings.HasPrefix(parts[1], "_") {
		service = strings.TrimPrefix(parts[0], "_")
		proto = strings.TrimPrefix(parts[1], "_")
		name = strings.Join(parts[2:], ".")
		if name != "" {
			return service, proto, name
		}
	}
	return "", "", trimmed
}

func lookupDNSAddressesByNetwork(ctx context.Context, resolver *net.Resolver, host string, network string) ([]string, error) {
	ips, err := resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		formatted := strings.TrimSpace(ip.String())
		if formatted == "" {
			continue
		}
		if _, ok := seen[formatted]; ok {
			continue
		}
		seen[formatted] = struct{}{}
		results = append(results, formatted)
	}
	sort.Strings(results)
	return results, nil
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
