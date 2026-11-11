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

// Well-known root server addresses used when the parent of a name is the DNS root.
// Used only to bootstrap authoritative TLD lookups; answers themselves are not cached.
var dnsRootHints = []string{
	"192.5.5.241:53",    // F.ROOT-SERVERS.NET
	"198.41.0.4:53",     // A.ROOT-SERVERS.NET
	"192.203.230.10:53", // E.ROOT-SERVERS.NET
	"199.9.14.201:53",   // B.ROOT-SERVERS.NET
}

// lookupDNSNS resolves NS records via the parent zone's authoritative servers so
// recursive resolver TTLs cannot hide nameserver changes. Falls back to a
// recursive query when the authoritative path yields nothing.
func lookupDNSNS(ctx context.Context, host string, preferredServer string, timeout time.Duration) ([]string, error) {
	host = strings.Trim(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, fmt.Errorf("missing hostname")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if records, err := lookupDNSNSAuthoritative(ctx, host, preferredServer, timeout); err == nil && len(records) > 0 {
		return records, nil
	} else if err != nil && ctx.Err() != nil {
		return nil, err
	}

	records, err := lookupDNSRawRR(ctx, host, mdns.TypeNS, preferredServer, timeout)
	if err != nil {
		return nil, err
	}
	return formatNSRecords(records), nil
}

func lookupDNSNSAuthoritative(ctx context.Context, host string, preferredServer string, timeout time.Duration) ([]string, error) {
	// Only trust a configured server when it answers authoritatively (AA).
	// Recursive resolvers may still return TTL-cached Answer sections with RD=false.
	if normalized, err := NormalizeDNSServer(preferredServer); err == nil && normalized != "" {
		if records, aa, err := exchangeNSAuthoritative(ctx, normalized, host, timeout); err == nil && aa && len(records) > 0 {
			return records, nil
		} else if err != nil && ctx.Err() != nil {
			return nil, err
		}
	}

	parent := dnsParentName(host)
	parentServers, glue, err := lookupParentAuthoritativeServersFn(ctx, parent, preferredServer, timeout)
	if err != nil {
		return nil, err
	}
	if len(parentServers) == 0 {
		return nil, fmt.Errorf("no authoritative parent servers for %q", parent)
	}

	var lastErr error
	for _, server := range parentServers {
		records, _, exchangeErr := exchangeNSAuthoritative(ctx, server, host, timeout)
		if exchangeErr != nil {
			lastErr = exchangeErr
			if ctx.Err() != nil {
				return nil, exchangeErr
			}
			continue
		}
		if len(records) > 0 {
			return records, nil
		}
	}

	// Rare: parent referral listed hosts without usable addresses on the first pass.
	for _, nsHost := range glue {
		for _, addr := range resolveDNSHostPortsFn(ctx, nsHost, timeout) {
			records, _, exchangeErr := exchangeNSAuthoritative(ctx, addr, host, timeout)
			if exchangeErr != nil {
				lastErr = exchangeErr
				continue
			}
			if len(records) > 0 {
				return records, nil
			}
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("authoritative NS lookup returned no records")
}

// Test seams for authoritative NS lookup (production defaults below).
var (
	lookupParentAuthoritativeServersFn = lookupParentAuthoritativeServers
	resolveDNSHostPortsFn              = resolveDNSHostPorts
)

func lookupParentAuthoritativeServers(ctx context.Context, parent string, preferredServer string, timeout time.Duration) ([]string, []string, error) {
	if parent == "." || parent == "" {
		return append([]string{}, dnsRootHints...), nil, nil
	}

	parentRecords, err := lookupDNSRawRR(ctx, parent, mdns.TypeNS, preferredServer, timeout)
	if err != nil {
		return nil, nil, err
	}
	nsHosts := formatNSRecords(parentRecords)
	if len(nsHosts) == 0 {
		return nil, nil, fmt.Errorf("parent %q has no NS records", parent)
	}

	servers := make([]string, 0, len(nsHosts)*2)
	seen := make(map[string]struct{}, len(nsHosts)*2)
	for _, nsHost := range nsHosts {
		for _, addr := range resolveDNSHostPortsFn(ctx, nsHost, timeout) {
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			servers = append(servers, addr)
		}
	}
	return servers, nsHosts, nil
}

func exchangeNSAuthoritative(ctx context.Context, server string, host string, timeout time.Duration) ([]string, bool, error) {
	question := new(mdns.Msg)
	question.SetQuestion(mdns.Fqdn(host), mdns.TypeNS)
	question.RecursionDesired = false
	client := &mdns.Client{Net: "udp", Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, question, server)
	if err != nil {
		return nil, false, err
	}
	if response == nil {
		return nil, false, fmt.Errorf("empty dns response from %s", server)
	}
	if response.Rcode != mdns.RcodeSuccess && response.Rcode != mdns.RcodeNameError {
		return nil, false, fmt.Errorf("dns rcode %s from %s", mdns.RcodeToString[response.Rcode], server)
	}

	records := collectNSRecords(response.Answer, host)
	if len(records) == 0 {
		// Parent referrals put the delegation NS set in the authority section.
		records = collectNSRecords(response.Ns, host)
	}
	return records, response.Authoritative, nil
}

func collectNSRecords(section []mdns.RR, host string) []string {
	want := strings.ToLower(strings.Trim(mdns.Fqdn(host), "."))
	results := make([]string, 0, len(section))
	seen := make(map[string]struct{}, len(section))
	for _, rr := range section {
		ns, ok := rr.(*mdns.NS)
		if !ok || ns.Header() == nil {
			continue
		}
		owner := strings.ToLower(strings.Trim(ns.Header().Name, "."))
		if owner != want && owner != strings.ToLower(host) {
			continue
		}
		trimmed := strings.TrimSpace(strings.TrimSuffix(ns.Ns, "."))
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, trimmed)
	}
	sort.Strings(results)
	return results
}

func formatNSRecords(records []mdns.RR) []string {
	results := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		ns, ok := record.(*mdns.NS)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(strings.TrimSuffix(ns.Ns, "."))
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		results = append(results, trimmed)
	}
	sort.Strings(results)
	return results
}

func dnsParentName(host string) string {
	host = strings.Trim(strings.TrimSpace(host), ".")
	if host == "" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) == 1 {
		return "."
	}
	return strings.Join(parts[1:], ".")
}

func resolveDNSHostPorts(ctx context.Context, host string, timeout time.Duration) []string {
	host = strings.Trim(strings.TrimSpace(host), ".")
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), "53")}
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil
	}
	addrs := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		formatted := strings.TrimSpace(ip.IP.String())
		if formatted == "" {
			continue
		}
		addr := net.JoinHostPort(formatted, "53")
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}
	return addrs
}
