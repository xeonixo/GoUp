package monitor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	dnsNSPerServerTimeout = 2 * time.Second
	dnsNSMaxParentServers = 4
)

// lookupDNSNS resolves NS records without relying on recursive answer caches.
//
// Strategy (Docker/firewall friendly):
//  1. Ask the configured/system recursive resolvers with RD=false. Public
//     resolvers typically return a parent referral (or an AA answer) quickly.
//  2. Query up to a few referred parent nameservers in parallel with a short
//     per-server timeout.
//  3. Fall back to a normal recursive (RD=true) lookup.
//
// Root-hint spraying is avoided: many container networks allow DNS only to the
// configured resolvers and would otherwise stall on UDP timeouts.
func lookupDNSNS(ctx context.Context, host string, preferredServer string, timeout time.Duration) ([]string, error) {
	host = strings.Trim(strings.TrimSpace(host), ".")
	if host == "" {
		return nil, fmt.Errorf("missing hostname")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	resolvers := dnsResolverServersFn(preferredServer)
	if records, err := lookupDNSNSFromResolvers(ctx, host, resolvers, false, timeout); err == nil && len(records) > 0 {
		return records, nil
	} else if err != nil && ctx.Err() != nil {
		return nil, err
	}

	if records, err := lookupDNSNSViaParentReferral(ctx, host, preferredServer, resolvers, timeout); err == nil && len(records) > 0 {
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

func lookupDNSNSFromResolvers(ctx context.Context, host string, resolvers []string, recursionDesired bool, timeout time.Duration) ([]string, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no dns resolvers")
	}
	perTry := dnsNSPerServerTimeout
	if timeout < perTry {
		perTry = timeout
	}

	var lastErr error
	for _, server := range resolvers {
		records, _, err := exchangeNS(ctx, server, host, recursionDesired, perTry)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if len(records) > 0 {
			return records, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no NS records from resolvers")
}

func lookupDNSNSViaParentReferral(ctx context.Context, host string, preferredServer string, resolvers []string, timeout time.Duration) ([]string, error) {
	parent := dnsParentName(host)
	if parent == "" {
		return nil, fmt.Errorf("no parent zone")
	}

	parentNSHosts, err := lookupParentNSHosts(ctx, parent, preferredServer, resolvers, timeout)
	if err != nil {
		return nil, err
	}
	if len(parentNSHosts) == 0 {
		return nil, fmt.Errorf("parent %q has no NS records", parent)
	}

	servers := make([]string, 0, dnsNSMaxParentServers)
	seen := make(map[string]struct{}, dnsNSMaxParentServers)
	for _, nsHost := range parentNSHosts {
		for _, addr := range resolveDNSHostPortsFn(ctx, nsHost, minDuration(timeout, dnsNSPerServerTimeout)) {
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			servers = append(servers, addr)
			if len(servers) >= dnsNSMaxParentServers {
				break
			}
		}
		if len(servers) >= dnsNSMaxParentServers {
			break
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("could not resolve parent nameservers for %q", parent)
	}

	return exchangeNSFirstSuccess(ctx, servers, host, false, timeout)
}

func lookupParentNSHosts(ctx context.Context, parent string, preferredServer string, resolvers []string, timeout time.Duration) ([]string, error) {
	if parent == "." {
		// Ask a recursive resolver for the root NS set instead of hard-coded root hints.
		records, err := lookupDNSNSFromResolvers(ctx, ".", resolvers, true, timeout)
		if err != nil {
			return nil, err
		}
		return records, nil
	}
	rrs, err := lookupDNSRawRR(ctx, parent, mdns.TypeNS, preferredServer, timeout)
	if err != nil {
		return nil, err
	}
	return formatNSRecords(rrs), nil
}

func exchangeNSFirstSuccess(ctx context.Context, servers []string, host string, recursionDesired bool, timeout time.Duration) ([]string, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers")
	}
	perTry := dnsNSPerServerTimeout
	if timeout < perTry {
		perTry = timeout
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		records []string
		err     error
	}
	results := make(chan result, len(servers))
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			records, _, err := exchangeNS(ctx, server, host, recursionDesired, perTry)
			if err != nil {
				results <- result{err: err}
				return
			}
			if len(records) == 0 {
				results <- result{err: fmt.Errorf("empty NS answer from %s", server)}
				return
			}
			results <- result{records: records}
		}(server)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var lastErr error
	for item := range results {
		if item.err != nil {
			lastErr = item.err
			continue
		}
		cancel()
		return item.records, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("authoritative NS lookup returned no records")
}

func exchangeNS(ctx context.Context, server string, host string, recursionDesired bool, timeout time.Duration) ([]string, bool, error) {
	question := new(mdns.Msg)
	qname := "."
	if host != "" && host != "." {
		qname = host
	}
	question.SetQuestion(mdns.Fqdn(qname), mdns.TypeNS)
	question.RecursionDesired = recursionDesired
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

	records := collectNSRecords(response.Answer, qname)
	if len(records) == 0 {
		// Parent referrals put the delegation NS set in the authority section.
		records = collectNSRecords(response.Ns, qname)
	}
	return records, response.Authoritative, nil
}

func collectNSRecords(section []mdns.RR, host string) []string {
	want := strings.ToLower(strings.Trim(mdns.Fqdn(host), "."))
	if want == "" {
		want = "."
	}
	results := make([]string, 0, len(section))
	seen := make(map[string]struct{}, len(section))
	for _, rr := range section {
		ns, ok := rr.(*mdns.NS)
		if !ok || ns.Header() == nil {
			continue
		}
		owner := strings.ToLower(strings.Trim(ns.Header().Name, "."))
		if owner == "" {
			owner = "."
		}
		if owner != want && owner != strings.ToLower(strings.Trim(host, ".")) {
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

func dnsResolverServers(preferredServer string) []string {
	servers := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	add := func(server string) {
		normalized, err := NormalizeDNSServer(server)
		if err != nil || normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		servers = append(servers, normalized)
	}
	add(preferredServer)
	if cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		port := strings.TrimSpace(cfg.Port)
		if port == "" {
			port = "53"
		}
		for _, srv := range cfg.Servers {
			add(net.JoinHostPort(strings.TrimSpace(srv), port))
		}
	}
	if len(servers) == 0 {
		add("1.1.1.1:53")
	}
	return servers
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

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Test seams for authoritative NS lookup (production defaults below).
var (
	resolveDNSHostPortsFn = resolveDNSHostPorts
	dnsResolverServersFn  = dnsResolverServers
)
