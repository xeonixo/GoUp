package monitor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// WhoisChecker queries the WHOIS system for a domain name and reports the
// number of days until the domain expires.
//
// Target:       bare domain name (e.g. "example.com")
//
// The check performs two WHOIS queries:
//  1. IANA (whois.iana.org) to discover the authoritative WHOIS server for
//     the TLD.
//  2. The authoritative WHOIS server to read the domain's expiry date.
//
// Result fields:
//   - TLSDaysRemaining – days until domain expiry (negative when already expired)
//   - TLSNotAfter      – domain expiry date (reused for display)
//
// Status logic:
//   - DOWN     if domain is expired (≤ 0 days) or expires within 7 days
//   - DEGRADED if expires within 30 days
//   - UP       otherwise
type WhoisChecker struct{}

const (
	whoisPort              = "43"
	whoisIANA              = "whois.iana.org"
	whoisDegradedThreshold = 30
	whoisDownThreshold     = 7
	whoisReadTimeout       = 15 * time.Second
)

var whoisExpiryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)registry expiry date:\s*(.+)`),
	regexp.MustCompile(`(?i)expir(?:y|ation|es on|ation date):\s*(.+)`),
	regexp.MustCompile(`(?i)expire(?:s|d)?:\s*(.+)`),
	regexp.MustCompile(`(?i)paid-till:\s*(.+)`),
	regexp.MustCompile(`(?i)valid-date:\s*(.+)`),
	regexp.MustCompile(`(?i)renewal date:\s*(.+)`),
	regexp.MustCompile(`(?i)domain expir(?:y|ation) date:\s*(.+)`),
}

var whoisExpiryDateFormats = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.000Z",
	"02/01/2006",
	"2006-01-02",
	"02-Jan-2006",
	"January 2, 2006",
	"2006.01.02",
	"02.01.2006",
}

func (c WhoisChecker) Check(ctx context.Context, item Monitor) Result {
	start := time.Now()
	domain := strings.ToLower(strings.TrimSpace(item.Target))
	isDEDomain := tldOf(domain) == "de"
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// Step 1: Ask IANA for the authoritative WHOIS server for this TLD.
	ianaResp, err := queryWhois(ctx, whoisIANA, tldOf(domain), timeout)
	latency := time.Since(start)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("WHOIS IANA lookup failed: %v", err),
		}
	}

	whoisServer := parseWhoisReferral(ianaResp)
	if whoisServer == "" {
		whoisServer = whoisIANA
	}

	// Step 2: Query the registrar's WHOIS server for the full domain record.
	domainResp, err := queryWhois(ctx, whoisServer, domain, timeout)
	latency = time.Since(start)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("WHOIS lookup at %s failed: %v", whoisServer, err),
		}
	}

	// Step 3: Parse the expiry date from the response.
	expiry, err := parseWhoisExpiry(domainResp)
	latency = time.Since(start)
	if err != nil {
		if isDEDomain {
			if whoisResponseIndicatesNoMatch(domainResp) {
				return Result{
					MonitorID: item.ID,
					CheckedAt: time.Now().UTC(),
					Status:    StatusDown,
					Latency:   latency,
					Message:   "DENIC WHOIS liefert kein Ablaufdatum; Domain scheint nicht registriert (keine WHOIS-Einträge)",
				}
			}

			if status, ok := parseWhoisStatus(domainResp); ok {
				return Result{
					MonitorID: item.ID,
					CheckedAt: time.Now().UTC(),
					Status:    StatusUp,
					Latency:   latency,
					Message:   fmt.Sprintf("DENIC WHOIS liefert kein Ablaufdatum; nur eingeschränkte Daten. Domain-Status: %s", status),
				}
			}

			return Result{
				MonitorID: item.ID,
				CheckedAt: time.Now().UTC(),
				Status:    StatusDegraded,
				Latency:   latency,
				Message:   "DENIC WHOIS liefert kein Ablaufdatum; Ablaufprüfung für .de nicht möglich",
			}
		}

		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDegraded,
			Latency:   latency,
			Message:   fmt.Sprintf("WHOIS expiry date not found: %v", err),
		}
	}

	now := time.Now().UTC()
	daysRemaining := int(expiry.UTC().Sub(now).Hours() / 24)

	var status Status
	var message string
	switch {
	case daysRemaining <= 0:
		status = StatusDown
		message = fmt.Sprintf("Domain expired on %s", expiry.UTC().Format("2006-01-02"))
	case daysRemaining <= whoisDownThreshold:
		status = StatusDown
		message = fmt.Sprintf("Domain expires in %d days (%s)", daysRemaining, expiry.UTC().Format("2006-01-02"))
	case daysRemaining <= whoisDegradedThreshold:
		status = StatusDegraded
		message = fmt.Sprintf("Domain expires in %d days (%s)", daysRemaining, expiry.UTC().Format("2006-01-02"))
	default:
		status = StatusUp
		message = fmt.Sprintf("Domain expires %s (%d days remaining)", expiry.UTC().Format("2006-01-02"), daysRemaining)
	}

	return Result{
		MonitorID:        item.ID,
		CheckedAt:        time.Now().UTC(),
		Status:           status,
		Latency:          latency,
		Message:          message,
		TLSDaysRemaining: &daysRemaining,
		TLSNotAfter:      &expiry,
	}
}

// tldOf returns the top-level domain of a FQDN (everything after the last dot).
func tldOf(domain string) string {
	if idx := strings.LastIndex(domain, "."); idx >= 0 {
		return domain[idx+1:]
	}
	return domain
}

// queryWhois dials a WHOIS server on port 43, sends "query\r\n", and returns
// the full response as a string.
func queryWhois(ctx context.Context, server, query string, timeout time.Duration) (string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(server, whoisPort))
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", server, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(whoisReadTimeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", fmt.Errorf("send to %s: %w", server, err)
	}

	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil && sb.Len() == 0 {
		return "", fmt.Errorf("read from %s: %w", server, err)
	}
	return sb.String(), nil
}

// parseWhoisReferral extracts the WHOIS server hostname from an IANA TLD response.
// It looks for "whois: <server>" lines produced by whois.iana.org.
func parseWhoisReferral(response string) string {
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		// IANA format: "whois:        whois.example.com"
		if strings.HasPrefix(lower, "whois:") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
		// Some registrars include "Registrar WHOIS Server: whois://..." in
		// the domain record itself — strip the protocol prefix if present.
		if strings.Contains(lower, "registrar whois server:") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				server = strings.TrimPrefix(server, "whois://")
				return server
			}
		}
	}
	return ""
}

// parseWhoisExpiry scans the WHOIS response for a recognisable expiry date line
// and returns the parsed time.
func parseWhoisExpiry(response string) (time.Time, error) {
	for _, pattern := range whoisExpiryPatterns {
		match := pattern.FindStringSubmatch(response)
		if len(match) < 2 {
			continue
		}
		raw := strings.TrimSpace(match[1])
		if raw == "" {
			continue
		}
		t, err := parseWhoisDate(raw)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no expiry date found in WHOIS response")
}

// parseWhoisDate tries to parse a raw date string using several common formats.
func parseWhoisDate(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	// Strip trailing notes like " (some note)" or " #comment"
	if idx := strings.Index(raw, " ("); idx > 0 {
		raw = strings.TrimSpace(raw[:idx])
	}
	if idx := strings.Index(raw, " #"); idx > 0 {
		raw = strings.TrimSpace(raw[:idx])
	}
	for _, format := range whoisExpiryDateFormats {
		if t, err := time.Parse(format, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse date %q", raw)
}

func parseWhoisStatus(response string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "status:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			status := strings.TrimSpace(parts[1])
			if status == "" {
				continue
			}
			return status, true
		}
	}
	return "", false
}

func whoisResponseIndicatesNoMatch(response string) bool {
	lower := strings.ToLower(response)
	markers := []string{
		"no entries found",
		"no match",
		"not found",
		"domain not found",
		"status: free",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
