package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const certificateWarningDays = 7
const maxHTTPSBodyBytes = 1024 * 1024

type HTTPSChecker struct{}

func (c HTTPSChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	checkedAt := startedAt.UTC()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	securityMode, family := ParseHTTPSTLSMode(item.TLSMode)
	parsedTarget, err := url.Parse(item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid request target: %v", err)
		return result
	}
	if parsedTarget == nil || parsedTarget.Host == "" {
		result.Message = "invalid request target: missing host"
		return result
	}
	host := strings.TrimSpace(parsedTarget.Hostname())
	if host == "" {
		result.Message = "invalid request target: missing host"
		return result
	}

	if schemeErr := validateHTTPSMonitorScheme(item.Target, securityMode); schemeErr != nil {
		result.Message = schemeErr.Error()
		return result
	}

	if family == TCPAddressFamilyDual && net.ParseIP(host) == nil {
		v4Attempt := c.checkTarget(ctx, item, checkedAt, securityMode, "tcp4")
		v6Attempt := c.checkTarget(ctx, item, checkedAt, securityMode, "tcp6")

		v4Label := formatHTTPAttemptLabel("IPv4", v4Attempt)
		v6Label := formatHTTPAttemptLabel("IPv6", v6Attempt)

		v4Up := v4Attempt.Status == StatusUp || v4Attempt.Status == StatusDegraded
		v6Up := v6Attempt.Status == StatusUp || v6Attempt.Status == StatusDegraded

		switch {
		case v4Up && v6Up:
			result.Status = StatusUp
			if v4Attempt.Status == StatusDegraded || v6Attempt.Status == StatusDegraded {
				result.Status = StatusDegraded
			}
			result.Latency = (v4Attempt.Latency + v6Attempt.Latency) / 2
			adoptHTTPAttemptMetadata(&result, v4Attempt)
			if result.TLSValid == nil {
				adoptHTTPAttemptMetadata(&result, v6Attempt)
			}
			statusText := "ok"
			if result.Status == StatusDegraded {
				statusText = "degraded"
			}
			result.Message = "HTTP dual stack " + statusText + " · " + v4Label + " · " + v6Label
			return result
		case v4Up || v6Up:
			result.Status = StatusDegraded
			if v4Up {
				result.Latency = v4Attempt.Latency
				adoptHTTPAttemptMetadata(&result, v4Attempt)
			} else {
				result.Latency = v6Attempt.Latency
				adoptHTTPAttemptMetadata(&result, v6Attempt)
			}
			result.Message = "HTTP dual stack degraded · " + v4Label + " · " + v6Label
			return result
		default:
			result.Status = StatusDown
			result.Latency = time.Since(startedAt)
			result.Message = "HTTP dual stack failed · " + v4Label + " · " + v6Label
			return result
		}
	}

	network, networkErr := httpsDialNetwork(host, family)
	if networkErr != nil {
		result.Latency = time.Since(startedAt)
		result.Message = fmt.Sprintf("request failed: %v", networkErr)
		return result
	}

	return c.checkTarget(ctx, item, checkedAt, securityMode, network)
}

func (c HTTPSChecker) checkTarget(ctx context.Context, item Monitor, checkedAt time.Time, securityMode TLSMode, network string) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: securityMode == TLSModeSTARTTLS,
	}
	if network != "" {
		dialer := &net.Dialer{Timeout: item.Timeout}
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
	}

	client := &http.Client{
		Timeout:   item.Timeout,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.Target, nil)
	if err != nil {
		result.Message = fmt.Sprintf("invalid request target: %v", err)
		return result
	}
	if schemeErr := validateHTTPSMonitorScheme(item.Target, securityMode); schemeErr != nil {
		result.Message = schemeErr.Error()
		return result
	}

	resp, err := client.Do(req)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatusCode = &resp.StatusCode
	status := StatusUp
	message := fmt.Sprintf("HTTP %d in %s", resp.StatusCode, formatLatency(result.Latency))

	if item.ExpectedStatusCode != nil && resp.StatusCode != *item.ExpectedStatusCode {
		status = StatusDown
		message = fmt.Sprintf("expected HTTP %d, got %d", *item.ExpectedStatusCode, resp.StatusCode)
	} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		status = StatusDown
		message = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
	}

	if status == StatusUp {
		keywords := parseExpectedKeywords(item.ExpectedText)
		if len(keywords) > 0 {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPSBodyBytes))
			if readErr != nil {
				status = StatusDown
				message = fmt.Sprintf("response read failed: %v", readErr)
			} else {
				lowerBody := strings.ToLower(string(body))
				for _, keyword := range keywords {
					if !strings.Contains(lowerBody, strings.ToLower(keyword)) {
						status = StatusDown
						message = fmt.Sprintf("keyword not found: %q", keyword)
						break
					}
				}
			}
		}
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		applyTLSMetadata(&result, *resp.TLS)
		daysRemaining := *result.TLSDaysRemaining
		leaf := resp.TLS.PeerCertificates[0]
		isSelfSigned := leaf.CheckSignatureFrom(leaf) == nil
		if daysRemaining < 0 {
			status = StatusDown
			message = fmt.Sprintf("certificate expired %d days ago", -daysRemaining)
		} else if daysRemaining <= certificateWarningDays && status == StatusUp {
			status = StatusDegraded
			message = fmt.Sprintf("certificate expires in %d days", daysRemaining)
		} else if isSelfSigned && status == StatusUp {
			message = fmt.Sprintf("HTTP %d in %s (self-signed cert, expires in %d days)", resp.StatusCode, formatLatency(result.Latency), daysRemaining)
		}
	}

	result.Status = status
	result.Message = message
	return result
}

func httpsDialNetwork(host string, family TCPAddressFamily) (string, error) {
	family = NormalizeTCPAddressFamily(string(family))
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip != nil {
		if ip.To4() != nil {
			if family == TCPAddressFamilyIPv6 {
				return "", fmt.Errorf("ip family is IPv6 but target is IPv4")
			}
			return "tcp4", nil
		}
		if family == TCPAddressFamilyIPv4 {
			return "", fmt.Errorf("ip family is IPv4 but target is IPv6")
		}
		return "tcp6", nil
	}

	switch family {
	case TCPAddressFamilyIPv4:
		return "tcp4", nil
	case TCPAddressFamilyIPv6:
		return "tcp6", nil
	default:
		return "tcp", nil
	}
}

func formatHTTPAttemptLabel(label string, attempt Result) string {
	if attempt.Status == StatusUp || attempt.Status == StatusDegraded {
		if attempt.Status == StatusDegraded {
			return fmt.Sprintf("%s degraded (%s)", label, attempt.Message)
		}
		return fmt.Sprintf("%s %s", label, formatLatency(attempt.Latency))
	}
	if strings.TrimSpace(attempt.Message) == "" {
		return label + " down"
	}
	return fmt.Sprintf("%s down (%s)", label, attempt.Message)
}

func adoptHTTPAttemptMetadata(target *Result, from Result) {
	if target == nil {
		return
	}
	target.HTTPStatusCode = from.HTTPStatusCode
	target.TLSValid = from.TLSValid
	target.TLSNotAfter = from.TLSNotAfter
	target.TLSDaysRemaining = from.TLSDaysRemaining
}

func validateHTTPSMonitorScheme(rawTarget string, tlsMode TLSMode) error {
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed == nil || parsed.Host == "" {
		return fmt.Errorf("target must be a valid http(s) URL")
	}
	if tlsMode == TLSModeNone {
		if parsed.Scheme != "http" {
			return fmt.Errorf("HTTP mode requires an http:// target URL")
		}
		return nil
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("HTTPS mode requires an https:// target URL")
	}
	return nil
}

func parseExpectedKeywords(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ','
	})
	keywords := make([]string, 0, len(parts))
	for _, part := range parts {
		keyword := strings.TrimSpace(part)
		if keyword == "" {
			continue
		}
		keywords = append(keywords, keyword)
	}
	return keywords
}
