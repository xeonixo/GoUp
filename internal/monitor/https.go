package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: item.TLSMode == TLSModeSTARTTLS,
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
	if schemeErr := validateHTTPSMonitorScheme(item.Target, item.TLSMode); schemeErr != nil {
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
	message := fmt.Sprintf("HTTP %d in %d ms", resp.StatusCode, result.Latency.Milliseconds())

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
			message = fmt.Sprintf("HTTP %d in %d ms (self-signed cert, expires in %d days)", resp.StatusCode, result.Latency.Milliseconds(), daysRemaining)
		}
	}

	result.Status = status
	result.Message = message
	return result
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
