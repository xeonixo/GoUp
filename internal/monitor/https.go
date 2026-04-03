package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

const certificateWarningDays = 14

type HTTPSChecker struct{}

func (c HTTPSChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}

	client := &http.Client{
		Timeout:   item.Timeout,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.Target, nil)
	if err != nil {
		result.Message = fmt.Sprintf("invalid request target: %v", err)
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

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		applyTLSMetadata(&result, *resp.TLS)
		daysRemaining := *result.TLSDaysRemaining
		if daysRemaining < 0 {
			status = StatusDown
			message = fmt.Sprintf("certificate expired %d days ago", -daysRemaining)
		} else if daysRemaining < certificateWarningDays && status == StatusUp {
			status = StatusDegraded
			message = fmt.Sprintf("certificate expires in %d days", daysRemaining)
		}
	}

	result.Status = status
	result.Message = message
	return result
}
