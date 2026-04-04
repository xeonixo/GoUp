package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TCPChecker struct{}

func (c TCPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	if item.TLSMode == TLSModeNone {
		dialer := &net.Dialer{Timeout: item.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", item.Target)
		result.Latency = time.Since(startedAt)
		if err != nil {
			result.Message = fmt.Sprintf("tcp connect failed: %v", err)
			return result
		}
		_ = conn.Close()

		result.Status = StatusUp
		result.Message = fmt.Sprintf("TCP connect ok in %d ms", result.Latency.Milliseconds())
		return result
	}

	host, _, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Latency = time.Since(startedAt)
		result.Message = fmt.Sprintf("invalid tcp target: %v", err)
		return result
	}
	host = strings.Trim(host, "[]")

	dialer := &net.Dialer{Timeout: item.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", item.Target, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: item.TLSMode == TLSModeSTARTTLS,
	})
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("tcp tls handshake failed: %v", err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	applyTLSMetadata(&result, state)
	status, message := finalizeTLSResult(&result, fmt.Sprintf("TCP TLS handshake ok in %d ms", result.Latency.Milliseconds()))
	if item.TLSMode == TLSModeSTARTTLS && len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if leaf.CheckSignatureFrom(leaf) == nil && result.TLSDaysRemaining != nil {
			message = fmt.Sprintf("TCP TLS handshake ok in %d ms (self-signed cert, expires in %d days)", result.Latency.Milliseconds(), *result.TLSDaysRemaining)
		}
	}
	result.Status = status
	result.Message = message
	return result
}
