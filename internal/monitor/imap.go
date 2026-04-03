package monitor

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type IMAPChecker struct{}

func (c IMAPChecker) Check(ctx context.Context, item Monitor) Result {
	switch item.TLSMode {
	case TLSModeTLS:
		return c.checkTLS(ctx, item)
	case TLSModeSTARTTLS:
		return c.checkSTARTTLS(ctx, item)
	default:
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Message:   "imap monitors require tls or starttls mode",
		}
	}
}

func (c IMAPChecker) checkTLS(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{MonitorID: item.ID, CheckedAt: startedAt.UTC(), Status: StatusDown}

	host, _, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid imap target: %v", err)
		return result
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: item.Timeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", item.Target)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("imap tls connect failed: %v", err)
		return result
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Message = "imap tls connection did not return tls.Conn"
		return result
	}
	if err := tlsConn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("imap tls deadline failed: %v", err)
		return result
	}

	reader := bufio.NewReader(tlsConn)
	line, err := readIMAPLine(reader)
	if err != nil {
		result.Message = fmt.Sprintf("imap greeting failed: %v", err)
		return result
	}
	if !strings.HasPrefix(strings.ToUpper(line), "* OK") {
		result.Message = fmt.Sprintf("unexpected imap greeting %q", line)
		return result
	}

	applyTLSMetadata(&result, tlsConn.ConnectionState())
	result.Status, result.Message = finalizeTLSResult(&result, fmt.Sprintf("IMAP TLS ok in %d ms", result.Latency.Milliseconds()))
	return result
}

func (c IMAPChecker) checkSTARTTLS(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{MonitorID: item.ID, CheckedAt: startedAt.UTC(), Status: StatusDown}

	host, _, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid imap target: %v", err)
		return result
	}

	conn, err := (&net.Dialer{Timeout: item.Timeout}).DialContext(ctx, "tcp", item.Target)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("imap connect failed: %v", err)
		return result
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("imap deadline failed: %v", err)
		return result
	}

	reader := bufio.NewReader(conn)
	line, err := readIMAPLine(reader)
	if err != nil {
		result.Message = fmt.Sprintf("imap greeting failed: %v", err)
		return result
	}
	if !strings.HasPrefix(strings.ToUpper(line), "* OK") {
		result.Message = fmt.Sprintf("unexpected imap greeting %q", line)
		return result
	}

	if err := writeCRLF(conn, "A001 CAPABILITY"); err != nil {
		result.Message = fmt.Sprintf("imap capability failed: %v", err)
		return result
	}
	lines, ok, err := readIMAPTaggedResponse(reader, "A001")
	if err != nil {
		result.Message = fmt.Sprintf("imap capability response failed: %v", err)
		return result
	}
	if !ok {
		result.Message = fmt.Sprintf("imap capability command failed: %s", strings.Join(lines, " | "))
		return result
	}
	if !containsToken(lines, "STARTTLS") {
		result.Message = "imap server does not advertise STARTTLS"
		return result
	}

	if err := writeCRLF(conn, "A002 STARTTLS"); err != nil {
		result.Message = fmt.Sprintf("imap starttls failed: %v", err)
		return result
	}
	lines, ok, err = readIMAPTaggedResponse(reader, "A002")
	if err != nil {
		result.Message = fmt.Sprintf("imap starttls response failed: %v", err)
		return result
	}
	if !ok {
		result.Message = fmt.Sprintf("imap starttls rejected: %s", strings.Join(lines, " | "))
		return result
	}

	tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Message = fmt.Sprintf("imap starttls handshake failed: %v", err)
		return result
	}
	result.Latency = time.Since(startedAt)

	applyTLSMetadata(&result, tlsConn.ConnectionState())
	result.Status, result.Message = finalizeTLSResult(&result, fmt.Sprintf("IMAP STARTTLS ok in %d ms", result.Latency.Milliseconds()))
	return result
}

func readIMAPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readIMAPTaggedResponse(reader *bufio.Reader, tag string) ([]string, bool, error) {
	var lines []string
	prefix := strings.ToUpper(tag) + " "
	for {
		line, err := readIMAPLine(reader)
		if err != nil {
			return lines, false, err
		}
		lines = append(lines, line)
		upperLine := strings.ToUpper(line)
		if strings.HasPrefix(upperLine, prefix) {
			return lines, strings.Contains(upperLine, " OK"), nil
		}
	}
}

func containsToken(lines []string, token string) bool {
	needle := strings.ToUpper(token)
	for _, line := range lines {
		if strings.Contains(strings.ToUpper(line), needle) {
			return true
		}
	}
	return false
}
