package monitor

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type SMTPChecker struct{}

func (c SMTPChecker) Check(ctx context.Context, item Monitor) Result {
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
			Message:   "smtp monitors require tls or starttls mode",
		}
	}
}

func (c SMTPChecker) checkTLS(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{MonitorID: item.ID, CheckedAt: startedAt.UTC(), Status: StatusDown}

	host, _, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid smtp target: %v", err)
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
		result.Message = fmt.Sprintf("smtp tls connect failed: %v", err)
		return result
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Message = "smtp tls connection did not return tls.Conn"
		return result
	}
	if err := tlsConn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("smtp tls deadline failed: %v", err)
		return result
	}

	reader := bufio.NewReader(tlsConn)
	code, _, err := readSMTPResponse(reader)
	if err != nil {
		result.Message = fmt.Sprintf("smtp banner failed: %v", err)
		return result
	}
	if code != 220 {
		result.Message = fmt.Sprintf("unexpected smtp banner code %d", code)
		return result
	}

	applyTLSMetadata(&result, tlsConn.ConnectionState())
	result.Status, result.Message = finalizeTLSResult(&result, fmt.Sprintf("SMTP TLS ok in %d ms", result.Latency.Milliseconds()))
	return result
}

func (c SMTPChecker) checkSTARTTLS(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{MonitorID: item.ID, CheckedAt: startedAt.UTC(), Status: StatusDown}

	host, _, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid smtp target: %v", err)
		return result
	}

	conn, err := (&net.Dialer{Timeout: item.Timeout}).DialContext(ctx, "tcp", item.Target)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("smtp connect failed: %v", err)
		return result
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("smtp deadline failed: %v", err)
		return result
	}

	reader := bufio.NewReader(conn)
	code, _, err := readSMTPResponse(reader)
	if err != nil {
		result.Message = fmt.Sprintf("smtp banner failed: %v", err)
		return result
	}
	if code != 220 {
		result.Message = fmt.Sprintf("unexpected smtp banner code %d", code)
		return result
	}

	if err := writeCRLF(conn, "EHLO goup.local"); err != nil {
		result.Message = fmt.Sprintf("smtp ehlo failed: %v", err)
		return result
	}
	code, response, err := readSMTPResponse(reader)
	if err != nil {
		result.Message = fmt.Sprintf("smtp ehlo response failed: %v", err)
		return result
	}
	if code != 250 {
		result.Message = fmt.Sprintf("unexpected smtp ehlo code %d", code)
		return result
	}
	if !strings.Contains(strings.ToUpper(response), "STARTTLS") {
		result.Message = "smtp server does not advertise STARTTLS"
		return result
	}

	if err := writeCRLF(conn, "STARTTLS"); err != nil {
		result.Message = fmt.Sprintf("smtp starttls command failed: %v", err)
		return result
	}
	code, _, err = readSMTPResponse(reader)
	if err != nil {
		result.Message = fmt.Sprintf("smtp starttls response failed: %v", err)
		return result
	}
	if code != 220 {
		result.Message = fmt.Sprintf("unexpected smtp starttls code %d", code)
		return result
	}

	tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Message = fmt.Sprintf("smtp starttls handshake failed: %v", err)
		return result
	}
	result.Latency = time.Since(startedAt)

	applyTLSMetadata(&result, tlsConn.ConnectionState())
	result.Status, result.Message = finalizeTLSResult(&result, fmt.Sprintf("SMTP STARTTLS ok in %d ms", result.Latency.Milliseconds()))
	return result
}

func readSMTPResponse(reader *bufio.Reader) (int, string, error) {
	var lines []string
	code := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, strings.Join(lines, " | "), err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 {
			if hint := detectNonSMTPBanner(line); hint != "" {
				return 0, strings.Join(lines, " | "), errors.New(hint)
			}
			return 0, strings.Join(lines, " | "), fmt.Errorf("invalid smtp response %q", line)
		}

		parsedCode, err := strconv.Atoi(line[:3])
		if err != nil {
			if hint := detectNonSMTPBanner(line); hint != "" {
				return 0, strings.Join(lines, " | "), errors.New(hint)
			}
			return 0, strings.Join(lines, " | "), fmt.Errorf("invalid smtp response code %q", line)
		}
		if code == 0 {
			code = parsedCode
		}
		if line[3] == ' ' {
			return code, strings.Join(lines, " | "), nil
		}
		if line[3] != '-' {
			return 0, strings.Join(lines, " | "), fmt.Errorf("invalid smtp continuation %q", line)
		}
	}
}

func detectNonSMTPBanner(line string) string {
	upper := strings.ToUpper(strings.TrimSpace(line))
	if strings.HasPrefix(upper, "* OK") || strings.Contains(upper, "IMAP4") || strings.Contains(upper, "DOVECOT") {
		return fmt.Sprintf("target speaks IMAP/Dovecot instead of SMTP: %q (verwende bitte IMAP- oder Dovecot-Monitor)", line)
	}
	return ""
}

func writeCRLF(writer io.Writer, value string) error {
	_, err := io.WriteString(writer, value+"\r\n")
	return err
}
