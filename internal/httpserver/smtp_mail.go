package httpserver

import (
	"crypto/tls"
	"fmt"
	store "goup/internal/store/sqlite"
	"net/smtp"
	"strings"
)

// sanitizeEmailHeader removes CR, LF, and NUL characters to prevent email header injection.
func sanitizeEmailHeader(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}

func sendSMTPMail(cfg store.GlobalSMTPDeliveryConfig, to, subject, body string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("recipient is required")
	}
	host := strings.TrimSpace(cfg.Settings.Host)
	port := cfg.Settings.Port
	if host == "" || port <= 0 {
		return fmt.Errorf("smtp host/port not configured")
	}

	fromEmail := sanitizeEmailHeader(cfg.Settings.FromEmail)
	fromName := sanitizeEmailHeader(cfg.Settings.FromName)
	to = sanitizeEmailHeader(to)
	subject = sanitizeEmailHeader(subject)
	// Reject residual CR/LF so CodeQL treats the check as a header-injection barrier.
	if strings.ContainsAny(to+subject+fromEmail+fromName, "\r\n\x00") {
		return fmt.Errorf("invalid header value")
	}
	fromHeader := fromEmail
	if strings.TrimSpace(fromName) != "" {
		fromHeader = fmt.Sprintf("%s <%s>", fromName, fromEmail)
	}
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\x00", ""), "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	msg := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%d", host, port)
	auth := smtp.PlainAuth("", cfg.Settings.Username, cfg.Password, host)

	switch strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) {
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
		if err != nil {
			return err
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer client.Close()

		if cfg.Settings.Username != "" || cfg.Password != "" {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(fromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil { // codeql[go/email-injection]: headers CRLF-sanitized+rejected; body is app text or reset mail using BaseURL (not Host).
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	case "none", "starttls":
		client, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer client.Close()

		if strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
					return err
				}
			}
		}

		if cfg.Settings.Username != "" || cfg.Password != "" {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(fromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil { // codeql[go/email-injection]: headers CRLF-sanitized+rejected; body is app text or reset mail using BaseURL (not Host).
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	default:
		return fmt.Errorf("unsupported smtp tls mode")
	}
}
