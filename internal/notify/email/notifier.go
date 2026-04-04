package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type Notifier struct {
	controlStore  *store.ControlPlaneStore
	endpointID    int64
	tenantID      int64
	recipients    []string
	subjectPrefix string
}

func NewNotifier(controlStore *store.ControlPlaneStore, endpointID int64, tenantID int64, recipients []string, subjectPrefix string) *Notifier {
	cleaned := make([]string, 0, len(recipients))
	seen := make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		value := strings.TrimSpace(recipient)
		if value == "" {
			continue
		}
		normalized := strings.ToLower(value)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		cleaned = append(cleaned, value)
	}

	return &Notifier{
		controlStore:  controlStore,
		endpointID:    endpointID,
		tenantID:      tenantID,
		recipients:    cleaned,
		subjectPrefix: strings.TrimSpace(subjectPrefix),
	}
}

func (n *Notifier) Enabled() bool {
	return n != nil && n.endpointID > 0 && n.tenantID > 0 && n.controlStore != nil
}

func (n *Notifier) EndpointID() int64 {
	if n == nil {
		return 0
	}
	return n.endpointID
}

func (n *Notifier) EventType() string {
	return "status_transition_email"
}

func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}

	deliveryCfg, err := n.controlStore.GetGlobalSMTPDeliveryConfig(ctx)
	if err != nil {
		return fmt.Errorf("load smtp delivery config: %w", err)
	}
	if strings.TrimSpace(deliveryCfg.Settings.Host) == "" || strings.TrimSpace(deliveryCfg.Settings.FromEmail) == "" {
		return fmt.Errorf("smtp host/from not configured")
	}
	if strings.TrimSpace(deliveryCfg.Password) == "" {
		return fmt.Errorf("smtp password not configured")
	}

	recipients, err := n.resolveRecipients(ctx)
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no tenant notification recipient with email configured")
	}

	subject := fmt.Sprintf("[%s] %s: %s -> %s", strings.ToUpper(string(transition.Current)), transition.Monitor.Name, strings.ToUpper(string(transition.Previous)), strings.ToUpper(string(transition.Current)))
	if n.subjectPrefix != "" {
		subject = strings.TrimSpace(n.subjectPrefix) + " " + subject
	}

	body := strings.Join([]string{
		"GoUp Monitor Status Change",
		"",
		"Monitor: " + transition.Monitor.Name,
		"Kind: " + strings.ToUpper(string(transition.Monitor.Kind)),
		"Target: " + transition.Monitor.Target,
		"Previous: " + strings.ToUpper(string(transition.Previous)),
		"Current: " + strings.ToUpper(string(transition.Current)),
		"Time: " + transition.CheckedAt.Local().Format(time.RFC3339),
		"",
		"Details: " + transition.ResultDetail,
	}, "\n")

	var sendErrors []string
	for _, recipient := range recipients {
		if err := sendSMTPMail(deliveryCfg, recipient, subject, body); err != nil {
			sendErrors = append(sendErrors, recipient+": "+err.Error())
		}
	}
	if len(sendErrors) > 0 {
		return fmt.Errorf("email delivery failed: %s", strings.Join(sendErrors, "; "))
	}

	return nil
}

func (n *Notifier) resolveRecipients(ctx context.Context) ([]string, error) {
	tenantRecipients, err := n.controlStore.ListTenantNotificationEmails(ctx, n.tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant notification recipients: %w", err)
	}

	combined := append([]string{}, tenantRecipients...)
	combined = append(combined, n.recipients...)

	seen := make(map[string]struct{}, len(combined))
	items := make([]string, 0, len(combined))
	for _, recipient := range combined {
		value := strings.TrimSpace(recipient)
		if value == "" {
			continue
		}
		normalized := strings.ToLower(value)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		items = append(items, value)
	}

	return items, nil
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

	fromHeader := cfg.Settings.FromEmail
	if strings.TrimSpace(cfg.Settings.FromName) != "" {
		fromHeader = fmt.Sprintf("%s <%s>", cfg.Settings.FromName, cfg.Settings.FromEmail)
	}
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
		if err := client.Mail(cfg.Settings.FromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
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
		if err := client.Mail(cfg.Settings.FromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
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
