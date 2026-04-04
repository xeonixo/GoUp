package email

import (
	"context"
	"crypto/tls"
	"fmt"
	htmlpkg "html"
	"net/smtp"
	"strings"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type Notifier struct {
	controlStore *store.ControlPlaneStore
	endpointID   int64
	tenantID     int64
	baseURL      string
	tenantSlug   string
}

func NewNotifier(controlStore *store.ControlPlaneStore, endpointID int64, tenantID int64, baseURL string, tenantSlug string) *Notifier {
	return &Notifier{
		controlStore: controlStore,
		endpointID:   endpointID,
		tenantID:     tenantID,
		baseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		tenantSlug:   strings.TrimSpace(tenantSlug),
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
		return monitor.ErrNoRecipients
	}

	subject := fmt.Sprintf("[%s] %s: %s → %s", strings.ToUpper(string(transition.Current)), transition.Monitor.Name, strings.ToUpper(string(transition.Previous)), strings.ToUpper(string(transition.Current)))

	dashURL := n.baseURL + "/"
	if n.tenantSlug != "" {
		dashURL = n.baseURL + "/" + n.tenantSlug + "/"
	}
	htmlBody := buildHTMLEmail(transition, dashURL)

	var sendErrors []string
	for _, recipient := range recipients {
		if err := sendSMTPMail(deliveryCfg, recipient, subject, htmlBody); err != nil {
			sendErrors = append(sendErrors, recipient+": "+err.Error())
		}
	}
	if len(sendErrors) > 0 {
		return fmt.Errorf("email delivery failed: %s", strings.Join(sendErrors, "; "))
	}

	return nil
}

func buildHTMLEmail(transition monitor.Transition, dashboardURL string) string {
	t := transition.CheckedAt.Local()
	tzOffset := "UTC" + t.Format("-07:00")
	checkedAt := t.Format("02.01.2006, 15:04:05") + " (" + tzOffset + ")"

	statusUpper := strings.ToUpper(string(transition.Current))
	prevUpper := strings.ToUpper(string(transition.Previous))

	var headerBg, badgeBg, badgeColor string
	switch transition.Current {
	case monitor.StatusUp:
		headerBg = "#22c55e"
		badgeBg = "#166534"
		badgeColor = "#4ade80"
	case monitor.StatusDegraded:
		headerBg = "#eab308"
		badgeBg = "#854d0e"
		badgeColor = "#facc15"
	default:
		headerBg = "#ef4444"
		badgeBg = "#7f1d1d"
		badgeColor = "#f87171"
	}

	detailRow := ""
	if msg := strings.TrimSpace(transition.ResultDetail); msg != "" {
		detailRow = `<tr><td style="padding:10px 16px;background:#141720;border-top:1px solid #2a2d3a;">` +
			`<div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">Details</div>` +
			`<div style="font-size:14px;color:#e8e9ef;margin-top:2px;word-break:break-word;">` +
			htmlpkg.EscapeString(msg) + `</div></td></tr>`
	}

	return strings.NewReplacer(
		"{headerBg}", headerBg,
		"{badgeBg}", badgeBg,
		"{badgeColor}", badgeColor,
		"{statusBadge}", statusUpper,
		"{fromStatus}", prevUpper,
		"{toStatus}", statusUpper,
		"{monitorName}", htmlpkg.EscapeString(transition.Monitor.Name),
		"{monitorKind}", strings.ToUpper(string(transition.Monitor.Kind)),
		"{monitorTarget}", htmlpkg.EscapeString(transition.Monitor.Target),
		"{checkedAt}", checkedAt,
		"{detailRow}", detailRow,
		"{dashboardURL}", htmlpkg.EscapeString(dashboardURL),
	).Replace(emailHTMLTemplate)
}

const emailHTMLTemplate = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;padding:32px 16px;"><tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#1a1d26;border-radius:12px;overflow:hidden;border:1px solid #2a2d3a;">
  <tr><td style="background:{headerBg};height:4px;font-size:0;line-height:0;">&nbsp;</td></tr>
  <tr><td style="padding:24px 32px 0;">
    <span style="font-size:18px;font-weight:700;color:#e8e9ef;letter-spacing:-0.5px;">GoUp</span>
    <span style="font-size:13px;color:#6b7280;margin-left:8px;">Statusänderung</span>
  </td></tr>
  <tr><td style="padding:16px 32px 0;">
    <span style="display:inline-block;padding:3px 10px;border-radius:5px;font-size:12px;font-weight:700;letter-spacing:0.8px;background:{badgeBg};color:{badgeColor};">{statusBadge}</span>
    <span style="color:#9ca3af;font-size:13px;margin-left:8px;">{fromStatus} &#8594; {toStatus}</span>
  </td></tr>
  <tr><td style="padding:8px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:#e8e9ef;">{monitorName}</div>
    <div style="font-size:13px;color:#6b7280;margin-top:4px;">{monitorKind} &middot; {monitorTarget}</div>
  </td></tr>
  <tr><td style="padding:20px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #2a2d3a;border-radius:8px;overflow:hidden;">
      <tr><td style="padding:10px 16px;background:#141720;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">Zeitpunkt</div>
        <div style="font-size:14px;color:#e8e9ef;margin-top:2px;">{checkedAt}</div>
      </td></tr>
      {detailRow}
    </table>
  </td></tr>
  <tr><td style="padding:24px 32px 8px;">
    <a href="{dashboardURL}" style="display:inline-block;padding:10px 20px;background:#3b82f6;color:#ffffff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:500;">Dashboard &#246;ffnen &#8594;</a>
  </td></tr>
  <tr><td style="padding:16px 32px 24px;border-top:1px solid #2a2d3a;">
    <p style="margin:0;font-size:12px;color:#4b5563;">Diese Nachricht wurde automatisch von GoUp generiert.</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`

func (n *Notifier) resolveRecipients(ctx context.Context) ([]string, error) {
	tenantRecipients, err := n.controlStore.ListTenantNotificationEmails(ctx, n.tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant notification recipients: %w", err)
	}

	combined := append([]string{}, tenantRecipients...)

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
		"Content-Type: text/html; charset=UTF-8",
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
