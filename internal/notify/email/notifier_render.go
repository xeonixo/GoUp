package email

import (
	htmlpkg "html"
	"strings"

	"goup/internal/monitor"
)

func buildStatusTransitionSubject(transition monitor.Transition, translations map[string]string) string {
	fromStatus := localizedMonitorStatus(transition.Previous, translations)
	toStatus := localizedMonitorStatus(transition.Current, translations)
	if transition.Reminder {
		return formatEmailTemplate(emailText(translations, "email.reminder.subject", "[STILL {to}] {monitor}: down for {duration}"), map[string]string{
			"to":       toStatus,
			"monitor":  strings.TrimSpace(transition.Monitor.Name),
			"duration": monitor.FormatOutageDuration(transition.OutageDuration),
		})
	}
	return formatEmailTemplate(emailText(translations, "email.status_transition.subject", "[{to}] {monitor}: {from} → {to}"), map[string]string{
		"from":    fromStatus,
		"to":      toStatus,
		"monitor": strings.TrimSpace(transition.Monitor.Name),
	})
}

func buildHTMLEmail(transition monitor.Transition, dashboardURL string, translations map[string]string) string {
	t := transition.CheckedAt.Local()
	tzOffset := "UTC" + t.Format("-07:00")
	checkedAt := t.Format("02.01.2006, 15:04:05") + " (" + tzOffset + ")"

	statusLabel := localizedMonitorStatus(transition.Current, translations)
	prevLabel := localizedMonitorStatus(transition.Previous, translations)

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
			`<div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">` + htmlpkg.EscapeString(emailText(translations, "email.status_transition.details_label", "Details")) + `</div>` +
			`<div style="font-size:14px;color:#e8e9ef;margin-top:2px;word-break:break-word;">` +
			htmlpkg.EscapeString(msg) + `</div></td></tr>`
	}

	groupRow := ""
	if grp := strings.TrimSpace(transition.Monitor.Group); grp != "" {
		groupRow = `<div style="font-size:13px;color:#6b7280;margin-top:2px;">` +
			htmlpkg.EscapeString(emailText(translations, "email.status_transition.group_label", "Group")) + `: ` +
			htmlpkg.EscapeString(grp) + `</div>`
	}

	changeLabel := emailText(translations, "email.status_transition.label", "Status change")
	transitionText := htmlpkg.EscapeString(prevLabel) + " &#8594; " + htmlpkg.EscapeString(statusLabel)
	if transition.Reminder {
		changeLabel = emailText(translations, "email.reminder.label", "Outage reminder")
		transitionText = htmlpkg.EscapeString(formatEmailTemplate(emailText(translations, "email.reminder.text", "Still down for {duration}"), map[string]string{
			"duration": monitor.FormatOutageDuration(transition.OutageDuration),
		}))
	} else if transition.CatchUp {
		transitionText += " &middot; " + htmlpkg.EscapeString(emailText(translations, "email.catchup", "Summary after mute or maintenance"))
	}

	return strings.NewReplacer(
		"{headerBg}", headerBg,
		"{badgeBg}", badgeBg,
		"{badgeColor}", badgeColor,
		"{statusChangeLabel}", htmlpkg.EscapeString(changeLabel),
		"{statusBadge}", htmlpkg.EscapeString(statusLabel),
		"{transitionText}", transitionText,
		"{monitorName}", htmlpkg.EscapeString(transition.Monitor.Name),
		"{monitorKind}", strings.ToUpper(string(transition.Monitor.Kind)),
		"{monitorTarget}", htmlpkg.EscapeString(transition.Monitor.Target),
		"{groupRow}", groupRow,
		"{timestampLabel}", htmlpkg.EscapeString(emailText(translations, "email.status_transition.timestamp", "Timestamp")),
		"{checkedAt}", checkedAt,
		"{detailRow}", detailRow,
		"{dashboardURL}", htmlpkg.EscapeString(dashboardURL),
		"{openDashboardButton}", htmlpkg.EscapeString(emailText(translations, "email.status_transition.open_dashboard", "Open dashboard →")),
		"{footer}", htmlpkg.EscapeString(emailText(translations, "email.status_transition.footer", "This message was generated automatically by GoUp.")),
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
		<span style="font-size:13px;color:#6b7280;margin-left:8px;">{statusChangeLabel}</span>
  </td></tr>
  <tr><td style="padding:16px 32px 0;">
    <span style="display:inline-block;padding:3px 10px;border-radius:5px;font-size:12px;font-weight:700;letter-spacing:0.8px;background:{badgeBg};color:{badgeColor};">{statusBadge}</span>
    <span style="color:#9ca3af;font-size:13px;margin-left:8px;">{transitionText}</span>
  </td></tr>
  <tr><td style="padding:8px 32px 0;">
    <div style="font-size:22px;font-weight:700;color:#e8e9ef;">{monitorName}</div>
    <div style="font-size:13px;color:#6b7280;margin-top:4px;">{monitorKind} &middot; {monitorTarget}</div>
    {groupRow}
  </td></tr>
  <tr><td style="padding:20px 32px 0;">
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #2a2d3a;border-radius:8px;overflow:hidden;">
      <tr><td style="padding:10px 16px;background:#141720;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;">{timestampLabel}</div>
        <div style="font-size:14px;color:#e8e9ef;margin-top:2px;">{checkedAt}</div>
      </td></tr>
      {detailRow}
    </table>
  </td></tr>
  <tr><td style="padding:24px 32px 8px;">
    <a href="{dashboardURL}" style="display:inline-block;padding:10px 20px;background:#3b82f6;color:#ffffff;text-decoration:none;border-radius:8px;font-size:14px;font-weight:500;">{openDashboardButton}</a>
  </td></tr>
  <tr><td style="padding:16px 32px 24px;border-top:1px solid #2a2d3a;">
    <p style="margin:0;font-size:12px;color:#4b5563;">{footer}</p>
  </td></tr>
</table>
</td></tr></table>
</body></html>`

func formatEmailTemplate(template string, values map[string]string) string {
	result := template
	for placeholder, value := range values {
		result = strings.ReplaceAll(result, "{"+placeholder+"}", value)
	}
	return result
}

// sanitizeEmailHeader removes CR, LF, and NUL characters to prevent email header injection.
func sanitizeEmailHeader(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}
