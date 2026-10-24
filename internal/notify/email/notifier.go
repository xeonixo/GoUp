package email

import (
	"context"
	"fmt"
	"strings"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

const defaultEmailLanguage = "en"

type emailRecipient struct {
	email    string
	language string
}

type Notifier struct {
	controlStore *store.ControlPlaneStore
	endpointID   int64
	tenantID     int64
	baseURL      string
	tenantSlug   string
	adminOnly    bool
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

func NewTenantAdminNotifier(controlStore *store.ControlPlaneStore, endpointID int64, tenantID int64, baseURL string, tenantSlug string) *Notifier {
	n := NewNotifier(controlStore, endpointID, tenantID, baseURL, tenantSlug)
	n.adminOnly = true
	return n
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

	dashURL := n.baseURL + "/"
	if n.tenantSlug != "" {
		dashURL = n.baseURL + "/" + n.tenantSlug + "/"
	}

	bundles := make(map[string]struct {
		subject string
		body    string
	})

	var sendErrors []string
	for _, recipient := range recipients {
		bundle, ok := bundles[recipient.language]
		if !ok {
			translations := emailTranslationsForLanguage(recipient.language)
			bundle = struct {
				subject string
				body    string
			}{
				subject: buildStatusTransitionSubject(transition, translations),
				body:    buildHTMLEmail(transition, dashURL, translations),
			}
			bundles[recipient.language] = bundle
		}

		if err := sendSMTPMail(deliveryCfg, recipient.email, bundle.subject, bundle.body); err != nil {
			sendErrors = append(sendErrors, recipient.email+": "+err.Error())
		}
	}
	if len(sendErrors) > 0 {
		return fmt.Errorf("email delivery failed: %s", strings.Join(sendErrors, "; "))
	}

	return nil
}

func (n *Notifier) resolveRecipients(ctx context.Context) ([]emailRecipient, error) {
	var (
		tenantRecipients []store.NotificationRecipient
		err              error
	)
	if n.adminOnly {
		tenantRecipients, err = n.controlStore.ListTenantAdminNotificationRecipients(ctx, n.tenantID)
	} else {
		tenantRecipients, err = n.controlStore.ListTenantNotificationRecipients(ctx, n.tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("load tenant notification recipients: %w", err)
	}

	combined := append([]store.NotificationRecipient{}, tenantRecipients...)

	seen := make(map[string]emailRecipient, len(combined))
	items := make([]emailRecipient, 0, len(combined))
	for _, recipient := range combined {
		value := strings.TrimSpace(recipient.Email)
		if value == "" {
			continue
		}
		normalized := strings.ToLower(value)
		item := emailRecipient{email: value, language: normalizeEmailLanguage(recipient.PreferredLanguage)}

		if existing, ok := seen[normalized]; ok {
			if existing.language == defaultEmailLanguage && item.language != defaultEmailLanguage {
				seen[normalized] = item
				for i := range items {
					if strings.EqualFold(items[i].email, value) {
						items[i] = item
						break
					}
				}
			}
			continue
		}
		seen[normalized] = item
		items = append(items, item)
	}

	return items, nil
}
