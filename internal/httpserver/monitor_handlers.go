package httpserver

import (
	"database/sql"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleSaveMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	monitorIDRaw := strings.TrimSpace(r.FormValue("id"))
	var monitorID int64
	if monitorIDRaw != "" {
		parsedID, parseErr := strconv.ParseInt(monitorIDRaw, 10, 64)
		if parseErr != nil || parsedID <= 0 {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
			return
		}
		monitorID = parsedID
	}

	intervalSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_seconds")))
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiges Intervall"), http.StatusSeeOther)
		return
	}
	// Heartbeat monitors use the timeout column as grace period, entered in its own field.
	timeoutFieldName := "timeout_seconds"
	if strings.EqualFold(strings.TrimSpace(r.FormValue("kind")), string(monitor.KindHeartbeat)) {
		timeoutFieldName = "heartbeat_grace_seconds"
	}
	timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue(timeoutFieldName)))
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiges Timeout"), http.StatusSeeOther)
		return
	}

	var expectedStatusCode *int
	expectedText := ""
	kind := monitor.Kind(strings.ToLower(strings.TrimSpace(r.FormValue("kind"))))
	if kind == "" {
		kind = monitor.KindHTTPS
	}
	tlsMode := normalizeTLSMode(kind, monitor.TLSMode(strings.ToLower(strings.TrimSpace(r.FormValue("tls_mode")))))
	if raw := strings.TrimSpace(r.FormValue("expected_status_code")); raw != "" && kind == monitor.KindHTTPS {
		value, err := strconv.Atoi(raw)
		if err != nil {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiger erwarteter HTTP-Status"), http.StatusSeeOther)
			return
		}
		expectedStatusCode = &value
	}
	if kind == monitor.KindHTTPS || kind == monitor.KindDNS || kind == monitor.KindUDP {
		expectedText = strings.TrimSpace(r.FormValue("expected_text"))
	}

	target := strings.TrimSpace(r.FormValue("target"))
	if kind == monitor.KindDNS {
		dnsHost := strings.TrimSpace(r.FormValue("dns_host"))
		dnsRecordType := monitor.NormalizeDNSRecordType(strings.TrimSpace(r.FormValue("dns_record_type")))
		dnsServer := strings.TrimSpace(r.FormValue("dns_server"))
		if dnsHost != "" || dnsServer != "" || dnsRecordType != monitor.DNSRecordTypeMixed {
			target = monitor.ComposeDNSTarget(dnsHost, dnsRecordType, dnsServer)
		}
		if normalizedTarget, normalizeErr := monitor.NormalizeDNSTarget(target); normalizeErr == nil {
			target = normalizedTarget
		}
	}
	if kind == monitor.KindHTTPS {
		httpHost := strings.TrimSpace(r.FormValue("http_host"))
		httpPort := strings.TrimSpace(r.FormValue("http_port"))
		httpPath := strings.TrimSpace(r.FormValue("http_path"))
		if httpHost != "" || httpPort != "" || httpPath != "" {
			target = buildHTTPMonitorTarget(httpHost, httpPort, httpPath, tlsMode)
		} else {
			target = normalizeHTTPMonitorTarget(target, tlsMode)
		}

		if parsedTarget, parseErr := url.Parse(target); parseErr == nil {
			hostname := strings.TrimSpace(parsedTarget.Hostname())
			if hostname != "" {
				if isLiteralIPAddress(hostname) {
					tlsMode = monitor.ComposeHTTPSTLSMode(tlsMode, monitor.TCPAddressFamilyDual)
				} else {
					family := monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("https_family")))
					tlsMode = monitor.ComposeHTTPSTLSMode(tlsMode, family)
				}
			}
		}
	}
	if kind == monitor.KindTCP {
		tcpHost := strings.TrimSpace(r.FormValue("tcp_host"))
		tcpPort := strings.TrimSpace(r.FormValue("tcp_port"))
		if tcpHost != "" || tcpPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(tcpHost, "[]"), tcpPort))
		}
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if isLiteralIPAddress(host) {
				tlsMode = monitor.ComposeTCPTLSMode(tlsMode, monitor.TCPAddressFamilyDual)
			} else {
				family := monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("tcp_family")))
				tlsMode = monitor.ComposeTCPTLSMode(tlsMode, family)
			}
		}
	}
	if kind == monitor.KindSMTP || kind == monitor.KindIMAP {
		mailHost := strings.TrimSpace(r.FormValue("mail_host"))
		mailPort := strings.TrimSpace(r.FormValue("mail_port"))
		if mailHost != "" || mailPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(mailHost, "[]"), mailPort))
		}
		mailSecurityMode, mailVerifyCert, _ := monitor.ParseMailTLSMode(tlsMode)
		if rawSkip := strings.TrimSpace(r.FormValue("mail_skip_cert")); rawSkip != "" {
			mailSkipCert := strings.EqualFold(rawSkip, "on") || strings.EqualFold(rawSkip, "true") || rawSkip == "1"
			mailVerifyCert = !mailSkipCert
		} else if rawVerify := strings.TrimSpace(r.FormValue("mail_verify_cert")); rawVerify != "" {
			// Backward compatibility for older form payloads.
			mailVerifyCert = strings.EqualFold(rawVerify, "on") || strings.EqualFold(rawVerify, "true") || rawVerify == "1"
		}
		if mailSecurityMode == monitor.TLSModeNone {
			mailVerifyCert = false
		}
		mailFamily := monitor.TCPAddressFamilyDual
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if isLiteralIPAddress(host) {
				mailFamily = monitor.TCPAddressFamilyDual
			} else {
				mailFamily = monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("mail_family")))
			}
		}
		tlsMode = monitor.ComposeMailTLSMode(mailSecurityMode, mailVerifyCert, mailFamily)
	}
	if kind == monitor.KindICMP {
		if !isLiteralIPAddress(target) && target != "" {
			switch strings.ToLower(strings.TrimSpace(r.FormValue("icmp_family"))) {
			case "ipv6":
				tlsMode = monitor.TLSModeSTARTTLS
			case "dual":
				tlsMode = monitor.TLSModeNone
			default:
				tlsMode = monitor.TLSModeTLS
			}
		} else {
			tlsMode = monitor.TLSModeNone
		}
	}
	if kind == monitor.KindUDP {
		udpHost := strings.TrimSpace(r.FormValue("udp_host"))
		udpPort := strings.TrimSpace(r.FormValue("udp_port"))
		if udpHost != "" || udpPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(udpHost, "[]"), udpPort))
		}
		probeKind := monitor.NormalizeUDPProbeKind(strings.TrimSpace(r.FormValue("udp_check")))
		family := monitor.TCPAddressFamilyDual
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if !isLiteralIPAddress(host) {
				family = monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("udp_family")))
			}
		}
		tlsMode = monitor.ComposeUDPMode(probeKind, family)
		if probeKind != monitor.UDPProbeKindWireGuard {
			expectedText = ""
		}
	}

	executorKind, executorRef := parseMonitorExecutorSelection(strings.TrimSpace(r.FormValue("executor")))
	if kind == monitor.KindHeartbeat {
		executorKind, executorRef = "local", ""
	}
	if executorKind == "remote" {
		tenantID := tenantIDFromRequest(r)
		if tenantID <= 0 {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
			return
		}
		if _, err := s.controlStore.GetRemoteNodeByTenantAndNodeID(r.Context(), tenantID, executorRef); err != nil {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ausgewählte Remote-Node ist nicht verfügbar"), http.StatusSeeOther)
			return
		}
	}

	params := store.CreateMonitorParams{
		Name:               strings.TrimSpace(r.FormValue("name")),
		Group:              strings.TrimSpace(r.FormValue("group")),
		ExecutorKind:       executorKind,
		ExecutorRef:        executorRef,
		Kind:               kind,
		Target:             target,
		Interval:           time.Duration(intervalSeconds) * time.Second,
		Timeout:            time.Duration(timeoutSeconds) * time.Second,
		Enabled:            r.FormValue("enabled") == "on",
		TLSMode:            tlsMode,
		ExpectedStatusCode: expectedStatusCode,
		ExpectedText:       expectedText,
		NotifyOnRecovery:   r.FormValue("notify_on_recovery") == "on",
		RetryCount:         func() int { v, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("retry_count"))); return v }(),
		RetryInterval: func() time.Duration {
			v, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("retry_interval_seconds")))
			return time.Duration(v) * time.Second
		}(),
		CertWarningDays: func() int { v, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("cert_warning_days"))); return v }(),
		ConfirmAfter:    func() int { v, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("confirm_after"))); return v }(),
		// Invalid values are rejected by the store (only the offered intervals are valid).
		RemindEveryMinutes: func() int { v, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("remind_every"))); return v }(),
	}

	if monitorID > 0 {
		err = appStore.UpdateMonitor(r.Context(), store.UpdateMonitorParams{
			ID:                  monitorID,
			CreateMonitorParams: params,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor aktualisiert"), http.StatusSeeOther)
		return
	}

	createdID, err := appStore.CreateMonitor(r.Context(), params)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if kind == monitor.KindHeartbeat {
		// The ping URL only exists now: show it on the detail page right away.
		http.Redirect(w, r, s.tenantAppBase(r)+"monitors/"+strconv.FormatInt(createdID, 10)+"?notice="+url.QueryEscape(strings.ToUpper(string(kind))+"-Monitor angelegt"), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(strings.ToUpper(string(kind))+"-Monitor angelegt"), http.StatusSeeOther)
}
