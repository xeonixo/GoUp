package sqlite

import (
	"errors"
	"fmt"
	"goup/internal/monitor"
	"net"
	"net/url"
	"strings"
	"time"
)

func validateCreateMonitorParams(params CreateMonitorParams) error {
	if strings.TrimSpace(params.Name) == "" {
		return errors.New("monitor name is required")
	}
	executorKind, executorRef := normalizeMonitorExecutor(params.ExecutorKind, params.ExecutorRef)
	if executorKind != "local" && executorKind != "remote" {
		return errors.New("monitor executor must be local or remote")
	}
	if executorKind == "remote" && executorRef == "" {
		return errors.New("remote executor requires a node id")
	}
	if len([]rune(strings.TrimSpace(params.Group))) > 80 {
		return errors.New("monitor group must not exceed 80 characters")
	}
	if params.Kind == monitor.KindHeartbeat {
		if executorKind != "local" {
			return errors.New("heartbeat monitors always run on the control plane")
		}
		if params.Interval < MinHeartbeatPeriod {
			return errors.New("heartbeat period must be at least 60 seconds")
		}
		if params.Timeout < 0 {
			return errors.New("heartbeat grace period must not be negative")
		}
	} else {
		if params.Interval < 15*time.Second {
			return errors.New("interval must be at least 15 seconds")
		}
		if params.Timeout < 1*time.Second {
			return errors.New("timeout must be at least 1 second")
		}
		if params.Timeout > params.Interval {
			return errors.New("timeout must not exceed interval")
		}
	}
	if params.RetryCount < 0 || params.RetryCount > 10 {
		return errors.New("retry count must be between 0 and 10")
	}
	if params.RetryInterval < 0 {
		return errors.New("retry interval must not be negative")
	}
	if params.CertWarningDays < 0 || params.CertWarningDays > 365 {
		return errors.New("certificate warning days must be between 1 and 365")
	}
	if !monitor.ValidRemindEvery(params.RemindEveryMinutes) {
		return errors.New("reminder interval must be one of 0, 15, 30, 60, 120, 240, 720 or 1440 minutes")
	}
	expectedText := strings.TrimSpace(params.ExpectedText)
	if expectedText != "" && params.Kind != monitor.KindHTTPS && params.Kind != monitor.KindDNS && params.Kind != monitor.KindUDP {
		return errors.New("expected value is only valid for HTTPS, DNS and UDP monitors")
	}
	return validateMonitorKindSettings(params.Kind, params.Target, params.TLSMode, params.ExpectedStatusCode)
}

func normalizeMonitorExecutor(kind, ref string) (string, string) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	ref = strings.TrimSpace(ref)
	if kind == "" || kind == "local" {
		return "local", ""
	}
	if kind != "remote" {
		return kind, ref
	}
	return "remote", ref
}

func validateMonitorKindSettings(kind monitor.Kind, target string, tlsMode monitor.TLSMode, expectedStatusCode *int) error {
	switch kind {
	case monitor.KindHTTPS:
		parsedTarget, err := url.Parse(target)
		if err != nil || parsedTarget == nil || parsedTarget.Host == "" {
			return errors.New("target must be a valid http(s) URL")
		}
		if !monitor.IsValidHTTPSTLSMode(tlsMode) {
			return errors.New("invalid HTTP(S) tls mode")
		}
		httpsTLSMode, _, _ := monitor.ParseHTTPSTLSMode(tlsMode)
		switch httpsTLSMode {
		case "", monitor.TLSModeTLS:
			if parsedTarget.Scheme != "https" {
				return errors.New("https mode requires an https URL")
			}
		case monitor.TLSModeSTARTTLS:
			if parsedTarget.Scheme != "https" {
				return errors.New("https mode requires an https URL")
			}
		case monitor.TLSModeNone:
			if parsedTarget.Scheme != "http" {
				return errors.New("http mode requires an http URL")
			}
		}
	case monitor.KindTCP:
		if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
			return errors.New("target must be a valid host:port for TCP monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if !monitor.IsValidTCPTLSMode(tlsMode) {
			return errors.New("tcp monitors support tls, tls_insecure, starttls, starttls_insecure or none")
		}
	case monitor.KindICMP:
		icmpTarget := strings.TrimSpace(target)
		icmpTarget = strings.Trim(icmpTarget, "[]")
		if strings.Contains(icmpTarget, "://") {
			return errors.New("icmp target must be a plain host or IP address")
		}
		if _, _, err := net.SplitHostPort(icmpTarget); err == nil {
			return errors.New("icmp target must not include a port")
		}
		if parsed := net.ParseIP(icmpTarget); parsed == nil {
			if icmpTarget == "" || strings.ContainsAny(icmpTarget, " /\\@") {
				return errors.New("target must be a valid IPv4/IPv6 address or hostname for ICMP monitors")
			}
			if tlsMode != monitor.TLSModeNone && tlsMode != monitor.TLSModeTLS && tlsMode != monitor.TLSModeSTARTTLS {
				return errors.New("for ICMP hostnames please choose IPv4, IPv6 or Dual Stack")
			}
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeNone && tlsMode != monitor.TLSModeTLS && tlsMode != monitor.TLSModeSTARTTLS {
			return errors.New("icmp monitors support auto, IPv4 or IPv6 address family")
		}
	case monitor.KindSMTP, monitor.KindIMAP:
		if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
			return errors.New("target must be a valid host:port for mail monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		tlsSecurityMode := monitor.NormalizeMailTLSSecurityMode(tlsMode)
		if tlsSecurityMode != monitor.TLSModeTLS && tlsSecurityMode != monitor.TLSModeSTARTTLS {
			return errors.New("mail monitors require tls or starttls mode")
		}
	case monitor.KindDNS:
		_, err := monitor.NormalizeDNSTarget(target)
		if err != nil {
			return err
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeNone {
			return errors.New("DNS monitors do not support TLS mode")
		}
	case monitor.KindUDP:
		if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
			return errors.New("target must be a valid host:port for UDP monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if !monitor.IsValidUDPMode(tlsMode) {
			return errors.New("UDP monitors support dns, ntp or wireguard check mode")
		}
	case monitor.KindWhois:
		whoisTarget := strings.TrimSpace(target)
		if whoisTarget == "" {
			return errors.New("target must be a domain name for WHOIS monitors")
		}
		if strings.ContainsAny(whoisTarget, " /\\@:") {
			return errors.New("WHOIS target must be a bare domain name (e.g. example.com)")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeNone {
			return errors.New("WHOIS monitors do not support TLS mode")
		}
	case monitor.KindHeartbeat:
		if strings.TrimSpace(target) != HeartbeatTarget {
			return errors.New("heartbeat monitors have no target")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
	default:
		return fmt.Errorf("unsupported monitor kind %q", kind)
	}

	return nil
}
