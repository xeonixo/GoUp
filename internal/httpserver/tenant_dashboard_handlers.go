package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	data, err := s.loadDashboardPageData(r, appStore, strings.TrimSpace(r.URL.Query().Get("trend")), strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")))
	if err != nil {
		http.Error(w, "unable to load dashboard", http.StatusInternalServerError)
		return
	}

	s.render(w, "dashboard", data)
}

func (s *Server) loadDashboardPageData(r *http.Request, appStore *store.Store, trendValue string, noticeText string, errorText string) (pageData, error) {
	stats, err := appStore.DashboardStats(r.Context())
	if err != nil {
		return pageData{}, err
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return pageData{}, err
	}

	events, err := appStore.ListRecentNotificationEvents(r.Context(), 100)
	if err != nil {
		s.logger.Warn("load notification events failed", "error", err)
		events = nil
	}

	stateEvents, err := appStore.ListRecentMonitorStateEvents(r.Context(), 200)
	if err != nil {
		s.logger.Warn("load monitor state events failed", "error", err)
		stateEvents = nil
	}

	groupMetadata, err := appStore.ListMonitorGroupMetadata(r.Context())
	if err != nil {
		return pageData{}, err
	}

	now := time.Now().UTC()
	selectedTrend := parseTrendRange(strings.TrimSpace(trendValue))
	trendSince := trendRangeStart(now, selectedTrend)
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendSince)
	if err != nil {
		s.logger.Warn("load monitor trends failed", "error", err)
		rollups = nil
	}

	tenantID := tenantIDFromRequest(r)
	remoteNodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Warn("load remote nodes failed", "tenant_id", tenantID, "error", err)
		remoteNodes = nil
	}
	monitorViews := buildMonitorViews(snapshots, rollups, now, selectedTrend, buildRemoteNodeNameMap(remoteNodes))
	availableGroups := buildAvailableGroups(groupMetadata)
	availableGroups = mergeAvailableGroups(availableGroups, monitorViews)
	remoteNodeViews := buildRemoteNodeViews(remoteNodes, now, s.cfg.BaseURL, nil)
	executorOptions := buildMonitorExecutorOptions(remoteNodes)

	curUser := s.currentUser(r)
	preferredLanguage := defaultUILanguage
	if curUser != nil {
		preferredLanguage = normalizeUILanguage(curUser.PreferredLanguage)
		if strings.TrimSpace(curUser.PreferredLanguage) == "" {
			preferredLanguage = detectPreferredLanguage(r)
		}
	} else {
		preferredLanguage = detectPreferredLanguage(r)
	}
	translations := s.translationsForLanguage(preferredLanguage)
	noticeLocalized := localizeFlashMessage(translations, noticeText)
	errorLocalized := localizeFlashMessage(translations, errorText)

	return pageData{
		Title:            "Dashboard · GoUp",
		User:             curUser,
		UILanguage:       preferredLanguage,
		Translations:     translations,
		IsAdmin:          curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Stats:            stats,
		Notice:           noticeLocalized,
		Error:            errorLocalized,
		AuthEnabled:      s.cfg.Auth.Mode == config.AuthModeOIDC,
		AuthDisabled:     s.cfg.Auth.Mode != config.AuthModeOIDC,
		TrendValue:       selectedTrend.Value,
		TrendLabel:       selectedTrend.Label,
		TrendRanges:      buildTrendRangeOptions(selectedTrend),
		Monitors:         monitorViews,
		MonitorGroups:    buildMonitorGroups(s.tenantAppBase(r), monitorViews, groupMetadata),
		AvailableGroups:  availableGroups,
		RemoteNodes:      remoteNodeViews,
		HasRemoteNodes:   len(executorOptions) > 1,
		MonitorExecutors: executorOptions,
		Events:           buildNotificationEventViews(events),
		StateEvents:      buildMonitorStateEventViews(stateEvents),
		AppBase:          s.tenantAppBase(r),
	}, nil
}

func (s *Server) handleReorderMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	if draggedIDRaw := strings.TrimSpace(r.FormValue("dragged_id")); draggedIDRaw != "" {
		draggedID, parseErr := strconv.ParseInt(draggedIDRaw, 10, 64)
		targetID, targetErr := strconv.ParseInt(strings.TrimSpace(r.FormValue("target_id")), 10, 64)
		if parseErr != nil || targetErr != nil || draggedID <= 0 || targetID <= 0 {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Drag&Drop-Monitor-ID"), http.StatusSeeOther)
			return
		}
		snapshots, err := appStore.ListMonitorSnapshots(r.Context())
		if err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"), http.StatusSeeOther)
			return
		}
		monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil)
		groupName := strings.TrimSpace(r.FormValue("group"))
		draggedGroupName := ""
		targetGroupName := ""
		orderedIDs := make([]int64, 0)
		for _, item := range monitorViews {
			trimmedGroup := monitorServiceLabel(item)
			if item.ID == draggedID {
				draggedGroupName = trimmedGroup
			}
			if item.ID == targetID {
				targetGroupName = trimmedGroup
			}
		}
		if draggedGroupName == "" || targetGroupName == "" {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		if groupName == "" {
			groupName = draggedGroupName
		}
		if draggedGroupName != groupName || targetGroupName != groupName {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore müssen in derselben Gruppe liegen"), http.StatusSeeOther)
			return
		}
		for _, item := range monitorViews {
			if monitorServiceLabel(item) == groupName {
				orderedIDs = append(orderedIDs, item.ID)
			}
		}
		reorderedIDs, ok := reorderMonitorIDs(orderedIDs, draggedID, targetID)
		if !ok {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor konnte nicht neu einsortiert werden"), http.StatusSeeOther)
			return
		}
		if err := appStore.ReorderMonitors(r.Context(), reorderedIDs); err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""), http.StatusSeeOther)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	direction := strings.TrimSpace(r.FormValue("direction"))
	if direction != "up" && direction != "down" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Sortierrichtung"), http.StatusSeeOther)
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"), http.StatusSeeOther)
		return
	}
	monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil)
	groupItems := make([]monitorView, 0)
	for _, item := range monitorViews {
		if monitorServiceLabel(item) == groupName {
			groupItems = append(groupItems, item)
		}
	}
	sort.Slice(groupItems, func(i, j int) bool {
		if groupItems[i].SortOrder != groupItems[j].SortOrder {
			return groupItems[i].SortOrder < groupItems[j].SortOrder
		}
		return groupItems[i].ID < groupItems[j].ID
	})
	currentIndex := -1
	for idx, item := range groupItems {
		if item.ID == id {
			currentIndex = idx
			break
		}
	}
	if currentIndex == -1 {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
		return
	}
	targetIndex := currentIndex - 1
	if direction == "down" {
		targetIndex = currentIndex + 1
	}
	if targetIndex < 0 || targetIndex >= len(groupItems) {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", ""), http.StatusSeeOther)
		return
	}
	if err := appStore.SwapMonitors(r.Context(), id, groupItems[targetIndex].ID); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""), http.StatusSeeOther)
}

func (s *Server) handleSaveGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, groupIconUploadMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(groupIconUploadMaxBytes + (256 << 10)); err != nil && err != http.ErrNotMultipart {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	newGroupName := strings.TrimSpace(r.FormValue("new_name"))
	if newGroupName == "" {
		newGroupName = groupName
	}
	if newGroupName != groupName {
		if err := appStore.RenameMonitorGroup(r.Context(), groupName, newGroupName); err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe konnte nicht umbenannt werden: "+err.Error()), http.StatusSeeOther)
			return
		}
		groupName = newGroupName
	}
	iconRef := normalizeGroupIconReference(strings.TrimSpace(r.FormValue("icon_slug")))
	uploadedIconRef, err := s.storeUploadedGroupIcon(r, groupName)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if uploadedIconRef != "" {
		iconRef = uploadedIconRef
	} else if err := s.persistSelectedDashboardIcon(r.Context(), s.tenantSlugForRequest(r), iconRef); err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if err := appStore.UpdateMonitorGroupIcon(r.Context(), groupName, iconRef); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe gespeichert", ""), http.StatusSeeOther)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	if err := appStore.DeleteMonitorGroup(r.Context(), groupName); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe inkl. Monitore gelöscht", ""), http.StatusSeeOther)
}

func (s *Server) handleReorderGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if draggedGroup := strings.TrimSpace(r.FormValue("dragged_group")); draggedGroup != "" {
		targetGroup := strings.TrimSpace(r.FormValue("target_group"))
		if err := appStore.ReorderMonitorGroups(r.Context(), draggedGroup, targetGroup); err != nil {
			if err == sql.ErrNoRows {
				http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
		return
	}
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	direction := strings.TrimSpace(r.FormValue("direction"))
	if err := appStore.MoveMonitorGroup(r.Context(), groupName, direction); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
}

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
	timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds")))
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

	_, err = appStore.CreateMonitor(r.Context(), params)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(strings.ToUpper(string(kind))+"-Monitor angelegt"), http.StatusSeeOther)
}

func (s *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
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

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	err = appStore.DeleteMonitor(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor gelöscht"), http.StatusSeeOther)
}

func (s *Server) handleSetMonitorEnabled(w http.ResponseWriter, r *http.Request) {
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

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	enabledRaw := strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
	enabled := enabledRaw == "1" || enabledRaw == "true" || enabledRaw == "on" || enabledRaw == "yes"

	if err := appStore.SetMonitorEnabled(r.Context(), id, enabled); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht aktualisiert werden"), http.StatusSeeOther)
		return
	}

	message := "Monitor pausiert"
	if enabled {
		message = "Monitor aktiviert"
	}
	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(message), http.StatusSeeOther)
}

func checkerForMonitorKind(kind monitor.Kind) (monitor.Checker, bool) {
	switch kind {
	case monitor.KindHTTPS:
		return monitor.HTTPSChecker{}, true
	case monitor.KindTCP:
		return monitor.TCPChecker{}, true
	case monitor.KindICMP:
		return monitor.ICMPChecker{}, true
	case monitor.KindSMTP:
		return monitor.SMTPChecker{}, true
	case monitor.KindIMAP:
		return monitor.IMAPChecker{}, true
	case monitor.KindDNS:
		return monitor.DNSChecker{}, true
	case monitor.KindUDP:
		return monitor.UDPChecker{}, true
	case monitor.KindWhois:
		return monitor.WhoisChecker{}, true
	default:
		return nil, false
	}
}

func (s *Server) handleCheckMonitorNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form payload", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor", http.StatusInternalServerError)
		return
	}

	var selected *monitor.Snapshot
	for i := range snapshots {
		if snapshots[i].Monitor.ID == id {
			selected = &snapshots[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}
	if strings.EqualFold(strings.TrimSpace(selected.Monitor.ExecutorKind), "remote") {
		http.Error(w, "manual checks are disabled for remote-node monitors", http.StatusConflict)
		return
	}

	checker, ok := checkerForMonitorKind(selected.Monitor.Kind)
	if !ok {
		http.Error(w, "monitor kind is not supported", http.StatusBadRequest)
		return
	}

	runCtx, cancel := context.WithTimeout(r.Context(), selected.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, selected.Monitor)
	cancel()

	if err := appStore.SaveMonitorResult(r.Context(), result); err != nil {
		http.Error(w, "unable to store check result", http.StatusInternalServerError)
		return
	}
	if err := appStore.RecordMonitorState(r.Context(), selected.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
		http.Error(w, "unable to store monitor state", http.StatusInternalServerError)
		return
	}
	s.writeAudit(r, "monitor.check_now", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", selected.Monitor.ID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool   `json:"ok"`
		CheckedAt string `json:"checked_at"`
		Status    string `json:"status"`
		Message   string `json:"message"`
	}{
		OK:        true,
		CheckedAt: result.CheckedAt.UTC().Format(time.RFC3339),
		Status:    string(result.Status),
		Message:   strings.TrimSpace(result.Message),
	})
}

func (s *Server) handleMonitorLatencyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	monitorID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("monitor_id")), 10, 64)
	if err != nil || monitorID <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	rangeValue := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeValue == "" {
		rangeValue = "1h"
	}

	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	limit := 480
	switch rangeValue {
	case "6h":
		since = now.Add(-6 * time.Hour)
		limit = 2400
	case "24h":
		since = now.Add(-24 * time.Hour)
		limit = 6000
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		limit = 24000
	default:
		rangeValue = "1h"
	}

	points, err := appStore.ListMonitorLatencyHistory(r.Context(), monitorID, since, limit)
	if err != nil {
		http.Error(w, "unable to load latency history", http.StatusInternalServerError)
		return
	}

	type latencyPointPayload struct {
		CheckedAt string `json:"checked_at"`
		LatencyMS int    `json:"latency_ms"`
		Status    string `json:"status"`
	}
	responsePoints := make([]latencyPointPayload, 0, len(points))
	latencySum := 0
	latencyCount := 0
	for _, point := range points {
		responsePoints = append(responsePoints, latencyPointPayload{
			CheckedAt: point.CheckedAt.UTC().Format(time.RFC3339),
			LatencyMS: point.LatencyMS,
			Status:    strings.TrimSpace(point.Status),
		})
		if !strings.EqualFold(strings.TrimSpace(point.Status), string(monitor.StatusDown)) && point.LatencyMS >= 0 {
			latencySum += point.LatencyMS
			latencyCount++
		}
	}

	averageMS := 0
	if latencyCount > 0 {
		averageMS = int(float64(latencySum)/float64(latencyCount) + 0.5)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool                  `json:"ok"`
		MonitorID int64                 `json:"monitor_id"`
		Range     string                `json:"range"`
		AverageMS int                   `json:"average_ms"`
		Points    []latencyPointPayload `json:"points"`
	}{
		OK:        true,
		MonitorID: monitorID,
		Range:     rangeValue,
		AverageMS: averageMS,
		Points:    responsePoints,
	})
}

func (s *Server) handleStateEventsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	const pageSize = 50
	page := 1
	if p, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && p > 1 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := appStore.CountMonitorStateEvents(r.Context())
	if err != nil {
		s.logger.Warn("count monitor state events failed", "error", err)
		total = 0
	}

	events, err := appStore.ListMonitorStateEventsPaginated(r.Context(), pageSize, offset)
	if err != nil {
		s.logger.Warn("load monitor state events history failed", "error", err)
		events = nil
	}

	pageCount := 1
	if total > 0 {
		pageCount = int((total + pageSize - 1) / pageSize)
	}
	if page > pageCount {
		page = pageCount
	}

	baseURL := s.tenantAppBase(r) + "state-events"

	curUser := s.currentUser(r)
	lang := defaultUILanguage
	if curUser != nil {
		lang = normalizeUILanguage(curUser.PreferredLanguage)
	}
	translations := s.translationsForLanguage(lang)

	subtitle := strings.ReplaceAll(translations["dashboard.state_events.history_subtitle"], "{total}", fmt.Sprintf("%d", total))
	pageLabel := strings.ReplaceAll(strings.ReplaceAll(translations["dashboard.state_events.page_of"], "{page}", fmt.Sprintf("%d", page)), "{total}", fmt.Sprintf("%d", pageCount))

	data := pageData{
		Title:                      "Statusänderungen · GoUp",
		UILanguage:                 lang,
		Translations:               translations,
		AppBase:                    s.tenantAppBase(r),
		User:                       curUser,
		IsAdmin:                    curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		StateEvents:                buildMonitorStateEventViews(events),
		StateEventHistorySubtitle:  subtitle,
		StateEventHistoryPageLabel: pageLabel,
		Pagination: paginationView{
			Page:      page,
			PageCount: pageCount,
			Total:     total,
			HasPrev:   page > 1,
			HasNext:   page < pageCount,
			PrevPage:  page - 1,
			NextPage:  page + 1,
			BaseURL:   baseURL,
		},
	}
	s.render(w, "state_events_history", data)
}

func (s *Server) handleNotificationEventsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	const pageSize = 50
	page := 1
	if p, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && p > 1 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := appStore.CountNotificationEvents(r.Context())
	if err != nil {
		s.logger.Warn("count notification events failed", "error", err)
		total = 0
	}

	events, err := appStore.ListNotificationEventsPaginated(r.Context(), pageSize, offset)
	if err != nil {
		s.logger.Warn("load notification events history failed", "error", err)
		events = nil
	}

	pageCount := 1
	if total > 0 {
		pageCount = int((total + pageSize - 1) / pageSize)
	}
	if page > pageCount {
		page = pageCount
	}

	baseURL := s.tenantAppBase(r) + "notification-events"

	curUser := s.currentUser(r)
	lang := defaultUILanguage
	if curUser != nil {
		lang = normalizeUILanguage(curUser.PreferredLanguage)
	}
	translations := s.translationsForLanguage(lang)

	subtitle := strings.ReplaceAll(translations["dashboard.notification_events.history_subtitle"], "{total}", fmt.Sprintf("%d", total))
	pageLabel := strings.ReplaceAll(strings.ReplaceAll(translations["dashboard.notification_events.page_of"], "{page}", fmt.Sprintf("%d", page)), "{total}", fmt.Sprintf("%d", pageCount))

	data := pageData{
		Title:                             "Notification-Events · GoUp",
		UILanguage:                        lang,
		Translations:                      translations,
		AppBase:                           s.tenantAppBase(r),
		User:                              curUser,
		IsAdmin:                           curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Events:                            buildNotificationEventViews(events),
		NotificationEventHistorySubtitle:  subtitle,
		NotificationEventHistoryPageLabel: pageLabel,
		Pagination: paginationView{
			Page:      page,
			PageCount: pageCount,
			Total:     total,
			HasPrev:   page > 1,
			HasNext:   page < pageCount,
			PrevPage:  page - 1,
			NextPage:  page + 1,
			BaseURL:   baseURL,
		},
	}
	s.render(w, "notification_events_history", data)
}

func (s *Server) handleUpdateMonitorTarget(w http.ResponseWriter, r *http.Request) {
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

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	target := strings.TrimSpace(r.FormValue("target"))
	if target == "" {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ziel darf nicht leer sein"), http.StatusSeeOther)
		return
	}

	err = appStore.UpdateMonitorTarget(r.Context(), id, target)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "monitor.target.update", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor-Ziel aktualisiert"), http.StatusSeeOther)
}
