(() => {
  window.addEventListener('DOMContentLoaded', () => {
    const page = document.getElementById('dashboard-page');
    if (!(page instanceof HTMLElement)) {
      return;
    }

    const appBase = page.dataset.appBase || '/';
    const currentTrend = page.dataset.trendValue || '24h';
    const dashboardStateOwner = page.dataset.stateOwner || 'anonymous';
    const isAdmin = page.dataset.isAdmin === '1';

    const dialog = document.getElementById('monitor-modal');
    const groupDialog = document.getElementById('group-modal');
    const openCreateButton = document.getElementById('open-create-monitor');
    const cancelButton = document.getElementById('monitor-cancel');
    const groupCancelButton = document.getElementById('group-cancel');
    const groupResetButton = document.getElementById('group-reset-icon');
    const trendDetailModal = document.getElementById('trend-detail-modal');
    const trendDetailClose = document.getElementById('trend-detail-close');
    const trendDetailTitle = document.getElementById('trend-detail-title');
    const trendDetailSubtitle = document.getElementById('trend-detail-subtitle');
    const trendDetailStatus = document.getElementById('trend-detail-status');
    const trendDetailUptime = document.getElementById('trend-detail-uptime');
    const trendDetailLastCheck = document.getElementById('trend-detail-last-check');
    const trendDetailLatency = document.getElementById('trend-detail-latency');
    const trendDetailChecks = document.getElementById('trend-detail-checks');
    const trendDetailTarget = document.getElementById('trend-detail-target');
    const trendDetailRangeTitle = document.getElementById('trend-detail-range-title');
    const trendDetailBars = document.getElementById('trend-detail-bars');
    const trendDetailHistory = document.getElementById('trend-detail-history');
    const title = document.getElementById('monitor-modal-title');
    const idField = document.getElementById('monitor-id');
    const groupModalTitle = document.getElementById('group-modal-title');
    const groupNameField = document.getElementById('group-name-field');
    const groupIconSlugField = document.getElementById('group-icon-slug');
    const groupForm = document.getElementById('group-form');
    const groupIconSearch = document.getElementById('group-icon-search');
    const groupIconSearchStatus = document.getElementById('group-icon-search-status');
    const groupIconResults = document.getElementById('group-icon-results');
    const groupIconCustom = document.getElementById('group-icon-custom');
    const groupIconSelection = document.getElementById('group-icon-selection');
    const groupIconPreview = document.getElementById('group-icon-preview');
    const groupIconPreviewFrame = document.getElementById('group-icon-preview-frame');
    const nameField = document.getElementById('monitor-name');
    const kindField = document.getElementById('monitor-kind');
    const groupField = document.getElementById('monitor-group');
    const tlsModeField = document.getElementById('monitor-tls-mode');
    const targetField = document.getElementById('monitor-target');
    const targetHintField = document.getElementById('monitor-target-hint');
    const intervalField = document.getElementById('monitor-interval');
    const timeoutField = document.getElementById('monitor-timeout');
    const expectedStatusField = document.getElementById('monitor-expected-status');
    const expectedTextField = document.getElementById('monitor-expected-text');
    const useHTTPSField = document.getElementById('monitor-use-https');
    const useHTTPSLabelField = document.getElementById('monitor-use-https-label');
    const verifyCertField = document.getElementById('monitor-verify-cert');
    const verifyCertLabelField = document.getElementById('monitor-verify-cert-label');
    const enabledField = document.getElementById('monitor-enabled');
    const notifyField = document.getElementById('monitor-notify');
    const tlsModeRow = document.getElementById('tls-mode-row');
    const httpsModeRow = document.getElementById('https-mode-row');
    const httpsVerifyRow = document.getElementById('https-verify-row');
    const expectedStatusRow = document.getElementById('expected-status-row');
    const expectedTextRow = document.getElementById('expected-text-row');
    const stateEventsBody = document.getElementById('state-events-body');
    const stateEventsSearch = document.getElementById('state-events-search');
    const stateEventsStatusFilter = document.getElementById('state-events-status-filter');
    const stateEventsIncidentsOnly = document.getElementById('state-events-incidents-only');
    const stateEventsExport = document.getElementById('state-events-export');
    const stateEventsFilterStatus = document.getElementById('state-events-filter-status');
    const stateEventsEmptyRow = document.getElementById('state-events-empty-row');
    const dashboardStateScope = `${appBase || '/'}:${dashboardStateOwner}:${window.location.pathname}`;
    const dashboardStateScrollKey = `goup.dashboard.scrollY:${dashboardStateScope}`;
    const dashboardStateGroupsKey = `goup.dashboard.openGroups:${dashboardStateScope}`;
    let iconSearchTimer = null;
    let iconSearchRequest = null;
    let liveSnapshotInFlight = false;

    const bindOnce = (element, key, listener) => {
      if (!(element instanceof Element)) {
        return;
      }
      const attr = `bound${key}`;
      if (element.dataset[attr] === '1') {
        return;
      }
      element.dataset[attr] = '1';
      element.addEventListener('click', listener);
    };

    const closeActionMenus = (except = null) => {
      document.querySelectorAll('.action-menu').forEach((menu) => {
        if (menu !== except) {
          menu.removeAttribute('open');
        }
      });
    };

    const normalizeIconSlug = (value) => value.trim().toLowerCase().replace(/\s+/g, '-');

    const currentOpenGroups = () => Array.from(document.querySelectorAll('.service-cluster[open]'))
      .map((element) => element.dataset.group || '')
      .filter(Boolean);

    const restoreOpenGroups = (groups) => {
      if (!Array.isArray(groups) || groups.length === 0) {
        return;
      }
      document.querySelectorAll('.service-cluster').forEach((cluster) => {
        const group = cluster.dataset.group || '';
        if (groups.includes(group)) {
          cluster.open = true;
        }
      });
    };

    let liveSocket = null;
    let liveReconnectTimer = null;
    let liveReconnectDelayMS = 1000;
    let liveReloadTimer = null;
    let liveUpdatesEnabled = true;
    let liveLastReloadAt = 0;
    let livePendingParts = new Set();
    let livePendingBoardGroups = new Set();
    const liveSnapshotHashes = {
      stats: '',
      board: '',
      stateEvents: '',
      notificationEvents: '',
      groupOptions: ''
    };
    let applyLiveSnapshot = async () => false;
    let rebindDynamicHandlers = () => {};
    let reformatLiveContent = () => {};

    const hasOpenDialog = () => Array.from(document.querySelectorAll('dialog')).some((dialogElement) => dialogElement.open);

    const scheduleLiveReload = () => {
      if (!liveUpdatesEnabled) {
        return;
      }
      if (liveReloadTimer !== null) {
        return;
      }
      liveReloadTimer = window.setTimeout(() => {
        liveReloadTimer = null;
        if (!liveUpdatesEnabled) {
          return;
        }
        if (hasOpenDialog()) {
          scheduleLiveReload();
          return;
        }

        const now = Date.now();
        if (now - liveLastReloadAt < 2000) {
          scheduleLiveReload();
          return;
        }

        if (!liveSnapshotInFlight) {
          liveSnapshotInFlight = true;
          const requestedParts = Array.from(livePendingParts);
          const requestedBoardGroups = Array.from(livePendingBoardGroups);
          livePendingParts = new Set();
          livePendingBoardGroups = new Set();
          applyLiveSnapshot(requestedParts, requestedBoardGroups).then((updated) => {
            liveSnapshotInFlight = false;
            if (updated) {
              liveLastReloadAt = Date.now();
              return;
            }
            liveLastReloadAt = Date.now();
            saveDashboardState();
            window.location.reload();
          }).catch(() => {
            liveSnapshotInFlight = false;
            liveLastReloadAt = Date.now();
            saveDashboardState();
            window.location.reload();
          });
          return;
        }

        liveLastReloadAt = now;
        saveDashboardState();
        window.location.reload();
      }, 500);
    };

    const queueLiveReconnect = () => {
      if (!liveUpdatesEnabled || liveReconnectTimer !== null) {
        return;
      }
      const delay = liveReconnectDelayMS;
      liveReconnectTimer = window.setTimeout(() => {
        liveReconnectTimer = null;
        connectLiveUpdates();
      }, delay);
      liveReconnectDelayMS = Math.min(liveReconnectDelayMS * 2, 15000);
    };

    const connectLiveUpdates = () => {
      if (!liveUpdatesEnabled || typeof window.WebSocket !== 'function') {
        return;
      }
      const wsURL = new URL(`${appBase}live?trend=${encodeURIComponent(currentTrend)}`, window.location.href);
      wsURL.protocol = wsURL.protocol === 'https:' ? 'wss:' : 'ws:';

      try {
        liveSocket = new window.WebSocket(wsURL.toString());
      } catch (_) {
        queueLiveReconnect();
        return;
      }

      liveSocket.addEventListener('open', () => {
        liveReconnectDelayMS = 1000;
      });

      liveSocket.addEventListener('message', (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload?.type === 'refresh') {
            const parts = Array.isArray(payload.parts) ? payload.parts : [];
            if (parts.length > 0) {
              parts.forEach((part) => {
                if (typeof part === 'string' && part.trim() !== '') {
                  livePendingParts.add(part.trim());
                }
              });
            } else {
              ['stats', 'board', 'state_events', 'notification_events', 'group_options'].forEach((part) => livePendingParts.add(part));
            }
            const boardGroups = Array.isArray(payload.board_groups) ? payload.board_groups : [];
            boardGroups.forEach((groupName) => {
              if (typeof groupName === 'string' && groupName.trim() !== '') {
                livePendingBoardGroups.add(groupName.trim());
              }
            });
            scheduleLiveReload();
          }
        } catch (_) {
        }
      });

      liveSocket.addEventListener('error', () => {
        try {
          liveSocket?.close();
        } catch (_) {
        }
      });

      liveSocket.addEventListener('close', () => {
        liveSocket = null;
        liveSnapshotInFlight = false;
        queueLiveReconnect();
      });
    };

    window.addEventListener('beforeunload', () => {
      liveUpdatesEnabled = false;
      if (liveReconnectTimer !== null) {
        window.clearTimeout(liveReconnectTimer);
        liveReconnectTimer = null;
      }
      if (liveReloadTimer !== null) {
        window.clearTimeout(liveReloadTimer);
        liveReloadTimer = null;
      }
      if (liveSocket) {
        try {
          liveSocket.close();
        } catch (_) {
        }
        liveSocket = null;
      }
    });

    const saveDashboardState = () => {
      try {
        sessionStorage.setItem(dashboardStateScrollKey, String(window.scrollY || window.pageYOffset || 0));
        const openGroups = Array.from(document.querySelectorAll('.service-cluster[open]'))
          .map((element) => element.dataset.group || '')
          .filter(Boolean);
        localStorage.setItem(dashboardStateGroupsKey, JSON.stringify(openGroups));
      } catch (_) {
      }
    };

    const restoreDashboardState = () => {
      try {
        const openGroupsRaw = localStorage.getItem(dashboardStateGroupsKey);
        if (openGroupsRaw) {
          const openGroups = JSON.parse(openGroupsRaw);
          if (Array.isArray(openGroups)) {
            document.querySelectorAll('.service-cluster').forEach((cluster) => {
              const group = cluster.dataset.group || '';
              cluster.open = openGroups.includes(group);
            });
          }
        }
        const scrollRaw = sessionStorage.getItem(dashboardStateScrollKey);
        if (scrollRaw) {
          const scrollY = Number(scrollRaw);
          if (Number.isFinite(scrollY) && scrollY >= 0) {
            requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, scrollY)));
          }
          sessionStorage.removeItem(dashboardStateScrollKey);
        }
      } catch (_) {
      }
    };

    connectLiveUpdates();

    const submitPost = (action, fields) => {
      saveDashboardState();
      const form = document.createElement('form');
      form.method = 'post';
      form.action = action;
      Object.entries(fields).forEach(([key, value]) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = value;
        form.appendChild(input);
      });
      document.body.appendChild(form);
      form.submit();
    };

    const buildIconUrl = (slug) => {
      if (!slug) {
        return '';
      }
      return `https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/${slug}.svg`;
    };

    const updateGroupIconPreview = () => {
      const slug = normalizeIconSlug(groupIconSlugField?.value || groupIconCustom?.value || '');
      if (groupIconSlugField) {
        groupIconSlugField.value = slug;
      }
      if (groupIconSelection) {
        groupIconSelection.textContent = slug ? `Ausgewählt: ${slug}` : 'Kein Icon ausgewählt.';
      }
      const iconUrl = buildIconUrl(slug);
      if (!iconUrl) {
        if (groupIconPreviewFrame) {
          groupIconPreviewFrame.hidden = true;
        }
        groupIconPreview?.removeAttribute('src');
        return;
      }
      if (groupIconPreviewFrame) {
        groupIconPreviewFrame.hidden = false;
      }
      if (groupIconPreview) {
        groupIconPreview.src = iconUrl;
      }
    };

    groupIconPreview?.addEventListener('error', () => {
      if (groupIconPreviewFrame) {
        groupIconPreviewFrame.hidden = true;
      }
      groupIconPreview.removeAttribute('src');
    });

    const renderIconResults = (results, query) => {
      if (!groupIconResults) {
        return;
      }
      const normalizedQuery = normalizeIconSlug(query || '');
      groupIconResults.innerHTML = '';

      if (normalizedQuery) {
        const useCustomButton = document.createElement('button');
        useCustomButton.type = 'button';
        useCustomButton.className = `group-icon-result${groupIconSlugField?.value === normalizedQuery ? ' is-selected' : ''}`;
        const customBody = document.createElement('div');
        customBody.className = 'group-icon-result-body';
        const customTitle = document.createElement('strong');
        customTitle.textContent = 'Eigenen Slug verwenden';
        const customSlug = document.createElement('span');
        customSlug.className = 'muted compact';
        customSlug.textContent = normalizedQuery;
        customBody.appendChild(customTitle);
        customBody.appendChild(customSlug);
        useCustomButton.appendChild(customBody);
        useCustomButton.addEventListener('click', () => {
          if (groupIconCustom) {
            groupIconCustom.value = normalizedQuery;
          }
          if (groupIconSlugField) {
            groupIconSlugField.value = normalizedQuery;
          }
          updateGroupIconPreview();
          renderIconResults(results, query);
        });
        groupIconResults.appendChild(useCustomButton);
      }

      results.forEach((result) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `group-icon-result${groupIconSlugField?.value === result.slug ? ' is-selected' : ''}`;
        const previewImage = document.createElement('img');
        previewImage.src = result.url;
        previewImage.alt = result.label;
        previewImage.loading = 'lazy';
        previewImage.referrerPolicy = 'no-referrer';
        const body = document.createElement('div');
        body.className = 'group-icon-result-body';
        const titleNode = document.createElement('strong');
        titleNode.textContent = result.label;
        const slugNode = document.createElement('span');
        slugNode.className = 'muted compact';
        slugNode.textContent = result.slug;
        body.appendChild(titleNode);
        body.appendChild(slugNode);
        button.appendChild(previewImage);
        button.appendChild(body);
        previewImage.addEventListener('error', () => {
          previewImage.hidden = true;
        });
        button.addEventListener('click', () => {
          if (groupIconCustom) {
            groupIconCustom.value = result.slug;
          }
          if (groupIconSlugField) {
            groupIconSlugField.value = result.slug;
          }
          updateGroupIconPreview();
          renderIconResults(results, query);
        });
        groupIconResults.appendChild(button);
      });

      if (groupIconSearchStatus) {
        if (!normalizedQuery) {
          groupIconSearchStatus.textContent = 'Suche nach Namen, Aliasen oder Kategorien.';
        } else if (results.length > 0) {
          groupIconSearchStatus.textContent = `${results.length} passende Icons gefunden.`;
        } else {
          groupIconSearchStatus.textContent = 'Keine Treffer gefunden. Du kannst den Slug direkt verwenden.';
        }
      }
    };

    const runIconSearch = async (query) => {
      const normalizedQuery = query.trim();
      if (iconSearchRequest) {
        iconSearchRequest.abort();
      }
      iconSearchRequest = new AbortController();
      try {
        const response = await fetch(`${appBase}icons/search?q=${encodeURIComponent(normalizedQuery)}`, {
          method: 'GET',
          headers: { Accept: 'application/json' },
          signal: iconSearchRequest.signal
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const payload = await response.json();
        renderIconResults(Array.isArray(payload.results) ? payload.results : [], normalizedQuery);
      } catch (error) {
        if (error.name === 'AbortError') {
          return;
        }
        renderIconResults([], normalizedQuery);
        if (groupIconSearchStatus) {
          groupIconSearchStatus.textContent = 'Icon-Suche gerade nicht erreichbar. Du kannst den Slug trotzdem direkt setzen.';
        }
      }
    };

    const scheduleIconSearch = (query) => {
      if (iconSearchTimer) {
        window.clearTimeout(iconSearchTimer);
      }
      iconSearchTimer = window.setTimeout(() => runIconSearch(query), 180);
    };

    const openGroupDialog = (button) => {
      if (!groupModalTitle || !groupNameField || !groupIconCustom || !groupIconSearch || !groupIconSlugField || !groupDialog) {
        return;
      }
      const groupName = button.dataset.group || 'Gruppe';
      const iconSlug = normalizeIconSlug(button.dataset.iconSlug || '');
      groupModalTitle.textContent = `Gruppe konfigurieren · ${groupName}`;
      groupNameField.value = groupName;
      groupIconCustom.value = iconSlug;
      groupIconSearch.value = iconSlug || groupName;
      groupIconSlugField.value = iconSlug;
      updateGroupIconPreview();
      scheduleIconSearch(groupIconSearch.value);
      groupDialog.showModal();
    };

    const applyKindRules = () => {
      if (!kindField || !tlsModeRow || !httpsModeRow || !httpsVerifyRow || !expectedStatusRow || !expectedTextRow || !tlsModeField || !expectedStatusField || !expectedTextField || !useHTTPSField || !verifyCertField) {
        return;
      }
      const kind = kindField.value;
      const isHTTPMonitor = kind === 'https';
      const isTCPMonitor = kind === 'tcp';
      const isMail = kind === 'smtp' || kind === 'imap';
      const isDNS = kind === 'dns';
      const isUDP = kind === 'udp';
      const isWhois = kind === 'whois';
      const supportsTLSChecks = isHTTPMonitor || isTCPMonitor;

      tlsModeRow.hidden = !isMail;
      httpsModeRow.hidden = !supportsTLSChecks;
      httpsVerifyRow.hidden = !supportsTLSChecks || !useHTTPSField.checked;
      expectedStatusRow.hidden = !isHTTPMonitor;
      expectedTextRow.hidden = !isHTTPMonitor && !isDNS;

      if (isHTTPMonitor) {
        if (useHTTPSLabelField) {
          useHTTPSLabelField.textContent = 'HTTPS verwenden';
        }
        if (verifyCertLabelField) {
          verifyCertLabelField.textContent = 'Zertifikat prüfen';
        }
        if (!useHTTPSField.checked) {
          verifyCertField.checked = false;
          tlsModeField.value = 'none';
        } else {
          tlsModeField.value = verifyCertField.checked ? 'tls' : 'starttls';
        }
        if (targetField) {
          targetField.placeholder = 'example.com/health';
        }
        if (targetHintField) {
          targetHintField.textContent = useHTTPSField.checked
            ? 'Für HTTPS: Host/Pfad ohne Protokoll (https:// wird automatisch ergänzt).'
            : 'Für HTTP: Host/Pfad ohne Protokoll (http:// wird automatisch ergänzt).';
        }
      } else if (isTCPMonitor) {
        if (useHTTPSLabelField) {
          useHTTPSLabelField.textContent = 'TLS Handshake prüfen';
        }
        if (verifyCertLabelField) {
          verifyCertLabelField.textContent = 'Zertifikat prüfen';
        }
        expectedStatusField.value = '';
        expectedTextField.value = '';
        if (!useHTTPSField.checked) {
          verifyCertField.checked = false;
          tlsModeField.value = 'none';
        } else {
          tlsModeField.value = verifyCertField.checked ? 'tls' : 'starttls';
        }
        if (targetField) {
          targetField.placeholder = 'example.com:443';
        }
        if (targetHintField) {
          targetHintField.textContent = 'Für TCP: host:port';
        }
      } else if (isMail) {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
        if (tlsModeField.value !== 'tls' && tlsModeField.value !== 'starttls') {
          tlsModeField.value = kind === 'smtp' ? 'starttls' : 'tls';
        }
        if (targetField) {
          targetField.placeholder = 'mail.example.com:587';
        }
        if (targetHintField) {
          targetHintField.textContent = 'Für Mail-Monitore: host:port';
        }
      } else if (isDNS) {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
        tlsModeField.value = 'none';
        expectedStatusField.value = '';
        if (targetField) {
          targetField.placeholder = 'example.com';
        }
        if (targetHintField) {
          targetHintField.textContent = 'Hostname, der aufgelöst werden soll (z. B. example.com).';
        }
        if (expectedTextField) {
          expectedTextField.placeholder = '1.2.3.4';
        }
      } else if (isUDP) {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
        tlsModeField.value = 'none';
        expectedStatusField.value = '';
        expectedTextField.value = '';
        if (targetField) {
          targetField.placeholder = 'example.com:53';
        }
        if (targetHintField) {
          targetHintField.textContent = 'Für UDP: host:port';
        }
      } else if (isWhois) {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
        tlsModeField.value = 'none';
        expectedStatusField.value = '';
        expectedTextField.value = '';
        if (targetField) {
          targetField.placeholder = 'example.com';
        }
        if (targetHintField) {
          targetHintField.textContent = 'Domain ohne Protokoll (z. B. example.com). Prüft Ablaufdatum via WHOIS.';
        }
      } else {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
        tlsModeField.value = 'none';
        expectedStatusField.value = '';
        expectedTextField.value = '';
        if (kind === 'tcp') {
          if (targetField) {
            targetField.placeholder = 'example.com:443';
          }
          if (targetHintField) {
            targetHintField.textContent = 'Für TCP: host:port';
          }
        } else if (kind === 'icmp') {
          if (targetField) {
            targetField.placeholder = '1.1.1.1';
          }
          if (targetHintField) {
            targetHintField.textContent = 'Für ICMP: IPv4/IPv6-Adresse';
          }
        }
      }
    };

    const openCreate = () => {
      if (!title || !idField || !nameField || !groupField || !kindField || !tlsModeField || !targetField || !intervalField || !timeoutField || !expectedStatusField || !expectedTextField || !enabledField || !notifyField || !dialog) {
        return;
      }
      title.textContent = 'Monitor anlegen';
      idField.value = '';
      nameField.value = '';
      groupField.value = '';
      kindField.value = 'https';
      tlsModeField.value = 'tls';
      targetField.value = '';
      intervalField.value = '60';
      timeoutField.value = '10';
      expectedStatusField.value = '';
      expectedTextField.value = '';
      useHTTPSField.checked = true;
      verifyCertField.checked = true;
      enabledField.checked = true;
      notifyField.checked = true;
      applyKindRules();
      dialog.showModal();
    };

    const openEdit = (button) => {
      if (!title || !idField || !nameField || !groupField || !kindField || !tlsModeField || !targetField || !intervalField || !timeoutField || !expectedStatusField || !expectedTextField || !enabledField || !notifyField || !dialog) {
        return;
      }
      title.textContent = 'Monitor bearbeiten';
      idField.value = button.dataset.id || '';
      nameField.value = button.dataset.name || '';
      groupField.value = button.dataset.group || '';
      kindField.value = button.dataset.kind || 'https';
      tlsModeField.value = button.dataset.tlsMode || 'tls';
      targetField.value = button.dataset.target || '';
      intervalField.value = button.dataset.interval || '60';
      timeoutField.value = button.dataset.timeout || '10';
      expectedStatusField.value = button.dataset.expectedStatus || '';
      expectedTextField.value = button.dataset.expectedText || '';
      const tlsMode = button.dataset.tlsMode || 'tls';
      if (tlsMode === 'none') {
        useHTTPSField.checked = false;
        verifyCertField.checked = false;
      } else if (tlsMode === 'starttls') {
        useHTTPSField.checked = true;
        verifyCertField.checked = false;
      } else {
        useHTTPSField.checked = true;
        verifyCertField.checked = true;
      }
      enabledField.checked = button.dataset.enabled === '1';
      notifyField.checked = button.dataset.notifyOnRecovery === '1';
      applyKindRules();
      dialog.showModal();
    };

    openCreateButton?.addEventListener('click', openCreate);
    cancelButton?.addEventListener('click', () => dialog?.close());
    groupCancelButton?.addEventListener('click', () => groupDialog?.close());
    groupResetButton?.addEventListener('click', () => {
      if (groupIconCustom) {
        groupIconCustom.value = '';
      }
      if (groupIconSearch) {
        groupIconSearch.value = groupNameField?.value || '';
      }
      if (groupIconSlugField) {
        groupIconSlugField.value = '';
      }
      updateGroupIconPreview();
      renderIconResults([], groupIconSearch?.value || '');
      scheduleIconSearch(groupIconSearch?.value || '');
    });
    kindField?.addEventListener('change', applyKindRules);
    useHTTPSField?.addEventListener('change', applyKindRules);
    verifyCertField?.addEventListener('change', applyKindRules);
    groupIconSearch?.addEventListener('input', () => scheduleIconSearch(groupIconSearch.value));
    groupIconCustom?.addEventListener('input', () => {
      if (groupIconSlugField) {
        groupIconSlugField.value = normalizeIconSlug(groupIconCustom.value || '');
      }
      updateGroupIconPreview();
    });
    groupForm?.addEventListener('submit', saveDashboardState);

    let globalDashboardListenersBound = false;
    const bindGlobalDashboardListeners = () => {
      if (globalDashboardListenersBound) {
        return;
      }
      globalDashboardListenersBound = true;
      document.addEventListener('click', (event) => {
        const target = event.target;
        if (!(target instanceof Element)) {
          closeActionMenus();
          return;
        }
        if (!target.closest('.action-menu')) {
          closeActionMenus();
        }
      });

      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          closeActionMenus();
        }
      });
    };

    const bindStateEventListeners = () => {
      const search = document.getElementById('state-events-search');
      const statusFilter = document.getElementById('state-events-status-filter');
      const incidentsOnly = document.getElementById('state-events-incidents-only');
      const exportButton = document.getElementById('state-events-export');

      bindOnce(search, 'StateSearch', applyStateEventFilters);
      if (search instanceof Element && search.dataset.boundStateSearchChange !== '1') {
        search.dataset.boundStateSearchChange = '1';
        search.addEventListener('input', applyStateEventFilters);
      }

      if (statusFilter instanceof Element && statusFilter.dataset.boundStateStatus !== '1') {
        statusFilter.dataset.boundStateStatus = '1';
        statusFilter.addEventListener('change', applyStateEventFilters);
      }
      if (incidentsOnly instanceof Element && incidentsOnly.dataset.boundStateIncidents !== '1') {
        incidentsOnly.dataset.boundStateIncidents = '1';
        incidentsOnly.addEventListener('change', applyStateEventFilters);
      }
      if (exportButton instanceof Element && exportButton.dataset.boundStateExport !== '1') {
        exportButton.dataset.boundStateExport = '1';
        exportButton.addEventListener('click', exportStateEventsCSV);
      }
    };

    const bindDynamicDashboardListeners = () => {
      document.querySelectorAll('.edit-monitor').forEach((button) => {
        if (button.dataset.boundEditMonitor === '1') {
          return;
        }
        button.dataset.boundEditMonitor = '1';
        button.addEventListener('click', () => openEdit(button));
      });

      document.querySelectorAll('.group-settings').forEach((button) => {
        if (button.dataset.boundGroupSettings === '1') {
          return;
        }
        button.dataset.boundGroupSettings = '1';
        button.addEventListener('click', () => openGroupDialog(button));
      });

      document.querySelectorAll('.action-menu').forEach((menu) => {
        if (menu.dataset.boundActionMenu !== '1') {
          menu.dataset.boundActionMenu = '1';
          menu.addEventListener('toggle', () => {
            if (menu.open) {
              closeActionMenus(menu);
            }
          });
          menu.addEventListener('click', (event) => {
            event.stopPropagation();
          });
        }
      });

      document.querySelectorAll('.action-menu-trigger, .action-menu-list').forEach((element) => {
        if (element.dataset.boundActionMenuClick === '1') {
          return;
        }
        element.dataset.boundActionMenuClick = '1';
        element.addEventListener('click', (event) => {
          event.stopPropagation();
        });
      });

      document.querySelectorAll(`form[action^="${appBase}"]`).forEach((form) => {
        if (form.dataset.boundDashboardSubmit === '1') {
          return;
        }
        form.dataset.boundDashboardSubmit = '1';
        form.addEventListener('submit', saveDashboardState);
      });

      document.querySelectorAll('.trend-range-toggle a').forEach((link) => {
        if (link.dataset.boundTrendLink === '1') {
          return;
        }
        link.dataset.boundTrendLink = '1';
        link.addEventListener('click', saveDashboardState);
      });

      document.querySelectorAll('.service-cluster').forEach((cluster) => {
        if (cluster.dataset.boundClusterToggle === '1') {
          return;
        }
        cluster.dataset.boundClusterToggle = '1';
        cluster.addEventListener('toggle', saveDashboardState);
      });

      document.querySelectorAll('.group-icon').forEach((image) => {
        if (image.dataset.boundGroupIconError === '1') {
          return;
        }
        image.dataset.boundGroupIconError = '1';
        image.addEventListener('error', () => {
          image.hidden = true;
        });
      });

      document.querySelectorAll('.service-summary-trend').forEach((button) => {
        if (button.dataset.boundServiceTrend === '1') {
          return;
        }
        button.dataset.boundServiceTrend = '1';
        button.addEventListener('click', (event) => {
          event.preventDefault();
          event.stopPropagation();
        });
      });

      document.querySelectorAll('.trend-trigger').forEach((button) => {
        if (button.dataset.boundTrendTrigger === '1') {
          return;
        }
        button.dataset.boundTrendTrigger = '1';
        button.addEventListener('click', () => openTrendDetail(button));
      });

      if (isAdmin) {
        document.querySelectorAll('.service-cluster').forEach((cluster) => {
          if (cluster.dataset.boundGroupDrag === '1') {
            return;
          }
          cluster.dataset.boundGroupDrag = '1';
          cluster.addEventListener('dragstart', (event) => {
            cluster.dataset.draggedGroup = cluster.dataset.group || '';
            cluster.classList.add('is-dragging');
            event.dataTransfer.effectAllowed = 'move';
            event.dataTransfer.setData('text/plain', cluster.dataset.draggedGroup || '');
          });
          cluster.addEventListener('dragend', () => {
            cluster.classList.remove('is-dragging');
            document.querySelectorAll('.service-cluster.drop-target').forEach((item) => item.classList.remove('drop-target'));
          });
          cluster.addEventListener('dragover', (event) => {
            const draggedGroup = event.dataTransfer.getData('text/plain') || '';
            const targetGroup = cluster.dataset.group || '';
            if (!draggedGroup || draggedGroup === targetGroup) {
              return;
            }
            event.preventDefault();
            cluster.classList.add('drop-target');
          });
          cluster.addEventListener('dragleave', () => {
            cluster.classList.remove('drop-target');
          });
          cluster.addEventListener('drop', (event) => {
            event.preventDefault();
            const draggedGroup = event.dataTransfer.getData('text/plain') || '';
            const targetGroup = cluster.dataset.group || '';
            cluster.classList.remove('drop-target');
            if (!draggedGroup || !targetGroup || draggedGroup === targetGroup) {
              return;
            }
            submitPost(appBase + 'groups/reorder', {
              dragged_group: draggedGroup,
              target_group: targetGroup,
              trend: currentTrend
            });
          });
        });

        document.querySelectorAll('.monitor-card').forEach((card) => {
          if (card.dataset.boundMonitorDrag === '1') {
            return;
          }
          card.dataset.boundMonitorDrag = '1';
          card.addEventListener('dragstart', (event) => {
            const payload = JSON.stringify({
              id: card.dataset.monitorId || '',
              group: card.dataset.group || ''
            });
            card.classList.add('is-dragging');
            event.dataTransfer.effectAllowed = 'move';
            event.dataTransfer.setData('text/plain', payload);
          });
          card.addEventListener('dragend', () => {
            card.classList.remove('is-dragging');
            document.querySelectorAll('.monitor-card.drop-target').forEach((item) => item.classList.remove('drop-target'));
          });
          card.addEventListener('dragover', (event) => {
            let dragged = null;
            try {
              dragged = JSON.parse(event.dataTransfer.getData('text/plain') || '{}');
            } catch (_) {
              return;
            }
            const targetId = card.dataset.monitorId || '';
            const targetGroup = card.dataset.group || '';
            if (!dragged || dragged.id === targetId || dragged.group !== targetGroup) {
              return;
            }
            event.preventDefault();
            card.classList.add('drop-target');
          });
          card.addEventListener('dragleave', () => {
            card.classList.remove('drop-target');
          });
          card.addEventListener('drop', (event) => {
            event.preventDefault();
            let dragged = null;
            try {
              dragged = JSON.parse(event.dataTransfer.getData('text/plain') || '{}');
            } catch (_) {
              return;
            }
            const targetId = card.dataset.monitorId || '';
            const targetGroup = card.dataset.group || '';
            card.classList.remove('drop-target');
            if (!dragged || !targetId || dragged.id === targetId || dragged.group !== targetGroup) {
              return;
            }
            submitPost(appBase + 'monitors/reorder', {
              dragged_id: dragged.id,
              target_id: targetId,
              group: targetGroup,
              trend: currentTrend
            });
          });
        });
      }

      bindStateEventListeners();
      applyStateEventFilters();
    };

    bindGlobalDashboardListeners();
    rebindDynamicHandlers = bindDynamicDashboardListeners;

    restoreDashboardState();

    const formatters = {
      datetime: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }),
      minute: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }),
      hour: new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' }),
      date: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }),
      month: new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' })
    };

    const formatClientTimes = (root = document) => {
      root.querySelectorAll('.client-time').forEach((element) => {
        const value = element.getAttribute('datetime');
        if (!value) {
          return;
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
          return;
        }
        const format = element.dataset.format || 'datetime';
        const formatter = formatters[format] || formatters.datetime;
        element.textContent = formatter.format(date);
        element.title = date.toLocaleString();
      });
    };

    const formatTrendBars = (root = document) => {
      root.querySelectorAll('.trend-bar').forEach((element) => {
        const bucket = element.dataset.bucket;
        const label = element.dataset.label || '';
        const format = element.dataset.format || 'hour';
        if (!bucket) {
          return;
        }
        const date = new Date(bucket);
        if (Number.isNaN(date.getTime())) {
          element.title = label;
          return;
        }
        const formatter = formatters[format] || formatters.hour;
        element.title = `${formatter.format(date)} · ${label}`;
      });
    };

    const replaceSectionByID = (id, html) => {
      const current = document.getElementById(id);
      if (!current || typeof html !== 'string' || html.trim() === '') {
        return false;
      }
      if (current.outerHTML.trim() === html.trim()) {
        return false;
      }
      const wrapper = document.createElement('div');
      wrapper.innerHTML = html.trim();
      const next = wrapper.firstElementChild;
      if (!next) {
        return false;
      }
      current.replaceWith(next);
      return true;
    };

    const parseFragmentRoot = (html) => {
      if (typeof html !== 'string' || html.trim() === '') {
        return null;
      }
      const wrapper = document.createElement('div');
      wrapper.innerHTML = html.trim();
      return wrapper.firstElementChild;
    };

    const patchMonitorGrid = (currentGrid, nextGrid) => {
      if (!(currentGrid instanceof Element) || !(nextGrid instanceof Element)) {
        return false;
      }

      let changed = false;
      const currentCards = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
      const nextCards = Array.from(nextGrid.querySelectorAll(':scope > .monitor-card'));
      const currentByID = new Map(currentCards.map((card) => [card.dataset.monitorId || '', card]));
      const nextIDs = new Set(nextCards.map((card) => card.dataset.monitorId || ''));

      currentCards.forEach((card) => {
        const id = card.dataset.monitorId || '';
        if (!nextIDs.has(id)) {
          card.remove();
          changed = true;
        }
      });

      nextCards.forEach((nextCard, index) => {
        const id = nextCard.dataset.monitorId || '';
        if (!id) {
          return;
        }
        const current = currentByID.get(id);
        if (!current) {
          const currentOrdered = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
          const reference = currentOrdered[index] || null;
          currentGrid.insertBefore(nextCard.cloneNode(true), reference);
          changed = true;
          return;
        }

        if (current.outerHTML !== nextCard.outerHTML) {
          current.replaceWith(nextCard.cloneNode(true));
          changed = true;
        }

        const orderedAfter = Array.from(currentGrid.querySelectorAll(':scope > .monitor-card'));
        const currentNode = orderedAfter.find((node) => (node.dataset.monitorId || '') === id);
        if (!currentNode) {
          return;
        }
        if (orderedAfter[index] !== currentNode) {
          currentGrid.insertBefore(currentNode, orderedAfter[index] || null);
          changed = true;
        }
      });

      return changed;
    };

    const patchServiceCluster = (currentCluster, nextCluster) => {
      if (!(currentCluster instanceof Element) || !(nextCluster instanceof Element)) {
        return false;
      }

      const wasOpen = currentCluster.open;
      let changed = false;

      const currentSummary = currentCluster.querySelector(':scope > .service-cluster-header');
      const nextSummary = nextCluster.querySelector(':scope > .service-cluster-header');
      if (currentSummary && nextSummary) {
        const patchAttr = (currentElement, nextElement, attributeName) => {
          const currentValue = currentElement.getAttribute(attributeName) || '';
          const nextValue = nextElement.getAttribute(attributeName) || '';
          if (currentValue !== nextValue) {
            if (nextValue === '') {
              currentElement.removeAttribute(attributeName);
            } else {
              currentElement.setAttribute(attributeName, nextValue);
            }
            return true;
          }
          return false;
        };

        const currentCount = currentSummary.querySelector('.service-summary-right .service-count');
        const nextCount = nextSummary.querySelector('.service-summary-right .service-count');
        if (currentCount && nextCount) {
          if (currentCount.textContent !== nextCount.textContent) {
            currentCount.textContent = nextCount.textContent;
            changed = true;
          }
          if (patchAttr(currentCount, nextCount, 'aria-label')) {
            changed = true;
          }
        }

        const currentStatus = currentSummary.querySelector('.service-summary-right .status-pill');
        const nextStatus = nextSummary.querySelector('.service-summary-right .status-pill');
        if (currentStatus && nextStatus) {
          if (currentStatus.textContent !== nextStatus.textContent) {
            currentStatus.textContent = nextStatus.textContent;
            changed = true;
          }
          if (currentStatus.className !== nextStatus.className) {
            currentStatus.className = nextStatus.className;
            changed = true;
          }
        }

        const currentSettings = currentSummary.querySelector('.group-settings');
        const nextSettings = nextSummary.querySelector('.group-settings');
        if (currentSettings && nextSettings) {
          if (patchAttr(currentSettings, nextSettings, 'data-icon-slug')) {
            changed = true;
          }
        }

        const currentTitle = currentSummary.querySelector('.service-cluster-title h4');
        const nextTitle = nextSummary.querySelector('.service-cluster-title h4');
        if (currentTitle && nextTitle && currentTitle.textContent !== nextTitle.textContent) {
          currentTitle.textContent = nextTitle.textContent;
          changed = true;
        }

        const currentIcon = currentSummary.querySelector('.service-cluster-title .group-icon');
        const nextIcon = nextSummary.querySelector('.service-cluster-title .group-icon');
        const currentTitleWrapper = currentSummary.querySelector('.service-cluster-title');
        if (currentIcon && nextIcon) {
          if (currentIcon.getAttribute('src') !== nextIcon.getAttribute('src')) {
            currentIcon.setAttribute('src', nextIcon.getAttribute('src') || '');
            changed = true;
          }
          if (currentIcon.getAttribute('alt') !== nextIcon.getAttribute('alt')) {
            currentIcon.setAttribute('alt', nextIcon.getAttribute('alt') || '');
            changed = true;
          }
        } else if (!currentIcon && nextIcon && currentTitleWrapper) {
          currentTitleWrapper.insertBefore(nextIcon.cloneNode(true), currentTitleWrapper.firstChild || null);
          changed = true;
        } else if (currentIcon && !nextIcon) {
          currentIcon.remove();
          changed = true;
        }

        const currentTrendTrigger = currentSummary.querySelector('.service-summary-trend');
        const nextTrendTrigger = nextSummary.querySelector('.service-summary-trend');
        if (currentTrendTrigger && nextTrendTrigger) {
          ['data-monitor-name', 'data-monitor-kind', 'data-target', 'data-status', 'data-uptime', 'data-trend-label', 'data-last-check', 'data-last-message', 'aria-label'].forEach((attributeName) => {
            if (patchAttr(currentTrendTrigger, nextTrendTrigger, attributeName)) {
              changed = true;
            }
          });

          const currentTrendBars = currentTrendTrigger.querySelector('.trend-bars');
          const nextTrendBars = nextTrendTrigger.querySelector('.trend-bars');
          if (currentTrendBars && nextTrendBars && currentTrendBars.innerHTML !== nextTrendBars.innerHTML) {
            currentTrendBars.innerHTML = nextTrendBars.innerHTML;
            changed = true;
          }
        } else if (!currentTrendTrigger && nextTrendTrigger) {
          const summaryBody = currentSummary.querySelector('.service-summary');
          if (summaryBody) {
            summaryBody.appendChild(nextTrendTrigger.cloneNode(true));
            changed = true;
          }
        } else if (currentTrendTrigger && !nextTrendTrigger) {
          currentTrendTrigger.remove();
          changed = true;
        }

        const currentMuted = currentSummary.querySelector('.service-summary > p.muted.compact');
        const nextMuted = nextSummary.querySelector('.service-summary > p.muted.compact');
        if (currentMuted && nextMuted) {
          if (currentMuted.textContent !== nextMuted.textContent) {
            currentMuted.textContent = nextMuted.textContent;
            changed = true;
          }
        } else if (!currentMuted && nextMuted) {
          const summaryBody = currentSummary.querySelector('.service-summary');
          if (summaryBody) {
            summaryBody.appendChild(nextMuted.cloneNode(true));
            changed = true;
          }
        } else if (currentMuted && !nextMuted) {
          currentMuted.remove();
          changed = true;
        }
      } else if (currentSummary?.innerHTML !== nextSummary?.innerHTML) {
        if (currentSummary && nextSummary) {
          currentSummary.innerHTML = nextSummary.innerHTML;
          changed = true;
        }
      }

      const currentGrid = currentCluster.querySelector(':scope > .monitor-grid');
      const nextGrid = nextCluster.querySelector(':scope > .monitor-grid');
      if (currentGrid && nextGrid) {
        if (patchMonitorGrid(currentGrid, nextGrid)) {
          changed = true;
        }
      } else if (currentCluster.outerHTML !== nextCluster.outerHTML) {
        currentCluster.replaceWith(nextCluster.cloneNode(true));
        return true;
      }

      currentCluster.open = wasOpen;
      return changed;
    };

    const patchBoardSection = (html) => {
      const currentBoard = document.getElementById('dashboard-live-board');
      const nextBoard = parseFragmentRoot(html);
      if (!(currentBoard instanceof Element) || !(nextBoard instanceof Element)) {
        return false;
      }

      const currentList = currentBoard.querySelector('.service-group-list');
      const nextList = nextBoard.querySelector('.service-group-list');
      if (!(currentList instanceof Element) || !(nextList instanceof Element)) {
        return replaceSectionByID('dashboard-live-board', html);
      }

      let changed = false;
      const currentClusters = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
      const nextClusters = Array.from(nextList.querySelectorAll(':scope > .service-cluster'));
      const currentByGroup = new Map(currentClusters.map((cluster) => [cluster.dataset.group || '', cluster]));
      const nextGroups = new Set(nextClusters.map((cluster) => cluster.dataset.group || ''));

      currentClusters.forEach((cluster) => {
        const key = cluster.dataset.group || '';
        if (!nextGroups.has(key)) {
          cluster.remove();
          changed = true;
        }
      });

      nextClusters.forEach((nextCluster, index) => {
        const key = nextCluster.dataset.group || '';
        if (!key) {
          return;
        }
        const currentCluster = currentByGroup.get(key);
        if (!currentCluster) {
          const ordered = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
          const reference = ordered[index] || null;
          currentList.insertBefore(nextCluster.cloneNode(true), reference);
          changed = true;
          return;
        }

        if (patchServiceCluster(currentCluster, nextCluster)) {
          changed = true;
        }

        const orderedAfter = Array.from(currentList.querySelectorAll(':scope > .service-cluster'));
        const currentNode = orderedAfter.find((node) => (node.dataset.group || '') === key);
        if (!currentNode) {
          return;
        }
        if (orderedAfter[index] !== currentNode) {
          currentList.insertBefore(currentNode, orderedAfter[index] || null);
          changed = true;
        }
      });

      const currentBoardClasses = currentBoard.className || '';
      const nextBoardClasses = nextBoard.className || '';
      if (currentBoardClasses !== nextBoardClasses) {
        currentBoard.className = nextBoardClasses;
        changed = true;
      }

      return changed;
    };

    const patchBoardGroups = (groupsHTML) => {
      if (!groupsHTML || typeof groupsHTML !== 'object' || Array.isArray(groupsHTML)) {
        return false;
      }

      const currentBoard = document.getElementById('dashboard-live-board');
      if (!(currentBoard instanceof Element)) {
        return false;
      }
      const currentList = currentBoard.querySelector('.service-group-list');
      if (!(currentList instanceof Element)) {
        return false;
      }

      let changed = false;
      Object.entries(groupsHTML).forEach(([groupName, html]) => {
        if (typeof groupName !== 'string' || groupName.trim() === '') {
          return;
        }
        const nextCluster = parseFragmentRoot(html);
        if (!(nextCluster instanceof Element)) {
          return;
        }

        const currentCluster = Array.from(currentList.querySelectorAll(':scope > .service-cluster'))
          .find((cluster) => (cluster.dataset.group || '') === groupName);

        if (!currentCluster) {
          currentList.appendChild(nextCluster.cloneNode(true));
          changed = true;
          return;
        }

        if (patchServiceCluster(currentCluster, nextCluster)) {
          changed = true;
        }
      });

      return changed;
    };

    applyLiveSnapshot = async (requestedParts = [], requestedBoardGroups = []) => {
      if (hasOpenDialog()) {
        return false;
      }

      const openGroupsBeforeUpdate = currentOpenGroups();

      const parts = Array.isArray(requestedParts)
        ? requestedParts
          .map((value) => String(value || '').trim())
          .filter((value) => value.length > 0)
        : [];
      const boardGroups = Array.isArray(requestedBoardGroups)
        ? requestedBoardGroups
          .map((value) => String(value || '').trim())
          .filter((value) => value.length > 0)
        : [];
      const uniqueParts = Array.from(new Set(parts));
      const uniqueBoardGroups = Array.from(new Set(boardGroups));
      const snapshotURL = new URL(`${appBase}live/snapshot`, window.location.href);
      snapshotURL.searchParams.set('trend', currentTrend);
      if (uniqueParts.length > 0) {
        snapshotURL.searchParams.set('parts', uniqueParts.join(','));
      }
      if (uniqueParts.includes('board') && uniqueBoardGroups.length > 0) {
        snapshotURL.searchParams.set('board_groups', uniqueBoardGroups.join(','));
      }

      const response = await fetch(snapshotURL.toString(), {
        method: 'GET',
        headers: { Accept: 'application/json' }
      });
      if (!response.ok) {
        return false;
      }
      const payload = await response.json();
      if (!payload || typeof payload !== 'object') {
        return false;
      }

      const updates = [];
      let boardReplaced = false;
      if (typeof payload.stats_hash === 'string' && payload.stats_hash !== liveSnapshotHashes.stats) {
        updates.push(replaceSectionByID('dashboard-live-stats', payload.stats_html));
        liveSnapshotHashes.stats = payload.stats_hash;
      }
      if (typeof payload.board_hash === 'string' && payload.board_hash !== liveSnapshotHashes.board) {
        if (payload.board_groups_html && typeof payload.board_groups_html === 'object' && !Array.isArray(payload.board_groups_html)) {
          boardReplaced = patchBoardGroups(payload.board_groups_html);
        } else {
          boardReplaced = patchBoardSection(payload.board_html);
        }
        updates.push(boardReplaced);
        liveSnapshotHashes.board = payload.board_hash;
      }
      if (typeof payload.state_events_hash === 'string' && payload.state_events_hash !== liveSnapshotHashes.stateEvents) {
        updates.push(replaceSectionByID('dashboard-live-state-events', payload.state_events_html));
        liveSnapshotHashes.stateEvents = payload.state_events_hash;
      }
      if (typeof payload.notification_events_hash === 'string' && payload.notification_events_hash !== liveSnapshotHashes.notificationEvents) {
        updates.push(replaceSectionByID('dashboard-live-notification-events', payload.notification_events_html));
        liveSnapshotHashes.notificationEvents = payload.notification_events_hash;
      }

      const groupOptions = document.getElementById('monitor-group-options');
      if (groupOptions && typeof payload.group_options_html === 'string' && typeof payload.group_options_hash === 'string' && payload.group_options_hash !== liveSnapshotHashes.groupOptions) {
        groupOptions.innerHTML = payload.group_options_html;
        liveSnapshotHashes.groupOptions = payload.group_options_hash;
      }

      const changed = updates.some(Boolean);

      if (!changed) {
        return false;
      }

      rebindDynamicHandlers();
      reformatLiveContent();

      if (boardReplaced) {
        restoreOpenGroups(openGroupsBeforeUpdate);
      }

      applyKindRules();
      return true;
    };

    reformatLiveContent = () => {
      formatClientTimes(document);
      formatTrendBars(document);
    };

    reformatLiveContent();

    const formatDateValue = (value, format = 'datetime') => {
      if (!value) {
        return '—';
      }
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {
        return value;
      }
      const formatter = formatters[format] || formatters.datetime;
      return formatter.format(date);
    };

    const formatLatency = (value) => {
      const numeric = Number(value);
      if (!Number.isFinite(numeric) || numeric <= 0) {
        return '—';
      }
      if (numeric < 1000) {
        return `${numeric} ms`;
      }
      return `${(numeric / 1000).toFixed(numeric % 1000 === 0 ? 0 : 2)} s`;
    };

    const openTrendDetail = (trigger) => {
      if (!trendDetailTitle || !trendDetailSubtitle || !trendDetailStatus || !trendDetailUptime || !trendDetailLastCheck || !trendDetailTarget || !trendDetailRangeTitle || !trendDetailLatency || !trendDetailChecks || !trendDetailBars || !trendDetailHistory || !trendDetailModal) {
        return;
      }
      const bars = Array.from(trigger.querySelectorAll('.trend-bar'));
      const barsDescending = [...bars].reverse();
      trendDetailTitle.textContent = trigger.dataset.monitorName || 'Trenddetails';
      trendDetailSubtitle.textContent = `${trigger.dataset.monitorKind || ''} · ${trigger.dataset.lastMessage || 'Keine Detailmeldung'}`;
      trendDetailStatus.textContent = trigger.dataset.status || 'UNKNOWN';
      trendDetailUptime.textContent = trigger.dataset.uptime || '—';
      trendDetailLastCheck.textContent = formatDateValue(trigger.dataset.lastCheck, 'datetime');
      trendDetailTarget.textContent = trigger.dataset.target || '—';
      trendDetailRangeTitle.textContent = `Verlauf ${trigger.dataset.trendLabel || ''}`.trim();

      const barsWithChecks = bars.filter((bar) => Number(bar.dataset.checks || '0') > 0);
      const totalChecks = barsWithChecks.reduce((sum, bar) => sum + Number(bar.dataset.checks || '0'), 0);
      const weightedLatency = barsWithChecks.reduce((sum, bar) => sum + (Number(bar.dataset.avgMs || '0') * Number(bar.dataset.checks || '0')), 0);
      const minLatency = barsWithChecks.reduce((min, bar) => {
        const value = Number(bar.dataset.minMs || '0');
        return min === 0 || (value > 0 && value < min) ? value : min;
      }, 0);
      const maxLatency = barsWithChecks.reduce((max, bar) => {
        const value = Number(bar.dataset.maxMs || '0');
        return value > max ? value : max;
      }, 0);
      const avgLatency = totalChecks > 0 ? Math.round(weightedLatency / totalChecks) : 0;
      trendDetailLatency.textContent = `${formatLatency(avgLatency)} / ${formatLatency(minLatency)} / ${formatLatency(maxLatency)}`;
      trendDetailChecks.textContent = totalChecks > 0 ? String(totalChecks) : '—';

      trendDetailBars.innerHTML = '';
      trendDetailHistory.innerHTML = '';

      bars.forEach((bar) => {
        const clone = document.createElement('span');
        clone.className = bar.className;
        clone.title = bar.title;
        trendDetailBars.appendChild(clone);
      });

      barsDescending.forEach((bar) => {
        const row = document.createElement('tr');
        const when = document.createElement('td');
        when.textContent = formatDateValue(bar.dataset.bucket, bar.dataset.format || 'hour');
        const result = document.createElement('td');
        const checks = Number(bar.dataset.checks || '0');
        if (checks > 0) {
          result.textContent = `${bar.dataset.label || '—'} · Ø ${formatLatency(bar.dataset.avgMs)} · Min ${formatLatency(bar.dataset.minMs)} · Max ${formatLatency(bar.dataset.maxMs)}`;
        } else {
          result.textContent = bar.dataset.label || 'Keine Daten';
        }
        row.appendChild(when);
        row.appendChild(result);
        trendDetailHistory.appendChild(row);
      });

      trendDetailModal.showModal();
    };

    trendDetailClose?.addEventListener('click', () => trendDetailModal?.close());

    const updateStateEventFilterStatus = (visible, total) => {
      const filterStatus = document.getElementById('state-events-filter-status');
      if (!filterStatus) {
        return;
      }
      if (total <= 0) {
        filterStatus.textContent = 'Keine Statusänderungen vorhanden.';
        return;
      }
      if (visible === total) {
        filterStatus.textContent = `${total} Einträge`;
        return;
      }
      filterStatus.textContent = `${visible} von ${total} Einträgen sichtbar`;
    };

    const applyStateEventFilters = () => {
      const body = document.getElementById('state-events-body');
      const search = document.getElementById('state-events-search');
      const statusFilterNode = document.getElementById('state-events-status-filter');
      const incidentsOnlyNode = document.getElementById('state-events-incidents-only');
      const emptyRow = document.getElementById('state-events-empty-row');
      const stateEventRows = body
        ? Array.from(body.querySelectorAll('tr')).filter((row) => row.id !== 'state-events-empty-row')
        : [];

      if (!stateEventRows.length) {
        updateStateEventFilterStatus(0, 0);
        return;
      }

      const query = (search?.value || '').trim().toLowerCase();
      const statusFilter = (statusFilterNode?.value || 'all').trim().toLowerCase();
      const incidentsOnly = incidentsOnlyNode?.checked === true;

      let visible = 0;
      stateEventRows.forEach((row) => {
        const monitor = (row.dataset.monitor || '').toLowerCase();
        const fromStatus = (row.dataset.from || '').toLowerCase();
        const toStatus = (row.dataset.to || '').toLowerCase();
        const message = (row.dataset.message || '').toLowerCase();
        const when = (row.dataset.when || '').toLowerCase();

        const matchesQuery = !query || monitor.includes(query) || message.includes(query) || when.includes(query) || fromStatus.includes(query) || toStatus.includes(query);
        const matchesStatus = statusFilter === 'all' || toStatus === statusFilter;
        const matchesIncidentsOnly = !incidentsOnly || toStatus === 'down' || toStatus === 'degraded';
        const rowVisible = matchesQuery && matchesStatus && matchesIncidentsOnly;

        row.hidden = !rowVisible;
        if (rowVisible) {
          visible += 1;
        }
      });

      if (emptyRow) {
        emptyRow.hidden = visible > 0;
      }
      updateStateEventFilterStatus(visible, stateEventRows.length);
    };

    const exportStateEventsCSV = () => {
      const body = document.getElementById('state-events-body');
      const stateEventRows = body
        ? Array.from(body.querySelectorAll('tr')).filter((row) => row.id !== 'state-events-empty-row')
        : [];
      if (!stateEventRows.length) {
        return;
      }

      const visibleRows = stateEventRows.filter((row) => !row.hidden);
      if (!visibleRows.length) {
        return;
      }

      const esc = (value) => {
        const text = String(value ?? '');
        return `"${text.replace(/"/g, '""')}"`;
      };

      const lines = [
        ['Zeitpunkt', 'Monitor', 'Von', 'Nach', 'Details'],
        ...visibleRows.map((row) => [
          row.dataset.when || '',
          row.dataset.monitor || '',
          row.dataset.from || '',
          row.dataset.to || '',
          row.dataset.message || ''
        ])
      ].map((columns) => columns.map((column) => esc(column)).join(';'));

      const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `goup-statusaenderungen-${new Date().toISOString().replace(/[:]/g, '-').slice(0, 19)}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    };

    rebindDynamicHandlers();
  });
})();
