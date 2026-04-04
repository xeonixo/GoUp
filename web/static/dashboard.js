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
    const actionMenus = Array.from(document.querySelectorAll('.action-menu'));
    let iconSearchTimer = null;
    let iconSearchRequest = null;

    const closeActionMenus = (except = null) => {
      actionMenus.forEach((menu) => {
        if (menu !== except) {
          menu.removeAttribute('open');
        }
      });
    };

    const normalizeIconSlug = (value) => value.trim().toLowerCase().replace(/\s+/g, '-');

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

    document.querySelectorAll('.edit-monitor').forEach((button) => {
      button.addEventListener('click', () => openEdit(button));
    });
    document.querySelectorAll('.group-settings').forEach((button) => {
      button.addEventListener('click', () => openGroupDialog(button));
    });

    actionMenus.forEach((menu) => {
      menu.addEventListener('toggle', () => {
        if (menu.open) {
          closeActionMenus(menu);
        }
      });
      menu.addEventListener('click', (event) => {
        event.stopPropagation();
      });
    });
    document.querySelectorAll('.action-menu-trigger, .action-menu-list').forEach((element) => {
      element.addEventListener('click', (event) => {
        event.stopPropagation();
      });
    });

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

    document.querySelectorAll(`form[action^="${appBase}"]`).forEach((form) => {
      form.addEventListener('submit', saveDashboardState);
    });
    document.querySelectorAll('.trend-range-toggle a').forEach((link) => {
      link.addEventListener('click', saveDashboardState);
    });
    document.querySelectorAll('.service-cluster').forEach((cluster) => {
      cluster.addEventListener('toggle', saveDashboardState);
    });
    document.querySelectorAll('.group-icon').forEach((image) => {
      image.addEventListener('error', () => {
        image.hidden = true;
      });
    });
    document.querySelectorAll('.service-summary-trend').forEach((button) => {
      button.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
      });
    });

    restoreDashboardState();

    const formatters = {
      datetime: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }),
      minute: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }),
      hour: new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' }),
      date: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }),
      month: new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' })
    };

    document.querySelectorAll('.client-time').forEach((element) => {
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

    document.querySelectorAll('.trend-bar').forEach((element) => {
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
    document.querySelectorAll('.trend-trigger').forEach((button) => {
      button.addEventListener('click', () => openTrendDetail(button));
    });

    const stateEventRows = stateEventsBody
      ? Array.from(stateEventsBody.querySelectorAll('tr')).filter((row) => row.id !== 'state-events-empty-row')
      : [];

    const updateStateEventFilterStatus = (visible, total) => {
      if (!stateEventsFilterStatus) {
        return;
      }
      if (total <= 0) {
        stateEventsFilterStatus.textContent = 'Keine Statusänderungen vorhanden.';
        return;
      }
      if (visible === total) {
        stateEventsFilterStatus.textContent = `${total} Einträge`;
        return;
      }
      stateEventsFilterStatus.textContent = `${visible} von ${total} Einträgen sichtbar`;
    };

    const applyStateEventFilters = () => {
      if (!stateEventRows.length) {
        updateStateEventFilterStatus(0, 0);
        return;
      }

      const query = (stateEventsSearch?.value || '').trim().toLowerCase();
      const statusFilter = (stateEventsStatusFilter?.value || 'all').trim().toLowerCase();
      const incidentsOnly = stateEventsIncidentsOnly?.checked === true;

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

      if (stateEventsEmptyRow) {
        stateEventsEmptyRow.hidden = visible > 0;
      }
      updateStateEventFilterStatus(visible, stateEventRows.length);
    };

    const exportStateEventsCSV = () => {
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

    stateEventsSearch?.addEventListener('input', applyStateEventFilters);
    stateEventsStatusFilter?.addEventListener('change', applyStateEventFilters);
    stateEventsIncidentsOnly?.addEventListener('change', applyStateEventFilters);
    stateEventsExport?.addEventListener('click', exportStateEventsCSV);
    applyStateEventFilters();

    if (!isAdmin) {
      return;
    }

    let draggedGroup = null;
    document.querySelectorAll('.service-cluster').forEach((cluster) => {
      cluster.addEventListener('dragstart', (event) => {
        draggedGroup = cluster.dataset.group || null;
        cluster.classList.add('is-dragging');
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', draggedGroup || '');
      });
      cluster.addEventListener('dragend', () => {
        draggedGroup = null;
        cluster.classList.remove('is-dragging');
        document.querySelectorAll('.service-cluster.drop-target').forEach((item) => item.classList.remove('drop-target'));
      });
      cluster.addEventListener('dragover', (event) => {
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

    let draggedMonitor = null;
    document.querySelectorAll('.monitor-card').forEach((card) => {
      card.addEventListener('dragstart', (event) => {
        draggedMonitor = {
          id: card.dataset.monitorId || '',
          group: card.dataset.group || ''
        };
        card.classList.add('is-dragging');
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', draggedMonitor.id);
      });
      card.addEventListener('dragend', () => {
        draggedMonitor = null;
        card.classList.remove('is-dragging');
        document.querySelectorAll('.monitor-card.drop-target').forEach((item) => item.classList.remove('drop-target'));
      });
      card.addEventListener('dragover', (event) => {
        const targetId = card.dataset.monitorId || '';
        const targetGroup = card.dataset.group || '';
        if (!draggedMonitor || draggedMonitor.id === targetId || draggedMonitor.group !== targetGroup) {
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
        const targetId = card.dataset.monitorId || '';
        const targetGroup = card.dataset.group || '';
        card.classList.remove('drop-target');
        if (!draggedMonitor || !targetId || draggedMonitor.id === targetId || draggedMonitor.group !== targetGroup) {
          return;
        }
        submitPost(appBase + 'monitors/reorder', {
          dragged_id: draggedMonitor.id,
          target_id: targetId,
          group: targetGroup,
          trend: currentTrend
        });
      });
    });
  });
})();
