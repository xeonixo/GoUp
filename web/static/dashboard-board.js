(() => {
  // Board search/status filter and in-place monitor actions (pause, delete, move up/down).
  const page = document.getElementById('dashboard-page');
  const searchInput = document.getElementById('board-search');
  const emptyHint = document.getElementById('board-filter-empty');
  const statusButtons = Array.from(document.querySelectorAll('[data-status-filter]'));
  if (!page || !searchInput) {
    return;
  }

  let i18n = {};
  try {
    i18n = JSON.parse(document.getElementById('goup-dashboard-i18n')?.textContent || '{}');
  } catch (_) {
  }
  const storageKey = 'goup:board-filter';
  const problemStatuses = new Set(['status-DOWN', 'status-DEGRADED']);
  const state = { query: '', status: 'all' };

  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || '{}');
    if (typeof saved.query === 'string') {
      state.query = saved.query;
    }
    if (['all', 'problems', 'paused'].includes(saved.status)) {
      state.status = saved.status;
    }
  } catch (_) {
  }
  searchInput.value = state.query;

  const persist = () => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(state));
    } catch (_) {
    }
  };

  const matchesStatus = (card) => {
    const status = card.dataset.status || '';
    if (state.status === 'problems') {
      return problemStatuses.has(status);
    }
    if (state.status === 'paused') {
      return status === 'status-PAUSED';
    }
    return true;
  };

  const applyFilter = () => {
    const terms = state.query.toLowerCase().split(/\s+/).filter(Boolean);
    const active = terms.length > 0 || state.status !== 'all';
    let visibleTotal = 0;

    document.querySelectorAll('#dashboard-live-board .service-cluster').forEach((cluster) => {
      let visibleInCluster = 0;
      cluster.querySelectorAll('.monitor-card').forEach((card) => {
        const haystack = String(card.dataset.search || '').toLowerCase();
        const visible = matchesStatus(card) && terms.every((term) => haystack.includes(term));
        card.hidden = !visible;
        if (visible) {
          visibleInCluster += 1;
        }
      });
      visibleTotal += visibleInCluster;
      cluster.hidden = active && visibleInCluster === 0;

      // Open matching groups while filtering, and close them again once the filter is cleared.
      if (active && visibleInCluster > 0 && !cluster.open) {
        cluster.open = true;
        cluster.dataset.filterOpened = '1';
      } else if (!active && cluster.dataset.filterOpened === '1') {
        cluster.open = false;
        delete cluster.dataset.filterOpened;
      }
    });

    if (emptyHint) {
      emptyHint.hidden = !active || visibleTotal > 0;
    }
    statusButtons.forEach((button) => {
      const selected = button.dataset.statusFilter === state.status;
      button.classList.toggle('button-secondary', !selected);
      button.setAttribute('aria-pressed', selected ? 'true' : 'false');
    });
  };

  searchInput.addEventListener('input', () => {
    state.query = searchInput.value.trim();
    persist();
    applyFilter();
  });
  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && searchInput.value) {
      searchInput.value = '';
      state.query = '';
      persist();
      applyFilter();
    }
  });
  statusButtons.forEach((button) => {
    button.addEventListener('click', () => {
      state.status = button.dataset.statusFilter || 'all';
      persist();
      applyFilter();
    });
  });

  // "/" focuses the search like in many web apps, unless the user is typing somewhere.
  document.addEventListener('keydown', (event) => {
    const target = event.target;
    const typing = target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
    if (event.key === '/' && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      searchInput.focus();
    }
  });

  document.addEventListener('goup:board-updated', applyFilter);

  const showToast = (message, isError) => {
    if (!message) {
      return;
    }
    const toast = document.createElement('div');
    toast.className = `board-toast ${isError ? 'board-toast-error' : ''}`;
    toast.setAttribute('role', isError ? 'alert' : 'status');
    toast.textContent = message;
    document.body.appendChild(toast);
    window.setTimeout(() => toast.remove(), isError ? 6000 : 2500);
  };

  // Runs after app.js's data-confirm handler, so a cancelled confirm arrives here as defaultPrevented.
  document.addEventListener('submit', async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.classList.contains('js-async-action') || event.defaultPrevented) {
      return;
    }
    event.preventDefault();

    const buttons = Array.from(form.querySelectorAll('button'));
    buttons.forEach((button) => {
      button.disabled = true;
    });
    try {
      const response = await fetch(form.action, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          Accept: 'application/json'
        },
        // Include the clicked button so multi-action forms (mute 1h/8h/24h) send their action.
        body: new URLSearchParams(new FormData(form, event.submitter || undefined)).toString()
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        showToast(payload.error || i18n.actionFailed || 'Action failed', true);
      } else {
        showToast(payload.notice, false);
      }
    } catch (_) {
      showToast(i18n.actionFailed || 'Action failed', true);
    } finally {
      buttons.forEach((button) => {
        button.disabled = false;
      });
      document.dispatchEvent(new CustomEvent('goup:refresh-board'));
    }
  });

  // Bulk selection: the selected ids live in a Set so they survive live re-renders of the cards.
  const bulkToggle = document.getElementById('bulk-toggle');
  const bulkBar = document.getElementById('bulk-bar');
  const bulkForm = document.getElementById('bulk-form');
  const bulkCount = document.getElementById('bulk-count');
  const board = document.getElementById('dashboard-live-board');
  const selected = new Set();
  let selecting = false;

  const syncBulkUI = () => {
    document.body.classList.toggle('bulk-selecting', selecting);
    document.querySelectorAll('#dashboard-live-board .bulk-select').forEach((checkbox) => {
      checkbox.checked = selected.has(checkbox.value);
    });
    if (bulkBar) {
      bulkBar.hidden = !selecting;
    }
    if (bulkCount) {
      bulkCount.textContent = String(i18n.bulkSelected || '{count} selected').replace('{count}', String(selected.size));
    }
    if (bulkForm) {
      bulkForm.querySelectorAll('button').forEach((button) => {
        button.disabled = selected.size === 0;
      });
    }
    if (bulkToggle) {
      bulkToggle.setAttribute('aria-pressed', selecting ? 'true' : 'false');
      bulkToggle.classList.toggle('button-secondary', !selecting);
    }
  };

  if (bulkToggle && bulkForm && board) {
    bulkToggle.addEventListener('click', () => {
      selecting = !selecting;
      if (!selecting) {
        selected.clear();
      }
      syncBulkUI();
    });
    board.addEventListener('change', (event) => {
      const checkbox = event.target;
      if (checkbox instanceof HTMLInputElement && checkbox.classList.contains('bulk-select')) {
        if (checkbox.checked) {
          selected.add(checkbox.value);
        } else {
          selected.delete(checkbox.value);
        }
        syncBulkUI();
      }
    });
    document.getElementById('bulk-select-visible')?.addEventListener('click', () => {
      document.querySelectorAll('#dashboard-live-board .monitor-card').forEach((card) => {
        if (!card.hidden && !card.closest('.service-cluster')?.hidden && card.dataset.monitorId) {
          selected.add(card.dataset.monitorId);
        }
      });
      syncBulkUI();
    });
    // Capture phase: runs before the async submit handler, so the ids are in place when it reads the form.
    bulkForm.addEventListener('submit', (event) => {
      if (event.submitter?.value === 'delete' && !window.confirm(bulkForm.dataset.confirmDelete || 'Delete?')) {
        event.preventDefault();
        return;
      }
      bulkForm.querySelectorAll('input[name="id"]').forEach((input) => input.remove());
      selected.forEach((id) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'id';
        input.value = id;
        bulkForm.appendChild(input);
      });
      if (event.submitter?.value === 'delete') {
        selected.clear();
      }
    }, true);
    document.addEventListener('goup:board-updated', syncBulkUI);
    syncBulkUI();
  }

  // The advanced section of the monitor modal: open it when a field inside fails validation
  // (the browser cannot focus fields in a closed <details>) or holds non-default values.
  const advanced = document.getElementById('monitor-advanced');
  if (advanced instanceof HTMLDetailsElement) {
    document.addEventListener('invalid', (event) => {
      if (advanced.contains(event.target)) {
        advanced.open = true;
      }
    }, true);
    document.addEventListener('click', (event) => {
      const trigger = event.target instanceof Element ? event.target.closest('.edit-monitor, #open-create-monitor') : null;
      if (!trigger) {
        return;
      }
      const data = trigger.dataset;
      const isEdit = trigger.classList.contains('edit-monitor');
      const certDays = isEdit ? Number(data.certWarningDays || 7) : 7;
      const certField = document.getElementById('monitor-cert-warning-days');
      if (certField) {
        certField.value = String(certDays);
      }
      const confirmAfter = isEdit ? Number(data.confirmAfter || 1) : 1;
      const confirmField = document.getElementById('monitor-confirm-after');
      if (confirmField) {
        confirmField.value = String(confirmAfter);
      }
      const remindEvery = isEdit ? Number(data.remindEvery || 0) : 0;
      const remindField = document.getElementById('monitor-remind-every');
      if (remindField) {
        remindField.value = String(remindEvery);
      }
      advanced.open = isEdit && (
        Number(data.retryCount || 0) > 0 ||
        confirmAfter > 1 ||
        remindEvery > 0 ||
        Number(data.timeout || 10) !== 10 ||
        data.notifyOnRecovery === '0' ||
        certDays !== 7
      );
    });
  }

  // Clone: open the edit dialog of the same card, then turn it into a new monitor.
  document.addEventListener('click', (event) => {
    const cloneButton = event.target instanceof Element ? event.target.closest('.clone-monitor') : null;
    const editButton = cloneButton?.closest('.action-menu-list')?.querySelector('.edit-monitor');
    if (!editButton) {
      return;
    }
    editButton.click();
    const idField = document.getElementById('monitor-id');
    const nameField = document.getElementById('monitor-name');
    const modalTitle = document.getElementById('monitor-modal-title');
    if (idField) {
      idField.value = '';
    }
    if (nameField) {
      nameField.value = `${nameField.value} ${i18n.copySuffix || '(copy)'}`.trim();
    }
    if (modalTitle) {
      modalTitle.textContent = i18n.cloneTitle || 'Clone monitor';
    }
  });

  applyFilter();
})();
