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
        body: new URLSearchParams(new FormData(form)).toString()
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
      advanced.open = trigger.classList.contains('edit-monitor') && (
        Number(data.retryCount || 0) > 0 ||
        Number(data.timeout || 10) !== 10 ||
        data.notifyOnRecovery === '0'
      );
    });
  }

  applyFilter();
})();
