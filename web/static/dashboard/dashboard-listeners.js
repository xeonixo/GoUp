import { appBase, isAdmin } from './config.js';
import { closeActionMenus } from './dom-utils.js';
import { bindDragDrop } from './drag-drop.js';
import {
  applyNotificationEventPagination, applyStateEventFilters, bindNotificationEventListeners,
  bindStateEventListeners
} from './events-table.js';
import { cycleLabels, updateMonitorCycleIndicators } from './formatting.js';
import { openGroupDialog } from './group-icon.js';
import { scheduleLiveReload } from './live.js';
import { openEdit } from './monitor-dialog.js';
import { postForm } from './requests.js';
import { S, manualCheckInFlight } from './state.js';
import { openTrendDetail } from './trend-detail.js';
import { saveDashboardState } from './ui-state.js';

let globalDashboardListenersBound = false;
export const bindGlobalDashboardListeners = () => {
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

export const bindDynamicDashboardListeners = () => {
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

  document.querySelectorAll('.monitor-cycle-trigger').forEach((button) => {
    if (button.dataset.boundCycleTrigger === '1') {
      return;
    }
    button.dataset.boundCycleTrigger = '1';
    button.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (!(button instanceof HTMLButtonElement)) {
        return;
      }
      const monitorID = Number.parseInt(button.dataset.checkMonitorId || '', 10);
      if (!Number.isFinite(monitorID) || monitorID <= 0) {
        return;
      }
      if (manualCheckInFlight.has(monitorID)) {
        return;
      }

      manualCheckInFlight.add(monitorID);
      button.classList.add('is-active');
      button.disabled = true;
      button.title = cycleLabels.checking;

      try {
        const response = await postForm(`${appBase}monitors/check-now`, { id: monitorID });
        if (!response.ok) {
          throw new Error(`manual check failed with HTTP ${response.status}`);
        }
        const payload = await response.json().catch(() => ({}));
        if (!payload || payload.ok !== true) {
          throw new Error('manual check response invalid');
        }

        S.livePendingParts.add('stats');
        S.livePendingParts.add('board');
        S.livePendingParts.add('state_events');
        scheduleLiveReload();
      } catch (error) {
        console.error('manual monitor check failed', error);
      } finally {
        manualCheckInFlight.delete(monitorID);
        button.disabled = false;
        updateMonitorCycleIndicators(document);
      }
    });
  });

  if (isAdmin) {
    bindDragDrop();
  }

  bindStateEventListeners();
  applyStateEventFilters();
  bindNotificationEventListeners();
  applyNotificationEventPagination();
};
