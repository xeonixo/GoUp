import { patchBoardGroups, patchBoardSection } from './board-patch.js';
import { appBase, currentTrend } from './config.js';
import { bindDynamicDashboardListeners } from './dashboard-listeners.js';
import { applySafeGroupOptionsHTML, replaceSectionByID } from './dom-patch.js';
import { hasOpenDialog } from './dom-utils.js';
import { reformatLiveContent } from './formatting.js';
import { applyKindRules } from './monitor-kind-rules.js';
import { S } from './state.js';
import {
  currentOpenActionMenus, currentOpenGroups, restoreOpenActionMenus, restoreOpenGroups
} from './ui-state.js';

const liveSnapshotHashes = {
  stats: '',
  board: '',
  stateEvents: '',
  notificationEvents: '',
  groupOptions: ''
};

// App icon badge (installed PWA): number of monitors that are currently down. The push
// handler in sw.js sets the same number while the app is closed.
const updateAppBadge = () => {
  if (typeof navigator.setAppBadge !== 'function') {
    return;
  }
  try {
    const downIDs = new Set();
    document.querySelectorAll('.monitor-card[data-status="status-DOWN"]').forEach((card) => {
      downIDs.add(card.getAttribute('data-monitor-id') || String(downIDs.size));
    });
    const result = downIDs.size > 0
      ? navigator.setAppBadge(downIDs.size)
      : (typeof navigator.clearAppBadge === 'function' ? navigator.clearAppBadge() : null);
    if (result && typeof result.catch === 'function') {
      result.catch(() => {});
    }
  } catch (_) {
  }
};

export async function applyLiveSnapshot(requestedParts = [], requestedBoardGroups = []) {
  if (hasOpenDialog()) {
    return false;
  }

  const openGroupsBeforeUpdate = currentOpenGroups();
  const openActionMenusBeforeUpdate = currentOpenActionMenus();

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
    S.stateEventsPage = 1;
  }
  if (typeof payload.notification_events_hash === 'string' && payload.notification_events_hash !== liveSnapshotHashes.notificationEvents) {
    updates.push(replaceSectionByID('dashboard-live-notification-events', payload.notification_events_html));
    liveSnapshotHashes.notificationEvents = payload.notification_events_hash;
    S.notificationEventsPage = 1;
  }

  const groupOptions = document.getElementById('monitor-group-options');
  if (groupOptions && typeof payload.group_options_html === 'string' && typeof payload.group_options_hash === 'string' && payload.group_options_hash !== liveSnapshotHashes.groupOptions) {
    if (applySafeGroupOptionsHTML(groupOptions, payload.group_options_html)) {
      liveSnapshotHashes.groupOptions = payload.group_options_hash;
    }
  }

  const changed = updates.some(Boolean);
  updateAppBadge();

  if (!changed) {
    return false;
  }

  bindDynamicDashboardListeners();
  reformatLiveContent();

  if (boardReplaced) {
    restoreOpenGroups(openGroupsBeforeUpdate);
    restoreOpenActionMenus(openActionMenusBeforeUpdate);
  }

  applyKindRules();
  document.dispatchEvent(new CustomEvent('goup:board-updated'));
  return true;
}

export function initSnapshot() {
  window.setTimeout(updateAppBadge, 0);

  // dashboard-board.js asks for a refresh after actions it performed via fetch.
  document.addEventListener('goup:refresh-board', () => {
    applyLiveSnapshot([]);
  });
}
