// WebSocket live connection and throttled snapshot reloads.

import { appBase, currentTrend } from './config.js';
import { hasOpenDialog } from './dom-utils.js';
import { liveConnectionIndicator, topbarElement, topbarHamburgerButton } from './dom.js';
import { tr } from './i18n.js';
import { applyLiveSnapshot } from './snapshot.js';
import { S } from './state.js';

let liveReloadTimer = null;

const setLiveConnectionState = (state) => {
  if (!(liveConnectionIndicator instanceof HTMLElement)) {
    return;
  }
  liveConnectionIndicator.classList.remove('is-connected', 'is-connecting', 'is-disconnected');

  let label = tr('liveDisconnected', 'Live connection disconnected');
  if (state === 'connected') {
    liveConnectionIndicator.classList.add('is-connected');
    label = tr('liveConnected', 'Live connection active');
  } else if (state === 'connecting') {
    liveConnectionIndicator.classList.add('is-connecting');
    label = tr('liveConnecting', 'Live connection is being established');
  } else {
    liveConnectionIndicator.classList.add('is-disconnected');
  }

  liveConnectionIndicator.setAttribute('aria-label', label);
  liveConnectionIndicator.setAttribute('title', label);
};

export const scheduleLiveReload = () => {
  if (!S.liveUpdatesEnabled) {
    return;
  }
  if (liveReloadTimer !== null) {
    return;
  }
  liveReloadTimer = window.setTimeout(() => {
    liveReloadTimer = null;
    if (!S.liveUpdatesEnabled) {
      return;
    }
    if (hasOpenDialog()) {
      scheduleLiveReload();
      return;
    }

    const now = Date.now();
    if (now - S.liveLastReloadAt < 2000) {
      scheduleLiveReload();
      return;
    }

    if (!S.liveSnapshotInFlight) {
      S.liveSnapshotInFlight = true;
      const requestedParts = Array.from(S.livePendingParts);
      const requestedBoardGroups = Array.from(S.livePendingBoardGroups);
      S.livePendingParts = new Set();
      S.livePendingBoardGroups = new Set();
      applyLiveSnapshot(requestedParts, requestedBoardGroups).then(() => {
        S.liveSnapshotInFlight = false;
        S.liveLastReloadAt = Date.now();
        if (S.livePendingParts.size > 0 || S.livePendingBoardGroups.size > 0) {
          scheduleLiveReload();
        }
      }).catch(() => {
        S.liveSnapshotInFlight = false;
        requestedParts.forEach((part) => S.livePendingParts.add(part));
        requestedBoardGroups.forEach((groupName) => S.livePendingBoardGroups.add(groupName));
        scheduleLiveReload();
      });
      return;
    }

    scheduleLiveReload();
  }, 500);
};

const queueLiveReconnect = () => {
  if (!S.liveUpdatesEnabled || S.liveReconnectTimer !== null) {
    return;
  }
  const delay = S.liveReconnectDelayMS;
  S.liveReconnectTimer = window.setTimeout(() => {
    S.liveReconnectTimer = null;
    connectLiveUpdates();
  }, delay);
  S.liveReconnectDelayMS = Math.min(S.liveReconnectDelayMS * 2, 15000);
};

export const connectLiveUpdates = () => {
  if (!S.liveUpdatesEnabled || typeof window.WebSocket !== 'function') {
    setLiveConnectionState('disconnected');
    return;
  }
  setLiveConnectionState('connecting');
  const wsURL = new URL(`${appBase}live?trend=${encodeURIComponent(currentTrend)}`, window.location.href);
  wsURL.protocol = wsURL.protocol === 'https:' ? 'wss:' : 'ws:';
  let wasConnected = false;

  try {
    S.liveSocket = new window.WebSocket(wsURL.toString());
  } catch (_) {
    setLiveConnectionState('disconnected');
    queueLiveReconnect();
    return;
  }

  S.liveSocket.addEventListener('open', () => {
    wasConnected = true;
    setLiveConnectionState('connected');
    S.liveReconnectDelayMS = 1000;
  });

  S.liveSocket.addEventListener('message', (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload?.type === 'session_expired') {
        S.liveUpdatesEnabled = false;
        window.location.href = `${appBase}login`;
        return;
      }
      if (payload?.type === 'refresh') {
        const parts = Array.isArray(payload.parts) ? payload.parts : [];
        if (parts.length > 0) {
          parts.forEach((part) => {
            if (typeof part === 'string' && part.trim() !== '') {
              S.livePendingParts.add(part.trim());
            }
          });
        } else {
          ['stats', 'board', 'state_events', 'notification_events', 'group_options'].forEach((part) => S.livePendingParts.add(part));
        }
        const boardGroups = Array.isArray(payload.board_groups) ? payload.board_groups : [];
        boardGroups.forEach((groupName) => {
          if (typeof groupName === 'string' && groupName.trim() !== '') {
            S.livePendingBoardGroups.add(groupName.trim());
          }
        });
        scheduleLiveReload();
      }
    } catch (_) {
    }
  });

  S.liveSocket.addEventListener('error', () => {
    setLiveConnectionState('disconnected');
    try {
      S.liveSocket?.close();
    } catch (_) {
    }
  });

  S.liveSocket.addEventListener('close', () => {
    setLiveConnectionState('disconnected');
    S.liveSocket = null;
    S.liveSnapshotInFlight = false;
    if (!wasConnected) {
      window.fetch(window.location.href, { redirect: 'follow', credentials: 'include' })
        .then((resp) => {
          if (resp.url && resp.url.includes('/login')) {
            S.liveUpdatesEnabled = false;
            window.location.href = resp.url;
          } else {
            queueLiveReconnect();
          }
        })
        .catch(() => queueLiveReconnect());
      return;
    }
    queueLiveReconnect();
  });
};

export function initLive() {
  if (liveConnectionIndicator instanceof HTMLElement && topbarElement instanceof HTMLElement && topbarHamburgerButton instanceof HTMLElement) {
    liveConnectionIndicator.classList.add('topbar-live-right');
    topbarElement.insertBefore(liveConnectionIndicator, topbarHamburgerButton);
  }

  window.addEventListener('beforeunload', () => {
    S.liveUpdatesEnabled = false;
    setLiveConnectionState('disconnected');
    if (S.liveReconnectTimer !== null) {
      window.clearTimeout(S.liveReconnectTimer);
      S.liveReconnectTimer = null;
    }
    if (liveReloadTimer !== null) {
      window.clearTimeout(liveReloadTimer);
      liveReloadTimer = null;
    }
    if (S.liveSocket) {
      try {
        S.liveSocket.close();
      } catch (_) {
      }
      S.liveSocket = null;
    }
  });

  connectLiveUpdates();
}
