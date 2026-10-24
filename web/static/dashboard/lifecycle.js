import { hasOpenDialog } from './dom-utils.js';
import { formatClientTimes, updateMonitorCycleIndicators } from './formatting.js';
import { connectLiveUpdates } from './live.js';
import { applyLiveSnapshot } from './snapshot.js';
import { S } from './state.js';

const tickClientClock = () => {
  formatClientTimes(document);
  updateMonitorCycleIndicators(document);
};
// The 1s clock is paused while the page is hidden (saves battery in a
// home-screen app) and resumed on visibility change.
let clientClockTimer = null;
const startClientClock = () => {
  if (clientClockTimer === null) {
    clientClockTimer = window.setInterval(tickClientClock, 1000);
  }
};
const stopClientClock = () => {
  if (clientClockTimer !== null) {
    window.clearInterval(clientClockTimer);
    clientClockTimer = null;
  }
};

// Bring the dashboard back in sync after the app was suspended (iOS kills
// or silently stalls WebSockets in the background) or the network changed.
let hiddenSince = document.hidden ? Date.now() : 0;
let lastResumeAt = Date.now();
const resumeLiveUpdates = (force) => {
  if (!S.liveUpdatesEnabled || document.hidden) {
    return;
  }
  // visibilitychange, pageshow and focus often fire together: coalesce.
  if (force !== true && Date.now() - lastResumeAt < 1500) {
    return;
  }
  lastResumeAt = Date.now();
  tickClientClock();
  startClientClock();

  const OPEN = window.WebSocket ? window.WebSocket.OPEN : 1;
  const CONNECTING = window.WebSocket ? window.WebSocket.CONNECTING : 0;
  const longHidden = hiddenSince > 0 && Date.now() - hiddenSince > 30000;
  hiddenSince = 0;
  if (S.liveSocket && S.liveSocket.readyState === OPEN) {
    if (longHidden) {
      // A socket that survived a long suspension is usually dead without
      // having noticed; recycle it. The close handler reconnects.
      S.liveReconnectDelayMS = 250;
      try {
        S.liveSocket.close();
      } catch (_) {
      }
    }
  } else if (!S.liveSocket || S.liveSocket.readyState !== CONNECTING) {
    if (S.liveReconnectTimer !== null) {
      window.clearTimeout(S.liveReconnectTimer);
      S.liveReconnectTimer = null;
    }
    if (!S.liveSocket) {
      S.liveReconnectDelayMS = 1000;
      connectLiveUpdates();
    }
  }
  refreshDashboardSnapshot();
};

const refreshDashboardSnapshot = () => {
  if (!S.liveUpdatesEnabled || S.liveSnapshotInFlight || hasOpenDialog()) {
    return;
  }
  S.liveSnapshotInFlight = true;
  Promise.resolve(applyLiveSnapshot([])).catch(() => {
  }).then(() => {
    S.liveSnapshotInFlight = false;
    S.liveLastReloadAt = Date.now();
  });
};

export function initLifecycle() {
  if (!document.hidden) {
    startClientClock();
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      hiddenSince = Date.now();
      stopClientClock();
      return;
    }
    resumeLiveUpdates(false);
  });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      // Restored from the back/forward cache: beforeunload had disabled us.
      S.liveUpdatesEnabled = true;
      hiddenSince = Date.now() - 60000;
      resumeLiveUpdates(true);
    }
  });
  window.addEventListener('online', () => resumeLiveUpdates(true));
  window.addEventListener('focus', () => resumeLiveUpdates(false));

  // Topbar refresh button (app.js dispatches "goup:refresh").
  window.addEventListener('goup:refresh', (event) => {
    event.preventDefault();
    hiddenSince = 0;
    if (S.liveSocket && S.liveSocket.readyState === (window.WebSocket ? window.WebSocket.OPEN : 1)) {
      refreshDashboardSnapshot();
    } else {
      resumeLiveUpdates(true);
    }
  });
}
