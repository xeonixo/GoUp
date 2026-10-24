// Mutable state shared between the dashboard modules (ES module bindings cannot be reassigned by importers).

export const S = {
  liveSnapshotInFlight: false,
  liveSocket: null,
  liveReconnectTimer: null,
  liveReconnectDelayMS: 1000,
  liveUpdatesEnabled: true,
  liveLastReloadAt: 0,
  livePendingParts: new Set(),
  livePendingBoardGroups: new Set(),
  stateEventsPage: 1,
  notificationEventsPage: 1
};

export const manualCheckInFlight = new Set();
