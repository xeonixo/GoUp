import { page } from './dom.js';
import { initLive } from './live.js';
import { initGroupDialog } from './group-icon.js';
import { initMonitorForm } from './monitor-form-events.js';
import {
  bindDynamicDashboardListeners, bindGlobalDashboardListeners
} from './dashboard-listeners.js';
import { restoreDashboardState } from './ui-state.js';
import { initSnapshot } from './snapshot.js';
import { reformatLiveContent } from './formatting.js';
import { initLifecycle } from './lifecycle.js';
import { initTrendDetail } from './trend-detail.js';

if (page instanceof HTMLElement) {
  initLive();
  initGroupDialog();
  initMonitorForm();
  bindGlobalDashboardListeners();
  restoreDashboardState();
  initSnapshot();
  reformatLiveContent();
  initLifecycle();
  initTrendDetail();
  bindDynamicDashboardListeners();
}
