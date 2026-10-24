// Heartbeat (push) monitors: form rows, grace period and the ping URL block of the monitor modal.

const byId = (id) => document.getElementById(id);

const intervalField = byId('monitor-interval');
const intervalLabel = byId('monitor-interval-label');
const graceRow = byId('heartbeat-grace-row');
const graceField = byId('monitor-heartbeat-grace');
const infoRow = byId('heartbeat-info-row');
const pendingRow = byId('heartbeat-pending-row');
const urlField = byId('monitor-heartbeat-url');
const curlField = byId('monitor-heartbeat-curl');
const curlFailField = byId('monitor-heartbeat-curl-fail');
const regenerateButton = byId('monitor-heartbeat-regenerate');
const hintField = byId('monitor-heartbeat-hint');
const timeoutRow = byId('monitor-timeout')?.closest('label');
const certWarningRow = byId('monitor-cert-warning-days')?.closest('label');
const executorRow = byId('monitor-executor-row');
const executorField = byId('monitor-executor');

const defaultGraceSeconds = '300';
const minHeartbeatPeriodSeconds = '60';

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

// Shows or hides everything that only applies to heartbeat monitors; called by applyKindRules.
export const syncHeartbeatRows = (isHeartbeat) => {
  if (graceRow) graceRow.hidden = !isHeartbeat;
  if (graceField) graceField.required = isHeartbeat;
  if (hintField) hintField.hidden = !isHeartbeat;
  if (timeoutRow) timeoutRow.hidden = isHeartbeat;
  if (certWarningRow) certWarningRow.hidden = isHeartbeat;
  if (executorRow) executorRow.hidden = isHeartbeat;
  if (isHeartbeat && executorField) executorField.value = 'local';
  if (intervalLabel) {
    intervalLabel.textContent = isHeartbeat
      ? (intervalLabel.dataset.heartbeatText || intervalLabel.textContent)
      : (intervalLabel.dataset.defaultText || intervalLabel.textContent);
  }
  if (intervalField) {
    intervalField.min = isHeartbeat ? minHeartbeatPeriodSeconds : '15';
  }
  const hasURL = Boolean(urlField?.value);
  if (infoRow) infoRow.hidden = !isHeartbeat || !hasURL;
  if (pendingRow) pendingRow.hidden = !isHeartbeat || hasURL;
};

// Fills the URL block for the monitor being edited (url is empty for new monitors and clones).
export const fillHeartbeat = (button) => {
  const url = String(button?.dataset?.heartbeatUrl || '');
  const isHeartbeat = (button?.dataset?.kind || '') === 'heartbeat';
  if (graceField) {
    graceField.value = isHeartbeat ? (button.dataset.timeout || defaultGraceSeconds) : defaultGraceSeconds;
  }
  showHeartbeatURL(isHeartbeat ? url : '');
};

export const resetHeartbeat = () => {
  if (graceField) graceField.value = defaultGraceSeconds;
  showHeartbeatURL('');
};

const showHeartbeatURL = (url) => {
  if (urlField) urlField.value = url;
  if (curlField) curlField.value = url ? `curl -fsS -m 10 --retry 3 ${shellQuote(url)}` : '';
  if (curlFailField) curlFailField.value = url ? `curl -fsS -m 10 --retry 3 --data-raw 'error message' ${shellQuote(`${url}/fail`)}` : '';
};

export const initHeartbeatForm = () => {
  regenerateButton?.addEventListener('click', (event) => {
    if (!window.confirm(regenerateButton.dataset.confirm || 'Generate a new URL?')) {
      event.preventDefault();
    }
  });
};
