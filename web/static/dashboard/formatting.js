import { tr } from './i18n.js';
import { manualCheckInFlight } from './state.js';

export const formatters = {
  datetime: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' }),
  minute: new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }),
  hour: new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' }),
  date: new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }),
  month: new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' })
};

const languageTag = ((document.documentElement && document.documentElement.lang) || (navigator.languages && navigator.languages[0]) || navigator.language || 'en').toLowerCase();
const durationUnits = (() => {
  if (languageTag.startsWith('de')) {
    return { day: 'T', hour: 'Std.', minute: 'Min.', second: 'Sek.' };
  }
  if (languageTag.startsWith('fr')) {
    return { day: 'j', hour: 'h', minute: 'min', second: 's' };
  }
  if (languageTag.startsWith('es')) {
    return { day: 'd', hour: 'h', minute: 'min', second: 's' };
  }
  return { day: 'd', hour: 'h', minute: 'min.', second: 'sec.' };
})();
export const cycleLabels = {
  checking: tr('monitorCycleChecking', 'Checking…'),
  nextIn: tr('monitorCycleNextIn', 'Next check in')
};

const formatDurationCompact = (totalSeconds) => {
  const safeSeconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  if (safeSeconds < 60) {
    return `${safeSeconds} ${durationUnits.second}`;
  }

  const minutes = Math.floor(safeSeconds / 60);
  const seconds = safeSeconds % 60;
  if (safeSeconds < 3600) {
    if (seconds > 0) {
      return `${minutes} ${durationUnits.minute} ${seconds} ${durationUnits.second}`;
    }
    return `${minutes} ${durationUnits.minute}`;
  }

  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  if (safeSeconds < 86400) {
    if (remMinutes > 0) {
      return `${hours} ${durationUnits.hour} ${remMinutes} ${durationUnits.minute}`;
    }
    return `${hours} ${durationUnits.hour}`;
  }

  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  if (remMinutes > 0) {
    return `${days} ${durationUnits.day} ${remHours} ${durationUnits.hour} ${remMinutes} ${durationUnits.minute}`;
  }
  if (remHours > 0) {
    return `${days} ${durationUnits.day} ${remHours} ${durationUnits.hour}`;
  }
  return `${days} ${durationUnits.day}`;
};

export const formatElapsedCompact = (date) => {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return '—';
  }

  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  return formatDurationCompact(elapsedSeconds);
};

export const updateMonitorCycleIndicators = (root = document) => {
  root.querySelectorAll('.monitor-card').forEach((card) => {
    const indicator = card.querySelector('.monitor-cycle-indicator');
    if (!(indicator instanceof HTMLElement)) {
      return;
    }

    const monitorID = Number.parseInt(card.dataset.monitorId || '', 10);
    if (Number.isFinite(monitorID) && manualCheckInFlight.has(monitorID)) {
      indicator.classList.add('is-active');
      indicator.title = cycleLabels.checking;
      return;
    }

    const intervalSeconds = Number.parseInt(card.dataset.intervalSeconds || '', 10);
    const rawLastCheck = card.dataset.lastCheck || '';
    const lastCheckDate = new Date(rawLastCheck);
    const paused = card.classList.contains('status-PAUSED');
    const hasInterval = Number.isFinite(intervalSeconds) && intervalSeconds > 0;
    const hasLastCheck = !Number.isNaN(lastCheckDate.getTime());

    if (indicator instanceof HTMLButtonElement) {
      indicator.disabled = paused || !hasInterval;
    }

    if (paused || !hasInterval) {
      indicator.classList.remove('is-active');
      indicator.removeAttribute('title');
      return;
    }

    if (!hasLastCheck) {
      indicator.classList.remove('is-active');
      indicator.title = `${cycleLabels.nextIn} ${formatDurationCompact(intervalSeconds)}`;
      return;
    }

    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - lastCheckDate.getTime()) / 1000));
    const checkWindowSeconds = Math.min(8, Math.max(2, Math.floor(intervalSeconds * 0.15)));
    const isChecking = elapsedSeconds >= intervalSeconds && elapsedSeconds <= (intervalSeconds + checkWindowSeconds);
    indicator.classList.toggle('is-active', isChecking);

    if (isChecking) {
      indicator.title = cycleLabels.checking;
      return;
    }

    const secondsUntilNext = Math.max(0, intervalSeconds - elapsedSeconds);
    indicator.title = `${cycleLabels.nextIn} ${formatDurationCompact(secondsUntilNext)}`;
  });
};

export const formatClientTimes = (root = document) => {
  root.querySelectorAll('.client-time').forEach((element) => {
    const value = element.getAttribute('datetime');
    if (!value) {
      return;
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return;
    }
    const format = element.dataset.format || 'datetime';
    if (format === 'relative-age') {
      element.textContent = formatElapsedCompact(date);
      element.title = formatters.datetime.format(date);
      return;
    }
    const formatter = formatters[format] || formatters.datetime;
    element.textContent = formatter.format(date);
    element.title = date.toLocaleString();
  });
};

const formatTrendBars = (root = document) => {
  root.querySelectorAll('.trend-bar').forEach((element) => {
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
};

export const formatDateValue = (value, format = 'datetime') => {
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

export const formatLatency = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return '—';
  }
  if (numeric === 0) {
    return '0 ms';
  }
  if (numeric > 0 && numeric < 1) {
    return '<1 ms';
  }
  if (numeric < 1000) {
    return `${numeric} ms`;
  }
  return `${(numeric / 1000).toFixed(numeric % 1000 === 0 ? 0 : 2)} s`;
};

export function reformatLiveContent() {
  formatClientTimes(document);
  formatTrendBars(document);
  updateMonitorCycleIndicators(document);
}
