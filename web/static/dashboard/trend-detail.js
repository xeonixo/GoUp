import { appBase, currentTrend } from './config.js';
import { bindDialogBackdropClose } from './dom-utils.js';
import {
  trendDetailBars, trendDetailChecks, trendDetailClose, trendDetailHistory,
  trendDetailHistorySummary, trendDetailHistoryTitle, trendDetailLastCheck, trendDetailLatency,
  trendDetailLatencyCaption, trendDetailLatencyChart, trendDetailLatencyPlot,
  trendDetailLatencyRangeButtons, trendDetailLatencyTooltip, trendDetailLatencyXEnd,
  trendDetailLatencyXStart, trendDetailLatencyYMax, trendDetailLatencyYMid, trendDetailLatencyYMin,
  trendDetailModal, trendDetailRangeTitle, trendDetailStatus, trendDetailSubtitle,
  trendDetailTarget, trendDetailTitle, trendDetailUptime
} from './dom.js';
import { formatDateValue, formatElapsedCompact, formatLatency, formatters } from './formatting.js';
import { entriesLabelFallback, tr } from './i18n.js';
import { hideLatencyTooltip, renderLatencyChart } from './latency-chart.js';
import {
  buildLatencyTimelineSlots, latencyRangeLabels, normalizeLatencyRange,
  setLatencyRangeButtonsState
} from './latency-timeline.js';

const renderTrendHistoryFromLatency = (points, rangeValue) => {
  if (!trendDetailHistory) {
    return;
  }
  const historyTitleFallback = String(trendDetailHistoryTitle?.textContent || '').trim() || 'History';
  const timeline = buildLatencyTimelineSlots(points, rangeValue);
  const selectedRange = timeline.selectedRange;
  const rows = timeline.slots
    .filter((slot) => slot.totalChecks > 0)
    .reverse();

  trendDetailHistory.innerHTML = '';
  if (trendDetailHistoryTitle) {
    trendDetailHistoryTitle.textContent = `${tr('trendHistoryTitle', historyTitleFallback)} ${latencyRangeLabels[selectedRange] || selectedRange}`.trim();
  }
  if (trendDetailHistorySummary) {
    trendDetailHistorySummary.textContent = rows.length > 0
      ? `${rows.length} ${tr('paginationEntries', entriesLabelFallback)}`
      : tr('trendNoData', 'No data');
  }

  if (rows.length === 0) {
    const row = document.createElement('tr');
    const empty = document.createElement('td');
    empty.colSpan = 2;
    empty.className = 'muted';
    empty.textContent = tr('trendNoData', 'No data');
    row.appendChild(empty);
    trendDetailHistory.appendChild(row);
    return;
  }

  rows.forEach((slot) => {
    const row = document.createElement('tr');
    const when = document.createElement('td');
    when.textContent = formatDateValue(new Date(slot.startMS).toISOString(), timeline.config.format || 'hour');

    const result = document.createElement('td');
    const percent = slot.totalChecks > 0 ? (Math.floor((slot.upChecks * 10000) / slot.totalChecks) / 100).toFixed(2) : '0.00';
    const badge = document.createElement('span');
    badge.className = `history-status-badge status-${String(slot.status || 'unknown').toUpperCase()}`;
    badge.textContent = String(slot.status || 'unknown').toUpperCase();
    const text = document.createElement('span');
    const latencyText = slot.latencyChecks > 0
      ? ` · Ø ${formatLatency(slot.latencyMS)} · ${formatLatency(slot.latencyMinMS)}-${formatLatency(slot.latencyMaxMS)}`
      : '';
    text.textContent = `${percent}% · ${slot.totalChecks} Checks${latencyText}`;
    result.appendChild(badge);
    result.appendChild(text);
    row.appendChild(when);
    row.appendChild(result);
    trendDetailHistory.appendChild(row);
  });
};

const loadTrendLatencyRange = async (monitorID, rangeValue = '1h') => {
  if (!trendDetailLatencyChart || !trendDetailLatencyCaption) {
    return;
  }
  const selectedRange = normalizeLatencyRange(rangeValue);

  if (!Number.isFinite(monitorID) || monitorID <= 0) {
    trendDetailLatencyChart.hidden = false;
    if (trendDetailLatencyPlot) {
      trendDetailLatencyPlot.innerHTML = '';
      if (trendDetailLatencyTooltip) {
        trendDetailLatencyPlot.appendChild(trendDetailLatencyTooltip);
      }
    }
    hideLatencyTooltip();
    if (trendDetailLatencyYMax) {
      trendDetailLatencyYMax.textContent = '—';
    }
    if (trendDetailLatencyYMid) {
      trendDetailLatencyYMid.textContent = '—';
    }
    if (trendDetailLatencyYMin) {
      trendDetailLatencyYMin.textContent = '0 ms';
    }
    if (trendDetailLatencyXStart) {
      trendDetailLatencyXStart.textContent = '—';
    }
    if (trendDetailLatencyXEnd) {
      trendDetailLatencyXEnd.textContent = '—';
    }
    setLatencyRangeButtonsState(selectedRange, true);
    trendDetailLatencyCaption.textContent = tr('trendLatencySingleOnly', 'Latency chart is only available for individual monitors.');
    return;
  }

  trendDetailLatencyChart.hidden = false;
  trendDetailLatencyChart.classList.add('is-loading');
  trendDetailLatencyChart.setAttribute('aria-busy', 'true');
  setLatencyRangeButtonsState(selectedRange, true);
  trendDetailLatencyCaption.textContent = tr('trendLatencyLoading', 'Loading latency ({range}) …', {
    range: latencyRangeLabels[selectedRange] || '1h'
  });

  try {
    const response = await fetch(`${appBase}monitors/latency-history?monitor_id=${encodeURIComponent(String(monitorID))}&range=${encodeURIComponent(selectedRange)}`, {
      method: 'GET',
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    const payloadRange = normalizeLatencyRange(payload?.range || selectedRange);
    const points = payload?.points || [];
    renderLatencyChart(points, payload?.average_ms, payloadRange);
    renderTrendHistoryFromLatency(points, payloadRange);
    setLatencyRangeButtonsState(payloadRange, false);
  } catch (_) {
    if (trendDetailLatencyPlot) {
      trendDetailLatencyPlot.innerHTML = '';
      if (trendDetailLatencyTooltip) {
        trendDetailLatencyPlot.appendChild(trendDetailLatencyTooltip);
      }
    }
    hideLatencyTooltip();
    trendDetailLatencyCaption.textContent = tr('trendLatencyLoadFailed', 'Could not load latency chart.');
    setLatencyRangeButtonsState(selectedRange, false);
  } finally {
    trendDetailLatencyChart.classList.remove('is-loading');
    trendDetailLatencyChart.removeAttribute('aria-busy');
  }
};

export const openTrendDetail = (trigger) => {
  if (!trendDetailTitle || !trendDetailSubtitle || !trendDetailStatus || !trendDetailUptime || !trendDetailLastCheck || !trendDetailTarget || !trendDetailRangeTitle || !trendDetailLatency || !trendDetailChecks || !trendDetailBars || !trendDetailHistory || !trendDetailModal) {
    return;
  }
  const monitorID = Number.parseInt(trigger.dataset.monitorId || '', 10);
  const bars = Array.from(trigger.querySelectorAll('.trend-bar'));
  const barsDescending = [...bars].reverse();
  trendDetailTitle.textContent = trigger.dataset.monitorName || tr('trendTitleFallback', 'Trend details');
  trendDetailSubtitle.textContent = `${trigger.dataset.monitorKind || ''} · ${trigger.dataset.lastMessage || tr('trendNoDetailMessage', 'No detail message')}`;
  trendDetailStatus.textContent = trigger.dataset.status || tr('statusUnknown', 'Unknown');
  trendDetailUptime.textContent = trigger.dataset.uptime || '—';
  const lastCheckDate = new Date(trigger.dataset.lastCheck || '');
  if (Number.isNaN(lastCheckDate.getTime())) {
    trendDetailLastCheck.textContent = '—';
    trendDetailLastCheck.removeAttribute('title');
  } else {
    trendDetailLastCheck.textContent = formatElapsedCompact(lastCheckDate);
    trendDetailLastCheck.setAttribute('title', formatters.datetime.format(lastCheckDate));
  }
  trendDetailTarget.textContent = trigger.dataset.target || '—';
  trendDetailRangeTitle.textContent = `Verlauf ${trigger.dataset.trendLabel || ''}`.trim();

  const barsWithChecks = bars.filter((bar) => Number(bar.dataset.checks || '0') > 0);
  const totalChecks = barsWithChecks.reduce((sum, bar) => sum + Number(bar.dataset.checks || '0'), 0);
  const barsWithLatency = bars.filter((bar) => Number(bar.dataset.latencyChecks || '0') > 0);
  const totalLatencyChecks = barsWithLatency.reduce((sum, bar) => sum + Number(bar.dataset.latencyChecks || '0'), 0);
  const weightedLatency = barsWithLatency.reduce((sum, bar) => sum + (Number(bar.dataset.avgMs || '0') * Number(bar.dataset.latencyChecks || '0')), 0);
  const minLatency = barsWithLatency.reduce((min, bar) => {
    const value = Number(bar.dataset.minMs || '0');
    return min === 0 || (value >= 0 && value < min) ? value : min;
  }, 0);
  const maxLatency = barsWithLatency.reduce((max, bar) => {
    const value = Number(bar.dataset.maxMs || '0');
    return value > max ? value : max;
  }, 0);
  const avgLatency = totalLatencyChecks > 0 ? Math.round(weightedLatency / totalLatencyChecks) : null;
  trendDetailLatency.textContent = totalLatencyChecks > 0
    ? `${formatLatency(avgLatency)} / ${formatLatency(minLatency)} / ${formatLatency(maxLatency)}`
    : '— / — / —';
  trendDetailChecks.textContent = totalChecks > 0 ? String(totalChecks) : '—';

  trendDetailBars.innerHTML = '';
  trendDetailHistory.innerHTML = '';

  if (trendDetailLatencyPlot) {
    trendDetailLatencyPlot.innerHTML = '';
  }
  if (trendDetailLatencyCaption) {
    trendDetailLatencyCaption.textContent = '—';
  }
  if (trendDetailLatencyChart) {
    trendDetailLatencyChart.hidden = false;
  }
  trendDetailLatencyRangeButtons.forEach((button) => {
    button.dataset.monitorId = Number.isFinite(monitorID) ? String(monitorID) : '';
  });
  const initialLatencyRange = normalizeLatencyRange(currentTrend);
  setLatencyRangeButtonsState(initialLatencyRange, false);

  bars.forEach((bar) => {
    const clone = document.createElement('span');
    clone.className = bar.className;
    clone.title = bar.title;
    trendDetailBars.appendChild(clone);
  });

  barsDescending.forEach((bar) => {
    const row = document.createElement('tr');
    const when = document.createElement('td');
    when.textContent = formatDateValue(bar.dataset.bucket, bar.dataset.format || 'hour');
    const result = document.createElement('td');
    const latencyChecks = Number(bar.dataset.latencyChecks || '0');
    if (latencyChecks > 0) {
      result.textContent = `${bar.dataset.label || '—'} · Ø ${formatLatency(bar.dataset.avgMs)} · Min ${formatLatency(bar.dataset.minMs)} · Max ${formatLatency(bar.dataset.maxMs)}`;
    } else {
      result.textContent = bar.dataset.label || tr('trendNoData', 'No data');
    }
    row.appendChild(when);
    row.appendChild(result);
    trendDetailHistory.appendChild(row);
  });

  trendDetailModal.showModal();
  loadTrendLatencyRange(monitorID, initialLatencyRange);
};

export function initTrendDetail() {
  bindDialogBackdropClose(trendDetailModal);

  trendDetailClose?.addEventListener('click', () => trendDetailModal?.close());
  trendDetailLatencyRangeButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const monitorID = Number.parseInt(button.dataset.monitorId || '', 10);
      const rangeValue = normalizeLatencyRange(button.dataset.range || '1h');
      loadTrendLatencyRange(monitorID, rangeValue);
    });
  });
}
