import {
  trendDetailLatencyCaption, trendDetailLatencyPlot, trendDetailLatencyTooltip,
  trendDetailLatencyXEnd, trendDetailLatencyXStart, trendDetailLatencyYMax, trendDetailLatencyYMid,
  trendDetailLatencyYMin
} from './dom.js';
import { formatDateValue, formatLatency } from './formatting.js';
import { tr } from './i18n.js';
import { buildLatencyTimelineSlots, latencyRangeLabels } from './latency-timeline.js';

const formatLatencyAxis = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return '0 ms';
  }
  return `${Math.round(numeric)} ms`;
};

export const hideLatencyTooltip = () => {
  if (!trendDetailLatencyTooltip) {
    return;
  }
  trendDetailLatencyTooltip.hidden = true;
  trendDetailLatencyTooltip.textContent = '';
};

const showLatencyTooltip = (event, text) => {
  if (!trendDetailLatencyTooltip || !trendDetailLatencyPlot) {
    return;
  }
  if (!text) {
    hideLatencyTooltip();
    return;
  }
  trendDetailLatencyTooltip.hidden = false;
  trendDetailLatencyTooltip.textContent = text;

  const plotRect = trendDetailLatencyPlot.getBoundingClientRect();
  const pointerX = event.clientX - plotRect.left;
  const pointerY = event.clientY - plotRect.top;
  const tooltipWidth = trendDetailLatencyTooltip.offsetWidth || 140;
  const tooltipHeight = trendDetailLatencyTooltip.offsetHeight || 20;

  const left = Math.max(6, Math.min(plotRect.width - tooltipWidth - 6, pointerX + 10));
  const top = Math.max(6, Math.min(plotRect.height - tooltipHeight - 6, pointerY - tooltipHeight - 10));

  trendDetailLatencyTooltip.style.left = `${left}px`;
  trendDetailLatencyTooltip.style.top = `${top}px`;
};

const bindLatencySlotTooltip = (element, text, highlightElement = null, highlightClass = 'is-hovered') => {
  if (!(element instanceof HTMLElement)) {
    return;
  }

  const activate = (event) => {
    if (highlightElement instanceof HTMLElement) {
      highlightElement.classList.add(highlightClass);
    }
    if (event instanceof MouseEvent) {
      showLatencyTooltip(event, text);
    }
  };

  const deactivate = () => {
    if (highlightElement instanceof HTMLElement) {
      highlightElement.classList.remove(highlightClass);
    }
    hideLatencyTooltip();
  };

  element.addEventListener('mouseenter', (event) => {
    activate(event);
  });
  element.addEventListener('mousemove', (event) => {
    activate(event);
  });
  element.addEventListener('mouseleave', deactivate);
  element.addEventListener('blur', deactivate);
};

export const renderLatencyChart = (points, averageMS, rangeValue) => {
  if (!trendDetailLatencyPlot || !trendDetailLatencyCaption || !trendDetailLatencyYMax || !trendDetailLatencyYMid || !trendDetailLatencyYMin || !trendDetailLatencyXStart || !trendDetailLatencyXEnd) {
    return;
  }

  const timeline = buildLatencyTimelineSlots(points, rangeValue);
  const slots = timeline.slots;
  const selectedRange = timeline.selectedRange;
  const slotsWithValues = slots.filter((slot) => slot.hasValue);
  const downSlots = slots.filter((slot) => slot.hasStatus && slot.status === 'down');
  const rawLatencyValues = Array.isArray(points)
    ? points
      .filter((point) => String(point?.status || '').trim().toLowerCase() !== 'down')
      .map((point) => Number(point?.latency_ms || 0))
      .filter((value) => Number.isFinite(value) && value >= 0)
    : [];

  hideLatencyTooltip();
  if (trendDetailLatencyTooltip) {
    trendDetailLatencyPlot.innerHTML = '';
    trendDetailLatencyPlot.appendChild(trendDetailLatencyTooltip);
  } else {
    trendDetailLatencyPlot.innerHTML = '';
  }

  const maxLatency = slotsWithValues.reduce((max, slot) => {
    return slot.latencyMS > max ? slot.latencyMS : max;
  }, 0);
  const safeMax = Math.max(maxLatency, Number(averageMS) || 0, 1);

  trendDetailLatencyYMax.textContent = formatLatencyAxis(safeMax);
  trendDetailLatencyYMid.textContent = formatLatencyAxis(Math.round(safeMax / 2));
  trendDetailLatencyYMin.textContent = '0 ms';
  trendDetailLatencyXStart.textContent = formatDateValue(timeline.startDate.toISOString(), timeline.config.format || 'minute');
  trendDetailLatencyXEnd.textContent = formatDateValue(timeline.endDate.toISOString(), timeline.config.format || 'minute');

  if (slotsWithValues.length === 0 && downSlots.length === 0) {
    trendDetailLatencyCaption.textContent = tr('trendLatencyNoValues', 'No latency values available for {range}.', {
      range: latencyRangeLabels[selectedRange] || '1h'
    });
    return;
  }

  const bars = document.createElement('div');
  bars.className = 'latency-bars';

  slots.forEach((slot) => {
    const item = document.createElement('span');
    item.className = 'latency-slot';
    const slotDate = new Date(slot.startMS).toISOString();

    if (slot.hasStatus && slot.status === 'down') {
      item.classList.add('latency-slot-down');
      const tooltipText = `${formatDateValue(slotDate, timeline.config.format || 'minute')} · OFFLINE`;
      item.title = tooltipText;
      bindLatencySlotTooltip(item, tooltipText, item);
    } else if (slot.hasValue) {
      const percent = Math.max(3, Math.round((slot.latencyMS / safeMax) * 100));
      item.style.height = `${percent}%`;
      if (slot.hasStatus && slot.status === 'degraded') {
        item.classList.add('latency-slot-degraded');
      } else {
        item.classList.add('latency-slot-value');
      }
      const tooltipText = `${formatDateValue(slotDate, timeline.config.format || 'minute')} · ${formatLatency(slot.latencyMS)}`;
      item.title = tooltipText;
      bindLatencySlotTooltip(item, tooltipText, item);
    } else {
      item.classList.add('latency-slot-empty');
      const tooltipText = `${formatDateValue(slotDate, timeline.config.format || 'minute')} · ${tr('trendNoData', 'No data')}`;
      item.title = tooltipText;
      bindLatencySlotTooltip(item, tooltipText);
    }

    bars.appendChild(item);
  });

  const avgLine = document.createElement('div');
  avgLine.className = 'latency-avg-line';
  const fallbackAverage = rawLatencyValues.length > 0
    ? Math.round(rawLatencyValues.reduce((sum, value) => sum + value, 0) / rawLatencyValues.length)
    : 0;
  const serverAverage = Number(averageMS);
  const hasAverageValue = rawLatencyValues.length > 0;
  const avgValueMS = hasAverageValue && Number.isFinite(serverAverage) && serverAverage >= 0
    ? serverAverage
    : fallbackAverage;
  const avgPercent = hasAverageValue
    ? Math.max(0, Math.min(100, Math.round((avgValueMS / safeMax) * 100)))
    : 0;
  avgLine.style.bottom = `${avgPercent}%`;
  const avgTooltipText = `Ø ${formatLatency(avgValueMS)} · ${latencyRangeLabels[selectedRange] || selectedRange}`;
  avgLine.title = hasAverageValue ? avgTooltipText : '';

  const avgHit = document.createElement('div');
  avgHit.className = 'latency-avg-hit';
  avgHit.style.bottom = `calc(${avgPercent}% - 5px)`;
  if (hasAverageValue) {
    bindLatencySlotTooltip(avgHit, avgTooltipText, avgLine);
  }

  const avgLabel = document.createElement('div');
  avgLabel.className = 'latency-avg-label';
  avgLabel.style.bottom = `calc(${avgPercent}% + 3px)`;
  avgLabel.textContent = `Ø ${formatLatency(avgValueMS)}`;

  trendDetailLatencyPlot.appendChild(bars);
  if (hasAverageValue) {
    trendDetailLatencyPlot.appendChild(avgLine);
    trendDetailLatencyPlot.appendChild(avgHit);
    trendDetailLatencyPlot.appendChild(avgLabel);
  }

  trendDetailLatencyCaption.textContent = '';
};
