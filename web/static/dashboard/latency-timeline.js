import { trendDetailLatencyRangeButtons } from './dom.js';

export const latencyRangeLabels = {
  '1h': '1h',
  '6h': '6h',
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
  '90d': '90d',
  '365d': '365d'
};

const latencyRangeConfig = {
  '1h': { durationMS: 60 * 60 * 1000, slotMS: 60 * 1000, format: 'minute' },
  '6h': { durationMS: 6 * 60 * 60 * 1000, slotMS: 5 * 60 * 1000, format: 'hour' },
  '24h': { durationMS: 24 * 60 * 60 * 1000, slotMS: 30 * 60 * 1000, format: 'hour' },
  '7d': { durationMS: 7 * 24 * 60 * 60 * 1000, slotMS: 24 * 60 * 60 * 1000, format: 'date', align: 'day' },
  // Long ranges come pre-aggregated per day from the hourly rollups.
  '30d': { durationMS: 30 * 24 * 60 * 60 * 1000, slotMS: 24 * 60 * 60 * 1000, format: 'date', align: 'day' },
  '90d': { durationMS: 90 * 24 * 60 * 60 * 1000, slotMS: 24 * 60 * 60 * 1000, format: 'date', align: 'day' },
  '365d': { durationMS: 52 * 7 * 24 * 60 * 60 * 1000, slotMS: 7 * 24 * 60 * 60 * 1000, format: 'date', align: 'day' }
};

export const normalizeLatencyRange = (value) => {
  const raw = String(value || '').trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(latencyRangeConfig, raw)) {
    return raw;
  }
  return '1h';
};

export const setLatencyRangeButtonsState = (activeRange, disabled = false) => {
  const selected = normalizeLatencyRange(activeRange);
  trendDetailLatencyRangeButtons.forEach((button) => {
    const buttonRange = normalizeLatencyRange(button.dataset.range || '1h');
    const isActive = buttonRange === selected;
    button.classList.toggle('button-secondary', !isActive);
    button.setAttribute('aria-selected', isActive ? 'true' : 'false');
    button.tabIndex = isActive ? 0 : -1;
    button.disabled = disabled;
  });
};

export const buildLatencyTimelineSlots = (points, rangeValue) => {
  const selectedRange = normalizeLatencyRange(rangeValue);
  const config = latencyRangeConfig[selectedRange] || latencyRangeConfig['1h'];
  const now = new Date();
  const endDate = config.align === 'day'
    ? new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
    : now;
  const endMS = endDate.getTime();
  const startMS = endMS - config.durationMS;
  const slotCount = Math.max(1, Math.floor(config.durationMS / config.slotMS));
  const slots = Array.from({ length: slotCount }, (_, index) => ({
    startMS: startMS + (index * config.slotMS),
    latencyMS: 0,
    status: '',
    hasValue: false,
    hasStatus: false,
    totalChecks: 0,
    upChecks: 0,
    downChecks: 0,
    degradedChecks: 0,
    latencyChecks: 0,
    latencySumMS: 0,
    latencyMinMS: 0,
    latencyMaxMS: 0
  }));

  const safePoints = Array.isArray(points) ? points : [];
  safePoints.forEach((point) => {
    const timestamp = new Date(String(point?.checked_at || '')).getTime();
    if (!Number.isFinite(timestamp) || timestamp < startMS || timestamp > endMS) {
      return;
    }
    const slotIndex = Math.max(0, Math.min(slotCount - 1, Math.floor((timestamp - startMS) / config.slotMS)));
    const slot = slots[slotIndex];
    if (!slot) {
      return;
    }
    const status = String(point?.status || '').trim().toLowerCase();
    const latencyMS = Number(point?.latency_ms || 0);
    // Unknown and maintenance checks are not part of the uptime denominator.
    const aggregatedChecks = Math.max(0, Number(point?.total_checks || 0) - Number(point?.unknown_checks || 0) - Number(point?.maintenance_checks || 0));
    if (aggregatedChecks > 0) {
      slot.hasStatus = true;
      slot.totalChecks += aggregatedChecks;
      slot.upChecks += Number(point?.up_checks || 0);
      slot.downChecks += Number(point?.down_checks || 0);
      slot.degradedChecks += Number(point?.degraded_checks || 0);
      const latencyChecks = Number(point?.latency_checks || 0);
      if (latencyChecks > 0) {
        const minMS = Number(point?.latency_min_ms || 0);
        const maxMS = Number(point?.latency_max_ms || 0);
        slot.latencyMinMS = slot.latencyChecks === 0 ? minMS : Math.min(slot.latencyMinMS, minMS);
        slot.latencyMaxMS = Math.max(slot.latencyMaxMS, maxMS);
        slot.latencyChecks += latencyChecks;
        slot.latencySumMS += Number(point?.latency_sum_ms || 0);
      }
      return;
    }
    if (status && status !== 'unknown') {
      slot.status = status;
      slot.hasStatus = true;
      slot.totalChecks += 1;
      if (status === 'up') {
        slot.upChecks += 1;
      } else if (status === 'down') {
        slot.downChecks += 1;
      } else if (status === 'degraded') {
        slot.degradedChecks += 1;
      }
    }
    if (Number.isFinite(latencyMS) && latencyMS >= 0 && status !== 'down' && status !== 'unknown') {
      slot.latencyChecks += 1;
      slot.latencySumMS += latencyMS;
      slot.latencyMinMS = slot.latencyChecks === 1 ? latencyMS : Math.min(slot.latencyMinMS, latencyMS);
      slot.latencyMaxMS = Math.max(slot.latencyMaxMS, latencyMS);
    }
  });

  slots.forEach((slot) => {
    if (slot.latencyChecks > 0) {
      slot.latencyMS = Math.round(slot.latencySumMS / slot.latencyChecks);
      slot.hasValue = true;
    }
    if (slot.totalChecks > 0) {
      if (slot.downChecks > 0 && slot.upChecks === 0 && slot.degradedChecks === 0) {
        slot.status = 'down';
      } else if (slot.downChecks > 0 || slot.degradedChecks > 0) {
        slot.status = 'degraded';
      } else {
        slot.status = 'up';
      }
      slot.hasStatus = true;
    }
  });

  return {
    selectedRange,
    config,
    slots,
    startDate: new Date(startMS),
    endDate: config.align === 'day' ? new Date(endMS - 1) : new Date(endMS)
  };
};
