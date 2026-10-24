import { tablePageSize } from './config.js';
import { bindOnce, renderTablePagination } from './dom-utils.js';
import { tr } from './i18n.js';
import { S } from './state.js';

export const bindStateEventListeners = () => {
  const search = document.getElementById('state-events-search');
  const statusFilter = document.getElementById('state-events-status-filter');
  const incidentsOnly = document.getElementById('state-events-incidents-only');
  const exportButton = document.getElementById('state-events-export');

  bindOnce(search, 'StateSearch', applyStateEventFilters);
  if (search instanceof Element && search.dataset.boundStateSearchChange !== '1') {
    search.dataset.boundStateSearchChange = '1';
    search.addEventListener('input', applyStateEventFilters);
  }

  if (statusFilter instanceof Element && statusFilter.dataset.boundStateStatus !== '1') {
    statusFilter.dataset.boundStateStatus = '1';
    statusFilter.addEventListener('change', applyStateEventFilters);
  }
  if (incidentsOnly instanceof Element && incidentsOnly.dataset.boundStateIncidents !== '1') {
    incidentsOnly.dataset.boundStateIncidents = '1';
    incidentsOnly.addEventListener('change', applyStateEventFilters);
  }
  if (exportButton instanceof Element && exportButton.dataset.boundStateExport !== '1') {
    exportButton.dataset.boundStateExport = '1';
    exportButton.addEventListener('click', exportStateEventsCSV);
  }
};

export const bindNotificationEventListeners = () => {
  applyNotificationEventPagination();
};

const updateStateEventFilterStatus = (visible, total, page, pageCount) => {
  const filterStatus = document.getElementById('state-events-filter-status');
  if (!filterStatus) {
    return;
  }
  if (total <= 0) {
    filterStatus.textContent = tr('stateEventsNone', 'No status changes yet.');
    return;
  }
  if (pageCount <= 1) {
    filterStatus.textContent = `${total} ${tr('paginationEntries', 'entries')}`;
    return;
  }
  filterStatus.textContent = tr('paginationSummary', 'Page {current} of {totalPages} · {totalItems} entries', {
    current: page,
    totalPages: pageCount,
    totalItems: `${visible} ${tr('paginationOf', 'of')} ${total}`
  });
};

export const applyStateEventFilters = (requestedPage = S.stateEventsPage) => {
  const body = document.getElementById('state-events-body');
  const search = document.getElementById('state-events-search');
  const statusFilterNode = document.getElementById('state-events-status-filter');
  const incidentsOnlyNode = document.getElementById('state-events-incidents-only');
  const emptyRow = document.getElementById('state-events-empty-row');
  const stateEventRows = body
    ? Array.from(body.querySelectorAll('tr')).filter((row) => row.id !== 'state-events-empty-row')
    : [];

  if (!stateEventRows.length) {
    const stateEventsPaginationRoot = document.getElementById('state-events-pagination');
    if (stateEventsPaginationRoot instanceof HTMLElement) {
      stateEventsPaginationRoot.hidden = true;
    }
    updateStateEventFilterStatus(0, 0, 1, 1);
    return;
  }

  const query = (search?.value || '').trim().toLowerCase();
  const statusFilter = (statusFilterNode?.value || 'all').trim().toLowerCase();
  const incidentsOnly = incidentsOnlyNode?.checked === true;

  const filteredRows = [];
  stateEventRows.forEach((row) => {
    const monitor = (row.dataset.monitor || '').toLowerCase();
    const group = (row.dataset.group || '').toLowerCase();
    const fromStatus = (row.dataset.from || '').toLowerCase();
    const toStatus = (row.dataset.to || '').toLowerCase();
    const message = (row.dataset.message || '').toLowerCase();
    const when = (row.dataset.when || '').toLowerCase();

    const matchesQuery = !query || monitor.includes(query) || group.includes(query) || message.includes(query) || when.includes(query) || fromStatus.includes(query) || toStatus.includes(query);
    const matchesStatus = statusFilter === 'all' || toStatus === statusFilter;
    const matchesIncidentsOnly = !incidentsOnly || toStatus === 'down' || toStatus === 'degraded';
    const rowVisible = matchesQuery && matchesStatus && matchesIncidentsOnly;

    row.dataset.filteredVisible = rowVisible ? '1' : '0';
    if (rowVisible) {
      filteredRows.push(row);
    }
  });

  const totalFiltered = filteredRows.length;
  const pageCount = Math.max(1, Math.ceil(Math.max(totalFiltered, 1) / tablePageSize));
  S.stateEventsPage = totalFiltered > 0 ? Math.min(Math.max(1, requestedPage), pageCount) : 1;
  const pageStart = (S.stateEventsPage - 1) * tablePageSize;
  const pageEnd = pageStart + tablePageSize;

  stateEventRows.forEach((row) => {
    row.hidden = row.dataset.filteredVisible !== '1';
  });

  filteredRows.forEach((row, index) => {
    row.hidden = index < pageStart || index >= pageEnd;
  });

  if (emptyRow) {
    emptyRow.hidden = totalFiltered > 0;
  }

  renderTablePagination(document.getElementById('state-events-pagination'), S.stateEventsPage, pageCount, totalFiltered, (nextPage) => {
    S.stateEventsPage = nextPage;
    applyStateEventFilters(nextPage);
  });

  updateStateEventFilterStatus(Math.max(0, Math.min(tablePageSize, totalFiltered - pageStart)), totalFiltered, S.stateEventsPage, pageCount);
};

export const applyNotificationEventPagination = (requestedPage = S.notificationEventsPage) => {
  const notificationBody = document.getElementById('notification-events-body');
  const rows = notificationBody ? Array.from(notificationBody.querySelectorAll('tr')) : [];
  if (!rows.length) {
    const notificationPaginationRoot = document.getElementById('notification-events-pagination');
    if (notificationPaginationRoot instanceof HTMLElement) {
      notificationPaginationRoot.hidden = true;
    }
    return;
  }

  const pageCount = Math.max(1, Math.ceil(rows.length / tablePageSize));
  S.notificationEventsPage = Math.min(Math.max(1, requestedPage), pageCount);
  const pageStart = (S.notificationEventsPage - 1) * tablePageSize;
  const pageEnd = pageStart + tablePageSize;

  rows.forEach((row, index) => {
    row.hidden = index < pageStart || index >= pageEnd;
  });

  renderTablePagination(document.getElementById('notification-events-pagination'), S.notificationEventsPage, pageCount, rows.length, (nextPage) => {
    S.notificationEventsPage = nextPage;
    applyNotificationEventPagination(nextPage);
  });
};

const exportStateEventsCSV = () => {
  const body = document.getElementById('state-events-body');
  const stateEventRows = body
    ? Array.from(body.querySelectorAll('tr')).filter((row) => row.id !== 'state-events-empty-row')
    : [];
  if (!stateEventRows.length) {
    return;
  }

  const visibleRows = stateEventRows.filter((row) => row.dataset.filteredVisible === '1');
  if (!visibleRows.length) {
    return;
  }

  const esc = (value) => {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
  };

  const lines = [
    [tr('csvHeaderTime', 'Time'), tr('csvHeaderGroup', 'Group'), tr('csvHeaderMonitor', 'Monitor'), tr('csvHeaderFrom', 'From'), tr('csvHeaderTo', 'To'), tr('csvHeaderDetails', 'Details')],
    ...visibleRows.map((row) => [
      row.dataset.when || '',
      row.dataset.group || '',
      row.dataset.monitor || '',
      row.dataset.from || '',
      row.dataset.to || '',
      row.dataset.message || ''
    ])
  ].map((columns) => columns.map((column) => esc(column)).join(';'));

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${tr('csvFilenamePrefix', 'goup-status-changes')}-${new Date().toISOString().replace(/[:]/g, '-').slice(0, 19)}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
