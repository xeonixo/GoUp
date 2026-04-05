(() => {
  window.addEventListener('DOMContentLoaded', () => {
    const page = document.getElementById('settings-remote-nodes-page');
    if (!(page instanceof HTMLElement)) {
      return;
    }

    const appBase = page.dataset.appBase || '/';
    const i18nOnline = page.dataset.i18nOnline || 'ONLINE';
    const i18nOffline = page.dataset.i18nOffline || 'OFFLINE';
    const i18nEntries = page.dataset.i18nEntries || 'entries';
    const i18nFrom = page.dataset.i18nFrom || 'From';
    const tableBody = document.getElementById('settings-remote-nodes-body');
    if (!(tableBody instanceof HTMLElement)) {
      return;
    }

    const buildWSURL = () => {
      const wsURL = new URL(`${appBase}settings/remote-nodes/live`, window.location.href);
      wsURL.protocol = wsURL.protocol === 'https:' ? 'wss:' : 'ws:';
      return wsURL.toString();
    };

    let socket = null;
    let reconnectTimer = null;
    let reconnectDelayMS = 1000;
    let active = true;
    let snapshotInFlight = false;

    const clearNode = (node) => {
      while (node.firstChild) {
        node.removeChild(node.firstChild);
      }
    };

    const updateStatusCell = (cell, online) => {
      clearNode(cell);
      const badge = document.createElement('span');
      badge.className = online ? 'status-badge status-badge-success' : 'status-badge status-badge-muted';
      badge.textContent = online ? i18nOnline : i18nOffline;
      cell.appendChild(badge);
    };

    const updateLastSeenCell = (cell, lastSeenAtRaw) => {
      clearNode(cell);
      const timestamp = String(lastSeenAtRaw || '').trim();
      if (!timestamp) {
        cell.appendChild(document.createTextNode('—'));
        return;
      }
      const age = document.createElement('span');
      age.className = 'js-relative-age';
      age.setAttribute('data-utc', timestamp);
      age.textContent = timestamp;
      cell.appendChild(age);
    };

    const buildLogDetails = (events, keepOpen) => {
      if (!Array.isArray(events) || events.length === 0) {
        const muted = document.createElement('span');
        muted.className = 'muted';
        muted.textContent = '—';
        return muted;
      }

      const details = document.createElement('details');
      details.className = 'remote-node-log';
      if (keepOpen) {
        details.open = true;
      }

      const summary = document.createElement('summary');
      summary.textContent = `${events.length} ${i18nEntries}`;
      details.appendChild(summary);

      const list = document.createElement('ul');
      list.className = 'remote-node-log-list';

      events.forEach((event) => {
        const item = document.createElement('li');

        const head = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = String(event?.event_label || '').trim();
        head.appendChild(strong);
        head.appendChild(document.createTextNode(' · '));

        const occurredAtRaw = String(event?.occurred_at_raw || '').trim();
        const age = document.createElement('span');
        age.className = 'js-relative-age';
        if (occurredAtRaw) {
          age.setAttribute('data-utc', occurredAtRaw);
          age.textContent = occurredAtRaw;
        } else {
          age.textContent = '—';
        }
        head.appendChild(age);

        const meta = document.createElement('div');
        meta.className = 'muted compact break-all';
        const detailsParts = [];
        const sourceIP = String(event?.source_ip || '').trim();
        const detailsText = String(event?.details || '').trim();
        const userAgent = String(event?.user_agent || '').trim();
        detailsParts.push(`${i18nFrom} ${sourceIP || '—'}`);
        if (detailsText) {
          detailsParts.push(detailsText);
        }
        if (userAgent) {
          detailsParts.push(userAgent);
        }
        meta.textContent = detailsParts.join(' · ');

        item.appendChild(head);
        item.appendChild(meta);
        list.appendChild(item);
      });

      details.appendChild(list);
      return details;
    };

    const updateLogsCell = (cell, events) => {
      const previousDetails = cell.querySelector('details.remote-node-log');
      const keepOpen = previousDetails instanceof HTMLDetailsElement && previousDetails.open;
      clearNode(cell);
      cell.appendChild(buildLogDetails(events, keepOpen));
    };

    const applySnapshot = (snapshot) => {
      const nodes = Array.isArray(snapshot?.nodes) ? snapshot.nodes : [];
      if (nodes.length === 0) {
        return;
      }

      const rowsByNode = new Map();
      tableBody.querySelectorAll('tr[data-node-id]').forEach((row) => {
        if (!(row instanceof HTMLTableRowElement)) {
          return;
        }
        const nodeID = String(row.dataset.nodeId || '').trim();
        if (nodeID) {
          rowsByNode.set(nodeID, row);
        }
      });

      nodes.forEach((node) => {
        const nodeID = String(node?.node_id || '').trim();
        if (!nodeID) {
          return;
        }
        const row = rowsByNode.get(nodeID);
        if (!(row instanceof HTMLTableRowElement)) {
          return;
        }

        const statusCell = row.querySelector('td[data-role="status"]');
        const lastSeenCell = row.querySelector('td[data-role="last-seen"]');
        const logsCell = row.querySelector('td[data-role="logs"]');
        if (statusCell instanceof HTMLTableCellElement) {
          updateStatusCell(statusCell, Boolean(node?.online));
        }
        if (lastSeenCell instanceof HTMLTableCellElement) {
          updateLastSeenCell(lastSeenCell, node?.last_seen_at_raw);
        }
        if (logsCell instanceof HTMLTableCellElement) {
          updateLogsCell(logsCell, node?.events);
        }
      });
    };

    const fetchSnapshot = async () => {
      if (!active || snapshotInFlight) {
        return;
      }
      snapshotInFlight = true;
      try {
        const response = await window.fetch(`${appBase}settings/remote-nodes/live/snapshot`, {
          method: 'GET',
          headers: {
            Accept: 'application/json'
          },
          credentials: 'same-origin'
        });
        if (!response.ok) {
          return;
        }
        const payload = await response.json();
        applySnapshot(payload);
      } catch (_) {
      } finally {
        snapshotInFlight = false;
      }
    };

    const queueReconnect = () => {
      if (!active || reconnectTimer !== null) {
        return;
      }
      const delay = reconnectDelayMS;
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
      reconnectDelayMS = Math.min(reconnectDelayMS * 2, 15000);
    };

    const connect = () => {
      if (!active || typeof window.WebSocket !== 'function') {
        return;
      }

      try {
        socket = new window.WebSocket(buildWSURL());
      } catch (_) {
        queueReconnect();
        return;
      }

      socket.addEventListener('open', () => {
        reconnectDelayMS = 1000;
        fetchSnapshot();
      });

      socket.addEventListener('message', (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload?.type === 'refresh') {
            fetchSnapshot();
          }
        } catch (_) {
        }
      });

      socket.addEventListener('error', () => {
        try {
          socket?.close();
        } catch (_) {
        }
      });

      socket.addEventListener('close', () => {
        socket = null;
        queueReconnect();
      });
    };

    window.addEventListener('beforeunload', () => {
      active = false;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket) {
        try {
          socket.close();
        } catch (_) {
        }
        socket = null;
      }
    });

    connect();
  });
})();
