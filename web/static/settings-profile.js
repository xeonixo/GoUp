(() => {
  window.addEventListener('DOMContentLoaded', () => {
    const themeSelect = document.querySelector('[data-theme-select]');
    if (themeSelect instanceof HTMLSelectElement && window.GoUpTheme) {
      themeSelect.value = window.GoUpTheme.get();
      themeSelect.addEventListener('change', () => {
        window.GoUpTheme.set(themeSelect.value);
      });
    }

    const matrixCard = document.getElementById('matrix-channel-card');
    const emptyState = document.getElementById('notifier-empty-state');
    const addButtons = Array.from(document.querySelectorAll('[data-add-notifier]'));

    if (!matrixCard && !emptyState && addButtons.length === 0) {
      return;
    }

    const syncNotifierState = () => {
      const hasMatrix = Boolean(matrixCard && !matrixCard.hidden);
      if (emptyState) {
        emptyState.hidden = hasMatrix;
      }
      addButtons.forEach((button) => {
        if (!(button instanceof HTMLButtonElement)) {
          return;
        }
        if (button.dataset.addNotifier === 'matrix') {
          button.disabled = hasMatrix;
        }
      });
    };

    addButtons.forEach((button) => {
      button.addEventListener('click', () => {
        if (button.dataset.addNotifier === 'matrix' && matrixCard) {
          matrixCard.hidden = false;
          const firstField = matrixCard.querySelector('input');
          if (firstField instanceof HTMLInputElement) {
            firstField.focus();
          }
          syncNotifierState();
        }
        const menu = button.closest('.action-menu');
        if (menu) {
          menu.removeAttribute('open');
        }
      });
    });

    syncNotifierState();
  });
})();

// ── Web Push (this device) ──────────────────────────────────────────────
(() => {
  const panel = document.getElementById('push-panel');
  if (!panel) {
    return;
  }
  const statusEl = panel.querySelector('[data-push-status]');
  const enableBtn = panel.querySelector('[data-push-enable]');
  const disableBtn = panel.querySelector('[data-push-disable]');
  const testBtn = panel.querySelector('[data-push-test]');
  const data = panel.dataset;
  const MESSAGE_KEY = 'goup-push-message';

  let registration = null;
  let subscription = null;
  let busy = false;

  const setStatus = (text, state) => {
    if (!statusEl) {
      return;
    }
    statusEl.textContent = text;
    if (state) {
      statusEl.dataset.state = state;
    } else {
      delete statusEl.dataset.state;
    }
  };

  const rememberMessage = (text, state) => {
    try {
      sessionStorage.setItem(MESSAGE_KEY, JSON.stringify({ text, state }));
    } catch (_) {
    }
  };

  const reloadSoon = () => {
    window.setTimeout(() => window.location.reload(), 500);
  };

  const isIOS = () => /iphone|ipad|ipod/i.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const isStandalone = () => navigator.standalone === true
    || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);

  const postJSON = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch (_) {
    }
    return { ok: response.ok, status: response.status, payload };
  };

  const errorText = (result) => {
    if (result.status === 429) {
      return data.msgRateLimited;
    }
    if (result.payload && result.payload.error === 'limit_reached') {
      return data.msgLimit;
    }
    if (result.payload && result.payload.error === 'no_devices') {
      return data.msgNoDevices;
    }
    return data.msgError;
  };

  const urlBase64ToUint8Array = (value) => {
    const padding = '='.repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = window.atob(base64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) {
      out[i] = raw.charCodeAt(i);
    }
    return out;
  };

  const deviceItems = () => Array.from(panel.querySelectorAll('[data-push-device]'));

  // The service worker needs the (tenant specific) subscribe URL to re-register after the
  // push service rotated the subscription ("pushsubscriptionchange").
  const storeWorkerConfig = async () => {
    try {
      const cache = await caches.open('push-config');
      await cache.put('/__push-config', new Response(JSON.stringify({
        subscribeUrl: data.pushSubscribeUrl,
        keyUrl: data.pushKeyUrl
      }), { headers: { 'Content-Type': 'application/json' } }));
    } catch (_) {
    }
  };

  const getRegistration = async () => {
    if (registration) {
      return registration;
    }
    const existing = await navigator.serviceWorker.getRegistration('/');
    if (existing) {
      registration = existing;
    } else {
      registration = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    }
    await navigator.serviceWorker.ready;
    return registration;
  };

  const render = () => {
    const known = subscription
      ? deviceItems().some((item) => item.dataset.endpoint === subscription.endpoint)
      : false;
    deviceItems().forEach((item) => {
      const badge = item.querySelector('[data-push-this-device]');
      if (badge) {
        badge.hidden = !(subscription && item.dataset.endpoint === subscription.endpoint);
      }
    });

    const denied = typeof Notification !== 'undefined' && Notification.permission === 'denied';
    if (denied) {
      setStatus(data.msgDenied, 'error');
    } else if (subscription && known) {
      setStatus(data.msgActive, 'active');
    } else if (subscription) {
      setStatus(data.msgStale, 'warn');
    } else {
      setStatus(data.msgInactive, '');
    }
    if (enableBtn) {
      enableBtn.hidden = denied || Boolean(subscription && known);
      enableBtn.disabled = busy;
    }
    if (disableBtn) {
      disableBtn.hidden = !subscription;
      disableBtn.disabled = busy;
    }
    if (testBtn) {
      testBtn.disabled = busy || deviceItems().length === 0;
    }
  };

  const withBusy = async (fn) => {
    if (busy) {
      return;
    }
    busy = true;
    render();
    const before = statusEl ? statusEl.textContent : '';
    try {
      await fn();
    } catch (_) {
      setStatus(data.msgError, 'error');
    } finally {
      busy = false;
      // Re-render the buttons, but keep a status message the action itself produced.
      const after = statusEl ? statusEl.textContent : '';
      const afterState = statusEl ? statusEl.dataset.state : '';
      render();
      if (after !== before) {
        setStatus(after, afterState);
      }
    }
  };

  const enable = () => {
    // requestPermission must be called synchronously inside the click handler (iOS requires
    // a user gesture), so it is started before any await.
    const permission = Notification.permission === 'granted'
      ? Promise.resolve('granted')
      : Notification.requestPermission();
    return withBusy(async () => {
      if (await permission !== 'granted') {
        render();
        return;
      }
      const reg = await getRegistration();
      const keyResponse = await fetch(data.pushKeyUrl, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      if (!keyResponse.ok) {
        setStatus(data.msgError, 'error');
        return;
      }
      const { publicKey } = await keyResponse.json();
      const options = { userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(publicKey) };
      let sub;
      try {
        sub = await reg.pushManager.subscribe(options);
      } catch (err) {
        // A subscription made with another application server key blocks subscribe().
        const old = await reg.pushManager.getSubscription();
        if (!old) {
          throw err;
        }
        await old.unsubscribe();
        sub = await reg.pushManager.subscribe(options);
      }
      const result = await postJSON(data.pushSubscribeUrl, sub.toJSON());
      if (!result.ok) {
        try {
          await sub.unsubscribe();
        } catch (_) {
        }
        setStatus(errorText(result), 'error');
        return;
      }
      await storeWorkerConfig();
      rememberMessage(data.msgEnabled, 'active');
      setStatus(data.msgEnabled, 'active');
      reloadSoon();
    });
  };

  const disable = () => withBusy(async () => {
    const sub = subscription || (registration ? await registration.pushManager.getSubscription() : null);
    if (sub) {
      const endpoint = sub.endpoint;
      try {
        await sub.unsubscribe();
      } catch (_) {
      }
      await postJSON(data.pushUnsubscribeUrl, { endpoint });
    }
    rememberMessage(data.msgDisabled, '');
    setStatus(data.msgDisabled, '');
    reloadSoon();
  });

  const sendTest = () => withBusy(async () => {
    const result = await postJSON(data.pushTestUrl, {});
    if (result.ok) {
      setStatus(data.msgTestSent, 'active');
    } else if (result.status === 502) {
      setStatus(data.msgTestFailed, 'error');
    } else {
      setStatus(errorText(result), 'error');
    }
  });

  const removeDevice = (item) => withBusy(async () => {
    const id = Number(item.dataset.id);
    const result = await postJSON(data.pushUnsubscribeUrl, { id });
    if (!result.ok && result.status !== 404) {
      setStatus(errorText(result), 'error');
      return;
    }
    if (subscription && item.dataset.endpoint === subscription.endpoint) {
      try {
        await subscription.unsubscribe();
      } catch (_) {
      }
    }
    rememberMessage(data.msgRemoved, '');
    reloadSoon();
  });

  const updatePref = async (item, input) => {
    const category = input.dataset.pushPref;
    const wanted = input.checked;
    input.disabled = true;
    try {
      const result = await postJSON(data.pushPrefsUrl, { id: Number(item.dataset.id), [category]: wanted });
      if (!result.ok) {
        input.checked = !wanted;
        setStatus(errorText(result), 'error');
      }
    } catch (_) {
      input.checked = !wanted;
      setStatus(data.msgError, 'error');
    } finally {
      input.disabled = false;
    }
  };

  const init = async () => {
    if (isIOS() && !isStandalone()) {
      setStatus(data.msgInstallIos, 'warn');
      if (testBtn) {
        testBtn.hidden = true;
      }
      return;
    }
    if (!window.isSecureContext) {
      setStatus(data.msgInsecure, 'error');
      return;
    }
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || typeof Notification === 'undefined') {
      setStatus(data.msgUnsupported, 'error');
      if (testBtn) {
        testBtn.hidden = true;
      }
      return;
    }

    if (enableBtn) {
      enableBtn.addEventListener('click', enable);
    }
    if (disableBtn) {
      disableBtn.addEventListener('click', disable);
    }
    if (testBtn) {
      testBtn.addEventListener('click', sendTest);
    }
    deviceItems().forEach((item) => {
      const removeBtn = item.querySelector('[data-push-remove]');
      if (removeBtn) {
        removeBtn.addEventListener('click', () => removeDevice(item));
      }
      item.querySelectorAll('[data-push-pref]').forEach((input) => {
        input.addEventListener('change', () => updatePref(item, input));
      });
    });

    try {
      const reg = await getRegistration();
      subscription = await reg.pushManager.getSubscription();
      if (subscription) {
        await storeWorkerConfig();
      }
    } catch (_) {
      setStatus(data.msgUnsupported, 'error');
      return;
    }
    render();

    try {
      const raw = sessionStorage.getItem(MESSAGE_KEY);
      if (raw) {
        sessionStorage.removeItem(MESSAGE_KEY);
        const saved = JSON.parse(raw);
        if (saved && saved.text) {
          setStatus(saved.text, saved.state || '');
        }
      }
    } catch (_) {
    }
  };

  window.addEventListener('DOMContentLoaded', init);
})();
