/* GoUp service worker.
 *
 * Served from /sw.js (scope "/") by the Go server, which replaces the version
 * placeholder below with the build version so every release gets its own cache.
 *
 * Strategy:
 *  - Precache the app shell assets and the /offline page.
 *  - Navigations: network-first; on network failure show /offline. HTML is never
 *    stored (it is authenticated and Cache-Control: no-store).
 *  - /static/, /assets/, /favicon/ and icon files: stale-while-revalidate when
 *    versioned (?v=), otherwise network-first with cache fallback.
 *  - Everything else (API, WebSocket upgrade, POST, live snapshots) is not
 *    intercepted and goes straight to the network.
 */
'use strict';

const VERSION = '__GOUP_VERSION__';
const CACHE_PREFIX = 'goup-';
const CACHE_NAME = CACHE_PREFIX + VERSION;
const OFFLINE_URL = '/offline';

const PRECACHE_URLS = [
  OFFLINE_URL,
  '/static/style.css?v=' + VERSION,
  '/static/theme.js?v=' + VERSION,
  '/static/app.js?v=' + VERSION,
  '/assets/logo_goup.svg',
  '/apple-touch-icon.png',
  '/favicon-32x32.png',
  '/favicon-16x16.png',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
  '/favicon/maskable-512x512.png'
];

const CACHEABLE_PREFIXES = ['/static/', '/assets/', '/favicon/'];
const CACHEABLE_PATHS = [
  '/apple-touch-icon.png',
  '/favicon.ico',
  '/favicon-32x32.png',
  '/favicon-16x16.png',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => Promise.all(PRECACHE_URLS.map((url) =>
        // Best effort per entry: a single missing file must not break install.
        cache.add(new Request(url, { cache: 'reload' })).catch(() => {})
      )))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys
        .filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME)
        .map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

function isCacheableAsset(url) {
  if (CACHEABLE_PATHS.includes(url.pathname)) {
    return true;
  }
  return CACHEABLE_PREFIXES.some((prefix) => url.pathname.startsWith(prefix));
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') {
    return;
  }
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) {
    return;
  }
  // Never touch the service worker script itself or the manifests.
  if (url.pathname === '/sw.js' || url.pathname.endsWith('.webmanifest')) {
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() =>
        caches.open(CACHE_NAME)
          .then((cache) => cache.match(OFFLINE_URL))
          .then((cached) => cached || new Response('Offline', {
            status: 503,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          }))
      )
    );
    return;
  }

  if (isCacheableAsset(url) && !url.searchParams.has('v')) {
    // Unversioned assets (e.g. ES modules imported by /static/dashboard/main.js)
    // must match the versioned entry point: network-first (cheap thanks to
    // ETags), cache only as offline fallback.
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) =>
        fetch(request).then((response) => {
          if (response && response.ok && response.type === 'basic') {
            cache.put(request, response.clone()).catch(() => {});
          }
          return response;
        }).catch(() => cache.match(request).then((cached) => cached || Response.error()))
      )
    );
    return;
  }

  if (isCacheableAsset(url)) {
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) =>
        cache.match(request).then((cached) => {
          const network = fetch(request).then((response) => {
            if (response && response.ok && response.type === 'basic') {
              cache.put(request, response.clone()).catch(() => {});
            }
            return response;
          });
          if (cached) {
            // Refresh in the background; ignore failures while offline.
            network.catch(() => {});
            return cached;
          }
          return network;
        })
      )
    );
  }
});

// ── Web Push ──────────────────────────────────────────────────────────
// Payload: { title, body, url, tag, badgeCount }
self.addEventListener('push', (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch (_) {
      payload = { body: event.data.text() };
    }
  }
  const title = (payload && payload.title) || 'GoUp';
  const options = {
    body: (payload && payload.body) || '',
    tag: (payload && payload.tag) || undefined,
    icon: '/android-chrome-192x192.png',
    badge: '/favicon-32x32.png',
    data: { url: (payload && payload.url) || '/' }
  };
  if (options.tag) {
    // A newer message for the same monitor replaces the old one and alerts again.
    options.renotify = true;
  }

  const tasks = [self.registration.showNotification(title, options)];
  const badgeCount = Number(payload && payload.badgeCount);
  if (Number.isFinite(badgeCount) && self.navigator && typeof self.navigator.setAppBadge === 'function') {
    const badgeTask = badgeCount > 0
      ? self.navigator.setAppBadge(badgeCount)
      : self.navigator.clearAppBadge && self.navigator.clearAppBadge();
    tasks.push(Promise.resolve(badgeTask).catch(() => {}));
  }
  event.waitUntil(Promise.all(tasks));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  let target = '/';
  try {
    // Only same-origin targets are allowed.
    const resolved = new URL(data.url || '/', self.location.origin);
    if (resolved.origin === self.location.origin) {
      target = resolved.href;
    }
  } catch (_) {
  }

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (new URL(client.url).origin === self.location.origin && 'focus' in client) {
          return client.focus().then((focused) => {
            if (focused && 'navigate' in focused) {
              return focused.navigate(target).catch(() => {});
            }
            return undefined;
          });
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(target);
      }
      return undefined;
    })
  );
});

function urlBase64ToUint8Array(value) {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

// The push service rotated or expired the subscription: subscribe again and tell the server,
// which moves the device's preferences over (oldEndpoint). The subscribe URL is tenant specific
// and was stored by the settings page in the "push-config" cache (not prefixed "goup-", so
// it survives cache cleanup on activate). Needs a still valid session cookie.
self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil((async () => {
    try {
      const cache = await caches.open('push-config');
      const stored = await cache.match('/__push-config');
      if (!stored) {
        return;
      }
      const config = await stored.json();
      const oldSubscription = event.oldSubscription || null;
      let key = oldSubscription && oldSubscription.options && oldSubscription.options.applicationServerKey;
      if (!key) {
        const response = await fetch(config.keyUrl, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
        if (!response.ok) {
          return;
        }
        key = urlBase64ToUint8Array((await response.json()).publicKey);
      }
      const subscription = event.newSubscription || await self.registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: key
      });
      const body = Object.assign({}, subscription.toJSON(), {
        oldEndpoint: oldSubscription ? oldSubscription.endpoint : ''
      });
      await fetch(config.subscribeUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(body)
      });
    } catch (_) {
    }
  })());
});
