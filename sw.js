/* Shree GatePass - Progressive Web App Service Worker */
const CACHE_NAME = 'shree-gatepass-v1';
const STATIC_ASSETS = [
  '/',
  '/portal',
  '/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/static/icons/icon-maskable-192.png',
  '/static/icons/icon-maskable-512.png',
  '/static/icons/apple-touch-icon-180.png',
  '/static/icons/apple-touch-icon-167.png',
  '/static/icons/apple-touch-icon-152.png',
  '/apple-touch-icon.png',
  '/favicon.ico'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[GatePass SW] Pre-cache partial failure:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Never cache API endpoints, SSE streams, or uploaded media
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/download/')) {
    return;
  }

  // Navigation requests: network-first with cache fallback
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => {
        return caches.match(req).then((cached) => cached || caches.match('/'));
      })
    );
    return;
  }

  // Static assets: stale-while-revalidate
  if (
    url.pathname.startsWith('/static/') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.ico') ||
    url.pathname === '/manifest.json'
  ) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const fetchPromise = fetch(req).then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const clone = networkRes.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, clone));
          }
          return networkRes;
        }).catch(() => cached || Response.error());
        return cached || fetchPromise;
      })
    );
  }
});

self.addEventListener('message', (event) => {
  if (!event.data) return;

  if (event.data.type === 'SHOW_NOTIFICATION') {
    const { title, options } = event.data;
    const notifOptions = Object.assign({
      body: '',
      icon: '/static/icons/icon-192.png',
      badge: '/static/icons/icon-192.png',
      tag: 'shree-gatepass-alert',
      renotify: true,
      vibrate: [220, 100, 220],
      requireInteraction: false,
      data: {}
    }, options);

    event.waitUntil(
      self.registration.showNotification(title || 'Shree GatePass', notifOptions)
    );
  } else if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const view = data.targetView || data.view || 'visitors';
  const targetUrl = data.url || `/?view=${encodeURIComponent(view)}`;

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if ('focus' in client) {
          client.focus();
          client.postMessage({
            type: 'PWA_NAVIGATE',
            view: view,
            id: data.targetId || data.id || '',
            meta: data
          });
          return;
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {
    payload = { title: 'Shree GatePass', body: event.data ? event.data.text() : '' };
  }

  const title = payload.title || 'Shree GatePass Alert';
  const options = {
    body: payload.body || 'New Visitor or Material Gate update.',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [220, 100, 220],
    data: payload.data || {}
  };

  event.waitUntil(self.registration.showNotification(title, options));
});
