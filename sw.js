/* Shree GatePass - Progressive Web App Service Worker */
const CACHE_NAME = 'shree-gatepass-v2';
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

    if (notifOptions.data && notifOptions.data.kind === 'visitor_stay_check' && notifOptions.data.targetId) {
      notifOptions.requireInteraction = true;
      if (!notifOptions.actions || !notifOptions.actions.length) {
        notifOptions.actions = [
          { action: 'still_inside', type: 'text', title: '⏳ Still Inside (Reply)', placeholder: 'Reason (e.g. Meeting pending)' },
          { action: 'mark_left', title: '🚪 Left / Out' }
        ];
      }
    }

    event.waitUntil(
      self.registration.showNotification(title || 'Shree GatePass', notifOptions).catch(() => {
        const fallbackOpts = Object.assign({}, notifOptions);
        if (Array.isArray(fallbackOpts.actions)) {
          fallbackOpts.actions = fallbackOpts.actions.map((a) => ({ action: a.action, title: a.title }));
        }
        return self.registration.showNotification(title || 'Shree GatePass', fallbackOpts);
      })
    );
  } else if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

async function focusOrOpenReplyWindow(targetUrl, view, vid, meta) {
  const windowClients = await clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of windowClients) {
    if ('focus' in client) {
      await client.focus();
      client.postMessage({
        type: 'PWA_NAVIGATE',
        view: view,
        id: vid,
        replyVisitor: vid || '',
        meta: Object.assign({}, meta || {}, vid ? { replyVisitor: vid } : {})
      });
      return;
    }
  }
  if (clients.openWindow) {
    return clients.openWindow(targetUrl);
  }
}

async function broadcastVisitorUpdated(vid, action, message) {
  const windowClients = await clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of windowClients) {
    client.postMessage({ type: 'PWA_VISITOR_UPDATED', visitorId: vid, action, message });
  }
}

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const action = event.action || '';
  const view = data.targetView || data.view || 'visitors';
  const vid = data.targetId || data.id || '';
  const targetUrl = data.url || `/?view=${encodeURIComponent(view)}`;

  if ((action === 'still_inside' || action === 'mark_left') && vid) {
    const replyText = (event.reply || '').trim();
    if (action === 'still_inside' && !replyText) {
      const replyUrl = `/?view=visitors&replyVisitor=${encodeURIComponent(vid)}`;
      event.waitUntil(focusOrOpenReplyWindow(replyUrl, 'visitors', vid, data));
      return;
    }
    event.waitUntil((async () => {
      try {
        const res = await fetch(`/api/visitors/${encodeURIComponent(vid)}/stay-response`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'ShreeGatePass' },
          body: JSON.stringify(
            action === 'mark_left'
              ? { action: 'left', reason: replyText || 'Marked left directly from notification bar' }
              : { action: 'still_inside', reason: replyText, extendMinutes: 30 }
          )
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const msg = action === 'mark_left'
          ? 'Visitor checked out from notification bar'
          : 'Visitor stay extended & reason saved from notification bar';
        await broadcastVisitorUpdated(vid, action, msg);
        await self.registration.showNotification('Shree GatePass · Updated', {
          body: msg,
          icon: '/static/icons/icon-192.png',
          badge: '/static/icons/icon-192.png',
          tag: 'gp-confirm-' + vid,
          requireInteraction: false,
          data: { targetView: 'visitors', targetId: vid }
        });
      } catch (_) {
        const replyUrl = `/?view=visitors&replyVisitor=${encodeURIComponent(vid)}`;
        await focusOrOpenReplyWindow(replyUrl, 'visitors', vid, data);
      }
    })());
    return;
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if ('focus' in client) {
          client.focus();
          client.postMessage({
            type: 'PWA_NAVIGATE',
            view: view,
            id: vid,
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
