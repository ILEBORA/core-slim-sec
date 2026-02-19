// service-worker.js.tpl

const CACHE_NAME = `bora-pwa-cache-${Date.now()}`;//'bora-pwa-cache-{{VERSION}}';
const ASSETS = {{ASSETS}};

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(ASSETS))
    ); 
}); 

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(
            keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
        ))
    );
});
self.addEventListener('fetch', event => {
    const req = event.request;
    const url = new URL(req.url);

    // Hard exclusions
    if (req.method !== 'GET') return;
    if (url.pathname.startsWith('/api')) return;
    if (url.pathname.startsWith('/realtime')) return;
    if (req.headers.get('accept') === 'text/event-stream') return;

    const isJS  = url.pathname.endsWith('.js');
    const isCSS = url.pathname.endsWith('.css');
    const isHTML = req.headers.get('accept')?.includes('text/html');

    // =========================
    // NETWORK-FIRST: JS + CSS
    // =========================
    if (isJS || isCSS) {
        event.respondWith(
            fetch(req)
                .then(res => {
                    if (!res || res.status !== 200 || res.type !== 'basic') {
                        return res;
                    }

                    const clone = res.clone();
                    caches.open(CACHE_NAME).then(c => c.put(req, clone));

                    return res;
                })
                .catch(() => caches.match(req))
        );
        return;
    }

    // =========================
    // HTML: GUEST ONLY
    // =========================
    if (isHTML) {
        const isGuestShell =
            url.pathname === '/' ||
            url.pathname === '/index.html';

        if (!isGuestShell) {
            // Client/Admin HTML → NEVER cached
            console.log('here is not GuestShell...');
            event.respondWith(
                fetch(req)
                    .then(res => {
                        if (
                            !res ||
                            res.status !== 200 ||
                            res.type !== 'basic'
                        ) {
                            return res;
                        }

                        const ct = res.headers.get('content-type') || '';
                        if (!ct.includes('text/html')) {
                            return res;
                        }

                        // Prevent auth poisoning
                        if (res.headers.has('set-cookie') || res.redirected) {
                            return res;
                        }

                        const clone = res.clone();
                        caches.open(CACHE_NAME).then(c => c.put(req, clone));

                        return res;
                    })
                    .catch(() => caches.match(req))
            
            );
            return;
        }

        // Guest shell only
        event.respondWith(
            fetch(req)
                .then(res => {
                    if (
                        !res ||
                        res.status !== 200 ||
                        res.type !== 'basic'
                    ) {
                        return res;
                    }

                    const ct = res.headers.get('content-type') || '';
                    if (!ct.includes('text/html')) {
                        return res;
                    }

                    // Prevent auth poisoning
                    if (res.headers.has('set-cookie') || res.redirected) {
                        return res;
                    }

                    const clone = res.clone();
                    caches.open(CACHE_NAME).then(c => c.put(req, clone));

                    return res;
                })
                .catch(() => caches.match(req))
        );
        return;
    }

    // =========================
    // CACHE-FIRST: IMAGES, FONTS, ETC
    // =========================
    event.respondWith(
        caches.match(req).then(cached => cached || fetch(req))
    );
});

// Push notifications
self.addEventListener('push', event => {
    const data = event.data ? event.data.json() : {};
    const count = data.unreadCount ?? 0;
    const title = data.title || "WahengaPlus Alert";

    const options = {
        body: data.body || "You have a new notification",
        icon: "/vendor/ilebora/core-slim-sec/public/core/pwa/icons/icon-192.png",
        badge: "/vendor/ilebora/core-slim-sec/public/core/pwa/icons/icon-72.png",
        vibrate: [200, 100, 200],
        data: data.url || "/"
    };

    event.waitUntil(self.registration.showNotification(title, options));

    if (self.navigator && 'setAppBadge' in self.navigator) {
        self.navigator.setAppBadge(count);
    }
});

// Badge events
async function updateBadge(count) {
    if ('setAppBadge' in navigator) {
        navigator.setAppBadge(count);
    }
}

async function setAppBadge(count = 0) {
    if ('setAppBadge' in navigator) {
        try {
            if (count > 0) {
                await navigator.setAppBadge(count);
            } else {
                await navigator.clearAppBadge();
            }
            console.log("Badge updated:", count);
        } catch (e) {
            console.warn("Badge API failed:", e);
        }
    } else {
        console.log("Badging API not supported on this device.");
    }
}

self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SET_BADGE') {
        updateBadge(event.data.count || 0);
    }
});

// Notification click
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if ('clearAppBadge' in navigator) {
    navigator.clearAppBadge();
  }

  event.waitUntil(
    clients.openWindow(event.notification.data || "/")
  );
});
