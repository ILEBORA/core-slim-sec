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
//New
self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    console.log('WORKER::',url);
    if (url.pathname.startsWith('/realtime')) return;
    if (url.pathname.startsWith('/api')) return;
    if (event.request.method !== 'GET') return;
    if (event.request.headers.get('accept') === 'text/event-stream') return;

    // Network-first for JS, CSS, HTML
    if (url.pathname.endsWith('.js') || url.pathname.endsWith('.css') || url.pathname.endsWith('.html')) {
        event.respondWith(
            fetch(event.request)
                .then(networkRes => {
                    caches.open(CACHE_NAME).then(cache => {
                        cache.put(event.request, networkRes.clone());
                    });
                    return networkRes;
                })
                .catch(() => caches.match(event.request)) // fallback offline
        );
        return;
    }

    // Cache-first for other assets
    event.respondWith(
        caches.match(event.request)
            .then(res => res || fetch(event.request))
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
