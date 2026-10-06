/* =============================================================================
   SERVICE WORKER — INPTIC Campus
   ============================================================================= */
const VERSION = "campus-inptic-v13";
const STATIC_CACHE = VERSION + "-static";
const FONT_CACHE = VERSION + "-fonts";
const BADGE_CACHE = "badge-counter";

const ASSETS = [
  "./", "./index.html", "./manifest.json",
  "./favicon-32.png", "./apple-touch-icon.png",
  "./icon-192.png", "./icon-512.png", "./icon-512-maskable.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) =>
        Promise.all(
          keys.filter((k) => k !== STATIC_CACHE && k !== FONT_CACHE && k !== BADGE_CACHE)
              .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

/* ============================= BADGE COUNTER ============================= */
async function getBadgeCount() {
  try {
    const cache = await caches.open(BADGE_CACHE);
    const res = await cache.match("/badge-count");
    if (!res) return 0;
    const n = parseInt(await res.text(), 10);
    return isNaN(n) ? 0 : n;
  } catch (e) { return 0; }
}
async function setBadgeCount(n) {
  try {
    const cache = await caches.open(BADGE_CACHE);
    await cache.put("/badge-count", new Response(String(n)));
  } catch (e) {}
}
async function clearBadgeCount() {
  try {
    const cache = await caches.open(BADGE_CACHE);
    await cache.delete("/badge-count");
  } catch (e) {}
}
async function applyAppBadge(n) {
  try {
    if ("setAppBadge" in self.navigator) {
      if (n > 0) await self.navigator.setAppBadge(n);
      else await self.navigator.clearAppBadge();
    }
  } catch (e) {}
}

/* ============================= FETCH ============================= */
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);

  /* 1. Polices Google : cache-first */
  if (url.hostname === "fonts.googleapis.com" || url.hostname === "fonts.gstatic.com") {
    event.respondWith(
      caches.open(FONT_CACHE).then((cache) =>
        cache.match(req).then((cached) => {
          if (cached) return cached;
          return fetch(req).then((res) => {
            if (res && (res.status === 200 || res.type === "opaque")) cache.put(req, res.clone());
            return res;
          });
        })
      ).catch(() => fetch(req))
    );
    return;
  }

  /* 2. Autres origines : ne pas intercepter */
  if (url.origin !== self.location.origin) return;

  /* 3. ⚠️ API : NE JAMAIS METTRE EN CACHE (critique pour les PDF) */
  if (url.pathname.startsWith("/api/")) return;

  /* 4. Navigation : network-first avec fallback index.html */
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(STATIC_CACHE).then((cache) => cache.put("./index.html", copy));
          }
          return res;
        })
        .catch(() => caches.match("./index.html").then((c) => c || caches.match("./")))
    );
    return;
  }

  /* 5. Assets statiques : cache-first + maj arrière-plan */
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(STATIC_CACHE).then((cache) => cache.put(req, copy));
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});

/* ============================= PUSH ============================= */
self.addEventListener("push", (event) => {
  let data = {
    title: "INPTIC", body: "Nouvelle publication disponible.",
    url: "/", tag: "inptic-notif", badgeCount: null
  };
  if (event.data) {
    try { data = Object.assign(data, event.data.json()); }
    catch (e) { data.body = event.data.text(); }
  }
  event.waitUntil((async () => {
    try {
      let next;
      if (typeof data.badgeCount === "number" && data.badgeCount >= 0) next = data.badgeCount;
      else { const current = await getBadgeCount(); next = current + 1; }
      await setBadgeCount(next);
      await applyAppBadge(next);
    } catch (e) {}
    try {
      await self.registration.showNotification(data.title, {
        body: data.body, icon: "/icon-192.png", badge: "/favicon-32.png",
        tag: data.tag || "inptic-" + Date.now(),
        data: { url: data.url || "/" },
        vibrate: [100, 50, 100], requireInteraction: false, renotify: true
      });
    } catch (e) {}
    try {
      const clientsList = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      clientsList.forEach(c => c.postMessage({
        type: "push-received",
        notif: { id: "push-" + Date.now(), title: data.title, text: data.body, url: data.url }
      }));
    } catch (e) {}
  })());
});

/* ============================= CLIC NOTIFICATION ============================= */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    try { await clearBadgeCount(); await applyAppBadge(0); } catch (e) {}
    const url = (event.notification.data && event.notification.data.url) || "/";
    const clientsList = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of clientsList) {
      if (c.url.includes(self.location.origin) && "focus" in c) {
        c.navigate(url);
        return c.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(url);
  })());
});

/* ============================= MESSAGE ============================= */
self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data.type === "clear-badge") {
    event.waitUntil((async () => { await clearBadgeCount(); await applyAppBadge(0); })());
  }
  if (data.type === "set-badge") {
    const n = parseInt(data.count, 10) || 0;
    event.waitUntil((async () => { await setBadgeCount(n); await applyAppBadge(n); })());
  }
  if (data.type === "skip-waiting") { self.skipWaiting(); }
});