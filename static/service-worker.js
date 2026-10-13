// MIS service worker v23 — offline persistence + last-page resume
const CACHE = "mis-v23";
const OFFLINE_URL = "/offline";
const PRECACHE = [OFFLINE_URL, "/", "/static/style.css"];

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      Promise.all(PRECACHE.map(u => cache.add(u).catch(() => {})))
    )
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Don't intercept these
  if (url.pathname.startsWith("/media/") ||
      url.pathname.endsWith(".pdf") ||
      url.pathname.endsWith(".misbak") ||
      url.pathname === "/manifest.json" ||
      url.pathname === "/service-worker.js" ||
      url.pathname.startsWith("/pwa-check")) {
    return;
  }

  // Page navigations — network first, cache fallback, then offline page
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          // Cache the last page the user saw
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() =>
          caches.match(req).then((cached) => cached || caches.match(OFFLINE_URL))
        )
    );
    return;
  }

  // Static assets — cache first, then network
  if (url.pathname.startsWith("/static/") || url.pathname.startsWith("/icon-")) {
    event.respondWith(
      caches.match(req).then((cached) =>
        cached || fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
      )
    );
    return;
  }

  // Everything else — network first, cache fallback
  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req))
  );
});
