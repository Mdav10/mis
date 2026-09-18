// MIS service worker v10 — self-destruct + network-first
self.addEventListener("install", e => {
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);

  // Never intercept media, downloads, or API
  if (url.pathname.startsWith("/media/") ||
      url.pathname.startsWith("/cases/") ||
      url.pathname.startsWith("/add") ||
      url.pathname.endsWith(".pdf")) {
    return;
  }

  // Network-first — always try fresh, fall back to cache only if offline
  e.respondWith(
    fetch(req).catch(() => caches.match(req))
  );
});
