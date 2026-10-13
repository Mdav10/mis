// MIS service worker v20 — offline fallback
const CACHE = "mis-v20";
const OFFLINE_URL = "/offline";

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll([OFFLINE_URL]))
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Never intercept API / media / dynamic routes
  if (url.pathname.startsWith("/media/") ||
      url.pathname.startsWith("/cases/") ||
      url.pathname.startsWith("/add") ||
      url.pathname.startsWith("/offline") ||
      url.pathname.endsWith(".pdf") ||
      url.pathname.endsWith(".misbak")) {
    return;
  }
  // Network-first, fall back to offline page on HTML navigations
  event.respondWith(
    fetch(req).catch(() => {
      if (req.mode === "navigate") {
        return caches.match(OFFLINE_URL);
      }
      return caches.match(req);
    })
  );
});
