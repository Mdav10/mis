// MIS service worker v21 — minimal, correct, installable
const CACHE = "mis-v21";
const PRECACHE = ["/", "/offline"];

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE).catch(() => {}))
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

  // Never intercept these — let the browser/network handle
  if (url.pathname.startsWith("/media/") ||
      url.pathname.startsWith("/static/") ||
      url.pathname.startsWith("/icon-") ||
      url.pathname.endsWith(".pdf") ||
      url.pathname.endsWith(".misbak") ||
      url.pathname === "/manifest.json" ||
      url.pathname === "/service-worker.js" ||
      url.pathname.startsWith("/pwa-check")) {
    return;
  }

  event.respondWith(
    fetch(req).catch(() => {
      if (req.mode === "navigate") {
        return caches.match("/offline").then((r) => r || caches.match("/"));
      }
      return caches.match(req);
    })
  );
});
