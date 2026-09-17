// MIS service worker — minimal offline shell
const CACHE = "mis-v4";
const SHELL = [
  "/static/style.css",
  "/static/icons/icon-192.png",
];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(()=>{}));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Never cache dynamic pages or media
  if (url.pathname.startsWith("/media/") ||
      url.pathname === "/" ||
      url.pathname.startsWith("/dashboard") ||
      url.pathname.startsWith("/cases") ||
      url.pathname.startsWith("/add") ||
      url.pathname.startsWith("/manifest.json") ||
      url.pathname.startsWith("/service-worker.js")) {
    return;
  }
  // Cache-first for static assets
  if (url.pathname.startsWith("/static/")) {
    e.respondWith(
      caches.match(req).then(hit => hit || fetch(req).then(res => {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(req, clone));
        return res;
      }).catch(() => hit))
    );
  }
});
