/* =========================================
   SHELFSENSE AI — Service Worker
   Enables offline support and caching
========================================= */

const CACHE_NAME = "shelfsense-v1";
const STATIC_ASSETS = [
  "/landing.html",
  "/login.html",
  "/register.html",
  "/style.css",
  "/theme.js",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png"
];

/* ===== INSTALL — cache static assets ===== */
self.addEventListener("install", event => {
  console.log("🔧 ShelfSense SW: Installing...");
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log("📦 ShelfSense SW: Caching static assets");
      return cache.addAll(STATIC_ASSETS.map(url => new Request(url, { cache: "reload" })));
    }).catch(err => {
      console.log("SW cache error (non-fatal):", err);
    })
  );
  self.skipWaiting();
});

/* ===== ACTIVATE — clean old caches ===== */
self.addEventListener("activate", event => {
  console.log("✅ ShelfSense SW: Activated");
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))
    )
  );
  self.clients.claim();
});

/* ===== FETCH — network first, cache fallback ===== */
self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);

  // Skip non-GET, API calls, and external resources
  if (event.request.method !== "GET") return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/")) return;
  if (!url.origin.includes(self.location.origin)) return;

  // API routes — network only (always fresh data)
  const apiRoutes = ["/shop-items", "/admin-data", "/my-orders", "/login", "/logout",
    "/login-store", "/checkout", "/register-store", "/signup", "/verify-otp"];
  if (apiRoutes.some(route => url.pathname.startsWith(route))) return;

  // HTML pages and static assets — network first, cache fallback
  event.respondWith(
    fetch(event.request)
      .then(response => {
        if (response && response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, responseClone));
        }
        return response;
      })
      .catch(() => {
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          // Offline fallback for HTML pages
          if (event.request.headers.get("accept")?.includes("text/html")) {
            return caches.match("/landing.html");
          }
        });
      })
  );
});

/* ===== PUSH NOTIFICATIONS (future) ===== */
self.addEventListener("push", event => {
  if (!event.data) return;
  const data = event.data.json();
  self.registration.showNotification(data.title || "ShelfSense AI", {
    body: data.body || "You have a new notification",
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    tag: "shelfsense-notification",
    data: { url: data.url || "/" }
  });
});

self.addEventListener("notificationclick", event => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data?.url || "/"));
});