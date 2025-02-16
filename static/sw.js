const CACHE_NAME = 'efisbin-v2.1';
const OFFLINE_URL = '/offline';
const ASSETS = [
  '/',
  '/static/css/theme.css',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/static/favicon.ico',
  '/static/site.webmanifest',
  '/login',
  '/register',
  '/privacy',
  '/terms',
  '/offline'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS))
      .catch(error => console.error('Cache addAll error:', error))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) return response;
        return fetch(event.request)
          .catch(() => caches.match(OFFLINE_URL))
      })
  );
});