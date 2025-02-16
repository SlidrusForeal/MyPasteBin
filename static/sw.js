const CACHE_NAME = 'efisbin-v2.0';
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
  '/terms'
  '/offline'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS))
      .catch(error => console.error('Cache addAll error:', error))
  );
});