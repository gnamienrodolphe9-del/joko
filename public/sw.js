// Service worker JOKO : rend l'application installable et lisible hors ligne (coque de l'application).
const CACHE = 'joko-v2';
const COQUE = ['/', '/manifest.json', '/icon.svg', '/icon-192.png', '/icon-512.png'];
self.addEventListener('install', (evenement) => { evenement.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(COQUE))); self.skipWaiting(); });
self.addEventListener('activate', (evenement) => {
  evenement.waitUntil(caches.keys().then((noms) => Promise.all(noms.filter((nom) => nom !== CACHE).map((nom) => caches.delete(nom)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (evenement) => {
  const adresse = new URL(evenement.request.url);
  if (evenement.request.method !== 'GET' || adresse.pathname.startsWith('/api')) return; // l'API n'est jamais mise en cache
  evenement.respondWith(fetch(evenement.request).then((reponse) => {
    if (reponse.ok && adresse.origin === location.origin) { const copie = reponse.clone(); caches.open(CACHE).then((cache) => cache.put(evenement.request, copie)); }
    return reponse;
  }).catch(() => caches.match(evenement.request).then((enCache) => enCache || (evenement.request.mode === 'navigate' ? caches.match('/') : undefined))));
});
