// Only these public, static assets are eligible for an offline cache. Never
// intercept navigation, share links, uploads, downloads, or API requests.
const CACHE_PREFIX = 'okuru-static-';
const CACHE_NAME = `${CACHE_PREFIX}v1`;
const ASSETS = new Map([
  ['/css/bootstrap.min.css', 'css'],
  ['/css/all.min.css', 'css'],
  ['/css/custom.css', 'css'],
  ['/scripts/bootstrap.min.js', 'js'],
  ['/scripts/clipboard.min.js', 'js'],
  ['/scripts/purify.min.js', 'js'],
]);

// Cache Storage does not enforce HTTP freshness or revalidation directives.
// Bypass storage and offline reuse when validation is required or forbidden.
function prohibitsOfflineReuse(headers) {
  const cacheControl = headers.get('Cache-Control') || '';
  const pragma = headers.get('Pragma') || '';
  return /(?:^|,)\s*(?:no-cache|no-store|private|must-revalidate|proxy-revalidate)(?:\s|=|,|$)/i.test(cacheControl) ||
    /(?:^|,)\s*no-cache(?:\s|,|$)/i.test(pragma);
}

function cacheable(response, kind) {
  if (response.status !== 200 || response.type !== 'basic' || response.redirected || prohibitsOfflineReuse(response.headers)) return false;
  const mime = (response.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
  return kind === 'css' ? mime === 'text/css' : /^(?:text|application)\/(?:java|ecma)script$/.test(mime);
}

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((names) => Promise.all(
    names.filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
      .map((name) => caches.delete(name))
  )));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET' || request.mode === 'navigate' || request.cache !== 'default' ||
      prohibitsOfflineReuse(request.headers) || request.headers.has('Authorization') ||
      ['Range', 'If-Range', 'If-Match', 'If-None-Match', 'If-Modified-Since', 'If-Unmodified-Since']
        .some((name) => request.headers.has(name))) return;
  const url = new URL(request.url);
  const kind = ASSETS.get(url.pathname);
  if (url.origin !== self.location.origin || url.href.includes('?') || !kind) return;

  event.respondWith((async () => {
    try {
      const response = await fetch(request);
      try {
        if (cacheable(response, kind)) {
          const cache = await caches.open(CACHE_NAME);
          await cache.put(request, response.clone());
        } else if (prohibitsOfflineReuse(response.headers)) {
          // Discard an old copy when the server now forbids offline reuse.
          const cache = await caches.open(CACHE_NAME);
          await cache.delete(request);
        }
      } catch (_) {
        // Cache failures must not hide a successful network response.
      }
      return response;
    } catch (networkError) {
      try {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match(request);
        if (cached && cacheable(cached, kind)) return cached;
      } catch (_) {
        // Preserve the original network failure if cache access also fails.
      }
      throw networkError;
    }
  })());
});
