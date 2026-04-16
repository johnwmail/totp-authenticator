/**
 * Service Worker for TOTP Authenticator
 * Enables offline support and PWA installation
 */

var CACHE_NAME = 'totp-authenticator-v5';

function absoluteUrl(path) {
  return new URL(path, self.registration.scope).toString();
}

var APP_SHELL_URL = absoluteUrl('./');
var INDEX_URL = absoluteUrl('./index.html');
var SCRIPT_URL = absoluteUrl('./js/totp-auth.js');
var SCRIPT_LEGACY_URL = absoluteUrl('./js/totp-auth.js?v=21');
var QR_URL = absoluteUrl('./lib/qrcode.js');
var QR_LEGACY_URL = absoluteUrl('./lib/qrcode.js?v=21');
var APP_SHELL_ASSETS = [
  QR_URL,
  SCRIPT_URL,
  absoluteUrl('./manifest.json'),
  absoluteUrl('./favicon.ico'),
  absoluteUrl('./img/icon_128.png'),
  absoluteUrl('./img/icon_512.png')
];

function fetchAndCache(cache, request, cacheKey) {
  return fetch(new Request(request, { cache: 'reload' })).then(function(response) {
    if (!response || response.status !== 200) {
      throw new Error('Failed to fetch ' + request);
    }
    return cache.put(cacheKey || request, response.clone());
  });
}

function cacheAliases(cache, sourceKey, aliasKeys) {
  return cache.match(sourceKey).then(function(response) {
    if (!response) {
      throw new Error('Missing cached asset ' + sourceKey);
    }

    return Promise.all(aliasKeys.map(function(aliasKey) {
      return cache.put(aliasKey, response.clone());
    }));
  });
}

function getCacheKey(url) {
  if (url.pathname === '/' || url.pathname === '/index.html') {
    return APP_SHELL_URL;
  }
  if (url.pathname === '/js/totp-auth.js') {
    return SCRIPT_URL;
  }
  if (url.pathname === '/lib/qrcode.js') {
    return QR_URL;
  }
  return url.toString();
}

// Install event - cache assets
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return fetchAndCache(cache, APP_SHELL_URL, APP_SHELL_URL)
        .then(function() {
          return cacheAliases(cache, APP_SHELL_URL, [INDEX_URL]);
        })
        .then(function() {
          return Promise.all(APP_SHELL_ASSETS.map(function(asset) {
            return fetchAndCache(cache, asset, asset);
          }));
        })
        .then(function() {
          return Promise.all([
            cacheAliases(cache, SCRIPT_URL, [SCRIPT_LEGACY_URL]),
            cacheAliases(cache, QR_URL, [QR_LEGACY_URL])
          ]);
        });
    })
  );
  // Force activation
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.map(function(cacheName) {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', function(event) {
  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // Skip cross-origin requests
  var requestUrl = new URL(event.request.url);
  if (requestUrl.origin !== location.origin) {
    return;
  }

  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then(function(response) {
          if (response && response.status === 200) {
            var responseToCache = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(APP_SHELL_URL, responseToCache);
              cache.put(INDEX_URL, response.clone());
            });
          }
          return response;
        })
        .catch(function() {
          return caches.match(APP_SHELL_URL);
        })
    );
    return;
  }

  event.respondWith(
    caches.match(getCacheKey(requestUrl))
      .then(function(response) {
        // Cache hit - return response
        if (response) {
          return response;
        }

        // Not in cache - fetch from network
        return fetch(event.request).then(function(response) {
          // Check if valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          // Clone the response
          var responseToCache = response.clone();
          var cacheKey = getCacheKey(requestUrl);

          caches.open(CACHE_NAME)
            .then(function(cache) {
              cache.put(cacheKey, responseToCache);
            });

          return response;
        });
      })
      .catch(function(err) {
        console.log('Fetch error:', err);
        return caches.match(getCacheKey(requestUrl));
      })
  );
});
