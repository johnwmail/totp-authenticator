(function() {
    // Wire up lock screen unlock button
    // lockScreenUnlock is handled inside totp-auth.js init()
    var keysController = new totpAuth.KeysController();
    keysController.init();
})();

// Register service worker for PWA support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('./sw.js')
            .then(function(registration) {
                console.log('ServiceWorker registration successful:', registration.scope);
            })
            .catch(function(err) {
                console.log('ServiceWorker registration failed:', err);
            });
    });
}
