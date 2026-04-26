(() => {
    // Wire up lock screen unlock button
    // lockScreenUnlock is handled inside totp-auth.js init()
    const keysController = new totpAuth.KeysController();
    keysController.init();
})();

// Register service worker for PWA support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker
            .register('./sw.js')
            .then(registration => {
                console.log('ServiceWorker registration successful:', registration.scope);
            })
            .catch(err => {
                console.log('ServiceWorker registration failed:', err);
            });
    });
}
