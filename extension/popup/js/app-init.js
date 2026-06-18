(() => {
    // Wire up lock screen unlock button
    const keysController = new totpAuth.KeysController();
    keysController.init();
})();
