// TOTP Authenticator - Extension Background Script
// Compatible with Chrome MV3 and Firefox MV2

// Cross-browser API detection
const api = (() => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return chrome;  // Chrome, Edge, Brave (MV3)
    }
    if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.id) {
        return browser;  // Firefox (MV2)
    }
    // Fallback for testing
    return { storage: { local: { get: () => {}, set: () => {} } }, runtime: {}, alarms: {} };
})();

// ---- Set badge with current count of accounts ----
function updateBadge() {
    try {
        api.storage.local.get(null, (result) => {
            if (api.runtime.lastError) return;

            const accounts = result && result['accounts'];
            const count = Array.isArray(accounts) ? accounts.length : 0;

            const action = api.action || api.browserAction;
            if (action) {
                action.setBadgeText({ text: count > 0 ? String(count) : '' });
                action.setBadgeBackgroundColor({ color: '#1e88e5' });
            }
        });
    } catch (e) {
        // Silently fail during development/testing
    }
}

// ---- Installation handler ----
function onInstalled(details) {
    console.log('TOTP Authenticator ' + (details.reason === 'install' ? 'installed' : 'updated'));
    updateBadge();
}

// ---- Listeners ----
try {
    api.runtime.onInstalled.addListener(onInstalled);
} catch (e) {
    // runtime API may not be available in all contexts
}

// ---- Periodic badge refresh ----
try {
    api.alarms.create('refreshBadge', { periodInMinutes: 1 });
    api.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === 'refreshBadge') {
            updateBadge();
        }
    });
} catch (e) {
    // alarms API may not be available
}

// Export for testing (Node.js)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { updateBadge };
}
