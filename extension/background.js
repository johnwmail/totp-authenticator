// TOTP Authenticator - Extension Background Script
// Compatible with Chrome MV3 and Firefox MV3

// ---- Set badge with current count of accounts ----
function updateBadge() {
    try {
        chrome.storage.local.get(null, (result) => {
            if (chrome.runtime.lastError) return;

            const accounts = result && result['accounts'];
            const count = Array.isArray(accounts) ? accounts.length : 0;

            chrome.action.setBadgeText({ text: count > 0 ? String(count) : '' });
            chrome.action.setBadgeBackgroundColor({ color: '#1e88e5' });
        });
    } catch (e) {
        // Silently fail during development/testing
    }
}

// ---- Installation handler ----
chrome.runtime.onInstalled.addListener((details) => {
    console.log('TOTP Authenticator ' + (details.reason === 'install' ? 'installed' : 'updated'));
    updateBadge();
});

// ---- Periodic badge refresh ----
chrome.alarms.create('refreshBadge', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'refreshBadge') {
        updateBadge();
    }
});

// Export for testing (Node.js)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { updateBadge };
}
