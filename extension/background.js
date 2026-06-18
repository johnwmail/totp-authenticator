// TOTP Authenticator - Extension Background Script
// Handles context menus, badge updates, and installation events.

const STORAGE_KEYS = {
    plain: 'accounts',
    encrypted: 'accounts_encrypted',
    meta: 'accounts_meta'
};

// ---- Utility: parse TOTP secret from a stored account ----
function getSecretFromAccount(account) {
    // Decode base32 secret
    // Accounts are stored with the full config
    return account.secret || '';
}

// ---- Set badge with current count of accounts ----
function updateBadge() {
    try {
        const storage = chrome.storage || browser.storage;
        const storageArea = storage ? storage.local : null;

        if (!storageArea) return;

        storageArea.get(null, (result) => {
            const accounts = result[STORAGE_KEYS.plain] || [];
            const count = Array.isArray(accounts) ? accounts.length : 0;

            if (count > 0) {
                const action = chrome.action || browser.browserAction;
                if (action) {
                    action.setBadgeText({ text: String(count) });
                    action.setBadgeBackgroundColor({ color: '#1e88e5' });
                }
            }
        });
    } catch (e) {
        // Silently fail - storage API may not be available in all contexts
    }
}

// ---- Context menu for quick access ----
function createContextMenus() {
    try {
        // Remove existing menus first
        if (chrome.contextMenus) {
            chrome.contextMenus.removeAll(() => {
                chrome.contextMenus.create({
                    id: 'open-totp',
                    title: 'TOTP Authenticator',
                    contexts: ['action']
                });
            });
        }
    } catch (e) {
        // contextMenus API may not be available
    }
}

// ---- Installation handler ----
function onInstalled(details) {
    if (details.reason === 'install') {
        // Open the popup to get started
        console.log('TOTP Authenticator installed');
    } else if (details.reason === 'update') {
        console.log('TOTP Authenticator updated');
    }
    updateBadge();
}

// ---- Listeners ----
try {
    if (chrome.runtime) {
        chrome.runtime.onInstalled.addListener(onInstalled);
    }
} catch (e) {
    // runtime API may not be available in all contexts
}

// ---- Periodic badge refresh ----
try {
    if (chrome.alarms) {
        chrome.alarms.create('refreshBadge', { periodInMinutes: 1 });
        chrome.alarms.onAlarm.addListener((alarm) => {
            if (alarm.name === 'refreshBadge') {
                updateBadge();
            }
        });
    }
} catch (e) {
    // alarms API may not be available
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { updateBadge, STORAGE_KEYS };
}
