// Authenticator — per-account TOTP with configurable algorithm/period/digits
// Uses native Web Crypto API (no external dependencies for crypto)
// Based on original work by Gerard Braad (GPL-3.0)
/* eslint-disable no-use-before-define */

(function (exports) {
    'use strict';

    const DEFAULTS = {
        algorithm: 'SHA-1',
        period: 30,
        digits: 6
    };

    function escapeHtml(str) {
        if (!str) {
            return '';
        }
        return String(str).replace(/[&<>"']/g, c => {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    // ---- Storage with optional AES-GCM encryption ----
    const StorageService = function () {
        const KEYS = {
            plain: 'accounts',
            encrypted: 'accounts_encrypted',
            meta: 'accounts_meta'
        };
        let aesKey = null; // derived CryptoKey when unlocked

        function isSupported() {
            return typeof Storage !== 'undefined';
        }

        function getPlain(k) {
            const v = localStorage.getItem(k);
            return v && JSON.parse(v);
        }
        function setPlain(k, v) {
            localStorage.setItem(k, JSON.stringify(v));
        }

        function isEncrypted() {
            return !!localStorage.getItem(KEYS.meta);
        }
        function isUnlocked() {
            return !!aesKey;
        }

        function randomBytes(n) {
            const b = new Uint8Array(n);
            crypto.getRandomValues(b);
            return b;
        }
        function bufToBase64(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)));
        }
        function base64ToBuf(b64) {
            const s = atob(b64);
            const b = new Uint8Array(s.length);
            for (let i = 0; i < s.length; i++) {
                b[i] = s.charCodeAt(i);
            }
            return b;
        }

        async function deriveKey(password, salt, iterations) {
            iterations = iterations || 310000;
            const enc = new TextEncoder();
            const baseKey = await crypto.subtle.importKey(
                'raw',
                enc.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        }

        async function encrypt(data, key) {
            const iv = randomBytes(12);
            const enc = new TextEncoder();
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(JSON.stringify(data))
            );
            return { iv: bufToBase64(iv), ct: bufToBase64(ct) };
        }

        async function decrypt(payload, key) {
            const iv = base64ToBuf(payload.iv);
            const ct = base64ToBuf(payload.ct);
            const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
            return JSON.parse(new TextDecoder().decode(plain));
        }

        async function setPassword(password) {
            const accounts = await getAccounts();
            if (!password) {
                // Remove encryption
                aesKey = null;
                localStorage.removeItem(KEYS.encrypted);
                localStorage.removeItem(KEYS.meta);
                setPlain(KEYS.plain, accounts);
                return;
            }
            const salt = randomBytes(16);
            const iterations = 310000;
            aesKey = await deriveKey(password, salt, iterations);
            const meta = { salt: bufToBase64(salt), iter: iterations };
            localStorage.setItem(KEYS.meta, JSON.stringify(meta));
            localStorage.removeItem(KEYS.plain);
            const payload = await encrypt(accounts, aesKey);
            localStorage.setItem(KEYS.encrypted, JSON.stringify(payload));
        }

        async function unlock(password) {
            const metaStr = localStorage.getItem(KEYS.meta);
            if (!metaStr) {
                return true;
            } // not encrypted
            const meta = JSON.parse(metaStr);
            const salt = base64ToBuf(meta.salt);
            try {
                const key = await deriveKey(password, salt, meta.iter);
                const payloadStr = localStorage.getItem(KEYS.encrypted);
                if (!payloadStr) {
                    aesKey = key;
                    return true;
                }
                await decrypt(JSON.parse(payloadStr), key); // test decrypt
                aesKey = key;
                return true;
            } catch (e) {
                return false;
            }
        }

        function lock() {
            aesKey = null;
        }

        async function getAccounts() {
            if (isEncrypted()) {
                if (!aesKey) {
                    return null;
                } // locked
                const payloadStr = localStorage.getItem(KEYS.encrypted);
                if (!payloadStr) {
                    return [];
                }
                try {
                    return await decrypt(JSON.parse(payloadStr), aesKey);
                } catch (e) {
                    return null;
                }
            }
            return getPlain(KEYS.plain) || [];
        }

        async function saveAccounts(accounts) {
            if (isEncrypted() && aesKey) {
                const payload = await encrypt(accounts, aesKey);
                localStorage.setItem(KEYS.encrypted, JSON.stringify(payload));
                localStorage.removeItem(KEYS.plain);
            } else {
                setPlain(KEYS.plain, accounts);
            }
        }

        function resetAll() {
            localStorage.removeItem(KEYS.plain);
            localStorage.removeItem(KEYS.encrypted);
            localStorage.removeItem(KEYS.meta);
            aesKey = null;
        }

        function hasAnyData() {
            return !!(localStorage.getItem(KEYS.plain) || localStorage.getItem(KEYS.encrypted));
        }

        return {
            isSupported: isSupported,
            isEncrypted: isEncrypted,
            isUnlocked: isUnlocked,
            setPassword: setPassword,
            unlock: unlock,
            lock: lock,
            getAccounts: getAccounts,
            saveAccounts: saveAccounts,
            resetAll: resetAll,
            hasAnyData: hasAnyData,
            // Legacy compat
            getObject: getPlain,
            setObject: setPlain
        };
    };

    // ---- TOTP (native Web Crypto API) ----
    const KeyUtilities = function () {
        const dec2hex = function (s) {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
        };
        const hex2dec = function (s) {
            return parseInt(s, 16);
        };
        const leftpad = function (str, len, pad) {
            if (len + 1 >= str.length) {
                str = new Array(len + 1 - str.length).join(pad) + str;
            }
            return str;
        };
        const base32tohex = function (b32) {
            const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let bits = '';
            let hex = '';
            for (let i = 0; i < b32.length; i++) {
                const v = c.indexOf(b32.charAt(i).toUpperCase());
                if (v >= 0) {
                    bits += leftpad(v.toString(2), 5, '0');
                }
            }
            for (let j = 0; j + 4 <= bits.length; j += 4) {
                hex += parseInt(bits.substring(j, j + 4), 2).toString(16);
            }
            return hex;
        };
        const hexToUint8Array = function (hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
            }
            return bytes;
        };

        return {
            generate: async function (secret, opts) {
                opts = opts || {};
                const algo = opts.algorithm || DEFAULTS.algorithm;
                const period = opts.period || DEFAULTS.period;
                const digits = opts.digits || DEFAULTS.digits;
                let key = base32tohex(secret);
                if (key.length % 2 !== 0) {
                    key += '0';
                }
                const epoch = opts.epoch || Math.round(Date.now() / 1000);
                const time = leftpad(dec2hex(Math.floor(epoch / period)), 16, '0');

                const keyBytes = hexToUint8Array(key);
                const timeBytes = hexToUint8Array(time);

                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'HMAC', hash: { name: algo } },
                    false,
                    ['sign']
                );
                const sig = await crypto.subtle.sign('HMAC', cryptoKey, timeBytes);
                const hmacBytes = new Uint8Array(sig);

                let hmac = '';
                for (let i = 0; i < hmacBytes.length; i++) {
                    hmac += ('0' + hmacBytes[i].toString(16)).slice(-2);
                }

                const off = hex2dec(hmac.substring(hmac.length - 1));
                const otp =
                    (hex2dec(hmac.substring(off * 2, off * 2 + 8)) & hex2dec('7fffffff')) + '';
                return leftpad(otp.substring(otp.length - digits), digits, '0');
            }
        };
    };

    // ---- Helpers ----

    function generateRandomSecret(length) {
        length = length || 32;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const arr = new Uint8Array(length);
        crypto.getRandomValues(arr);
        let secret = '';
        for (let i = 0; i < length; i++) {
            secret += chars[arr[i] % 32];
        }
        return secret;
    }

    let clipboardClearTimer = null;
    let lastCopiedValue = null;

    function copyToClipboard(text, el) {
        navigator.clipboard.writeText(text).then(() => {
            el.classList.add('copied');
            setTimeout(() => {
                el.classList.remove('copied');
            }, 1200);
            lastCopiedValue = text;
            if (clipboardClearTimer) {
                clearTimeout(clipboardClearTimer);
            }
            // Clear clipboard after 30 seconds for security (only if value is unchanged)
            clipboardClearTimer = setTimeout(() => {
                if (!navigator.clipboard.readText) {
                    showToast('Clipboard auto-clear unavailable');
                    return;
                }
                navigator.clipboard
                    .readText()
                    .then(currentValue => {
                        if (currentValue === lastCopiedValue) {
                            navigator.clipboard
                                .writeText('')
                                .then(() => {
                                    showToast('Clipboard cleared');
                                })
                                .catch(() => {
                                    showToast('Clipboard clear attempted');
                                });
                        }
                    })
                    .catch(() => {
                        showToast('Clipboard auto-clear unavailable');
                    });
            }, 30000);
        });
    }

    function showToast(message) {
        // Remove existing toast if any
        const existingToast = document.querySelector('.toast');
        if (existingToast) {
            existingToast.remove();
        }
        // Create toast element
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        toast.setAttribute('aria-atomic', 'true');
        toast.textContent = message;
        document.body.appendChild(toast);
        // Trigger reflow for animation
        void toast.offsetWidth;
        toast.classList.add('show');
        // Auto-remove after 2 seconds
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                toast.remove();
            }, 300);
        }, 2000);
    }

    // Parse otpauth:// URI
    function parseOtpauth(uri) {
        uri = uri.trim();
        if (uri.indexOf('otpauth://') !== 0) {
            return null;
        }
        try {
            const url = new URL(uri);
            const path = decodeURIComponent(url.pathname);
            let name = path
                .replace(/^\/totp\//, '')
                .replace(/^\/hotp\//, '')
                .replace(/^\//, '');
            const issuer = url.searchParams.get('issuer');
            if (issuer && name.indexOf(issuer + ':') === 0) {
                name = `${issuer} (${name.substring(issuer.length + 1).trim()})`;
            } else if (issuer && issuer !== name && name.indexOf(':') === -1) {
                name = `${issuer} (${name})`;
            }
            const secret = (url.searchParams.get('secret') || '').toUpperCase().replace(/\s/g, '');
            const algoParam = (url.searchParams.get('algorithm') || '')
                .toUpperCase()
                .replace('-', '');
            let algorithm = DEFAULTS.algorithm;
            if (algoParam === 'SHA1') {
                algorithm = 'SHA-1';
            }
            if (algoParam === 'SHA256') {
                algorithm = 'SHA-256';
            }
            if (algoParam === 'SHA512') {
                algorithm = 'SHA-512';
            }
            const period = parseInt(url.searchParams.get('period'), 10) || DEFAULTS.period;
            const digits = parseInt(url.searchParams.get('digits'), 10) || DEFAULTS.digits;
            return {
                name: name,
                secret: secret,
                algorithm: algorithm,
                period: period,
                digits: digits,
                issuer: issuer || ''
            };
        } catch (e) {
            return null;
        }
    }

    exports.parseOtpauth = parseOtpauth;

    function looksLikeHtmlDocument(text) {
        return /^\s*<(?:!doctype|html)\b/i.test(text);
    }

    // ---- Controller ----
    const KeysController = function () {
        let store,
            keys,
            editing = false;
        let editIndex = -1;
        let renderToken = 0;
        let tickTimer = null;
        let lastRenderedAt = 0;
        let lastCodeStepByIndex = {};

        const $ = function (sel) {
            return document.querySelector(sel);
        };

        const startTicker = function () {
            if (tickTimer) {
                clearInterval(tickTimer);
            }
            tickTimer = setInterval(tick, 1000);
        };

        const stopTicker = function () {
            if (tickTimer) {
                clearInterval(tickTimer);
            }
            tickTimer = null;
        };

        const addFallbackAccount = async function () {
            const accounts = await store.getAccounts();
            if (accounts === null || accounts.length > 0) {
                return;
            }
            await store.saveAccounts([
                {
                    name: 'demo@example.com',
                    secret: generateRandomSecret(),
                    algorithm: DEFAULTS.algorithm,
                    period: DEFAULTS.period,
                    digits: DEFAULTS.digits,
                    url: 'https://github.com',
                    issuer: 'Github'
                }
            ]);
            await render();
        };

        const stripJsonComments = function (text) {
            return text.replace(/^\s*\/\/.*$/gm, '').replace(/^\s*#.*$/gm, '');
        };

        const loadDefaultAccounts = async function () {
            try {
                let existing = await store.getAccounts();
                if (existing === null || existing.length > 0) {
                    return;
                }

                if (typeof navigator !== 'undefined' && navigator.onLine === false) {
                    await addFallbackAccount();
                    return;
                }

                const res = await fetch('accounts.json');
                if (!res.ok) {
                    throw new Error('not found');
                }

                const text = await res.text();
                if (looksLikeHtmlDocument(text)) {
                    throw new Error('not json');
                }
                const arr = JSON.parse(stripJsonComments(text));
                if (!arr || !Array.isArray(arr) || arr.length === 0) {
                    throw new Error('empty');
                }

                const imported = [];
                for (let i = 0; i < arr.length; i++) {
                    const item = arr[i];
                    if (item.secret) {
                        imported.push({
                            name: item.name || 'Imported',
                            secret: item.secret,
                            algorithm: item.algorithm || DEFAULTS.algorithm,
                            period: item.period || DEFAULTS.period,
                            digits: item.digits || DEFAULTS.digits,
                            url: item.url || '',
                            issuer: item.issuer || ''
                        });
                    } else if (item.otpauth) {
                        const parsed = parseOtpauth(item.otpauth);
                        if (parsed) {
                            imported.push({
                                name: parsed.name,
                                secret: parsed.secret,
                                algorithm: parsed.algorithm,
                                period: parsed.period,
                                digits: parsed.digits,
                                url: '',
                                issuer: parsed.issuer
                            });
                        }
                    }
                }

                if (imported.length === 0) {
                    await addFallbackAccount();
                    return;
                }

                existing = await store.getAccounts();
                if (existing === null || existing.length > 0) {
                    return;
                }
                await store.saveAccounts(imported);
                await render();
            } catch (e) {
                await addFallbackAccount();
            }
        };

        const init = async function () {
            store = new StorageService();
            keys = new KeyUtilities();

            if (!store.isSupported()) {
                return;
            }

            // Bind UI
            $('#editBtn').addEventListener('click', toggleEdit);
            $('#exportBtn').addEventListener('click', exportAccounts);
            $('#importBtn').addEventListener('click', () => {
                $('#importFile').click();
            });
            $('#importFile').addEventListener('change', importAccounts);
            $('#resetBtn').addEventListener('click', resetAccounts);
            $('#addBtn').addEventListener('click', () => {
                $('#keySecret').value = generateRandomSecret();
                $('#addModal').classList.add('open');
            });
            $('#regenSecret').addEventListener('click', () => {
                $('#keySecret').value = generateRandomSecret();
            });
            $('#addKeyCancel').addEventListener('click', closeModal);
            $('#addKeyButton').addEventListener('click', onSave);
            $('#addModal').addEventListener('click', e => {
                if (e.target === $('#addModal')) {
                    closeModal();
                }
            });

            // QR modal
            $('#qrClose').addEventListener('click', closeQR);
            $('#qrModal').addEventListener('click', e => {
                if (e.target === $('#qrModal')) {
                    closeQR();
                }
            });

            // Encryption UI
            $('#lockScreenUnlock').addEventListener('click', () => {
                openPasswordModal('unlock');
            });
            $('#lockBtn').addEventListener('click', onLockToggle);
            $('#passwordModal').addEventListener('click', e => {
                if (e.target === $('#passwordModal')) {
                    closePasswordModal();
                }
            });
            $('#pwCancel').addEventListener('click', closePasswordModal);
            $('#pwSubmit').addEventListener('click', onPasswordSubmit);
            $('#pwInput').addEventListener('keydown', e => {
                if (e.key === 'Enter') {
                    onPasswordSubmit();
                }
            });
            $('#setPwModal').addEventListener('click', e => {
                if (e.target === $('#setPwModal')) {
                    closeSetPwModal();
                }
            });
            $('#setPwCancel').addEventListener('click', closeSetPwModal);
            $('#setPwSubmit').addEventListener('click', onSetPasswordSubmit);

            // Dark mode toggle
            $('#themeBtn').addEventListener('click', toggleTheme);
            applyTheme();

            // Check encryption state
            if (store.isEncrypted()) {
                stopTicker();
                showLockScreen();
            } else {
                if (!store.hasAnyData()) {
                    await loadDefaultAccounts();
                }
                await render();
                startTicker();
            }
        };

        // ---- Theme (auto-detect by local time: 08:00–22:00 = light) ----
        let manualTheme = null; // manual override for current session

        const getTimeBasedTheme = function () {
            const hour = new Date().getHours();
            return hour >= 8 && hour < 22 ? 'light' : 'dark';
        };

        const toggleTheme = function () {
            const current =
                document.documentElement.getAttribute('data-theme') || getTimeBasedTheme();
            manualTheme = current === 'dark' ? 'light' : 'dark';
            applyTheme();
        };

        const applyTheme = function () {
            const theme = manualTheme || getTimeBasedTheme();
            document.documentElement.setAttribute('data-theme', theme);
            const btn = $('#themeBtn');
            if (btn) {
                btn.textContent = theme === 'dark' ? '☀️' : '🌙';
            }
        };

        // ---- Encryption UI ----
        const showLockScreen = function () {
            stopTicker();
            $('#lockScreen').style.display = 'flex';
            $('#accounts').style.display = 'none';
            $('#addRow').style.display = 'none';
            updateLockIcon();
        };

        const hideLockScreen = function () {
            $('#lockScreen').style.display = 'none';
            $('#accounts').style.display = '';
            $('#addRow').style.display = editing ? '' : 'none';
        };

        const onLockToggle = function () {
            if (store.isEncrypted() && store.isUnlocked()) {
                // Lock it
                store.lock();
                showLockScreen();
            } else if (!store.isEncrypted()) {
                // Open set-password dialog
                openSetPassword();
            }
        };

        const updateLockIcon = function () {
            const btn = $('#lockBtn');
            if (!btn) {
                return;
            }
            if (store.isEncrypted()) {
                btn.textContent = store.isUnlocked() ? '🔓' : '🔒';
                btn.title = store.isUnlocked() ? 'Lock accounts' : 'Unlock accounts';
                btn.classList.remove('hidden');
            } else {
                btn.textContent = '🔐';
                btn.title = 'Set encryption password';
                btn.classList.toggle('hidden', !editing);
            }
        };

        // Unlock modal
        let passwordAction = ''; // 'unlock'

        const openPasswordModal = function (action) {
            passwordAction = action;
            $('#pwInput').value = '';
            $('#pwError').textContent = '';
            if (action === 'unlock') {
                $('#pwTitle').textContent = 'Unlock Accounts';
                $('#pwSubmit').textContent = 'Unlock';
            }
            $('#passwordModal').classList.add('open');
            setTimeout(() => {
                $('#pwInput').focus();
            }, 100);
        };

        const closePasswordModal = function () {
            $('#passwordModal').classList.remove('open');
            $('#pwInput').value = '';
            $('#pwError').textContent = '';
        };

        const onPasswordSubmit = async function () {
            const pw = $('#pwInput').value;
            if (!pw) {
                $('#pwInput').focus();
                return;
            }
            if (passwordAction === 'unlock') {
                const ok = await store.unlock(pw);
                if (ok) {
                    closePasswordModal();
                    hideLockScreen();
                    updateLockIcon();
                    await render();
                    startTicker();
                } else {
                    $('#pwError').textContent = 'Wrong password';
                    $('#pwInput').select();
                }
            }
        };

        // Set password modal
        const openSetPassword = function () {
            $('#setPwInput').value = '';
            $('#setPwConfirm').value = '';
            $('#setPwError').textContent = '';
            if (store.isEncrypted()) {
                $('#setPwTitle').textContent = 'Change Password';
                $('#setPwHint').textContent = 'Leave empty to remove encryption.';
            } else {
                $('#setPwTitle').textContent = 'Set Encryption Password';
                $('#setPwHint').textContent = 'Encrypts accounts in localStorage with AES-GCM.';
            }
            $('#setPwModal').classList.add('open');
            setTimeout(() => {
                $('#setPwInput').focus();
            }, 100);
        };

        const closeSetPwModal = function () {
            $('#setPwModal').classList.remove('open');
        };

        const onSetPasswordSubmit = async function () {
            const pw = $('#setPwInput').value;
            const confirm = $('#setPwConfirm').value;
            if (pw && pw !== confirm) {
                $('#setPwError').textContent = 'Passwords do not match';
                return;
            }
            await store.setPassword(pw || null);
            closeSetPwModal();
            updateLockIcon();
            await render();
        };

        // ---- Drag and Drop ----
        let dragFromIdx = -1;

        const onDragStart = function (e) {
            const card = e.target.closest('.account-card');
            if (!card || !editing) {
                return;
            }
            dragFromIdx = parseInt(card.getAttribute('data-idx'), 10);
            card.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        };

        const onDragOver = function (e) {
            if (dragFromIdx < 0 || !editing) {
                return;
            }
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            const card = e.target.closest('.account-card');
            if (card) {
                // Remove highlight from all
                const cards = document.querySelectorAll('.account-card');
                for (let i = 0; i < cards.length; i++) {
                    cards[i].classList.remove('drag-over');
                }
                card.classList.add('drag-over');
            }
        };

        const onDrop = async function (e) {
            e.preventDefault();
            const card = e.target.closest('.account-card');
            if (!card || dragFromIdx < 0) {
                return;
            }
            const toIdx = parseInt(card.getAttribute('data-idx'), 10);
            if (dragFromIdx !== toIdx) {
                const accounts = (await store.getAccounts()) || [];
                const item = accounts.splice(dragFromIdx, 1)[0];
                accounts.splice(toIdx, 0, item);
                await store.saveAccounts(accounts);
                await render();
            }
            cleanupDrag();
        };

        const onDragEnd = function () {
            cleanupDrag();
        };

        const cleanupDrag = function () {
            dragFromIdx = -1;
            const cards = document.querySelectorAll('.account-card');
            for (let i = 0; i < cards.length; i++) {
                cards[i].classList.remove('dragging', 'drag-over');
            }
        };

        // ---- Render ----
        const render = async function () {
            return renderAt(Math.round(Date.now() / 1000));
        };

        const renderAt = async function (now) {
            const list = $('#accounts');
            const token = ++renderToken;
            const accounts = await store.getAccounts();
            if (token !== renderToken) {
                return;
            }

            list.innerHTML = '';
            if (accounts === null) {
                return;
            } // locked
            lastRenderedAt = now;
            lastCodeStepByIndex = {};

            for (let _i = 0; _i < accounts.length; _i++) {
                const acc = accounts[_i];
                const i = _i;
                const algo = acc.algorithm || DEFAULTS.algorithm;
                const period = acc.period || DEFAULTS.period;
                const digits = acc.digits || DEFAULTS.digits;
                const code = await keys.generate(acc.secret, {
                    algorithm: algo,
                    period: period,
                    digits: digits
                });
                if (token !== renderToken) {
                    return;
                }
                const cd = period - (now % period);

                const card = document.createElement('div');
                card.className = 'account-card';
                card.setAttribute('data-idx', i);
                card.setAttribute('data-period', period);
                lastCodeStepByIndex[i] = Math.floor(now / period);
                if (editing) {
                    card.setAttribute('draggable', 'true');
                }

                const displayName = acc.issuer
                    ? `${escapeHtml(acc.issuer)}${acc.name ? ` (${escapeHtml(acc.name)})` : ''}`
                    : escapeHtml(acc.name);
                const nameHtml = acc.url
                    ? `<a href="${escapeHtml(acc.url)}" target="_blank" rel="noopener noreferrer">${displayName}</a>`
                    : displayName;

                let actionsHtml = '<div class="card-actions">';
                actionsHtml += `<button class="qr-btn" data-idx="${i}" title="Show QR code"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="2" y="14" width="8" height="8" rx="1"/><rect x="14" y="14" width="4" height="4" rx="0.5"/><rect x="20" y="14" width="2" height="2"/><rect x="14" y="20" width="2" height="2"/><rect x="18" y="18" width="4" height="4" rx="0.5"/><rect x="5" y="5" width="2" height="2"/><rect x="17" y="5" width="2" height="2"/><rect x="5" y="17" width="2" height="2"/></svg></button>`;
                if (editing) {
                    actionsHtml += '<button class="drag-handle" title="Drag to reorder">≡</button>';
                    actionsHtml += `<button class="edit-btn" data-idx="${i}" title="Edit">&#x270E;</button>`;
                    actionsHtml += `<button class="delete-btn" data-idx="${i}" title="Delete">&times;</button>`;
                }
                actionsHtml += '</div>';

                card.innerHTML =
                    '<div class="account-info">' +
                    `<div class="totp-code" data-code="${code}">${code}<span class="copy-tip">Copied!</span></div>` +
                    '<div class="account-meta">' +
                    `<span class="account-name">${nameHtml}</span>` +
                    ` <span class="meta-countdown">${cd}s</span>` +
                    '</div>' +
                    '</div>' +
                    actionsHtml;

                const codeEl = card.querySelector('.totp-code');
                codeEl.addEventListener('click', function (e) {
                    e.preventDefault();
                    copyToClipboard(this.getAttribute('data-code'), this);
                });

                card.querySelector('.qr-btn').addEventListener('click', function () {
                    showQR(parseInt(this.getAttribute('data-idx'), 10));
                });

                if (editing) {
                    card.querySelector('.edit-btn').addEventListener('click', function () {
                        openEdit(parseInt(this.getAttribute('data-idx'), 10));
                    });
                    card.querySelector('.delete-btn').addEventListener('click', function () {
                        deleteAccount(parseInt(this.getAttribute('data-idx'), 10));
                    });
                    card.addEventListener('dragstart', onDragStart);
                    card.addEventListener('dragover', onDragOver);
                    card.addEventListener('drop', onDrop);
                    card.addEventListener('dragend', onDragEnd);
                }

                list.appendChild(card);
            }
            updateLockIcon();
        };

        const toggleEdit = function () {
            editing = !editing;
            $('#editBtn').classList.toggle('active', editing);
            $('#themeBtn').classList.toggle('hidden', !editing);
            $('#resetBtn').classList.toggle('hidden', !editing);
            $('#importBtn').classList.toggle('hidden', !editing);
            $('#exportBtn').classList.toggle('hidden', !editing);
            $('#addRow').style.display = editing ? '' : 'none';
            updateLockIcon();
            render();
        };

        const buildOtpauth = function (acc) {
            const algo = acc.algorithm || DEFAULTS.algorithm;
            const period = acc.period || DEFAULTS.period;
            const digits = acc.digits || DEFAULTS.digits;
            const issuer = acc.issuer || '';
            const label = issuer
                ? `${encodeURIComponent(issuer)}:${encodeURIComponent(acc.name)}`
                : encodeURIComponent(acc.name);
            let params = `secret=${encodeURIComponent(acc.secret)}`;
            if (issuer) {
                params += `&issuer=${encodeURIComponent(issuer)}`;
            }
            params += `&algorithm=${algo.replace('SHA-', 'SHA').replace('-', '')}`;
            params += `&digits=${digits}`;
            params += `&period=${period}`;
            return `otpauth://totp/${label}?${params}`;
        };

        const exportAccounts = async function () {
            const accounts = (await store.getAccounts()) || [];
            const full = accounts.map(acc => {
                return {
                    name: acc.name,
                    issuer: acc.issuer || '',
                    secret: acc.secret,
                    algorithm: acc.algorithm || DEFAULTS.algorithm,
                    period: acc.period || DEFAULTS.period,
                    digits: acc.digits || DEFAULTS.digits,
                    url: acc.url || '',
                    otpauth: buildOtpauth(acc)
                };
            });
            const data = JSON.stringify(full, null, 2);
            const blob = new Blob([data], { type: 'text/plain;charset=utf-8' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'authenticator-export.json';
            a.click();
        };

        const importAccounts = function (e) {
            const file = e.target.files[0];
            if (!file) {
                return;
            }
            const reader = new FileReader();
            reader.onload = async function (ev) {
                const text = ev.target.result;
                let imported = 0;
                try {
                    let arr = JSON.parse(text);
                    if (!Array.isArray(arr)) {
                        arr = [arr];
                    }
                    for (let i = 0; i < arr.length; i++) {
                        const item = arr[i];
                        if (item.secret) {
                            await addAccount(
                                item.name || 'Imported',
                                item.secret,
                                item.algorithm || DEFAULTS.algorithm,
                                item.period || DEFAULTS.period,
                                item.digits || DEFAULTS.digits,
                                item.url || '',
                                item.issuer || ''
                            );
                            imported++;
                        } else if (item.otpauth) {
                            const parsed = parseOtpauth(item.otpauth);
                            if (parsed) {
                                await addAccount(
                                    parsed.name,
                                    parsed.secret,
                                    parsed.algorithm,
                                    parsed.period,
                                    parsed.digits,
                                    '',
                                    parsed.issuer
                                );
                                imported++;
                            }
                        }
                    }
                } catch (ex) {
                    const lines = text.split('\n');
                    for (let j = 0; j < lines.length; j++) {
                        const line = lines[j].trim();
                        if (line.indexOf('otpauth://') === 0) {
                            const parsed = parseOtpauth(line);
                            if (parsed) {
                                await addAccount(
                                    parsed.name,
                                    parsed.secret,
                                    parsed.algorithm,
                                    parsed.period,
                                    parsed.digits,
                                    '',
                                    parsed.issuer
                                );
                                imported++;
                            }
                        }
                    }
                }
                if (imported > 0) {
                    showToast(`Imported ${imported} account${imported > 1 ? 's' : ''}.`);
                } else {
                    showToast('No valid accounts found in file.');
                }
                e.target.value = '';
            };
            reader.readAsText(file);
        };

        const deleteAccount = async function (idx) {
            const accounts = (await store.getAccounts()) || [];
            accounts.splice(idx, 1);
            await store.saveAccounts(accounts);
            render();
        };

        const resetAccounts = function () {
            if (!confirm('Delete all accounts? This cannot be undone.')) {
                return;
            }
            store.resetAll();
            editing = false;
            $('#editBtn').classList.remove('active');
            $('#resetBtn').classList.add('hidden');
            $('#exportBtn').classList.add('hidden');
            $('#addRow').style.display = 'none';
            updateLockIcon();
            render();
        };

        const addAccount = async function (name, secret, algorithm, period, digits, url, issuer) {
            if (!secret) {
                return false;
            }
            const acc = {
                name: name,
                secret: secret,
                algorithm: algorithm || DEFAULTS.algorithm,
                period: period || DEFAULTS.period,
                digits: digits || DEFAULTS.digits,
                url: url || '',
                issuer: issuer || ''
            };
            const accounts = (await store.getAccounts()) || [];
            accounts.push(acc);
            await store.saveAccounts(accounts);
            render();
            return true;
        };

        const showQR = async function (idx) {
            const accounts = (await store.getAccounts()) || [];
            const acc = accounts[idx];
            if (!acc) {
                return;
            }
            const uri = buildOtpauth(acc);
            $('#qrTitle').textContent = acc.issuer
                ? `${acc.issuer}${acc.name ? ` (${acc.name})` : ''}`
                : acc.name;
            $('#qrUri').textContent = uri;

            const qr = qrcode(0, 'M');
            qr.addData(uri);
            qr.make();

            const canvas = $('#qrCanvas');
            const size = 240;
            const modules = qr.getModuleCount();
            const cellSize = Math.floor(size / modules);
            const realSize = cellSize * modules;
            canvas.width = realSize;
            canvas.height = realSize;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, realSize, realSize);
            ctx.fillStyle = '#000';
            for (let r = 0; r < modules; r++) {
                for (let c = 0; c < modules; c++) {
                    if (qr.isDark(r, c)) {
                        ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
                    }
                }
            }

            $('#qrModal').classList.add('open');
        };

        const closeQR = function () {
            $('#qrModal').classList.remove('open');
        };

        const openEdit = async function (idx) {
            const accounts = (await store.getAccounts()) || [];
            const acc = accounts[idx];
            if (!acc) {
                return;
            }
            editIndex = idx;
            $('#modalTitle').textContent = 'Edit Account';
            $('#addKeyButton').textContent = 'Save';
            $('#keyIssuer').value = acc.issuer || '';
            $('#keyAccount').value = acc.name || '';
            $('#keySecret').value = acc.secret || '';
            $('#keyUrl').value = acc.url || '';
            $('#keyAlgorithm').value = acc.algorithm || DEFAULTS.algorithm;
            $('#keyPeriod').value = acc.period || DEFAULTS.period;
            $('#keyDigits').value = acc.digits || DEFAULTS.digits;
            $('#addModal').classList.add('open');
        };

        const onSave = async function () {
            const issuer = $('#keyIssuer').value.trim();
            const name = $('#keyAccount').value.trim();
            const secret = $('#keySecret').value.replace(/\s/g, '');
            const url = $('#keyUrl').value.trim();
            const algo = $('#keyAlgorithm').value;
            const period = parseInt($('#keyPeriod').value, 10);
            const digits = parseInt($('#keyDigits').value, 10);
            if (!name) {
                $('#keyAccount').focus();
                return;
            }
            if (!secret) {
                $('#keySecret').focus();
                return;
            }

            if (editIndex >= 0) {
                const accounts = (await store.getAccounts()) || [];
                accounts[editIndex] = {
                    name: name,
                    secret: secret,
                    algorithm: algo || DEFAULTS.algorithm,
                    period: period || DEFAULTS.period,
                    digits: digits || DEFAULTS.digits,
                    url: url || '',
                    issuer: issuer || ''
                };
                await store.saveAccounts(accounts);
                render();
            } else {
                await addAccount(name, secret, algo, period, digits, url, issuer);
            }
            closeModal();
        };

        const closeModal = function () {
            $('#addModal').classList.remove('open');
            editIndex = -1;
            $('#modalTitle').textContent = 'Add Account';
            $('#addKeyButton').textContent = 'Add';
            $('#keyIssuer').value = '';
            $('#keyAccount').value = '';
            $('#keySecret').value = '';
            $('#keyUrl').value = '';
            $('#keyAlgorithm').value = DEFAULTS.algorithm;
            $('#keyPeriod').value = DEFAULTS.period;
            $('#keyDigits').value = DEFAULTS.digits;
        };

        const tick = function () {
            const now = Math.round(Date.now() / 1000);
            if (now === lastRenderedAt) {
                return;
            }

            const countdowns = document.querySelectorAll('.meta-countdown');
            const codes = document.querySelectorAll('.totp-code');
            let needsFullRender = false;

            for (let i = 0; i < countdowns.length; i++) {
                const card = countdowns[i].closest('.account-card');
                if (!card) {
                    continue;
                }
                const period = parseInt(card.getAttribute('data-period'), 10) || DEFAULTS.period;
                const step = Math.floor(now / period);
                const cd = period - (now % period);
                countdowns[i].textContent = `${cd}s`;

                if (lastCodeStepByIndex[i] !== step) {
                    needsFullRender = true;
                }
            }

            lastRenderedAt = now;
            if (needsFullRender || codes.length !== countdowns.length) {
                renderAt(now);
            }
        };

        return { init: init, addAccount: addAccount, deleteAccount: deleteAccount };
    };

    exports.KeysController = KeysController;
    exports.DEFAULTS = DEFAULTS;
    exports.StorageService = StorageService;
    exports.KeyUtilities = KeyUtilities;
})(typeof exports === 'undefined' ? (this.totpAuth = {}) : exports);
