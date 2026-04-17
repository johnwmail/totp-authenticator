// Authenticator — per-account TOTP with configurable algorithm/period/digits
// Uses native Web Crypto API (no external dependencies for crypto)
// Based on original work by Gerard Braad (GPL-3.0)

(function (exports) {
    'use strict';

    var DEFAULTS = {
        algorithm: 'SHA-1',
        period: 30,
        digits: 6
    };

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    // ---- Storage with optional AES-GCM encryption ----
    var StorageService = function () {
        var KEYS = {
            plain: 'accounts',
            encrypted: 'accounts_encrypted',
            meta: 'accounts_meta'
        };
        var aesKey = null; // derived CryptoKey when unlocked

        function isSupported() {
            return typeof Storage !== 'undefined';
        }

        function getPlain(k) {
            var v = localStorage.getItem(k);
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
            var b = new Uint8Array(n);
            crypto.getRandomValues(b);
            return b;
        }
        function bufToBase64(buf) {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
        }
        function base64ToBuf(b64) {
            var s = atob(b64);
            var b = new Uint8Array(s.length);
            for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
            return b;
        }

        async function deriveKey(password, salt, iterations) {
            iterations = iterations || 310000;
            var enc = new TextEncoder();
            var baseKey = await crypto.subtle.importKey(
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
            var iv = randomBytes(12);
            var enc = new TextEncoder();
            var ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(JSON.stringify(data))
            );
            return { iv: bufToBase64(iv), ct: bufToBase64(ct) };
        }

        async function decrypt(payload, key) {
            var iv = base64ToBuf(payload.iv);
            var ct = base64ToBuf(payload.ct);
            var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
            return JSON.parse(new TextDecoder().decode(plain));
        }

        async function setPassword(password) {
            var accounts = await getAccounts();
            if (!password) {
                // Remove encryption
                aesKey = null;
                localStorage.removeItem(KEYS.encrypted);
                localStorage.removeItem(KEYS.meta);
                setPlain(KEYS.plain, accounts);
                return;
            }
            var salt = randomBytes(16);
            var iterations = 310000;
            aesKey = await deriveKey(password, salt, iterations);
            var meta = { salt: bufToBase64(salt), iter: iterations };
            localStorage.setItem(KEYS.meta, JSON.stringify(meta));
            localStorage.removeItem(KEYS.plain);
            var payload = await encrypt(accounts, aesKey);
            localStorage.setItem(KEYS.encrypted, JSON.stringify(payload));
        }

        async function unlock(password) {
            var metaStr = localStorage.getItem(KEYS.meta);
            if (!metaStr) return true; // not encrypted
            var meta = JSON.parse(metaStr);
            var salt = base64ToBuf(meta.salt);
            try {
                var key = await deriveKey(password, salt, meta.iter);
                var payloadStr = localStorage.getItem(KEYS.encrypted);
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
                if (!aesKey) return null; // locked
                var payloadStr = localStorage.getItem(KEYS.encrypted);
                if (!payloadStr) return [];
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
                var payload = await encrypt(accounts, aesKey);
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
    var KeyUtilities = function () {
        var dec2hex = function (s) {
            return (s < 15.5 ? '0' : '') + Math.round(s).toString(16);
        };
        var hex2dec = function (s) {
            return parseInt(s, 16);
        };
        var leftpad = function (str, len, pad) {
            if (len + 1 >= str.length) str = new Array(len + 1 - str.length).join(pad) + str;
            return str;
        };
        var base32tohex = function (b32) {
            var c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                bits = '',
                hex = '';
            for (var i = 0; i < b32.length; i++) {
                var v = c.indexOf(b32.charAt(i).toUpperCase());
                if (v >= 0) bits += leftpad(v.toString(2), 5, '0');
            }
            for (var j = 0; j + 4 <= bits.length; j += 4)
                hex += parseInt(bits.substr(j, 4), 2).toString(16);
            return hex;
        };
        var hexToUint8Array = function (hex) {
            var bytes = new Uint8Array(hex.length / 2);
            for (var i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            return bytes;
        };

        return {
            generate: async function (secret, opts) {
                opts = opts || {};
                var algo = opts.algorithm || DEFAULTS.algorithm;
                var period = opts.period || DEFAULTS.period;
                var digits = opts.digits || DEFAULTS.digits;
                var key = base32tohex(secret);
                if (key.length % 2 !== 0) key += '0';
                var epoch = opts.epoch || Math.round(Date.now() / 1000);
                var time = leftpad(dec2hex(Math.floor(epoch / period)), 16, '0');

                var keyBytes = hexToUint8Array(key);
                var timeBytes = hexToUint8Array(time);

                var cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'HMAC', hash: { name: algo } },
                    false,
                    ['sign']
                );
                var sig = await crypto.subtle.sign('HMAC', cryptoKey, timeBytes);
                var hmacBytes = new Uint8Array(sig);

                var hmac = '';
                for (var i = 0; i < hmacBytes.length; i++)
                    hmac += ('0' + hmacBytes[i].toString(16)).slice(-2);

                var off = hex2dec(hmac.substring(hmac.length - 1));
                var otp = (hex2dec(hmac.substr(off * 2, 8)) & hex2dec('7fffffff')) + '';
                return leftpad(otp.substr(otp.length - digits, digits), digits, '0');
            }
        };
    };

    // ---- Helpers ----
    function periodLabel(p) {
        if (p >= 86400) return p / 86400 + 'd';
        if (p >= 3600) return p / 3600 + 'h';
        if (p >= 60) return p / 60 + 'm';
        return p + 's';
    }
    function algoLabel(a) {
        return a.replace('SHA-', 'S');
    }

    function generateRandomSecret(length) {
        length = length || 32;
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        var arr = new Uint8Array(length);
        crypto.getRandomValues(arr);
        var secret = '';
        for (var i = 0; i < length; i++) {
            secret += chars[arr[i] % 32];
        }
        return secret;
    }

    var clipboardClearTimer = null;
    var lastCopiedValue = null;

    function copyToClipboard(text, el) {
        navigator.clipboard.writeText(text).then(function () {
            el.classList.add('copied');
            setTimeout(function () {
                el.classList.remove('copied');
            }, 1200);
            lastCopiedValue = text;
            if (clipboardClearTimer) {
                clearTimeout(clipboardClearTimer);
            }
            // Clear clipboard after 30 seconds for security (only if value is unchanged)
            clipboardClearTimer = setTimeout(function () {
                if (!navigator.clipboard.readText) {
                    showToast('Clipboard auto-clear unavailable');
                    return;
                }
                navigator.clipboard
                    .readText()
                    .then(function (currentValue) {
                        if (currentValue === lastCopiedValue) {
                            navigator.clipboard
                                .writeText('')
                                .then(function () {
                                    showToast('Clipboard cleared');
                                })
                                .catch(function () {
                                    showToast('Clipboard clear attempted');
                                });
                        }
                    })
                    .catch(function () {
                        showToast('Clipboard auto-clear unavailable');
                    });
            }, 30000);
        });
    }

    function showToast(message) {
        // Remove existing toast if any
        var existingToast = document.querySelector('.toast');
        if (existingToast) {
            existingToast.remove();
        }
        // Create toast element
        var toast = document.createElement('div');
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
        setTimeout(function () {
            toast.classList.remove('show');
            setTimeout(function () {
                toast.remove();
            }, 300);
        }, 2000);
    }

    // Parse otpauth:// URI
    function parseOtpauth(uri) {
        uri = uri.trim();
        if (uri.indexOf('otpauth://') !== 0) return null;
        try {
            var url = new URL(uri);
            var path = decodeURIComponent(url.pathname);
            var name = path
                .replace(/^\/totp\//, '')
                .replace(/^\/hotp\//, '')
                .replace(/^\//, '');
            var issuer = url.searchParams.get('issuer');
            if (issuer && name.indexOf(issuer + ':') === 0) {
                name = issuer + ' (' + name.substring(issuer.length + 1).trim() + ')';
            } else if (issuer && issuer !== name && name.indexOf(':') === -1) {
                name = issuer + ' (' + name + ')';
            }
            var secret = (url.searchParams.get('secret') || '').toUpperCase().replace(/\s/g, '');
            var algoParam = (url.searchParams.get('algorithm') || '')
                .toUpperCase()
                .replace('-', '');
            var algorithm = DEFAULTS.algorithm;
            if (algoParam === 'SHA1') algorithm = 'SHA-1';
            if (algoParam === 'SHA256') algorithm = 'SHA-256';
            if (algoParam === 'SHA512') algorithm = 'SHA-512';
            var period = parseInt(url.searchParams.get('period'), 10) || DEFAULTS.period;
            var digits = parseInt(url.searchParams.get('digits'), 10) || DEFAULTS.digits;
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
    var KeysController = function () {
        var store,
            keys,
            editing = false;
        var editIndex = -1;
        var renderToken = 0;
        var tickTimer = null;
        var lastRenderedAt = 0;
        var lastCodeStepByIndex = {};

        var $ = function (sel) {
            return document.querySelector(sel);
        };

        var startTicker = function () {
            if (tickTimer) clearInterval(tickTimer);
            tickTimer = setInterval(tick, 1000);
        };

        var stopTicker = function () {
            if (tickTimer) clearInterval(tickTimer);
            tickTimer = null;
        };

        var addFallbackAccount = async function () {
            var accounts = await store.getAccounts();
            if (accounts === null || accounts.length > 0) return;
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

        var stripJsonComments = function (text) {
            return text.replace(/^\s*\/\/.*$/gm, '').replace(/^\s*#.*$/gm, '');
        };

        var loadDefaultAccounts = async function () {
            try {
                var existing = await store.getAccounts();
                if (existing === null || existing.length > 0) return;

                if (typeof navigator !== 'undefined' && navigator.onLine === false) {
                    await addFallbackAccount();
                    return;
                }

                var res = await fetch('accounts.json');
                if (!res.ok) throw new Error('not found');

                var text = await res.text();
                if (looksLikeHtmlDocument(text)) throw new Error('not json');
                var arr = JSON.parse(stripJsonComments(text));
                if (!arr || !Array.isArray(arr) || arr.length === 0) throw new Error('empty');

                var imported = [];
                for (var i = 0; i < arr.length; i++) {
                    var item = arr[i];
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
                        var parsed = parseOtpauth(item.otpauth);
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
                if (existing === null || existing.length > 0) return;
                await store.saveAccounts(imported);
                await render();
            } catch (e) {
                await addFallbackAccount();
            }
        };

        var init = async function () {
            store = new StorageService();
            keys = new KeyUtilities();

            if (!store.isSupported()) return;

            // Bind UI
            $('#editBtn').addEventListener('click', toggleEdit);
            $('#exportBtn').addEventListener('click', exportAccounts);
            $('#importBtn').addEventListener('click', function () {
                $('#importFile').click();
            });
            $('#importFile').addEventListener('change', importAccounts);
            $('#resetBtn').addEventListener('click', resetAccounts);
            $('#addBtn').addEventListener('click', function () {
                $('#keySecret').value = generateRandomSecret();
                $('#addModal').classList.add('open');
            });
            $('#regenSecret').addEventListener('click', function () {
                $('#keySecret').value = generateRandomSecret();
            });
            $('#addKeyCancel').addEventListener('click', closeModal);
            $('#addKeyButton').addEventListener('click', onSave);
            $('#addModal').addEventListener('click', function (e) {
                if (e.target === $('#addModal')) closeModal();
            });

            // QR modal
            $('#qrClose').addEventListener('click', closeQR);
            $('#qrModal').addEventListener('click', function (e) {
                if (e.target === $('#qrModal')) closeQR();
            });

            // Encryption UI
            $('#lockScreenUnlock').addEventListener('click', function () {
                openPasswordModal('unlock');
            });
            $('#lockBtn').addEventListener('click', onLockToggle);
            $('#passwordModal').addEventListener('click', function (e) {
                if (e.target === $('#passwordModal')) closePasswordModal();
            });
            $('#pwCancel').addEventListener('click', closePasswordModal);
            $('#pwSubmit').addEventListener('click', onPasswordSubmit);
            $('#pwInput').addEventListener('keydown', function (e) {
                if (e.key === 'Enter') onPasswordSubmit();
            });
            $('#setPwModal').addEventListener('click', function (e) {
                if (e.target === $('#setPwModal')) closeSetPwModal();
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
        var manualTheme = null; // manual override for current session

        var getTimeBasedTheme = function () {
            var hour = new Date().getHours();
            return hour >= 8 && hour < 22 ? 'light' : 'dark';
        };

        var toggleTheme = function () {
            var current =
                document.documentElement.getAttribute('data-theme') || getTimeBasedTheme();
            manualTheme = current === 'dark' ? 'light' : 'dark';
            applyTheme();
        };

        var applyTheme = function () {
            var theme = manualTheme || getTimeBasedTheme();
            document.documentElement.setAttribute('data-theme', theme);
            var btn = $('#themeBtn');
            if (btn) btn.textContent = theme === 'dark' ? '☀️' : '🌙';
        };

        // ---- Encryption UI ----
        var showLockScreen = function () {
            stopTicker();
            $('#lockScreen').style.display = 'flex';
            $('#accounts').style.display = 'none';
            $('#addRow').style.display = 'none';
            updateLockIcon();
        };

        var hideLockScreen = function () {
            $('#lockScreen').style.display = 'none';
            $('#accounts').style.display = '';
        };

        var onLockToggle = function () {
            if (store.isEncrypted() && store.isUnlocked()) {
                // Lock it
                store.lock();
                showLockScreen();
            } else if (!store.isEncrypted()) {
                // Open set-password dialog
                openSetPassword();
            }
        };

        var updateLockIcon = function () {
            var btn = $('#lockBtn');
            if (!btn) return;
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
        var passwordAction = ''; // 'unlock'

        var openPasswordModal = function (action) {
            passwordAction = action;
            $('#pwInput').value = '';
            $('#pwError').textContent = '';
            if (action === 'unlock') {
                $('#pwTitle').textContent = 'Unlock Accounts';
                $('#pwSubmit').textContent = 'Unlock';
            }
            $('#passwordModal').classList.add('open');
            setTimeout(function () {
                $('#pwInput').focus();
            }, 100);
        };

        var closePasswordModal = function () {
            $('#passwordModal').classList.remove('open');
            $('#pwInput').value = '';
            $('#pwError').textContent = '';
        };

        var onPasswordSubmit = async function () {
            var pw = $('#pwInput').value;
            if (!pw) {
                $('#pwInput').focus();
                return;
            }
            if (passwordAction === 'unlock') {
                var ok = await store.unlock(pw);
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
        var openSetPassword = function () {
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
            setTimeout(function () {
                $('#setPwInput').focus();
            }, 100);
        };

        var closeSetPwModal = function () {
            $('#setPwModal').classList.remove('open');
        };

        var onSetPasswordSubmit = async function () {
            var pw = $('#setPwInput').value;
            var confirm = $('#setPwConfirm').value;
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
        var dragFromIdx = -1;

        var onDragStart = function (e) {
            var card = e.target.closest('.account-card');
            if (!card || !editing) return;
            dragFromIdx = parseInt(card.getAttribute('data-idx'), 10);
            card.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
        };

        var onDragOver = function (e) {
            if (dragFromIdx < 0 || !editing) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            var card = e.target.closest('.account-card');
            if (card) {
                // Remove highlight from all
                var cards = document.querySelectorAll('.account-card');
                for (var i = 0; i < cards.length; i++) cards[i].classList.remove('drag-over');
                card.classList.add('drag-over');
            }
        };

        var onDrop = async function (e) {
            e.preventDefault();
            var card = e.target.closest('.account-card');
            if (!card || dragFromIdx < 0) return;
            var toIdx = parseInt(card.getAttribute('data-idx'), 10);
            if (dragFromIdx !== toIdx) {
                var accounts = (await store.getAccounts()) || [];
                var item = accounts.splice(dragFromIdx, 1)[0];
                accounts.splice(toIdx, 0, item);
                await store.saveAccounts(accounts);
                await render();
            }
            cleanupDrag();
        };

        var onDragEnd = function () {
            cleanupDrag();
        };

        var cleanupDrag = function () {
            dragFromIdx = -1;
            var cards = document.querySelectorAll('.account-card');
            for (var i = 0; i < cards.length; i++) {
                cards[i].classList.remove('dragging', 'drag-over');
            }
        };

        // ---- Render ----
        var render = async function () {
            return renderAt(Math.round(Date.now() / 1000));
        };

        var renderAt = async function (now) {
            var list = $('#accounts');
            var token = ++renderToken;
            var accounts = await store.getAccounts();
            if (token !== renderToken) return;

            list.innerHTML = '';
            if (accounts === null) return; // locked
            lastRenderedAt = now;
            lastCodeStepByIndex = {};

            for (var _i = 0; _i < accounts.length; _i++) {
                var acc = accounts[_i];
                var i = _i;
                var algo = acc.algorithm || DEFAULTS.algorithm;
                var period = acc.period || DEFAULTS.period;
                var digits = acc.digits || DEFAULTS.digits;
                var code = await keys.generate(acc.secret, {
                    algorithm: algo,
                    period: period,
                    digits: digits
                });
                if (token !== renderToken) return;
                var cd = period - (now % period);

                var card = document.createElement('div');
                card.className = 'account-card';
                card.setAttribute('data-idx', i);
                card.setAttribute('data-period', period);
                lastCodeStepByIndex[i] = Math.floor(now / period);
                if (editing) card.setAttribute('draggable', 'true');

                var displayName = acc.issuer
                    ? escapeHtml(acc.issuer) + (acc.name ? ' (' + escapeHtml(acc.name) + ')' : '')
                    : escapeHtml(acc.name);
                var nameHtml = acc.url
                    ? '<a href="' +
                      escapeHtml(acc.url) +
                      '" target="_blank" rel="noopener noreferrer">' +
                      displayName +
                      '</a>'
                    : displayName;

                var extras = [];
                if (algo !== DEFAULTS.algorithm) extras.push(algoLabel(algo));
                if (digits !== DEFAULTS.digits) extras.push(digits + 'd');
                var extraHtml = extras.length
                    ? '<span class="meta-sep">\u00b7</span><span class="meta-extra">' +
                      extras.join(' \u00b7 ') +
                      '</span>'
                    : '';

                var actionsHtml = '<div class="card-actions">';
                actionsHtml +=
                    '<button class="qr-btn" data-idx="' +
                    i +
                    '" title="Show QR code"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="2" y="14" width="8" height="8" rx="1"/><rect x="14" y="14" width="4" height="4" rx="0.5"/><rect x="20" y="14" width="2" height="2"/><rect x="14" y="20" width="2" height="2"/><rect x="18" y="18" width="4" height="4" rx="0.5"/><rect x="5" y="5" width="2" height="2"/><rect x="17" y="5" width="2" height="2"/><rect x="5" y="17" width="2" height="2"/></svg></button>';
                if (editing) {
                    actionsHtml += '<button class="drag-handle" title="Drag to reorder">≡</button>';
                    actionsHtml +=
                        '<button class="edit-btn" data-idx="' +
                        i +
                        '" title="Edit">&#x270E;</button>';
                    actionsHtml +=
                        '<button class="delete-btn" data-idx="' +
                        i +
                        '" title="Delete">&times;</button>';
                }
                actionsHtml += '</div>';

                card.innerHTML =
                    '<div class="account-info">' +
                    '<div class="totp-code" data-code="' +
                    code +
                    '">' +
                    code +
                    '<span class="copy-tip">Copied!</span></div>' +
                    '<div class="account-meta">' +
                    '<span class="account-name">' +
                    nameHtml +
                    '</span>' +
                    ' <span class="meta-countdown">' +
                    cd +
                    's</span>' +
                    '</div>' +
                    '</div>' +
                    actionsHtml;

                var codeEl = card.querySelector('.totp-code');
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

        var toggleEdit = function () {
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

        var buildOtpauth = function (acc) {
            var algo = acc.algorithm || DEFAULTS.algorithm;
            var period = acc.period || DEFAULTS.period;
            var digits = acc.digits || DEFAULTS.digits;
            var issuer = acc.issuer || '';
            var label = issuer
                ? encodeURIComponent(issuer) + ':' + encodeURIComponent(acc.name)
                : encodeURIComponent(acc.name);
            var params = 'secret=' + encodeURIComponent(acc.secret);
            if (issuer) params += '&issuer=' + encodeURIComponent(issuer);
            params += '&algorithm=' + algo.replace('SHA-', 'SHA').replace('-', '');
            params += '&digits=' + digits;
            params += '&period=' + period;
            return 'otpauth://totp/' + label + '?' + params;
        };

        var exportAccounts = async function () {
            var accounts = (await store.getAccounts()) || [];
            var full = accounts.map(function (acc) {
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
            var data = JSON.stringify(full, null, 2);
            var blob = new Blob([data], { type: 'text/plain;charset=utf-8' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'authenticator-export.json';
            a.click();
        };

        var importAccounts = function (e) {
            var file = e.target.files[0];
            if (!file) return;
            var reader = new FileReader();
            reader.onload = async function (ev) {
                var text = ev.target.result;
                var imported = 0;
                try {
                    var arr = JSON.parse(text);
                    if (!Array.isArray(arr)) arr = [arr];
                    for (var i = 0; i < arr.length; i++) {
                        var item = arr[i];
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
                            var parsed = parseOtpauth(item.otpauth);
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
                    var lines = text.split('\n');
                    for (var j = 0; j < lines.length; j++) {
                        var line = lines[j].trim();
                        if (line.indexOf('otpauth://') === 0) {
                            var parsed = parseOtpauth(line);
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
                    showToast(
                        'Imported ' + imported + ' account' + (imported > 1 ? 's' : '') + '.'
                    );
                } else {
                    showToast('No valid accounts found in file.');
                }
                e.target.value = '';
            };
            reader.readAsText(file);
        };

        var deleteAccount = async function (idx) {
            var accounts = await store.getAccounts();
            accounts.splice(idx, 1);
            await store.saveAccounts(accounts);
            render();
        };

        var resetAccounts = function () {
            if (!confirm('Delete all accounts? This cannot be undone.')) return;
            store.resetAll();
            editing = false;
            $('#editBtn').classList.remove('active');
            $('#resetBtn').classList.add('hidden');
            $('#exportBtn').classList.add('hidden');
            $('#addRow').style.display = 'none';
            updateLockIcon();
            render();
        };

        var addAccount = async function (name, secret, algorithm, period, digits, url, issuer) {
            if (!secret) return false;
            var acc = {
                name: name,
                secret: secret,
                algorithm: algorithm || DEFAULTS.algorithm,
                period: period || DEFAULTS.period,
                digits: digits || DEFAULTS.digits,
                url: url || '',
                issuer: issuer || ''
            };
            var accounts = (await store.getAccounts()) || [];
            accounts.push(acc);
            await store.saveAccounts(accounts);
            render();
            return true;
        };

        var showQR = async function (idx) {
            var accounts = (await store.getAccounts()) || [];
            var acc = accounts[idx];
            if (!acc) return;
            var uri = buildOtpauth(acc);
            $('#qrTitle').textContent = acc.issuer
                ? acc.issuer + (acc.name ? ' (' + acc.name + ')' : '')
                : acc.name;
            $('#qrUri').textContent = uri;

            var qr = qrcode(0, 'M');
            qr.addData(uri);
            qr.make();

            var canvas = $('#qrCanvas');
            var size = 240;
            var modules = qr.getModuleCount();
            var cellSize = Math.floor(size / modules);
            var realSize = cellSize * modules;
            canvas.width = realSize;
            canvas.height = realSize;
            var ctx = canvas.getContext('2d');
            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, realSize, realSize);
            ctx.fillStyle = '#000';
            for (var r = 0; r < modules; r++) {
                for (var c = 0; c < modules; c++) {
                    if (qr.isDark(r, c)) {
                        ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
                    }
                }
            }

            $('#qrModal').classList.add('open');
        };

        var closeQR = function () {
            $('#qrModal').classList.remove('open');
        };

        var openEdit = async function (idx) {
            var accounts = (await store.getAccounts()) || [];
            var acc = accounts[idx];
            if (!acc) return;
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

        var onSave = async function () {
            var issuer = $('#keyIssuer').value.trim();
            var name = $('#keyAccount').value.trim();
            var secret = $('#keySecret').value.replace(/\s/g, '');
            var url = $('#keyUrl').value.trim();
            var algo = $('#keyAlgorithm').value;
            var period = parseInt($('#keyPeriod').value, 10);
            var digits = parseInt($('#keyDigits').value, 10);
            if (!name) {
                $('#keyAccount').focus();
                return;
            }
            if (!secret) {
                $('#keySecret').focus();
                return;
            }

            if (editIndex >= 0) {
                var accounts = (await store.getAccounts()) || [];
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

        var closeModal = function () {
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

        var tick = function () {
            var now = Math.round(Date.now() / 1000);
            if (now === lastRenderedAt) return;

            var countdowns = document.querySelectorAll('.meta-countdown');
            var codes = document.querySelectorAll('.totp-code');
            var needsFullRender = false;

            for (var i = 0; i < countdowns.length; i++) {
                var card = countdowns[i].closest('.account-card');
                if (!card) continue;
                var period = parseInt(card.getAttribute('data-period'), 10) || DEFAULTS.period;
                var step = Math.floor(now / period);
                var cd = period - (now % period);
                countdowns[i].textContent = cd + 's';

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
})(typeof exports === 'undefined' ? (this['totpAuth'] = {}) : exports);
