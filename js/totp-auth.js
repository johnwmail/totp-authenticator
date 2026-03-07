// Authenticator — per-account TOTP with configurable algorithm/period/digits
// Based on original work by Gerard Braad (GPL-3.0)

(function(exports) {
    "use strict";

    var DEFAULTS = {
        algorithm: 'SHA-1',
        period: 30,
        digits: 6
    };

    // ---- Storage ----
    var StorageService = function() {
        return {
            isSupported: function() { return typeof Storage !== 'undefined'; },
            getObject: function(k) { var v = localStorage.getItem(k); return v && JSON.parse(v); },
            setObject: function(k, v) { localStorage.setItem(k, JSON.stringify(v)); }
        };
    };

    // ---- TOTP ----
    var KeyUtilities = function() {
        var dec2hex = function(s) { return (s < 15.5 ? '0' : '') + Math.round(s).toString(16); };
        var hex2dec = function(s) { return parseInt(s, 16); };
        var leftpad = function(str, len, pad) {
            if (len + 1 >= str.length) str = new Array(len + 1 - str.length).join(pad) + str;
            return str;
        };
        var base32tohex = function(b32) {
            var c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', bits = '', hex = '';
            for (var i = 0; i < b32.length; i++) {
                var v = c.indexOf(b32.charAt(i).toUpperCase());
                if (v >= 0) bits += leftpad(v.toString(2), 5, '0');
            }
            for (var j = 0; j + 4 <= bits.length; j += 4)
                hex += parseInt(bits.substr(j, 4), 2).toString(16);
            return hex;
        };

        return {
            generate: function(secret, opts) {
                opts = opts || {};
                var algo   = opts.algorithm || DEFAULTS.algorithm;
                var period = opts.period    || DEFAULTS.period;
                var digits = opts.digits    || DEFAULTS.digits;
                var key = base32tohex(secret);
                if (key.length % 2 !== 0) key += '0';
                var epoch = opts.epoch || Math.round(Date.now() / 1000);
                var time = leftpad(dec2hex(Math.floor(epoch / period)), 16, '0');
                var h = new jsSHA(algo, 'HEX');
                h.setHMACKey(key, 'HEX');
                h.update(time);
                var hmac = h.getHMAC('HEX');
                var off = hex2dec(hmac.substring(hmac.length - 1));
                var otp = (hex2dec(hmac.substr(off * 2, 8)) & hex2dec('7fffffff')) + '';
                return leftpad(otp.substr(otp.length - digits, digits), digits, '0');
            }
        };
    };

    // ---- Helpers ----
    function periodLabel(p) {
        if (p >= 86400) return (p / 86400) + 'd';
        if (p >= 3600)  return (p / 3600) + 'h';
        if (p >= 60)    return (p / 60) + 'm';
        return p + 's';
    }
    function algoLabel(a) { return a.replace('SHA-', 'S'); }

    function generateRandomSecret(length) {
        length = length || 32; // 32 base32 chars = 160 bits (RFC 4226 recommended)
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        var arr = new Uint8Array(length);
        crypto.getRandomValues(arr);
        var secret = '';
        for (var i = 0; i < length; i++) {
            secret += chars[arr[i] % 32];
        }
        return secret;
    }

    function copyToClipboard(text, el) {
        navigator.clipboard.writeText(text).then(function() {
            el.classList.add('copied');
            setTimeout(function() { el.classList.remove('copied'); }, 1200);
        });
    }

    // Parse otpauth:// URI
    // otpauth://totp/Label:user@example.com?secret=XXX&issuer=Label&algorithm=SHA256&digits=6&period=30
    function parseOtpauth(uri) {
        uri = uri.trim();
        if (uri.indexOf('otpauth://') !== 0) return null;
        try {
            var url = new URL(uri);
            var path = decodeURIComponent(url.pathname); // /totp/Label:user@example.com
            var name = path.replace(/^\/totp\//, '').replace(/^\/hotp\//, '').replace(/^\//, '');
            var issuer = url.searchParams.get('issuer');
            // If name has "Issuer:account" format, prettify it
            if (issuer && name.indexOf(issuer + ':') === 0) {
                name = issuer + ' (' + name.substring(issuer.length + 1).trim() + ')';
            } else if (issuer && issuer !== name && name.indexOf(':') === -1) {
                name = issuer + ' (' + name + ')';
            }
            var secret = (url.searchParams.get('secret') || '').toUpperCase().replace(/\s/g, '');
            var algoParam = (url.searchParams.get('algorithm') || '').toUpperCase().replace('-', '');
            var algorithm = DEFAULTS.algorithm;
            if (algoParam === 'SHA1')   algorithm = 'SHA-1';
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
        } catch(e) {
            return null;
        }
    }

    exports.parseOtpauth = parseOtpauth;

    // ---- Controller ----
    var KeysController = function() {
        var store, keys, editing = false;
        var editIndex = -1; // -1 = adding new, >= 0 = editing existing

        var $ = function(sel) { return document.querySelector(sel); };

        var addFallbackAccount = function() {
            // addAccount(name, secret, algorithm, period, digits, url, issuer)
            addAccount('demo@example.com', generateRandomSecret(), DEFAULTS.algorithm, DEFAULTS.period, DEFAULTS.digits, 'https://github.com', 'Github');
        };

        var stripJsonComments = function(text) {
            return text.replace(/^\s*\/\/.*$/gm, '').replace(/^\s*#.*$/gm, '');
        };

        var loadDefaultAccounts = function() {
            fetch('accounts.json').then(function(res) {
                if (!res.ok) throw new Error('not found');
                return res.text();
            }).then(function(text) {
                var arr = JSON.parse(stripJsonComments(text));
                if (!arr || !Array.isArray(arr) || arr.length === 0) throw new Error('empty');
                var imported = 0;
                arr.forEach(function(item) {
                    if (item.secret) {
                        addAccount(
                            item.name      || 'Imported',
                            item.secret,
                            item.algorithm || DEFAULTS.algorithm,
                            item.period    || DEFAULTS.period,
                            item.digits    || DEFAULTS.digits,
                            item.url       || '',
                            item.issuer    || ''
                        );
                        imported++;
                    } else if (item.otpauth) {
                        var parsed = parseOtpauth(item.otpauth);
                        if (parsed) {
                            addAccount(parsed.name, parsed.secret, parsed.algorithm, parsed.period, parsed.digits, '', parsed.issuer);
                            imported++;
                        }
                    }
                });
                if (imported === 0) addFallbackAccount();
            }).catch(function() {
                addFallbackAccount();
            });
        };

        var init = function() {
            store = new StorageService();
            keys  = new KeyUtilities();

            if (!store.isSupported()) return;

            if (!store.getObject('accounts')) {
                loadDefaultAccounts();
            }

            // Bind UI
            $('#editBtn').addEventListener('click', toggleEdit);
            $('#exportBtn').addEventListener('click', exportAccounts);
            $('#importBtn').addEventListener('click', function() { $('#importFile').click(); });
            $('#importFile').addEventListener('change', importAccounts);
            $('#resetBtn').addEventListener('click', resetAccounts);
            $('#addBtn').addEventListener('click', function() {
                $('#keySecret').value = generateRandomSecret();
                $('#addModal').classList.add('open');
            });
            $('#regenSecret').addEventListener('click', function() {
                $('#keySecret').value = generateRandomSecret();
            });
            $('#addKeyCancel').addEventListener('click', closeModal);
            $('#addKeyButton').addEventListener('click', onSave);
            // Close modal on overlay click
            $('#addModal').addEventListener('click', function(e) {
                if (e.target === $('#addModal')) closeModal();
            });

            // QR modal
            $('#qrClose').addEventListener('click', closeQR);
            $('#qrModal').addEventListener('click', function(e) {
                if (e.target === $('#qrModal')) closeQR();
            });

            render();
            setInterval(tick, 1000);
        };

        var render = function() {
            var list = $('#accounts');
            list.innerHTML = '';
            var accounts = store.getObject('accounts') || [];
            var now = Math.round(Date.now() / 1000);

            accounts.forEach(function(acc, i) {
                var algo   = acc.algorithm || DEFAULTS.algorithm;
                var period = acc.period    || DEFAULTS.period;
                var digits = acc.digits    || DEFAULTS.digits;
                var code   = keys.generate(acc.secret, { algorithm: algo, period: period, digits: digits });
                var cd     = period - (now % period);

                var card = document.createElement('div');
                card.className = 'account-card';

                // Name HTML — show "Issuer (name)" or just name
                var displayName = acc.issuer
                    ? acc.issuer + (acc.name ? ' (' + acc.name + ')' : '')
                    : acc.name;
                var nameHtml = acc.url
                    ? '<a href="' + acc.url + '" target="_blank" rel="noopener">' + displayName + '</a>'
                    : displayName;

                // Extra info (non-default algo/digits)
                var extras = [];
                if (algo !== DEFAULTS.algorithm) extras.push(algoLabel(algo));
                if (digits !== DEFAULTS.digits)  extras.push(digits + 'd');
                var extraHtml = extras.length
                    ? '<span class="meta-sep">\u00b7</span><span class="meta-extra">' + extras.join(' \u00b7 ') + '</span>'
                    : '';

                var actionsHtml = '<div class="card-actions">';
                actionsHtml += '<button class="qr-btn" data-idx="' + i + '" title="Show QR code"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="2" y="14" width="8" height="8" rx="1"/><rect x="14" y="14" width="4" height="4" rx="0.5"/><rect x="20" y="14" width="2" height="2"/><rect x="14" y="20" width="2" height="2"/><rect x="18" y="18" width="4" height="4" rx="0.5"/><rect x="5" y="5" width="2" height="2"/><rect x="17" y="5" width="2" height="2"/><rect x="5" y="17" width="2" height="2"/></svg></button>';
                if (editing) {
                    actionsHtml += '<button class="edit-btn" data-idx="' + i + '" title="Edit">&#x270E;</button>';
                    actionsHtml += '<button class="delete-btn" data-idx="' + i + '" title="Delete">&times;</button>';
                }
                actionsHtml += '</div>';

                card.innerHTML =
                    '<div class="account-info">' +
                        '<div class="totp-code" data-code="' + code + '">' + code + '<span class="copy-tip">Copied!</span></div>' +
                        '<div class="account-meta">' +
                            '<span class="account-name">' + nameHtml + '</span>' +
                            ' <span class="meta-countdown">' + cd + 's</span>' +
                        '</div>' +
                    '</div>' + actionsHtml;

                // Click code to copy
                var codeEl = card.querySelector('.totp-code');
                codeEl.addEventListener('click', function(e) {
                    e.preventDefault();
                    copyToClipboard(this.getAttribute('data-code'), this);
                });

                // QR handler (always visible)
                card.querySelector('.qr-btn').addEventListener('click', function() {
                    showQR(parseInt(this.getAttribute('data-idx'), 10));
                });

                // Edit & delete handlers
                if (editing) {
                    card.querySelector('.edit-btn').addEventListener('click', function() {
                        openEdit(parseInt(this.getAttribute('data-idx'), 10));
                    });
                    card.querySelector('.delete-btn').addEventListener('click', function() {
                        deleteAccount(parseInt(this.getAttribute('data-idx'), 10));
                    });
                }

                list.appendChild(card);
            });
        };

        var toggleEdit = function() {
            editing = !editing;
            $('#editBtn').classList.toggle('active', editing);
            $('#resetBtn').classList.toggle('hidden', !editing);
            $('#importBtn').classList.toggle('hidden', !editing);
            $('#exportBtn').classList.toggle('hidden', !editing);
            $('#addRow').style.display = editing ? '' : 'none';
            render();
        };

        var buildOtpauth = function(acc) {
            var algo   = acc.algorithm || DEFAULTS.algorithm;
            var period = acc.period    || DEFAULTS.period;
            var digits = acc.digits    || DEFAULTS.digits;
            var issuer = acc.issuer || '';
            var label  = issuer
                ? (encodeURIComponent(issuer) + ':' + encodeURIComponent(acc.name))
                : encodeURIComponent(acc.name);
            var params = 'secret=' + encodeURIComponent(acc.secret);
            if (issuer) params += '&issuer=' + encodeURIComponent(issuer);
            params += '&algorithm=' + algo.replace('SHA-', 'SHA').replace('-', '');
            params += '&digits=' + digits;
            params += '&period=' + period;
            return 'otpauth://totp/' + label + '?' + params;
        };

        var exportAccounts = function() {
            var accounts = store.getObject('accounts') || [];
            // Export every field explicitly (even defaults)
            var full = accounts.map(function(acc) {
                return {
                    name:      acc.name,
                    issuer:    acc.issuer    || '',
                    secret:    acc.secret,
                    algorithm: acc.algorithm || DEFAULTS.algorithm,
                    period:    acc.period    || DEFAULTS.period,
                    digits:    acc.digits    || DEFAULTS.digits,
                    url:       acc.url       || '',
                    otpauth:   buildOtpauth(acc)
                };
            });
            var data = JSON.stringify(full, null, 2);
            var blob = new Blob([data], { type: 'text/plain;charset=utf-8' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'authenticator-export.json';
            a.click();
        };

        // Import from JSON (our export format) or text file with otpauth:// URIs
        var importAccounts = function(e) {
            var file = e.target.files[0];
            if (!file) return;
            var reader = new FileReader();
            reader.onload = function(ev) {
                var text = ev.target.result;
                var imported = 0;
                try {
                    // Try JSON first (our export format)
                    var arr = JSON.parse(text);
                    if (!Array.isArray(arr)) arr = [arr];
                    arr.forEach(function(item) {
                        // Support our export format or otpauth field
                        if (item.secret) {
                            addAccount(
                                item.name      || 'Imported',
                                item.secret,
                                item.algorithm || DEFAULTS.algorithm,
                                item.period    || DEFAULTS.period,
                                item.digits    || DEFAULTS.digits,
                                item.url       || '',
                                item.issuer    || ''
                            );
                            imported++;
                        } else if (item.otpauth) {
                            var parsed = parseOtpauth(item.otpauth);
                            if (parsed) {
                                addAccount(parsed.name, parsed.secret, parsed.algorithm, parsed.period, parsed.digits, '', parsed.issuer);
                                imported++;
                            }
                        }
                    });
                } catch(ex) {
                    // Not JSON — try line-by-line otpauth:// URIs
                    text.split('\n').forEach(function(line) {
                        line = line.trim();
                        if (line.indexOf('otpauth://') === 0) {
                            var parsed = parseOtpauth(line);
                            if (parsed) {
                                addAccount(parsed.name, parsed.secret, parsed.algorithm, parsed.period, parsed.digits, '', parsed.issuer);
                                imported++;
                            }
                        }
                    });
                }
                if (imported > 0) {
                    alert('Imported ' + imported + ' account' + (imported > 1 ? 's' : '') + '.');
                } else {
                    alert('No valid accounts found in file.');
                }
                // Reset file input so same file can be re-imported
                e.target.value = '';
            };
            reader.readAsText(file);
        };

        var deleteAccount = function(idx) {
            var accounts = store.getObject('accounts');
            accounts.splice(idx, 1);
            store.setObject('accounts', accounts);
            render();
        };

        var resetAccounts = function() {
            if (!confirm('Delete all accounts? This cannot be undone.')) return;
            localStorage.removeItem('accounts');
            editing = false;
            $('#editBtn').classList.remove('active');
            $('#resetBtn').classList.add('hidden');
            $('#exportBtn').classList.add('hidden');
            $('#addRow').style.display = 'none';
            render();
        };

        // Store every field explicitly (even defaults)
        var addAccount = function(name, secret, algorithm, period, digits, url, issuer) {
            if (!secret) return false;
            var acc = {
                name:      name,
                secret:    secret,
                algorithm: algorithm || DEFAULTS.algorithm,
                period:    period    || DEFAULTS.period,
                digits:    digits    || DEFAULTS.digits,
                url:       url       || '',
                issuer:    issuer    || ''
            };
            var accounts = store.getObject('accounts') || [];
            accounts.push(acc);
            store.setObject('accounts', accounts);
            render();
            return true;
        };

        var showQR = function(idx) {
            var accounts = store.getObject('accounts') || [];
            var acc = accounts[idx];
            if (!acc) return;
            var uri = buildOtpauth(acc);
            $('#qrTitle').textContent = acc.issuer ? acc.issuer + (acc.name ? ' (' + acc.name + ')' : '') : acc.name;
            $('#qrUri').textContent = uri;

            // Generate QR code
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

        var closeQR = function() {
            $('#qrModal').classList.remove('open');
        };

        var openEdit = function(idx) {
            var accounts = store.getObject('accounts') || [];
            var acc = accounts[idx];
            if (!acc) return;
            editIndex = idx;
            $('#modalTitle').textContent = 'Edit Account';
            $('#addKeyButton').textContent = 'Save';
            $('#keyIssuer').value    = acc.issuer || '';
            $('#keyAccount').value   = acc.name || '';
            $('#keySecret').value    = acc.secret || '';
            $('#keyUrl').value       = acc.url || '';
            $('#keyAlgorithm').value = acc.algorithm || DEFAULTS.algorithm;
            $('#keyPeriod').value    = acc.period || DEFAULTS.period;
            $('#keyDigits').value    = acc.digits || DEFAULTS.digits;
            $('#addModal').classList.add('open');
        };

        var onSave = function() {
            var issuer = $('#keyIssuer').value.trim();
            var name   = $('#keyAccount').value.trim();
            var secret = $('#keySecret').value.replace(/\s/g, '');
            var url    = $('#keyUrl').value.trim();
            var algo   = $('#keyAlgorithm').value;
            var period = parseInt($('#keyPeriod').value, 10);
            var digits = parseInt($('#keyDigits').value, 10);
            if (!name)   { $('#keyAccount').focus(); return; }
            if (!secret) { $('#keySecret').focus(); return; }

            if (editIndex >= 0) {
                // Update existing — store every field explicitly
                var accounts = store.getObject('accounts') || [];
                var acc = {
                    name:      name,
                    secret:    secret,
                    algorithm: algo   || DEFAULTS.algorithm,
                    period:    period || DEFAULTS.period,
                    digits:    digits || DEFAULTS.digits,
                    url:       url    || '',
                    issuer:    issuer || ''
                };
                accounts[editIndex] = acc;
                store.setObject('accounts', accounts);
                render();
            } else {
                // Add new
                addAccount(name, secret, algo, period, digits, url, issuer);
            }
            closeModal();
        };

        var closeModal = function() {
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

        var tick = function() {
            render();
        };

        return { init: init, addAccount: addAccount, deleteAccount: deleteAccount };
    };

    exports.KeysController = KeysController;
    exports.DEFAULTS = DEFAULTS;

})(typeof exports === 'undefined' ? this['totpAuth'] = {} : exports);
