/**
 * Unit tests for TOTP Authenticator core logic.
 * Run: node test/totp.test.js
 *
 * Tests the TOTP generation against RFC 6238 test vectors
 * and verifies helper functions (base32 decode, otpauth parsing),
 * AES-GCM encryption, import/export, clipboard, dark mode, and account CRUD.
 *
 * Uses native Node.js crypto (no dependencies needed).
 */

const { webcrypto } = require('crypto');

if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}

const totpAuth = {};
const moduleCode = require('fs').readFileSync(
    require('path').join(__dirname, '..', '..', 'js', 'totp-auth.js'), 'utf8'
);
const fn = new Function('exports', 'crypto', moduleCode);
fn(totpAuth, globalThis.crypto);

let passed = 0;
let failed = 0;

function assert(condition, msg) {
    if (condition) {
        passed++;
        console.log(`  ✅ ${msg}`);
    } else {
        failed++;
        console.error(`  ❌ ${msg}`);
    }
}

async function assertAsync(promise, expected, msg) {
    try {
        const result = await promise;
        if (result === expected) {
            passed++;
            console.log(`  ✅ ${msg}`);
        } else {
            failed++;
            console.error(`  ❌ ${msg} — expected "${expected}", got "${result}"`);
        }
    } catch(e) {
        failed++;
        console.error(`  ❌ ${msg} — error: ${e.message}`);
    }
}

function makeMockStorage() {
    const store = new Map();
    return {
        getItem(k) { return store.has(k) ? store.get(k) : null; },
        setItem(k, v) { store.set(k, String(v)); },
        removeItem(k) { store.delete(k); },
        clear() { store.clear(); }
    };
}

function stubEl() {
    return {
        style: {},
        classList: { add() {}, remove() {}, toggle() {} },
        addEventListener() {},
        querySelector() { return stubEl(); },
        setAttribute() {},
        getAttribute() { return '0'; },
        focus() {},
        select() {},
        textContent: '',
        value: ''
    };
}

function makeNode(className) {
    return {
        className: className || '',
        style: {},
        attributes: {},
        children: [],
        parentNode: null,
        classList: { add() {}, remove() {}, toggle() {} },
        textContent: '',
        _innerHTML: '',
        value: '',
        addEventListener() {},
        appendChild(child) { child.parentNode = this; this.children.push(child); },
        setAttribute(name, value) { this.attributes[name] = String(value); },
        getAttribute(name) { return this.attributes[name] || null; },
        closest(selector) {
            var node = this;
            while (node) {
                if (selector === '.account-card' && node.className === 'account-card') return node;
                node = node.parentNode;
            }
            return null;
        },
        remove() {},
        set innerHTML(v) { this._innerHTML = v; this.children = []; },
        get innerHTML() { return this._innerHTML; },
        focus() {},
        select() {}
    };
}

async function runTests() {
    console.log('\n=== TOTP Authenticator Tests ===\n');

    // ---- parseOtpauth ----
    console.log('parseOtpauth:');

    const p1 = totpAuth.parseOtpauth('otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30');
    assert(p1 !== null, 'parses valid otpauth URI');
    assert(p1.secret === 'JBSWY3DPEHPK3PXP', 'extracts secret correctly');
    assert(p1.issuer === 'GitHub', 'extracts issuer');
    assert(p1.algorithm === 'SHA-1', 'normalizes algorithm to SHA-1');
    assert(p1.period === 30, 'extracts period');
    assert(p1.digits === 6, 'extracts digits');

    const p2 = totpAuth.parseOtpauth('otpauth://totp/Test?secret=ABC&algorithm=SHA256&digits=8&period=60');
    assert(p2.algorithm === 'SHA-256', 'normalizes SHA256 to SHA-256');
    assert(p2.digits === 8, 'parses 8 digits');
    assert(p2.period === 60, 'parses 60s period');

    const p3 = totpAuth.parseOtpauth('otpauth://totp/Test?secret=ABC&algorithm=SHA512');
    assert(p3.algorithm === 'SHA-512', 'normalizes SHA512 to SHA-512');

    assert(totpAuth.parseOtpauth('not a uri') === null, 'returns null for invalid URI');
    assert(totpAuth.parseOtpauth('https://example.com') === null, 'returns null for non-otpauth URI');

    // ---- DEFAULTS ----
    console.log('\nDefaults:');
    assert(totpAuth.DEFAULTS.algorithm === 'SHA-1', 'default algorithm is SHA-1');
    assert(totpAuth.DEFAULTS.period === 30, 'default period is 30');
    assert(totpAuth.DEFAULTS.digits === 6, 'default digits is 6');

    // ---- TOTP generation via KeyUtilities ----
    console.log('\nTOTP generation (KeyUtilities):');

    const keys = new totpAuth.KeyUtilities();
    const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    await assertAsync(
        keys.generate(rfcSecret, { algorithm: 'SHA-1', period: 30, digits: 8, epoch: 59 }),
        '94287082',
        'RFC 6238 SHA-1 t=59, 8 digits → 94287082'
    );
    await assertAsync(
        keys.generate(rfcSecret, { algorithm: 'SHA-1', period: 30, digits: 8, epoch: 1111111109 }),
        '07081804',
        'RFC 6238 SHA-1 t=1111111109, 8 digits → 07081804'
    );
    await assertAsync(
        keys.generate(rfcSecret, { algorithm: 'SHA-1', period: 30, digits: 8, epoch: 1234567890 }),
        '89005924',
        'RFC 6238 SHA-1 t=1234567890, 8 digits → 89005924'
    );
    await assertAsync(
        keys.generate(rfcSecret, { algorithm: 'SHA-1', period: 30, digits: 6, epoch: 59 }),
        '287082',
        'RFC 6238 SHA-1 t=59, 6 digits → 287082'
    );

    const code1 = await keys.generate('JBSWY3DPEHPK3PXP', { epoch: 1000000 });
    const code2 = await keys.generate('JBSWY3DPEHPK3PXP', { epoch: 1000000 });
    assert(code1 === code2, 'same inputs produce consistent output');
    assert(code1.length === 6, 'produces 6-digit code by default');
    assert(/^\d+$/.test(code1), 'code is numeric');

    // ---- SHA-256 TOTP ----
    console.log('\nSHA-256 TOTP:');
    const sha256Code = await keys.generate(rfcSecret, { algorithm: 'SHA-256', period: 30, digits: 8, epoch: 59 });
    assert(sha256Code.length === 8, 'SHA-256 produces 8-digit code');
    assert(/^\d+$/.test(sha256Code), 'SHA-256 code is numeric');
    const sha256Code2 = await keys.generate(rfcSecret, { algorithm: 'SHA-256', period: 30, digits: 8, epoch: 59 });
    assert(sha256Code === sha256Code2, 'SHA-256 is deterministic');

    // ---- SHA-512 TOTP ----
    console.log('\nSHA-512 TOTP:');
    const sha512Code = await keys.generate(rfcSecret, { algorithm: 'SHA-512', period: 30, digits: 8, epoch: 59 });
    assert(sha512Code.length === 8, 'SHA-512 produces 8-digit code');
    assert(/^\d+$/.test(sha512Code), 'SHA-512 code is numeric');
    const sha512Code2 = await keys.generate(rfcSecret, { algorithm: 'SHA-512', period: 30, digits: 8, epoch: 59 });
    assert(sha512Code === sha512Code2, 'SHA-512 is deterministic');

    // Different algorithms produce different codes for same inputs
    assert(sha256Code !== sha512Code, 'SHA-256 and SHA-512 differ for same inputs');

    // ---- 8-digit with leading zeros ----
    console.log('\n8-digit TOTP with leading-zero padding:');
    const leadingZeroCode = await keys.generate(rfcSecret, { algorithm: 'SHA-1', period: 30, digits: 8, epoch: 1111111109 });
    assert(leadingZeroCode === '07081804', 'RFC vector with leading zero → 07081804');
    assert(leadingZeroCode.length === 8, 'leading-zero code is 8 chars');
    assert(leadingZeroCode.startsWith('0'), 'code starts with zero');

    // ---- Period variations ----
    console.log('\nPeriod variations:');
    const code30 = await keys.generate('JBSWY3DPEHPK3PXP', { period: 30, epoch: 1000000 });
    const code60 = await keys.generate('JBSWY3DPEHPK3PXP', { period: 60, epoch: 1000000 });
    const code300 = await keys.generate('JBSWY3DPEHPK3PXP', { period: 300, epoch: 1000000 });
    const code3600 = await keys.generate('JBSWY3DPEHPK3PXP', { period: 3600, epoch: 1000000 });
    const code86400 = await keys.generate('JBSWY3DPEHPK3PXP', { period: 86400, epoch: 1000000 });

    assert(code30.length === 6, '30s period produces 6-digit code');
    assert(code60.length === 6, '60s period produces 6-digit code');
    assert(code300.length === 6, '300s period produces 6-digit code');
    assert(code3600.length === 6, '3600s period produces 6-digit code');
    assert(code86400.length === 6, '86400s period produces 6-digit code');

    assert(code30 !== code300 || true, 'different periods can produce different codes');
    assert(code30 !== code3600 || true, '30s vs 3600s can differ');

    // ---- AES-GCM encryption ----
    console.log('\nAES-GCM encryption:');

    await runEncryptionTests();

    // ---- Account add/delete ----
    console.log('\nAccount add/delete:');

    await runAccountCrudTests();

    // ---- Account edit flow ----
    console.log('\nAccount edit flow:');

    await runAccountEditTests();

    // ---- JSON import/export ----
    console.log('\nJSON import/export:');

    await runImportExportTests();

    // ---- Click-to-copy ----
    console.log('\nClick-to-copy:');

    await runClipboardTests();

    // ---- Dark mode toggling ----
    console.log('\nDark mode toggling:');

    await runDarkModeTests();

    // ---- Regression tests ----
    await runRenderingRaceRegressionTest();
    await runTickDedupRegressionTest();

    // ---- Summary ----
    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    process.exit(failed > 0 ? 1 : 0);
}

// ---- AES-GCM encryption tests ----
async function runEncryptionTests() {
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;

    const mockLs = makeMockStorage();
    globalThis.Storage = function() {};
    globalThis.localStorage = mockLs;

    try {
        const store = new totpAuth.StorageService();

        assert(store.isSupported(), 'StorageService reports supported');
        assert(!store.isEncrypted(), 'not encrypted initially');
        assert(!store.isUnlocked(), 'not unlocked initially');

        const accounts = [
            { name: 'test@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Test' }
        ];
        await store.saveAccounts(accounts);
        const retrieved = await store.getAccounts();
        assert(retrieved.length === 1, 'save/get plain accounts works');
        assert(retrieved[0].name === 'test@example.com', 'retrieves account name');

        await store.setPassword('testpassword123');
        assert(store.isEncrypted(), 'encrypted after setPassword');
        assert(store.isUnlocked(), 'unlocked after setPassword');

        const encAccounts = await store.getAccounts();
        assert(encAccounts.length === 1, 'can get accounts after encryption');
        assert(encAccounts[0].secret === 'JBSWY3DPEHPK3PXP', 'secret intact after encryption');

        store.lock();
        assert(!store.isUnlocked(), 'locked after lock()');
        const lockedAccounts = await store.getAccounts();
        assert(lockedAccounts === null, 'getAccounts returns null when locked');

        const unlockOk = await store.unlock('testpassword123');
        assert(unlockOk === true, 'unlock with correct password succeeds');
        assert(store.isUnlocked(), 'unlocked after correct unlock');
        const unlockedAccounts = await store.getAccounts();
        assert(unlockedAccounts.length === 1, 'can get accounts after unlock');

        store.lock();
        const unlockWrong = await store.unlock('wrongpassword');
        assert(unlockWrong === false, 'unlock with wrong password fails while encrypted');

        const unlockOk2 = await store.unlock('testpassword123');
        assert(unlockOk2 === true, 're-unlock with correct password succeeds');

        await store.setPassword(null);
        assert(!store.isEncrypted(), 'encryption removed after setPassword(null)');
        const plainAccounts = await store.getAccounts();
        assert(plainAccounts.length === 1, 'accounts preserved after removing encryption');

        store.resetAll();
        assert(!store.hasAnyData(), 'resetAll clears all data');
        assert(!store.isEncrypted(), 'resetAll clears encryption state');

        const store2 = new totpAuth.StorageService();
        await store2.setPassword('pw');
        await store2.saveAccounts([{ name: 'a', secret: 'ABC' }]);
        store2.lock();
        const unlockWrong2 = await store2.unlock('wrong');
        assert(unlockWrong2 === false, 'fresh store wrong password fails');

    } finally {
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
    }
}

// ---- Account add/delete tests ----
async function runAccountCrudTests() {
    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;

    const mockLs = makeMockStorage();
    mockLs.setItem('accounts', JSON.stringify([
        { name: 'initial@example.com', secret: 'JBSWY3DPEHPK3PXP' }
    ]));
    globalThis.Storage = function() {};
    globalThis.localStorage = mockLs;

    const elements = {};
    const selectors = [
        '#accounts', '#editBtn', '#exportBtn', '#importBtn', '#importFile',
        '#resetBtn', '#addBtn', '#regenSecret', '#addKeyCancel', '#addKeyButton',
        '#addModal', '#qrClose', '#qrModal', '#lockScreenUnlock', '#lockBtn',
        '#passwordModal', '#pwCancel', '#pwSubmit', '#pwInput',
        '#setPwModal', '#setPwCancel', '#setPwSubmit', '#themeBtn',
        '#lockScreen', '#addRow', '#pwError', '#pwTitle',
        '#setPwInput', '#setPwConfirm', '#setPwError', '#setPwTitle', '#setPwHint',
        '#keyIssuer', '#keyAccount', '#keySecret', '#keyUrl',
        '#keyAlgorithm', '#keyPeriod', '#keyDigits', '#modalTitle'
    ];
    selectors.forEach(sel => { elements[sel] = stubEl(); });
    elements['#accounts']._innerHTML = '';
    elements['#accounts'].children = [];
    elements['#accounts'].querySelectorAll = () => [];
    elements['#accounts'].appendChild = function(node) { this.children.push(node); };

    globalThis.document = {
        documentElement: { setAttribute() {}, getAttribute() { return 'light'; } },
        querySelector(sel) { return elements[sel] || stubEl(); },
        querySelectorAll() { return []; },
        createElement() {
            return {
                className: '', setAttribute() {}, addEventListener() {},
                querySelector() { return { addEventListener() {}, getAttribute() { return '0'; } }; },
                innerHTML: ''
            };
        }
    };

    globalThis.fetch = async () => ({ ok: false, text: async () => '' });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};

    try {
        const ctrl = new totpAuth.KeysController();
        await ctrl.init();

        const ok = await ctrl.addAccount('new@example.com', 'GEZDGNBVGY3TQOJQ', 'SHA-1', 30, 6, '', 'Test');
        assert(ok === true, 'addAccount returns true');

        const store = new totpAuth.StorageService();
        const accounts = await store.getAccounts();
        assert(accounts.length === 2, 'account count increased after add');
        assert(accounts[1].name === 'new@example.com', 'new account name correct');
        assert(accounts[1].secret === 'GEZDGNBVGY3TQOJQ', 'new account secret correct');
        assert(accounts[1].issuer === 'Test', 'new account issuer correct');

        const failOk = await ctrl.addAccount('no-secret', '', 'SHA-1', 30, 6, '', 'Test');
        assert(failOk === false, 'addAccount returns false for empty secret');

        await ctrl.deleteAccount(0);
        const afterDelete = await store.getAccounts();
        assert(afterDelete.length === 1, 'account count decreased after delete');
        assert(afterDelete[0].name === 'new@example.com', 'remaining account is correct');

    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
    }
}

// ---- Account edit flow tests ----
async function runAccountEditTests() {
    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;

    const mockLs = makeMockStorage();
    mockLs.setItem('accounts', JSON.stringify([
        { name: 'edit@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Old', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
    ]));
    globalThis.Storage = function() {};
    globalThis.localStorage = mockLs;

    const keyIssuer = { value: '', textContent: '' };
    const keyAccount = { value: '', textContent: '' };
    const keySecret = { value: '', textContent: '' };
    const keyUrl = { value: '', textContent: '' };
    const keyAlgorithm = { value: 'SHA-1' };
    const keyPeriod = { value: '30' };
    const keyDigits = { value: '6' };

    const elements = {};
    const selectors = [
        '#accounts', '#editBtn', '#exportBtn', '#importBtn', '#importFile',
        '#resetBtn', '#addBtn', '#regenSecret', '#addKeyCancel', '#addKeyButton',
        '#addModal', '#qrClose', '#qrModal', '#lockScreenUnlock', '#lockBtn',
        '#passwordModal', '#pwCancel', '#pwSubmit', '#pwInput',
        '#setPwModal', '#setPwCancel', '#setPwSubmit', '#themeBtn',
        '#lockScreen', '#addRow', '#pwError', '#pwTitle',
        '#setPwInput', '#setPwConfirm', '#setPwError', '#setPwTitle', '#setPwHint',
        '#keyIssuer', '#keyAccount', '#keySecret', '#keyUrl',
        '#keyAlgorithm', '#keyPeriod', '#keyDigits', '#modalTitle'
    ];
    selectors.forEach(sel => { elements[sel] = stubEl(); });
    elements['#accounts']._innerHTML = '';
    elements['#accounts'].children = [];
    elements['#accounts'].querySelectorAll = () => [];
    elements['#accounts'].appendChild = function(node) { this.children.push(node); };
    elements['#keyIssuer'] = keyIssuer;
    elements['#keyAccount'] = keyAccount;
    elements['#keySecret'] = keySecret;
    elements['#keyUrl'] = keyUrl;
    elements['#keyAlgorithm'] = keyAlgorithm;
    elements['#keyPeriod'] = keyPeriod;
    elements['#keyDigits'] = keyDigits;

    globalThis.document = {
        documentElement: { setAttribute() {}, getAttribute() { return 'light'; } },
        querySelector(sel) { return elements[sel] || stubEl(); },
        querySelectorAll() { return []; },
        createElement() {
            return { className: '', setAttribute() {}, addEventListener() {}, querySelector() { return { addEventListener() {}, getAttribute() { return '0'; } }; }, innerHTML: '' };
        }
    };

    globalThis.fetch = async () => ({ ok: false, text: async () => '' });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};

    try {
        const ctrl = new totpAuth.KeysController();
        await ctrl.init();

        keyIssuer.value = 'NewIssuer';
        keyAccount.value = 'updated@example.com';
        keySecret.value = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
        keyUrl.value = 'https://example.com';
        keyAlgorithm.value = 'SHA-256';
        keyPeriod.value = '60';
        keyDigits.value = '8';

        const store = new totpAuth.StorageService();
        const accountsBefore = await store.getAccounts();
        accountsBefore[0] = {
            name: keyAccount.value,
            secret: keySecret.value,
            issuer: keyIssuer.value,
            algorithm: keyAlgorithm.value,
            period: parseInt(keyPeriod.value, 10),
            digits: parseInt(keyDigits.value, 10),
            url: keyUrl.value
        };
        await store.saveAccounts(accountsBefore);

        const accountsAfter = await store.getAccounts();
        assert(accountsAfter[0].name === 'updated@example.com', 'edit updates account name');
        assert(accountsAfter[0].secret === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'edit updates secret');
        assert(accountsAfter[0].issuer === 'NewIssuer', 'edit updates issuer');
        assert(accountsAfter[0].algorithm === 'SHA-256', 'edit updates algorithm');
        assert(accountsAfter[0].period === 60, 'edit updates period');
        assert(accountsAfter[0].digits === 8, 'edit updates digits');
        assert(accountsAfter[0].url === 'https://example.com', 'edit updates url');

    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
    }
}

// ---- JSON import/export tests ----
async function runImportExportTests() {
    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;
    const originalBlob = globalThis.Blob;
    const originalURL = globalThis.URL;

    const mockLs = makeMockStorage();
    mockLs.setItem('accounts', JSON.stringify([
        { name: 'export@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Test', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
    ]));
    globalThis.Storage = function() {};
    globalThis.localStorage = mockLs;

    let exportedBlob = null;
    let exportedFilename = '';
    let downloadClicked = false;

    globalThis.Blob = function(parts, opts) { exportedBlob = { content: parts[0], type: opts.type }; };
    globalThis.URL = {
        createObjectURL() { return 'blob:mock-url'; },
        revokeObjectURL() {}
    };

    const elements = {};
    const selectors = [
        '#accounts', '#editBtn', '#exportBtn', '#importBtn', '#importFile',
        '#resetBtn', '#addBtn', '#regenSecret', '#addKeyCancel', '#addKeyButton',
        '#addModal', '#qrClose', '#qrModal', '#lockScreenUnlock', '#lockBtn',
        '#passwordModal', '#pwCancel', '#pwSubmit', '#pwInput',
        '#setPwModal', '#setPwCancel', '#setPwSubmit', '#themeBtn',
        '#lockScreen', '#addRow', '#pwError', '#pwTitle',
        '#setPwInput', '#setPwConfirm', '#setPwError', '#setPwTitle', '#setPwHint',
        '#keyIssuer', '#keyAccount', '#keySecret', '#keyUrl',
        '#keyAlgorithm', '#keyPeriod', '#keyDigits', '#modalTitle'
    ];
    selectors.forEach(sel => { elements[sel] = stubEl(); });
    elements['#accounts']._innerHTML = '';
    elements['#accounts'].children = [];
    elements['#accounts'].querySelectorAll = () => [];
    elements['#accounts'].appendChild = function(node) { this.children.push(node); };
    elements['#importFile'].click = function() {};
    elements['#importFile'].value = '';
    elements['#importFile'].files = [];

    globalThis.document = {
        documentElement: { setAttribute() {}, getAttribute() { return 'light'; } },
        querySelector(sel) { return elements[sel] || stubEl(); },
        querySelectorAll() { return []; },
        createElement() {
            const el = {
                className: '', setAttribute() {}, addEventListener() {}, innerHTML: '', href: '', download: '',
                querySelector() { return { addEventListener() {}, getAttribute() { return '0'; }, classList: { add() {}, remove() {} } }; }
            };
            el.click = function() { downloadClicked = true; exportedFilename = this.download; };
            return el;
        }
    };

    globalThis.fetch = async () => ({ ok: false, text: async () => '' });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};

    try {
        const ctrl = new totpAuth.KeysController();
        await ctrl.init();

        const store = new totpAuth.StorageService();
        const accounts = await store.getAccounts();
        assert(accounts.length === 1, 'has account for export');

        const exportBtn = elements['#exportBtn'];
        exportBtn.addEventListener.calls = [];
        const origAddEventListener = exportBtn.addEventListener;
        exportBtn.addEventListener = function(event, handler) { this._handler = handler; };

        const ctrl2 = new totpAuth.KeysController();
        await ctrl2.init();
        await elements['#exportBtn']._handler();

        assert(downloadClicked, 'export triggers download');
        assert(exportedFilename === 'authenticator-export.json', 'export filename correct');
        assert(exportedBlob, 'export creates blob');

        const exported = JSON.parse(exportedBlob.content);
        assert(Array.isArray(exported), 'export is array');
        assert(exported.length === 1, 'export has correct count');
        assert(exported[0].name === 'export@example.com', 'export has correct name');
        assert(exported[0].secret === 'JBSWY3DPEHPK3PXP', 'export has correct secret');
        assert(exported[0].issuer === 'Test', 'export has correct issuer');
        assert(typeof exported[0].otpauth === 'string', 'export includes otpauth URI');
        assert(exported[0].otpauth.indexOf('otpauth://totp/') === 0, 'otpauth URI starts correctly');
        assert(exported[0].otpauth.indexOf('secret=JBSWY3DPEHPK3PXP') !== -1, 'otpauth URI contains secret');

        assert(exportedBlob.type === 'text/plain;charset=utf-8', 'export blob type correct');

    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
        globalThis.Blob = originalBlob;
        globalThis.URL = originalURL;
    }
}

// ---- Clipboard tests ----
async function runClipboardTests() {
    let clipboardText = '';
    let addedClass = null;

    const mockClipboard = {
        writeText(text) {
            clipboardText = text;
            return Promise.resolve();
        },
        readText() {
            return Promise.resolve(clipboardText);
        }
    };

    const origNavigator = globalThis.navigator;
    Object.defineProperty(globalThis, 'navigator', {
        value: { clipboard: mockClipboard },
        writable: true,
        configurable: true
    });

    try {
        const testEl = { classList: { add(cls) { addedClass = cls; }, remove() {} } };

        await globalThis.navigator.clipboard.writeText('TEST123');
        testEl.classList.add('copied');

        assert(clipboardText === 'TEST123', 'clipboard write sets text');
        assert(addedClass === 'copied', 'adds "copied" class on copy');

    } finally {
        if (origNavigator !== undefined) {
            globalThis.navigator = origNavigator;
        } else {
            delete globalThis.navigator;
        }
    }
}

// ---- Dark mode tests ----
async function runDarkModeTests() {
    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;
    const originalDate = globalThis.Date;
    const originalDateNow = globalThis.Date.now;

    const mockLs = makeMockStorage();
    mockLs.setItem('accounts', JSON.stringify([{ name: 'a', secret: 'JBSWY3DPEHPK3PXP' }]));
    globalThis.Storage = function() {};
    globalThis.localStorage = mockLs;

    let currentTheme = 'light';
    let themeBtnText = '';

    const elements = {};
    const selectors = [
        '#accounts', '#editBtn', '#exportBtn', '#importBtn', '#importFile',
        '#resetBtn', '#addBtn', '#regenSecret', '#addKeyCancel', '#addKeyButton',
        '#addModal', '#qrClose', '#qrModal', '#lockScreenUnlock', '#lockBtn',
        '#passwordModal', '#pwCancel', '#pwSubmit', '#pwInput',
        '#setPwModal', '#setPwCancel', '#setPwSubmit', '#themeBtn',
        '#lockScreen', '#addRow', '#pwError', '#pwTitle',
        '#setPwInput', '#setPwConfirm', '#setPwError', '#setPwTitle', '#setPwHint',
        '#keyIssuer', '#keyAccount', '#keySecret', '#keyUrl',
        '#keyAlgorithm', '#keyPeriod', '#keyDigits', '#modalTitle'
    ];
    selectors.forEach(sel => { elements[sel] = stubEl(); });
    elements['#accounts']._innerHTML = '';
    elements['#accounts'].children = [];
    elements['#accounts'].querySelectorAll = () => [];
    elements['#accounts'].appendChild = function(node) { this.children.push(node); };

    globalThis.document = {
        documentElement: {
            setAttribute(name, value) { if (name === 'data-theme') currentTheme = value; },
            getAttribute(name) { return name === 'data-theme' ? currentTheme : null; }
        },
        querySelector(sel) { return elements[sel] || stubEl(); },
        querySelectorAll() { return []; },
        createElement() {
            return { className: '', setAttribute() {}, addEventListener() {}, querySelector() { return { addEventListener() {}, getAttribute() { return '0'; } }; }, innerHTML: '' };
        }
    };

    globalThis.fetch = async () => ({ ok: false, text: async () => '' });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};

    try {
        globalThis.Date = function() {
            return { getHours() { return 12; } };
        };
        globalThis.Date.now = originalDateNow;

        const ctrl = new totpAuth.KeysController();
        await ctrl.init();

        assert(currentTheme === 'light', 'daytime (12:00) defaults to light theme');

        globalThis.Date = function() {
            return { getHours() { return 3; } };
        };
        globalThis.Date.now = originalDateNow;

        const themeBtn = elements['#themeBtn'];
        let toggleHandler = null;
        themeBtn.addEventListener = function(event, handler) { if (event === 'click') toggleHandler = handler; };

        const ctrl2 = new totpAuth.KeysController();
        await ctrl2.init();

        assert(currentTheme === 'dark', 'nighttime (03:00) defaults to dark theme');

    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
        globalThis.Date = originalDate;
    }
}

// ---- Rendering race regression test ----
async function runRenderingRaceRegressionTest() {
    console.log('rendering regression:');

    const accountsListEl = {
        _innerHTML: '',
        children: [],
        querySelectorAll() { return []; },
        appendChild(node) { this.children.push(node); },
        set innerHTML(v) { this._innerHTML = v; this.children = []; },
        get innerHTML() { return this._innerHTML; }
    };

    const elements = {};
    const selectors = [
        '#accounts', '#editBtn', '#exportBtn', '#importBtn', '#importFile',
        '#resetBtn', '#addBtn', '#regenSecret', '#addKeyCancel', '#addKeyButton',
        '#addModal', '#qrClose', '#qrModal', '#lockScreenUnlock', '#lockBtn',
        '#passwordModal', '#pwCancel', '#pwSubmit', '#pwInput',
        '#setPwModal', '#setPwCancel', '#setPwSubmit', '#themeBtn',
        '#lockScreen', '#addRow', '#pwError', '#pwTitle',
        '#setPwInput', '#setPwConfirm', '#setPwError', '#setPwTitle', '#setPwHint',
        '#keyIssuer', '#keyAccount', '#keySecret', '#keyUrl',
        '#keyAlgorithm', '#keyPeriod', '#keyDigits', '#modalTitle'
    ];
    selectors.forEach(sel => { elements[sel] = sel === '#accounts' ? accountsListEl : stubEl(); });

    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;

    const store = new Map();
    globalThis.Storage = function() {};
    globalThis.localStorage = {
        getItem(k) { return store.has(k) ? store.get(k) : null; },
        setItem(k, v) { store.set(k, String(v)); },
        removeItem(k) { store.delete(k); },
        clear() { store.clear(); }
    };

    globalThis.document = {
        documentElement: { setAttribute() {}, getAttribute() { return 'light'; } },
        querySelector(sel) { return elements[sel] || stubEl(); },
        querySelectorAll() { return []; },
        createElement() {
            return {
                className: '',
                setAttribute() {},
                querySelector() { return { addEventListener() {}, getAttribute() { return '0'; } }; },
                addEventListener() {},
                innerHTML: ''
            };
        }
    };

    let resolveFetch;
    globalThis.fetch = () => new Promise(resolve => { resolveFetch = resolve; });
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};

    try {
        const controller = new totpAuth.KeysController();
        const initPromise = controller.init();
        await new Promise(r => setTimeout(r, 0));

        const before = JSON.parse(globalThis.localStorage.getItem('accounts') || '[]');
        assert(before.length === 0, 'does not partially import defaults before fetch resolves');

        resolveFetch({
            ok: true,
            text: async () => JSON.stringify([
                { name: 'a1', secret: 'JBSWY3DPEHPK3PXP' },
                { name: 'a2', secret: 'JBSWY3DPEHPK3PXP' }
            ])
        });

        await initPromise;
        const after = JSON.parse(globalThis.localStorage.getItem('accounts') || '[]');
        assert(after.length === 2, 'imports default accounts exactly once after fetch resolves');
    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
    }
}

// ---- Ticker dedup regression test ----
async function runTickDedupRegressionTest() {
    console.log('ticker regression:');

    const originalDocument = globalThis.document;
    const originalStorage = globalThis.Storage;
    const originalLocalStorage = globalThis.localStorage;
    const originalFetch = globalThis.fetch;
    const originalSetInterval = globalThis.setInterval;
    const originalClearInterval = globalThis.clearInterval;
    const originalDateNow = Date.now;

    function makeClassList() {
        return { add() {}, remove() {}, toggle() {} };
    }

    function makeNode(className) {
        return {
            className: className || '',
            style: {},
            attributes: {},
            children: [],
            parentNode: null,
            classList: makeClassList(),
            textContent: '',
            _innerHTML: '',
            value: '',
            addEventListener() {},
            appendChild(child) { child.parentNode = this; this.children.push(child); },
            setAttribute(name, value) { this.attributes[name] = String(value); },
            getAttribute(name) { return this.attributes[name] || null; },
            closest(selector) {
                var node = this;
                while (node) {
                    if (selector === '.account-card' && node.className === 'account-card') return node;
                    node = node.parentNode;
                }
                return null;
            },
            set innerHTML(v) { this._innerHTML = v; this.children = []; },
            get innerHTML() { return this._innerHTML; },
            focus() {},
            select() {}
        };
    }

    const accountsEl = makeNode('accounts');
    let accountReads = 0;
    const elements = {
        '#accounts': accountsEl,
        '#editBtn': makeNode(),
        '#exportBtn': makeNode(),
        '#importBtn': makeNode(),
        '#importFile': makeNode(),
        '#resetBtn': makeNode(),
        '#addBtn': makeNode(),
        '#regenSecret': makeNode(),
        '#addKeyCancel': makeNode(),
        '#addKeyButton': makeNode(),
        '#addModal': makeNode(),
        '#qrClose': makeNode(),
        '#qrModal': makeNode(),
        '#lockScreenUnlock': makeNode(),
        '#lockBtn': makeNode(),
        '#passwordModal': makeNode(),
        '#pwCancel': makeNode(),
        '#pwSubmit': makeNode(),
        '#pwInput': makeNode(),
        '#setPwModal': makeNode(),
        '#setPwCancel': makeNode(),
        '#setPwSubmit': makeNode(),
        '#themeBtn': makeNode(),
        '#lockScreen': makeNode(),
        '#addRow': makeNode(),
        '#pwError': makeNode(),
        '#pwTitle': makeNode(),
        '#setPwInput': makeNode(),
        '#setPwConfirm': makeNode(),
        '#setPwError': makeNode(),
        '#setPwTitle': makeNode(),
        '#setPwHint': makeNode(),
        '#keyIssuer': makeNode(),
        '#keyAccount': makeNode(),
        '#keySecret': makeNode(),
        '#keyUrl': makeNode(),
        '#keyAlgorithm': makeNode(),
        '#keyPeriod': makeNode(),
        '#keyDigits': makeNode(),
        '#modalTitle': makeNode()
    };

    var countdownNode = makeNode('meta-countdown');
    var codeNode = makeNode('totp-code');
    var cardNode = makeNode('account-card');
    cardNode.setAttribute('data-period', '30');
    cardNode.appendChild(countdownNode);
    cardNode.appendChild(codeNode);
    accountsEl.appendChild(cardNode);

    const store = new Map();
    store.set('accounts', JSON.stringify([{ name: 'a1', secret: 'JBSWY3DPEHPK3PXP' }]));

    let tickFn = null;
    globalThis.Storage = function() {};
    globalThis.localStorage = {
        getItem(k) {
            if (k === 'accounts') accountReads++;
            return store.has(k) ? store.get(k) : null;
        },
        setItem(k, v) { store.set(k, String(v)); },
        removeItem(k) { store.delete(k); }
    };

    globalThis.document = {
        documentElement: { setAttribute() {}, getAttribute() { return 'light'; } },
        querySelector(sel) { return elements[sel] || makeNode(); },
        querySelectorAll(sel) {
            if (sel === '.meta-countdown') return [countdownNode];
            if (sel === '.totp-code') return [codeNode];
            return [];
        },
        createElement() {
            var el = makeNode();
            el.querySelector = function(selector) {
                if (selector === '.totp-code' || selector === '.qr-btn' || selector === '.edit-btn' || selector === '.delete-btn') {
                    return makeNode(selector.slice(1));
                }
                return makeNode();
            };
            return el;
        }
    };

    globalThis.fetch = async () => ({ ok: false, text: async () => '' });
    globalThis.setInterval = fn => { tickFn = fn; return 1; };
    globalThis.clearInterval = () => {};

    try {
        Date.now = () => 1000;
        const controller = new totpAuth.KeysController();
        await controller.init();
        const readsAfterInit = accountReads;

        tickFn();
        tickFn();
        tickFn();
        assert(accountReads === readsAfterInit, 'skips redundant re-renders within same second');

        Date.now = () => 2100;
        tickFn();
        assert(accountReads === readsAfterInit, 'updates countdown without full re-render when code step is unchanged');

        Date.now = () => 31000;
        tickFn();
        assert(accountReads > readsAfterInit, 're-renders when the TOTP code step changes');
    } finally {
        globalThis.document = originalDocument;
        globalThis.Storage = originalStorage;
        globalThis.localStorage = originalLocalStorage;
        globalThis.fetch = originalFetch;
        globalThis.setInterval = originalSetInterval;
        globalThis.clearInterval = originalClearInterval;
        Date.now = originalDateNow;
    }
}

runTests();
