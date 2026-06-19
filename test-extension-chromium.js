#!/usr/bin/env node

/**
 * Test the TOTP Authenticator extension in headless Chromium
 * Uses CDP (Chrome DevTools Protocol) directly — no Puppeteer, no Playwright.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const assert = require('assert');

const EXTENSION_DIR = path.join(__dirname, 'extension', 'dist', 'chrome');
const USER_DATA_DIR = path.join(__dirname, '.tmp-chrome-test-profile');

// Clean up previous test profile
if (fs.existsSync(USER_DATA_DIR)) {
    fs.rmSync(USER_DATA_DIR, { recursive: true, force: true });
}

let chromeProcess = null;
let chromeDebugPort = 9222;
let testResults = [];
let passedCount = 0;
let failedCount = 0;

function test(name, fn) {
    testResults.push({ name, fn });
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

/**
 * Connect to a CDP target via WebSocket.
 */
function connectCDP(wsUrl) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        ws.addEventListener('open', () => {
            const session = {
                ws,
                _id: 0,
                _pending: new Map(),
                send(method, params = {}) {
                    return new Promise((resolve, reject) => {
                        if (ws.readyState !== WebSocket.OPEN) {
                            reject(new Error('WebSocket not open'));
                            return;
                        }
                        const id = ++this._id;
                        this._pending.set(id, { resolve, reject });
                        ws.send(JSON.stringify({ id, method, params }));
                    });
                },
                close() {
                    ws.close();
                }
            };

            ws.addEventListener('message', (event) => {
                const raw = typeof event.data === 'string' ? event.data : Buffer.from(event.data).toString();
                let msg;
                try {
                    msg = JSON.parse(raw);
                } catch {
                    return;
                }
                if (msg.id && session._pending.has(msg.id)) {
                    const { resolve, reject } = session._pending.get(msg.id);
                    session._pending.delete(msg.id);
                    if (msg.error) {
                        reject(new Error(msg.error.message));
                    } else {
                        resolve(msg.result);
                    }
                }
            });

            ws.addEventListener('close', () => {
                // Reject all pending
                for (const [id, { reject }] of session._pending) {
                    reject(new Error('WebSocket closed'));
                }
                session._pending.clear();
            });

            resolve(session);
        });
        ws.addEventListener('error', (err) => reject(err));
    });
}

async function ensureChromiumRunning() {
    // Kill any existing chromium with our profile
    try {
        require('child_process').execSync('pkill -f "tmp-chrome-test-profile" 2>/dev/null || true');
    } catch {}
    await sleep(500);

    console.log('  Launching Chromium (headless) with extension...');
    console.log(`  Extension dir: ${EXTENSION_DIR}`);

    const args = [
        `--user-data-dir=${USER_DATA_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        '--headless=new',
        '--no-sandbox',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-dev-shm-usage',
        `--remote-debugging-port=${chromeDebugPort}`,
        '--remote-debugging-address=127.0.0.1',
        '--window-size=400,600',
    ];

    chromeProcess = spawn('chromium', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, DISPLAY: ':99' },
    });

    chromeProcess.stderr.on('data', () => {});
    chromeProcess.stdout.on('data', () => {});

    chromeProcess.on('exit', (code) => {
        if (code !== null && code !== 0) {
            console.log(`  Chromium exited with code ${code}`);
        }
    });

    // Wait for debug port
    console.log('  Waiting for debug port...');
    for (let i = 0; i < 30; i++) {
        try {
            const resp = await fetch(`http://127.0.0.1:${chromeDebugPort}/json/version`);
            if (resp.ok) {
                console.log('  Debug port ready.');
                return;
            }
        } catch {}
        await sleep(500);
    }
    throw new Error('Chromium did not start in time');
}

async function getBrowserSession() {
    const res = await fetch(`http://127.0.0.1:${chromeDebugPort}/json/version`);
    const data = await res.json();
    return connectCDP(data.webSocketDebuggerUrl);
}

async function getPageTargets(browserSession) {
    const result = await browserSession.send('Target.getTargets');
    return result.targetInfos;
}

async function findExtensionId(browserSession) {
    const targets = await getPageTargets(browserSession);
    
    // Look for extension pages
    for (const t of targets) {
        if (t.url && t.url.startsWith('chrome-extension://')) {
            const match = t.url.match(/chrome-extension:\/\/([^/]+)/);
            if (match) return match[1];
        }
    }

    // Print all targets for debugging
    console.log('  Available targets:');
    for (const t of targets) {
        console.log(`    - type: ${t.type}, title: "${t.title}", url: "${(t.url || '').substring(0, 100)}"`);
    }
    throw new Error('Could not find extension ID');
}

async function attachToPage(browserSession, targetId) {
    const result = await browserSession.send('Target.attachToTarget', {
        targetId,
        flatten: true,
    });
    return connectCDP(); // We'll actually use the sessionId from result
}

async function navigateToPopup(browserSession, tabSession, extId) {
    const popupUrl = `chrome-extension://${extId}/popup/index.html`;
    console.log(`  Opening popup: ${popupUrl}`);

    // Create a new page tab and navigate
    const result = await browserSession.send('Target.createTarget', {
        url: 'about:blank',
        type: 'tab',
    });
    const pageTargetId = result.targetId;

    // Attach to the new page
    const attachResult = await browserSession.send('Target.attachToTarget', {
        targetId: pageTargetId,
        flatten: true,
    });

    // Create a new session for this page
    const pageWsUrl = `http://127.0.0.1:${chromeDebugPort}/devtools/page/${pageTargetId}`;
    // Actually, with flatten:true, we need to use the sessionId...
    // Let's use a simpler approach: connect directly to the page's WebSocket

    // Get page info from /json
    const pagesRes = await fetch(`http://127.0.0.1:${chromeDebugPort}/json`);
    const pages = await pagesRes.json();
    const page = pages.find(p => p.id === pageTargetId);
    if (!page) throw new Error('Page not found');

    const pageSession = await connectCDP(page.webSocketDebuggerUrl);
    await pageSession.send('Page.enable');
    await pageSession.send('Page.navigate', { url: popupUrl });
    await waitForPageLoad(pageSession);
    await sleep(1500);
    
    return pageSession;
}

async function createAndNavigatePage(extId) {
    // Get page list to find a blank page or create one
    const pagesRes = await fetch(`http://127.0.0.1:${chromeDebugPort}/json`);
    let pages = await pagesRes.json();
    
    // Find a suitable page or create one via browser target
    const browserSession = await getBrowserSession();
    
    // Create a new tab
    const createResult = await browserSession.send('Target.createTarget', {
        url: 'about:blank',
    });
    const targetId = createResult.targetId;
    await browserSession.close();

    // Now get the WebSocket URL for this target
    await sleep(500);
    const pagesRes2 = await fetch(`http://127.0.0.1:${chromeDebugPort}/json`);
    const pages2 = await pagesRes2.json();
    const myPage = pages2.find(p => p.id === targetId);
    if (!myPage) throw new Error('Created page not found in listing');

    const popupUrl = `chrome-extension://${extId}/popup/index.html`;
    console.log(`  Opening popup: ${popupUrl}`);

    const session = await connectCDP(myPage.webSocketDebuggerUrl);
    await session.send('Page.enable');
    await session.send('Page.navigate', { url: popupUrl });
    await waitForPageLoad(session);
    await sleep(1500);
    
    return session;
}

async function waitForPageLoad(session, timeout = 15000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        try {
            const result = await session.send('Runtime.evaluate', {
                expression: 'document.readyState',
            });
            if (result.result.value === 'complete') return;
        } catch {}
        await sleep(300);
    }
    console.log('  Warning: Page load timeout reached');
}

async function evaluate(session, expression) {
    const result = await session.send('Runtime.evaluate', {
        expression,
        awaitPromise: true,
        timeout: 5000,
    });
    if (result.exceptionDetails) {
        const exc = result.exceptionDetails;
        let msg = exc.text || 'Evaluation error';
        if (exc.exception && exc.exception.description) {
            msg = exc.exception.description;
        }
        throw new Error(msg.trim());
    }
    return result.result.value;
}

async function clickSelector(session, selector) {
    const result = await session.send('Runtime.evaluate', {
        expression: `
            (() => {
                const el = document.querySelector('${selector}');
                if (!el) throw new Error('Selector not found: ${selector}');
                el.click();
                return true;
            })()
        `,
        awaitPromise: true,
        timeout: 3000,
    });
    if (result.exceptionDetails) {
        throw new Error(`Click failed for "${selector}": ${result.exceptionDetails.text}`);
    }
    return result.result.value;
}

// ============================================================
// Tests
// ============================================================

test('popup title is correct', async (session) => {
    const title = await evaluate(session, 'document.title');
    assert.strictEqual(title, 'TOTP Authenticator');
});

test('topbar-title displays TOTP Authenticator', async (session) => {
    const text = await evaluate(session, 'document.querySelector(".topbar-title")?.textContent');
    assert.ok(text && text.includes('TOTP Authenticator'), `Expected "TOTP Authenticator" in title, got "${text}"`);
});

test('displays account cards', async (session) => {
    const count = await evaluate(session, 'document.querySelectorAll(".account-card").length');
    assert.ok(count >= 1, `Expected at least 1 account card, got ${count}`);
});

test('displays TOTP codes as 6-digit numbers', async (session) => {
    const code = await evaluate(session, 'document.querySelector(".totp-code")?.textContent');
    assert.ok(code, 'No TOTP code element found');
    const cleaned = code.replace('Copied!', '').trim();
    assert.ok(/^\d{6}$/.test(cleaned), `TOTP code "${cleaned}" is not a 6-digit number`);
});

test('shows countdown timer', async (session) => {
    const countdown = await evaluate(session, 'document.querySelector(".meta-countdown")?.textContent');
    assert.ok(countdown, 'No countdown element found');
    assert.ok(/\d+s/.test(countdown), `Countdown "${countdown}" doesn't match pattern like "30s"`);
});

test('account name is visible', async (session) => {
    const name = await evaluate(session, 'document.querySelector(".account-name")?.textContent');
    assert.ok(name && name.length > 0, 'Account name should not be empty');
});

test('toggle edit mode shows add button', async (session) => {
    await clickSelector(session, '#editBtn');
    await sleep(500);

    const addBtnVisible = await evaluate(session, `
        (() => {
            const btn = document.querySelector('#addBtn');
            if (!btn) return false;
            const style = window.getComputedStyle(btn);
            return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
        })()
    `);
    assert.ok(addBtnVisible, 'Add button should be visible in edit mode');

    // Toggle edit mode off
    await clickSelector(session, '#editBtn');
});

test('add a new account', async (session) => {
    await clickSelector(session, '#editBtn');
    await sleep(300);

    const initialCount = await evaluate(session, 'document.querySelectorAll(".account-card").length');

    await clickSelector(session, '#addBtn');
    await sleep(500);

    await evaluate(session, `
        document.querySelector('#keyIssuer').value = 'TestIssuer';
        document.querySelector('#keyAccount').value = 'test@example.com';
        document.querySelector('#keySecret').value = 'JBSWY3DPEHPK3PXP';
    `);

    await clickSelector(session, '#addKeyButton');
    await sleep(600);

    const newCount = await evaluate(session, 'document.querySelectorAll(".account-card").length');
    assert.strictEqual(newCount, initialCount + 1, `Expected ${initialCount + 1} accounts, got ${newCount}`);

    const lastName = await evaluate(session, 'document.querySelectorAll(".account-name")[document.querySelectorAll(".account-name").length - 1]?.textContent');
    assert.ok(lastName && lastName.includes('TestIssuer'), `Expected "TestIssuer" in account name, got "${lastName}"`);

    // Exit edit mode
    await clickSelector(session, '#editBtn');
});

test('delete an account', async (session) => {
    await clickSelector(session, '#editBtn');
    await sleep(300);

    const initialCount = await evaluate(session, 'document.querySelectorAll(".account-card").length');
    if (initialCount < 2) {
        console.log('     Skipping: need at least 2 accounts');
        await clickSelector(session, '#editBtn');
        return;
    }

    await clickSelector(session, '.delete-btn');
    await sleep(500);

    const newCount = await evaluate(session, 'document.querySelectorAll(".account-card").length');
    assert.strictEqual(newCount, initialCount - 1, `Expected ${initialCount - 1} accounts, got ${newCount}`);

    await clickSelector(session, '#editBtn');
});

test('localStorage has accounts data', async (session) => {
    const hasData = await evaluate(session, `
        (() => {
            try {
                const data = localStorage.getItem('accounts');
                return data !== null;
            } catch { return false; }
        })()
    `);
    assert.ok(hasData, 'localStorage should have accounts data');
});

test('dark mode toggle button exists', async (session) => {
    const exists = await evaluate(session, 'document.querySelector("#themeBtn") !== null');
    assert.ok(exists, 'Dark mode toggle button should exist');
});

// ============================================================
// Main
// ============================================================

async function main() {
    console.log('🧪 TOTP Authenticator Extension Test Suite\n');

    await ensureChromiumRunning();

    // 1) Connect to browser-level CDP and find extension ID
    console.log('  Connecting to browser CDP...');
    const browserSession = await getBrowserSession();
    const extId = await findExtensionId(browserSession);
    console.log(`  Extension ID: ${extId}\n`);
    
    // 2) Navigate to popup page
    const pageSession = await createAndNavigatePage(extId);
    console.log('  Popup loaded.\n');

    // 3) Run tests
    for (const { name, fn } of testResults) {
        try {
            await fn(pageSession);
            console.log(`  ✅ ${name}`);
            passedCount++;
        } catch (err) {
            console.log(`  ❌ ${name}`);
            console.log(`     ${err.message}`);
            failedCount++;
            // Try to get a screenshot on failure
            try {
                const shot = await pageSession.send('Page.captureScreenshot', { format: 'png' });
                fs.writeFileSync(path.join(__dirname, `test-failure-${name.replace(/[^a-z0-9]/gi, '-')}.png`), Buffer.from(shot.data, 'base64'));
                console.log(`     (screenshot saved)`);
            } catch {}
        }
    }

    // Final screenshot
    try {
        const shot = await pageSession.send('Page.captureScreenshot', { format: 'png' });
        fs.writeFileSync(path.join(__dirname, 'test-screenshot.png'), Buffer.from(shot.data, 'base64'));
        console.log(`\n  Screenshot saved to test-screenshot.png`);
    } catch (e) {
        console.log(`\n  Screenshot not available: ${e.message}`);
    }

    pageSession.close();
    browserSession.close();

    // Summary
    console.log(`\n  ─────────────────────────────`);
    console.log(`  Results: ${passedCount} passed, ${failedCount} failed\n`);
}

main().catch(err => {
    console.error('Fatal error:', err);
    cleanup();
    process.exit(1);
}).then(() => {
    cleanup();
    process.exit(failedCount > 0 ? 1 : 0);
});

function cleanup() {
    if (chromeProcess) {
        try { chromeProcess.kill('SIGKILL'); } catch {}
    }
    if (fs.existsSync(USER_DATA_DIR)) {
        try { fs.rmSync(USER_DATA_DIR, { recursive: true, force: true }); } catch {}
    }
}

process.on('SIGINT', () => { cleanup(); process.exit(1); });
process.on('SIGTERM', () => { cleanup(); process.exit(1); });
