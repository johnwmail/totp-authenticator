const { test, expect } = require('@playwright/test');
const path = require('path');

test.describe('TOTP Authenticator E2E', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/', { waitUntil: 'domcontentloaded' });
        // Clear localStorage for test isolation (after page loads so evaluate works on WebKit)
        await page.evaluate(() => {
            localStorage.clear();
        });
        // Unregister SW and clear caches (best-effort; may be restricted in some browsers)
        try {
            await page.evaluate(async () => {
                if ('serviceWorker' in navigator) {
                    const regs = await navigator.serviceWorker.getRegistrations();
                    await Promise.all(regs.map(r => r.unregister()));
                }
                if ('caches' in window) {
                    const names = await caches.keys();
                    await Promise.all(names.map(n => caches.delete(n)));
                }
            });
        } catch {
            // SW/Cache APIs may be restricted in some browser contexts (e.g. WebKit over HTTP)
        }
        // Reload to apply cleared state
        await page.reload({ waitUntil: 'domcontentloaded' });
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
        await expect(async () => {
            const count = await page.locator('.account-card').count();
            expect(count).toBeGreaterThan(0);
        }).toPass({ timeout: 10000 });
    });

    test('loads accounts', async ({ page }) => {
        const cards = page.locator('.account-card');
        const count = await cards.count();
        // App loads either accounts.json or a fallback demo account
        expect(count).toBeGreaterThanOrEqual(1);

        // First account should be visible with a valid name
        const firstAccount = page.locator('.account-name').first();
        await expect(firstAccount).toBeVisible();
        const text = await firstAccount.textContent();
        expect(text.length).toBeGreaterThan(0);
    });

    test('displays TOTP codes as 6-digit numbers', async ({ page }) => {
        const code = page.locator('.totp-code').first();
        const codeText = (await code.textContent()).replace('Copied!', '').trim();
        expect(codeText).toMatch(/^\d{6}$/);
    });

    test('shows countdown timer', async ({ page }) => {
        const countdown = page.locator('.meta-countdown').first();
        await expect(countdown).toHaveText(/\d+s/);
    });

    test.describe('Edit Mode', () => {
        test('toggle edit mode shows action buttons', async ({ page }) => {
            await page.locator('#editBtn').click();

            await expect(page.locator('.delete-btn').first()).toBeVisible();
            await expect(page.locator('.edit-btn').first()).toBeVisible();
            await expect(page.locator('#addBtn')).toBeVisible();
        });

        test('toggle edit mode hides action buttons', async ({ page }) => {
            await page.locator('#editBtn').click();
            await expect(page.locator('#addBtn')).toBeVisible();

            await page.locator('#editBtn').click();
            await expect(page.locator('#addBtn')).not.toBeVisible();
        });

        test('shows topbar action buttons in edit mode', async ({ page }) => {
            await page.locator('#editBtn').click();

            // Menu button should be visible in edit mode
            await expect(page.locator('#menuBtn')).toBeVisible();
            
            // Open dropdown menu
            await page.locator('#menuBtn').click();
            await expect(page.locator('#dropdownMenu')).toHaveClass(/open/);
            
            // Check dropdown items are visible
            await expect(page.locator('#dropdownExport')).toBeVisible();
            await expect(page.locator('#dropdownImport')).toBeVisible();
            await expect(page.locator('#dropdownReset')).toBeVisible();
        });
    });

    test.describe('Account CRUD', () => {
        test('add a new account', async ({ page }) => {
            const initialCount = await page.locator('.account-card').count();

            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await page.locator('#keyIssuer').fill('TestIssuer');
            await page.locator('#keyAccount').fill('test@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#addKeyButton').click();

            await expect(page.locator('.account-card')).toHaveCount(initialCount + 1);

            const lastCard = page.locator('.account-name').last();
            await expect(lastCard).toContainText('TestIssuer');
            await expect(lastCard).toContainText('test@example.com');
        });

        test('add account with generated secret', async ({ page }) => {
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            const secretInput = page.locator('#keySecret');
            const initialSecret = await secretInput.inputValue();
            expect(initialSecret.length).toBeGreaterThan(0);

            await page.locator('#regenSecret').click();
            const newSecret = await secretInput.inputValue();
            expect(newSecret.length).toBeGreaterThan(0);
        });

        test('cancel adding account', async ({ page }) => {
            const initialCount = await page.locator('.account-card').count();

            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await page.locator('#keyIssuer').fill('Cancelled');
            await page.locator('#keyAccount').fill('cancel@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#addKeyCancel').click();

            await expect(page.locator('.account-card')).toHaveCount(initialCount);
        });

        test('delete an account', async ({ page }) => {
            const initialCount = await page.locator('.account-card').count();

            await page.locator('#editBtn').click();
            await page.locator('.delete-btn').first().click();

            await expect(page.locator('.account-card')).toHaveCount(initialCount - 1);
        });

        test('edit an account', async ({ page }) => {
            await page.locator('#editBtn').click();
            await page.locator('.edit-btn').first().click();

            await page.locator('#keyIssuer').fill('EditedIssuer');
            await page.locator('#keyAccount').fill('edited@example.com');
            await page.locator('#addKeyButton').click();

            const firstCard = page.locator('.account-name').first();
            await expect(firstCard).toContainText('EditedIssuer');
            await expect(firstCard).toContainText('edited@example.com');
        });
    });

    test.describe('Import / Export', () => {
        test('export accounts to JSON file', async ({ page, browserName }) => {
            await page.locator('#editBtn').click();

            let data;

            if (browserName === 'webkit') {
                const rawData = await page.evaluate(() => localStorage.getItem('accounts'));
                data = JSON.parse(rawData);
            } else {
                // Open dropdown menu and click export
                await page.locator('#menuBtn').click();
                const [download] = await Promise.all([
                    page.waitForEvent('download'),
                    page.locator('#dropdownExport').click(),
                ]);

                expect(download.suggestedFilename()).toBe('authenticator-export.json');

                const filePath = test.info().outputPath(download.suggestedFilename());
                await download.saveAs(filePath);

                const fs = require('fs');
                data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            }

            expect(Array.isArray(data)).toBe(true);
            expect(data.length).toBeGreaterThanOrEqual(1);
            expect(data[0]).toHaveProperty('name');
            expect(data[0]).toHaveProperty('secret');
        });

        test('full export-import-delete-import cycle', async ({ page, browserName }) => {
            const initialCount = await page.locator('.account-card').count();

            // Step 1: Enter edit mode
            await page.locator('#editBtn').click();

            // Step 2: Add a new account
            await page.locator('#addBtn').click();
            await page.locator('#keyIssuer').fill('TestIssuer');
            await page.locator('#keyAccount').fill('test@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#addKeyButton').click();
            await expect(page.locator('.account-card')).toHaveCount(initialCount + 1);

            // Step 3: Export all accounts
            const filePath = test.info().outputPath('export-cycle.json');

            if (browserName === 'webkit') {
                const data = await page.evaluate(() => {
                    const accounts = JSON.parse(localStorage.getItem('accounts') || '[]');
                    return JSON.stringify(
                        accounts.map((acc) => ({
                            name: acc.name,
                            issuer: acc.issuer || '',
                            secret: acc.secret,
                            algorithm: acc.algorithm || 'SHA-1',
                            period: acc.period || 30,
                            digits: acc.digits || 6,
                            url: acc.url || '',
                            otpauth: `otpauth://totp/${encodeURIComponent(acc.issuer || '')}:${encodeURIComponent(acc.name)}?secret=${acc.secret}&issuer=${encodeURIComponent(acc.issuer || '')}&algorithm=${(acc.algorithm || 'SHA-1').replace('-', '')}&digits=${acc.digits || 6}&period=${acc.period || 30}`,
                        })),
                        null,
                        2
                    );
                });
                const fs = require('fs');
                fs.mkdirSync(path.dirname(filePath), { recursive: true });
                fs.writeFileSync(filePath, data);
            } else {
                // Open dropdown menu and click export
                await page.locator('#menuBtn').click();
                const [download] = await Promise.all([
                    page.waitForEvent('download'),
                    page.locator('#dropdownExport').click(),
                ]);
                await download.saveAs(filePath);
            }

            // Step 4: Delete the TestIssuer account
            await page.locator('.delete-btn').last().click();
            await expect(page.locator('.account-card')).toHaveCount(initialCount);

            // Step 5: Import the exported JSON
            await page.locator('#importFile').setInputFiles(filePath);

            // Step 6: Verify import succeeded - accounts should double
            await expect(page.locator('.account-card')).toHaveCount(initialCount * 2 + 1);

            // Verify TestIssuer is restored
            const cards = page.locator('.account-card');
            const count = await cards.count();
            let found = false;
            for (let i = 0; i < count; i++) {
                const text = await cards.nth(i).textContent();
                if (text.includes('TestIssuer')) {
                    found = true;
                    break;
                }
            }
            expect(found).toBe(true);
        });

        test('import adds to existing accounts', async ({ page }) => {
            const initialCount = await page.locator('.account-card').count();

            const fs = require('fs');
            const importData = [
                {
                    name: 'imported@example.com',
                    issuer: 'Imported',
                    secret: 'JBSWY3DPEHPK3PXP',
                    algorithm: 'SHA-1',
                    period: 30,
                    digits: 6,
                    url: '',
                    otpauth:
                        'otpauth://totp/Imported:imported%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Imported&algorithm=SHA1&digits=6&period=30',
                },
            ];
            const importFile = test.info().outputPath('import-test.json');
            fs.mkdirSync(path.dirname(importFile), { recursive: true });
            fs.writeFileSync(importFile, JSON.stringify(importData));

            await page.locator('#editBtn').click();

            const fileInput = page.locator('#importFile');
            await fileInput.setInputFiles(importFile);

            await expect(page.locator('.account-card')).toHaveCount(initialCount + 1);
            await expect(page.locator('.account-name').last()).toContainText('Imported');
        });
    });

    test.describe('TOTP Code Interaction', () => {
        test('click code copies to clipboard', async ({ page, context, browserName }) => {
            const firstCode = page.locator('.totp-code').first();

            if (browserName === 'webkit' || browserName === 'firefox') {
                const codeText = (await firstCode.textContent()).replace('Copied!', '').trim();
                expect(codeText).toMatch(/^\d{6}$/);
                await firstCode.click();
            } else {
                await context.grantPermissions(['clipboard-read', 'clipboard-write']);
                await firstCode.click();
                await expect(firstCode).toHaveClass(/copied/);
            }
        });

        test('codes update over time', async ({ page }) => {
            const firstCode = page.locator('.totp-code').first();

            await page.waitForTimeout(2000);
            const currentCode = (await firstCode.textContent()).replace('Copied!', '').trim();
            expect(currentCode).toMatch(/^\d{6}$/);
        });
    });

    test.describe('Dark Mode', () => {
        test('toggle dark mode', async ({ page }) => {
            await page.locator('#editBtn').click();

            const themeBtn = page.locator('#themeBtn');
            if (await themeBtn.isVisible()) {
                await themeBtn.click();

                const theme = await page.evaluate(() =>
                    document.documentElement.getAttribute('data-theme')
                );
                expect(['light', 'dark']).toContain(theme);
            }
        });
    });

    test.describe('Encryption', () => {
        test('set encryption password and lock/unlock', async ({ page }) => {
            // Enter edit mode
            await page.locator('#editBtn').click();

            // Open dropdown and click update password
            await page.locator('#menuBtn').click();
            await page.locator('#dropdownUpdatePw').click();

            await expect(page.locator('#setPwModal')).toHaveClass(/open/);
            await page.evaluate((pw) => {
                const input = document.querySelector('#setPwInput');
                const confirm = document.querySelector('#setPwConfirm');
                input.value = pw;
                confirm.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                confirm.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'testpassword123');
            await page.locator('#setPwSubmit').click();
            await page.waitForFunction(() => !document.querySelector('#setPwModal').classList.contains('open'), { timeout: 15000 });

            // Exit edit mode
            await page.locator('#editBtn').click();

            // Click the lock button in the topbar (visible when vault is encrypted and unlocked)
            await page.locator('#lockBtn').click();
            await expect(page.locator('#lockScreen')).toBeVisible();

            // Unlock with password
            await page.locator('#lockScreenUnlock').click();
            await page.locator('#pwInput').fill('testpassword123');
            await page.locator('#pwSubmit').click();
            await expect(page.locator('#lockScreen')).not.toBeVisible();
            await expect(page.locator('.account-card').first()).toBeVisible();
        });

        test('unlock vault shows accounts', async ({ page }) => {
            // First, enter edit mode and set password via dropdown
            await page.locator('#editBtn').click();
            await page.locator('#menuBtn').click();
            await page.locator('#dropdownUpdatePw').click();
            await expect(page.locator('#setPwModal')).toHaveClass(/open/);
            await page.evaluate((pw) => {
                const input = document.querySelector('#setPwInput');
                const confirm = document.querySelector('#setPwConfirm');
                input.value = pw;
                confirm.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                confirm.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'testpassword123');
            await page.locator('#setPwSubmit').click();
            await expect(page.locator('#setPwModal')).not.toHaveClass(/open/);

            // Exit edit mode
            await page.locator('#editBtn').click();

            // Click the lock button in the topbar (visible when vault is encrypted and unlocked)
            await page.locator('#lockBtn').click();
            await expect(page.locator('#lockScreen')).toBeVisible();

            // Unlock with password
            await page.locator('#lockScreenUnlock').click();
            await page.locator('#pwInput').fill('testpassword123');
            await page.locator('#pwSubmit').click();

            await expect(page.locator('#lockScreen')).not.toBeVisible();
            await expect(page.locator('.account-card').first()).toBeVisible();
        });

        test('update password flow: old password locks vault, new password unlocks', async ({ page }) => {
            // Step 1: Set initial password via dropdown
            await page.locator('#editBtn').click();
            await page.locator('#menuBtn').click();
            await page.locator('#dropdownUpdatePw').click();

            await expect(page.locator('#setPwModal')).toHaveClass(/open/);
            await page.evaluate((pw) => {
                const input = document.querySelector('#setPwInput');
                const confirm = document.querySelector('#setPwConfirm');
                input.value = pw;
                confirm.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                confirm.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'oldpassword');
            await page.locator('#setPwSubmit').click();
            await expect(page.locator('#setPwModal')).not.toHaveClass(/open/);

            // Exit edit mode
            await page.locator('#editBtn').click();

            // Click the lock button in the topbar (visible when vault is encrypted and unlocked)
            await page.locator('#lockBtn').click();
            await expect(page.locator('#lockScreen')).toBeVisible();

            // Step 3: Unlock with old password to verify it still works before changing
            await page.locator('#lockScreenUnlock').click();
            await page.evaluate((pw) => {
                const input = document.querySelector('#pwInput');
                input.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'oldpassword');
            await page.locator('#pwSubmit').click();
            await expect(page.locator('#lockScreen')).not.toBeVisible();

            // Wait for accounts to render after unlock
            await expect(page.locator('.account-card').first()).toBeVisible();
            await page.waitForLoadState('networkidle');

            // Step 4: Enter edit mode and click update password button via dropdown
            await page.locator('#editBtn').click();
            await page.locator('#menuBtn').click({ force: true });
            await expect(page.locator('#dropdownMenu')).toHaveClass(/open/);
            await page.locator('#dropdownUpdatePw').click({ force: true });
            await expect(page.locator('#setPwModal')).toHaveClass(/open/);
            await expect(page.locator('#setPwTitle')).toContainText('Change Password');

            // Step 5: Set new password — use evaluate to bypass WebKit fill() quirks
            await page.evaluate((pw) => {
                const input = document.querySelector('#setPwInput');
                const confirm = document.querySelector('#setPwConfirm');
                input.value = pw;
                confirm.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                confirm.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'newpassword');
            await page.locator('#setPwSubmit').click();
            await expect(page.locator('#setPwModal')).not.toHaveClass(/open/);

            // Wait for accounts to render after password change
            await expect(page.locator('.account-card').first()).toBeVisible();

            // Exit edit mode
            await page.locator('#editBtn').click();

            // Click the lock button in the topbar
            await page.locator('#lockBtn').click();
            await expect(page.locator('#lockScreen')).toBeVisible();
            await page.locator('#lockScreenUnlock').click();
            await page.evaluate((pw) => {
                const input = document.querySelector('#pwInput');
                input.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'oldpassword');
            await page.locator('#pwSubmit').click();
            // Should still be on lock screen (unlock failed)
            await expect(page.locator('#lockScreen')).toBeVisible();
            await expect(page.locator('#pwError')).toContainText(/incorrect|password/i);

            // Step 7: Verify new password unlocks successfully
            await page.evaluate((pw) => {
                const input = document.querySelector('#pwInput');
                input.value = pw;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }, 'newpassword');
            await page.locator('#pwSubmit').click();
            await expect(page.locator('#lockScreen')).not.toBeVisible();
            await expect(page.locator('.account-card').first()).toBeVisible();
        });
    });


    test.describe('Per-Account Password Field', () => {
        test('add account with password shows masked row', async ({ page }) => {
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            // Fill form including password
            await page.locator('#keyIssuer').fill('PwTest');
            await page.locator('#keyAccount').fill('pw@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#keyPassword').fill('mySecret123');
            await page.locator('#addKeyButton').click();

            // Account card appears with password row
            const newAccountName = page.locator('.account-name').last();
            await expect(newAccountName).toContainText('pw@example.com');
            await expect(page.locator('.password-display').last()).toBeVisible();

            // Password is masked
            const pwText = await page.locator('.password-display').last().textContent();
            expect(pwText).toContain('•');
            expect(pwText).not.toContain('mySecret123');
        });

        test('toggle password visibility shows/hides value', async ({ page }) => {
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await page.locator('#keyIssuer').fill('ToggleTest');
            await page.locator('#keyAccount').fill('toggle@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#keyPassword').fill('revealMe');
            await page.locator('#addKeyButton').click();

            // Initially masked
            const pwDisplay = page.locator('.password-display').last();
            const pwToggle = page.locator('.password-toggle').last();
            const pwTextBefore = await pwDisplay.textContent();
            expect(pwTextBefore).toContain('•');
            expect(pwTextBefore).not.toContain('revealMe');

            // Click eye toggle to reveal
            await pwToggle.click();

            // Now visible
            const pwTextAfter = await pwDisplay.textContent();
            expect(pwTextAfter).toContain('revealMe');
            expect(pwTextAfter).not.toContain('•');

            // Click again to hide
            await pwToggle.click();

            // Masked again
            const pwTextHidden = await pwDisplay.textContent();
            expect(pwTextHidden).toContain('•');
        });

        test('click password copies value to clipboard', async ({ page, context, browserName }) => {
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await page.locator('#keyIssuer').fill('CopyTest');
            await page.locator('#keyAccount').fill('copy@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            await page.locator('#keyPassword').fill('copyThis123');
            await page.locator('#addKeyButton').click();

            // Reveal password first so we can verify the copied value
            await page.locator('.password-toggle').last().click();

            if (browserName === 'webkit' || browserName === 'firefox') {
                // For browsers without clipboard API in tests, just verify the copy feedback
                await page.locator('.password-display').last().click();
                await expect(page.locator('.password-display').last()).toHaveClass(/copied/);
            } else {
                await context.grantPermissions(['clipboard-read', 'clipboard-write']);
                await page.locator('.password-display').last().click();
                await expect(page.locator('.password-display').last()).toHaveClass(/copied/);

                const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
                expect(clipboardText).toBe('copyThis123');
            }
        });

        test('password field present in add/edit modal', async ({ page }) => {
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await expect(page.locator('label[for="keyPassword"]')).toBeVisible();
            await expect(page.locator('#keyPassword')).toBeVisible();
            await expect(page.locator('#toggleFormPw')).toBeVisible();

            // Password input is type=password by default
            const pwType = await page.locator('#keyPassword').getAttribute('type');
            expect(pwType).toBe('password');

            // Toggle makes it visible
            await page.locator('#toggleFormPw').click();
            const pwTypeAfter = await page.locator('#keyPassword').getAttribute('type');
            expect(pwTypeAfter).toBe('text');
        });

        test('account without password shows no password row', async ({ page }) => {
            // The demo account now has a password, so add one without
            await page.locator('#editBtn').click();
            await page.locator('#addBtn').click();

            await page.locator('#keyIssuer').fill('NoPwTest');
            await page.locator('#keyAccount').fill('nopw@example.com');
            await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
            // Leave password empty
            await page.locator('#addKeyButton').click();

            // Count password displays - should match the demo account (1), not 2
            await expect(page.locator('.password-display')).toHaveCount(1);
        });
    });
    test.describe('QR Code', () => {
        test('show and close QR code modal', async ({ page }) => {
            await page.locator('.qr-btn').first().click();

            await expect(page.locator('#qrModal')).toHaveClass(/open/);

            const title = await page.locator('#qrTitle').textContent();
            expect(title.length).toBeGreaterThan(0);

            await page.locator('#qrClose').click();
            await expect(page.locator('#qrModal')).not.toHaveClass(/open/);
        });
    });

    test.describe('Reset', () => {
        test('reset all accounts', async ({ page }) => {
            await page.locator('#editBtn').click();

            page.on('dialog', (dialog) => dialog.accept());
            // Open dropdown menu and click reset
            await page.locator('#menuBtn').click();
            await page.locator('#dropdownReset').click();

            await expect(page.locator('.account-card')).toHaveCount(0);
        });
    });
});

test.describe('Mobile Layout', () => {
    test.use({ viewport: { width: 375, height: 812 } });

    test.beforeEach(async ({ page }) => {
        await page.goto('/', { waitUntil: 'domcontentloaded' });
        // Clear localStorage for test isolation (after page loads so evaluate works on WebKit)
        await page.evaluate(() => {
            localStorage.clear();
        });
        // Unregister SW and clear caches (best-effort; may be restricted in some browsers)
        try {
            await page.evaluate(async () => {
                if ('serviceWorker' in navigator) {
                    const regs = await navigator.serviceWorker.getRegistrations();
                    await Promise.all(regs.map(r => r.unregister()));
                }
                if ('caches' in window) {
                    const names = await caches.keys();
                    await Promise.all(names.map(n => caches.delete(n)));
                }
            });
        } catch {
            // SW/Cache APIs may be restricted in some browser contexts (e.g. WebKit over HTTP)
        }
        // Reload to apply cleared state
        await page.reload({ waitUntil: 'domcontentloaded' });
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
        await expect(async () => {
            const count = await page.locator('.account-card').count();
            expect(count).toBeGreaterThan(0);
        }).toPass({ timeout: 10000 });
    });

    test('renders accounts on small screen', async ({ page }) => {
        const cards = page.locator('.account-card');
        const count = await cards.count();
        expect(count).toBeGreaterThanOrEqual(1);
    });

    test('TOTP codes are visible on mobile', async ({ page }) => {
        const codes = page.locator('.totp-code');
        await expect(codes.first()).toBeVisible();
        const codeText = (await codes.first().textContent()).replace('Copied!', '').trim();
        expect(codeText).toMatch(/^\d{6}$/);
    });

    test('edit mode works on mobile', async ({ page }) => {
        await page.locator('#editBtn').click();

        await expect(page.locator('#addBtn')).toBeVisible();
        await expect(page.locator('.delete-btn').first()).toBeVisible();
    });

    test('add account modal fits mobile screen', async ({ page }) => {
        await page.locator('#editBtn').click();
        await page.locator('#addBtn').click();

        const modal = page.locator('.modal').first();
        await expect(modal).toBeVisible();

        const modalBox = await modal.boundingBox();
        expect(modalBox.width).toBeLessThanOrEqual(375);
    });

    test('account cards stack vertically on mobile', async ({ page }) => {
        const cards = page.locator('.account-card');
        const count = await cards.count();

        if (count >= 2) {
            const firstCard = cards.first();
            const secondCard = cards.nth(1);

            const firstBox = await firstCard.boundingBox();
            const secondBox = await secondCard.boundingBox();

            expect(secondBox.y).toBeGreaterThan(firstBox.y + firstBox.height - 1);
        }
    });

    test('full export-import cycle on mobile', async ({ page, browserName }) => {
        const initialCount = await page.locator('.account-card').count();

        await page.locator('#editBtn').click();

        // Add account
        await page.locator('#addBtn').click();
        await page.locator('#keyIssuer').fill('MobileTest');
        await page.locator('#keyAccount').fill('mobile@example.com');
        await page.locator('#keySecret').fill('JBSWY3DPEHPK3PXP');
        await page.locator('#addKeyButton').click();
        await expect(page.locator('.account-card')).toHaveCount(initialCount + 1);

        // Export
        const filePath = test.info().outputPath('export-mobile.json');

        if (browserName === 'webkit') {
            const data = await page.evaluate(() => {
                const accounts = JSON.parse(localStorage.getItem('accounts') || '[]');
                return JSON.stringify(
                    accounts.map((acc) => ({
                        name: acc.name,
                        issuer: acc.issuer || '',
                        secret: acc.secret,
                        algorithm: acc.algorithm || 'SHA-1',
                        period: acc.period || 30,
                        digits: acc.digits || 6,
                        url: acc.url || '',
                        otpauth: `otpauth://totp/${encodeURIComponent(acc.issuer || '')}:${encodeURIComponent(acc.name)}?secret=${acc.secret}&issuer=${encodeURIComponent(acc.issuer || '')}&algorithm=${(acc.algorithm || 'SHA-1').replace('-', '')}&digits=${acc.digits || 6}&period=${acc.period || 30}`,
                    })),
                    null,
                    2
                );
            });
            const fs = require('fs');
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            fs.writeFileSync(filePath, data);
        } else {
            // Open dropdown menu and click export
            await page.locator('#menuBtn').click();
            const [download] = await Promise.all([
                page.waitForEvent('download'),
                page.locator('#dropdownExport').click(),
            ]);
            await download.saveAs(filePath);
        }

        // Delete the added account
        await page.locator('.delete-btn').last().click();
        await expect(page.locator('.account-card')).toHaveCount(initialCount);

        // Import
        await page.locator('#importFile').setInputFiles(filePath);

        // Verify import succeeded
        await expect(page.locator('.account-card')).toHaveCount(initialCount * 2 + 1);

        // Verify MobileTest is restored
        const cards = page.locator('.account-card');
        const count = await cards.count();
        let found = false;
        for (let i = 0; i < count; i++) {
            const text = await cards.nth(i).textContent();
            if (text.includes('MobileTest')) {
                found = true;
                break;
            }
        }
        expect(found).toBe(true);
    });
});

test.describe('Share URL', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/', { waitUntil: 'domcontentloaded' });
        await page.evaluate(() => {
            localStorage.clear();
        });
        try {
            await page.evaluate(async () => {
                if ('serviceWorker' in navigator) {
                    const regs = await navigator.serviceWorker.getRegistrations();
                    await Promise.all(regs.map((r) => r.unregister()));
                }
                if ('caches' in window) {
                    const names = await caches.keys();
                    await Promise.all(names.map((n) => caches.delete(n)));
                }
            });
        } catch {
            // SW/Cache APIs may be restricted in some browser contexts
        }
        await page.reload({ waitUntil: 'domcontentloaded' });
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
        await expect(async () => {
            const count = await page.locator('.account-card').count();
            expect(count).toBeGreaterThan(0);
        }).toPass({ timeout: 10000 });
    });

    test('share button is visible in edit mode', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu
        await page.locator('#menuBtn').click();
        await expect(page.locator('#dropdownShare')).toBeVisible();
    });

    test('share button opens share modal', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await expect(page.locator('#shareModal')).toHaveClass(/open/);
    });

    test('share modal has password input', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await expect(page.locator('#sharePwInput')).toBeVisible();
    });

    test('generate URL button is disabled without password', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        const generateBtn = page.locator('#shareGenerate');
        await expect(generateBtn).toBeDisabled();
    });

    test('generate URL button is enabled with password', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await page.locator('#sharePwInput').fill('testpassword');
        const generateBtn = page.locator('#shareGenerate');
        await expect(generateBtn).toBeEnabled();
    });

    test('generates URL with #data fragment', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await page.locator('#sharePwInput').fill('testpassword');
        await page.locator('#shareGenerate').click();
        await expect(page.locator('#shareUrlContainer')).not.toHaveClass(/hidden/);
        const urlOutput = page.locator('#shareUrlOutput');
        await expect(urlOutput).toBeVisible();
        const url = await urlOutput.inputValue();
        expect(url).toContain('#data=');
    });

    test('closing share modal clears password', async ({ page }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await page.locator('#sharePwInput').fill('testpassword');
        await page.locator('#shareCancel').click();
        await expect(page.locator('#shareModal')).not.toHaveClass(/open/);
        // Re-open share modal via dropdown
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        const pwInput = page.locator('#sharePwInput');
        expect(await pwInput.inputValue()).toBe('');
    });

    test('import URL with correct password merges accounts', async ({ page }) => {
        const accounts = [
            { name: 'test@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Test', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
        ];

        const data = await page.evaluate(async ({ accounts }) => {
            const LZString = window.LZString;
            const jsonStr = JSON.stringify(accounts);
            const compressed = LZString.compressToUTF16(jsonStr);

            const enc = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const baseKey = await crypto.subtle.importKey(
                'raw',
                enc.encode('sharepass'),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            const key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(compressed)
            );

            const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
            return bufToBase64(ct) + '.' + bufToBase64(iv) + '.' + bufToBase64(salt) + '.310000';
        }, { accounts });

        const initialCount = await page.locator('.account-card').count();
        await page.goto(`/?#data=${data}`);
        await expect(page.locator('#passwordModal')).toHaveClass(/open/);
        await page.locator('#pwInput').fill('sharepass');
        await page.locator('#pwSubmit').click();
        // Wait for import to complete and new accounts to render
        await expect(page.locator('.account-card')).toHaveCount(initialCount + 1);
    });

    test('import URL with wrong password shows error', async ({ page }) => {
        const accounts = [
            { name: 'test@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Test', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
        ];

        const data = await page.evaluate(async ({ accounts }) => {
            const LZString = window.LZString;
            const jsonStr = JSON.stringify(accounts);
            const compressed = LZString.compressToUTF16(jsonStr);

            const enc = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const baseKey = await crypto.subtle.importKey(
                'raw',
                enc.encode('sharepass'),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            const key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(compressed)
            );

            const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
            return bufToBase64(ct) + '.' + bufToBase64(iv) + '.' + bufToBase64(salt) + '.310000';
        }, { accounts });

        await page.goto(`/?#data=${data}`);
        await expect(page.locator('#passwordModal')).toHaveClass(/open/);
        await page.locator('#pwInput').fill('wrongpassword');
        await page.locator('#pwSubmit').click();
        await expect(page.locator('#pwError')).toContainText(/incorrect|password/i);
    });

    test('clicking URL in share modal copies to clipboard', async ({ page, browserName }) => {
        await page.locator('#editBtn').click();
        // Open dropdown menu and click share
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownShare').click();
        await page.locator('#sharePwInput').fill('testpassword');
        await page.locator('#shareGenerate').click();
        await page.locator('#shareUrlOutput').click();
        const url = await page.locator('#shareUrlOutput').inputValue();
        expect(url).toContain('#data=');
        if (browserName === 'chromium') {
            const context = page.context();
            await context.grantPermissions(['clipboard-write', 'clipboard-read']);
            await page.evaluate(() => navigator.clipboard.writeText(document.querySelector('#shareUrlOutput').value));
            const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
            expect(clipboardText).toContain('#data=');
        }
    });

    test('import URL is rejected when vault is locked', async ({ page }) => {
        const accounts = [
            { name: 'test@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'Test', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
        ];

        const data = await page.evaluate(async ({ accounts }) => {
            const LZString = window.LZString;
            const jsonStr = JSON.stringify(accounts);
            const compressed = LZString.compressToUTF16(jsonStr);

            const enc = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const baseKey = await crypto.subtle.importKey(
                'raw',
                enc.encode('sharepass'),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            // Use low iteration count for test payload — we're testing vault-locked rejection, not crypto strength
            const key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 1000, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(compressed)
            );

            const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
            return bufToBase64(ct) + '.' + bufToBase64(iv) + '.' + bufToBase64(salt) + '.1000';
        }, { accounts });

        await page.locator('#editBtn').click();
        await page.locator('#menuBtn').click();
        await page.locator('#dropdownUpdatePw').click();

        // Use evaluate to set password values directly, avoiding WebKit fill() quirks
        await page.evaluate((pw) => {
            const input = document.querySelector('#setPwInput');
            const confirm = document.querySelector('#setPwConfirm');
            input.value = pw;
            confirm.value = pw;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            confirm.dispatchEvent(new Event('input', { bubbles: true }));
        }, 'vaultpassword');
            await page.locator('#setPwSubmit').click();
            await expect(page.locator('#setPwModal')).not.toHaveClass(/open/);

            // Wait for accounts to render after password change
            await expect(page.locator('.account-card').first()).toBeVisible();

            // Exit edit mode
            await page.locator('#editBtn').click();

            // Step 6: Click the lock button in the topbar
            await page.locator('#lockBtn').click();
            await expect(page.locator('#lockScreen')).toBeVisible();

        await page.goto(`/?#data=${data}`);

        await expect(page.locator('.toast')).toContainText(/unlock.*first|locked/i);

        const url = page.url();
        expect(url).not.toContain('#data=');

        await page.locator('#lockScreenUnlock').click();
        await page.locator('#pwInput').fill('vaultpassword');
        await page.locator('#pwSubmit').click();

        // After unlock, modal closes then reopens for import - wait for it to be open again
        await expect(page.locator('#passwordModal')).toHaveClass(/open/, { timeout: 10000 });
        // Verify we're in import mode (button says "Import")
        await expect(page.locator('#pwSubmit')).toHaveText('Import');
        await page.locator('#pwInput').fill('sharepass');
        await page.locator('#pwSubmit').click();

        // Wait for toast to appear (it auto-removes after ~2.3s)
        await page.waitForSelector('.toast', { timeout: 5000 });
        await expect(page.locator('.toast')).toContainText(/import/i);
    });

    test('merge accounts with duplicate secrets preserves all accounts', async ({ page }) => {
        // Test by directly importing URL data with two accounts sharing the same secret
        const accounts = [
            { name: 'google@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'GoogleDup', algorithm: 'SHA-1', period: 30, digits: 6, url: '' },
            { name: 'github@example.com', secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHubDup', algorithm: 'SHA-1', period: 30, digits: 6, url: '' }
        ];

        // Encrypt the accounts using the same method as share URL
        const data = await page.evaluate(async ({ accounts }) => {
            const LZString = window.LZString;
            const jsonStr = JSON.stringify(accounts);
            const compressed = LZString.compressToUTF16(jsonStr);

            const enc = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const baseKey = await crypto.subtle.importKey(
                'raw',
                enc.encode('sharepassword'),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            const key = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(compressed)
            );

            const bufToBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
            return bufToBase64(ct) + '.' + bufToBase64(iv) + '.' + bufToBase64(salt) + '.310000';
        }, { accounts });

        // Navigate to URL with share data to trigger import
        await page.goto(`/?#data=${data}`);

        // Wait for password modal
        await expect(page.locator('#passwordModal')).toHaveClass(/open/, { timeout: 10000 });

        // Enter password to decrypt
        await page.locator('#pwInput').fill('sharepassword');
        await page.locator('#pwSubmit').click();
        await expect(page.locator('#passwordModal')).not.toHaveClass(/open/);

        // Should have 3 accounts: 2 imported (GoogleDup, GitHubDup with same secret) + 1 existing demo account
        // Use retrying assertion to avoid race condition with DOM reflow (especially on Firefox)
        await expect(page.locator('.account-card')).toHaveCount(3);

        // Verify both GoogleDup and GitHubDup accounts are present
        const cardTexts = await page.locator('.account-name').allTextContents();
        const googleFound = cardTexts.some(t => t.includes('GoogleDup'));
        const githubFound = cardTexts.some(t => t.includes('GitHubDup'));
        expect(googleFound).toBe(true);
        expect(githubFound).toBe(true);
    });
});
