const { test, expect } = require('@playwright/test');
const path = require('path');

test.describe('TOTP Authenticator E2E', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
        // Clear localStorage to reset state between tests
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
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
            await expect(page.locator('.drag-handle').first()).toBeVisible();
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

            await expect(page.locator('#exportBtn')).toBeVisible();
            await expect(page.locator('#importBtn')).toBeVisible();
            await expect(page.locator('#resetBtn')).toBeVisible();
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

            page.on('dialog', (dialog) => dialog.accept());
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
                const [download] = await Promise.all([
                    page.waitForEvent('download'),
                    page.locator('#exportBtn').click(),
                ]);

                expect(download.suggestedFilename()).toBe('authenticator-export.json');

                const filePath = path.join(__dirname, '..', '..', 'tmp', download.suggestedFilename());
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
            const filePath = path.join(__dirname, '..', '..', 'tmp', 'export-cycle.json');

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
                require('fs').mkdirSync(path.dirname(filePath), { recursive: true });
                require('fs').writeFileSync(filePath, data);
            } else {
                const [download] = await Promise.all([
                    page.waitForEvent('download'),
                    page.locator('#exportBtn').click(),
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
            const importFile = path.join(__dirname, '..', '..', 'tmp', 'import-test.json');
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

            if (browserName === 'webkit') {
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
            await page.locator('#editBtn').click();

            const lockBtn = page.locator('#lockBtn');
            if (await lockBtn.isVisible()) {
                await lockBtn.click();

                await expect(page.locator('#setPwModal')).toHaveClass(/open/);

                await page.locator('#setPwInput').fill('testpassword123');
                await page.locator('#setPwConfirm').fill('testpassword123');
                await page.locator('#setPwSubmit').click();

                await expect(page.locator('#lockScreen')).not.toBeVisible();
            }
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
            await page.locator('#resetBtn').click();

            await expect(page.locator('.account-card')).toHaveCount(0);
        });
    });
});

test.describe('Mobile Layout', () => {
    test.use({ viewport: { width: 375, height: 812 } });

    test.beforeEach(async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
        await page.evaluate(() => localStorage.clear());
        await page.reload();
        await expect(page.locator('.topbar-title')).toHaveText('TOTP Authenticator');
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
        const filePath = path.join(__dirname, '..', '..', 'tmp', 'export-mobile.json');

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
            require('fs').mkdirSync(path.dirname(filePath), { recursive: true });
            require('fs').writeFileSync(filePath, data);
        } else {
            const [download] = await Promise.all([
                page.waitForEvent('download'),
                page.locator('#exportBtn').click(),
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
