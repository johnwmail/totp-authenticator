# TOTP Authenticator

A lightweight, self-hosted TOTP authenticator that runs entirely in the browser. No server, no build step, no external crypto dependencies — just open and go.

**Live demo:** [totp-1sr.pages.dev](https://totp-1sr.pages.dev)

## Features

- **Per-account TOTP** — configurable algorithm (SHA-1 / SHA-256 / SHA-512), period (30 s / 60 s / 5 min / 1 h / 1 d), and digits (6 / 8)
- **Issuer field** for Google Authenticator compatibility
- **Auto-load accounts** from `accounts.json` on first visit
- **Import / Export** accounts as JSON or `otpauth://` URIs
- **QR code generation** for easy scanning into mobile authenticator apps
- **Click-to-copy** codes to clipboard
- **Responsive layout** — works on desktop and mobile
- **Dark mode** — toggle button, respects system preference, persists in `localStorage`
- **AES-GCM encryption** — set a password to encrypt secrets at rest using PBKDF2-SHA256 (310 000 iterations); vault locks on reload
- **Drag-and-drop reorder** in edit mode
- **Native Web Crypto API** — HMAC-based TOTP generation with zero external crypto dependencies
- **CI/CD** — GitHub Actions deploys to Cloudflare Pages on tag-based releases
- **Version injection** — shows `vDev` locally; CI replaces it with the release tag

## Quick Start

Serve the files with any static HTTP server:

```bash
# Python
python3 -m http.server 8000

# Node
npx serve .

# BusyBox
busybox httpd -f -p 8000 -h .

# Cloudflare Wrangler (local preview)
npx wrangler pages dev .
```

Then open `http://localhost:8000` in your browser.

## Default Accounts

On first visit (empty `localStorage`), the app tries to fetch `accounts.json` from the server. If the file is missing or invalid, a random demo account is generated instead.

To seed your own accounts:

```bash
cp accounts.example.json accounts.json
# Edit accounts.json with your real secrets
```

The file supports `//` and `#` line comments.

> **Note:** `accounts.json` is in `.gitignore` — it contains real secrets and should never be committed.

## Account Format

```jsonc
[
  {
    "name": "user@example.com",     // Account name (required)
    "issuer": "GitHub",              // Service provider (optional, recommended)
    "secret": "BASE32SECRET",        // Base32-encoded TOTP secret (required)
    "algorithm": "SHA-1",            // SHA-1, SHA-256, or SHA-512 (default: SHA-1)
    "period": 30,                    // Seconds: 30, 60, 300, 3600, 86400 (default: 30)
    "digits": 6,                     // 6 or 8 (default: 6)
    "url": "https://github.com"      // Optional link on the account name
  }
]
```

## Encryption

The app can encrypt all stored secrets at rest using **AES-256-GCM**.

1. Click the **lock** button and set a password.
2. The password is run through **PBKDF2-SHA256** (310 000 iterations) with a random 16-byte salt to derive a 256-bit AES key.
3. Accounts are encrypted with AES-GCM (random 12-byte IV) and stored in `localStorage` under `accounts_encrypted`.
4. Plain-text account data is removed.
5. On reload the vault is **locked** — enter your password to decrypt and resume.

To remove encryption, unlock the vault and clear the password.

All cryptographic operations use the browser's native **Web Crypto API** (`crypto.subtle`) — no external libraries.

## Dark Mode

Click the **☀️ / 🌙** button in the header to toggle between light and dark themes.

- The theme is **auto-detected by local time**: 08:00–22:00 = light, otherwise dark.
- Click the toggle to override for the current session.
- Theming is implemented with CSS custom properties (`data-theme` attribute on `<html>`).
- The toggle is available in **edit mode** (click the ⚙️ gear icon).

## Import / Export

| Action | How |
|--------|-----|
| **Export JSON** | Click the **Export** button → downloads `accounts.json` with all accounts. |
| **Import JSON** | Click **Import** → select a `.json` file matching the account format above. |
| **otpauth:// URIs** | Import/export supports standard `otpauth://totp/…` URIs for interop with other authenticator apps. |
| **QR Codes** | In edit mode, click the QR icon on any account to display a scannable `otpauth://` QR code. Scan it with Google Authenticator, Authy, or any TOTP-compatible app. |

## CI/CD Deployment

The project deploys to **Cloudflare Pages** via GitHub Actions (`.github/workflows/ci.yml`).

| Trigger | Branch / Ref | Deployment |
|---------|-------------|------------|
| Push tag `v*` | `main` | **Production** → [totp-1sr.pages.dev](https://totp-1sr.pages.dev) |
| Pull request | PR branch | **Preview** (unique URL per PR) |

**CI Pipeline:**
1. **Unit Tests** — `npm test`
2. **E2E Tests** — Playwright (Chromium, Mobile Chrome, Mobile Safari)
3. **Deploy** — only runs after both test jobs pass

The workflow uses [`cloudflare/wrangler-action@v3`](https://github.com/cloudflare/wrangler-action) and requires two repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

### Version injection

The source contains the placeholder `vDev`. During CI the workflow runs:

```bash
sed -i "s/vDev/${GITHUB_REF_NAME}/g" index.html
```

So a release tagged `v1.2.0` will display **v1.2.0** in the UI; local development always shows **vDev**.

## Google Authenticator Compatibility

For maximum compatibility with Google Authenticator and other mobile apps:

- Use **SHA-1** algorithm (default)
- Use **30-second** period (default)
- Use **6 digits** (default)
- Set the **issuer** field — Google Authenticator uses it to group and label entries

The generated `otpauth://` URIs and QR codes follow the [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) specification.

## Storage

All data lives in the browser's `localStorage`:

| Key | Contents |
|-----|----------|
| `accounts` | Plain-text JSON array of accounts (when encryption is off) |
| `accounts_encrypted` | AES-GCM ciphertext + IV (when encryption is on) |
| `accounts_meta` | PBKDF2 salt and iteration count |


Use the **Export** button regularly to back up your accounts. `localStorage` can be cleared by the browser.

## Tech Stack

- Pure **HTML / CSS / JavaScript** — no framework, no build step
- **Web Crypto API** (`crypto.subtle`) for HMAC-SHA-1/256/512 (TOTP) and AES-GCM + PBKDF2 (encryption)
- [qrcode.js](https://github.com/davidshimjs/qrcodejs) vendored in `lib/` — the only external dependency
- CSS custom properties for light / dark theming
- [Playwright](https://playwright.dev/) for E2E testing

## Testing

```
tests/
  unit/totp.test.js    # Unit tests (Node.js)
  e2e/e2e.spec.js      # E2E tests (Playwright)
```

### Unit Tests

```bash
npm test
```

### E2E Tests (Playwright)

```bash
# Install browsers (one-time)
npx playwright install --with-deps chromium webkit

# Run all tests
npm run test:e2e

# Run with UI
npm run test:e2e:ui

# Run specific browser
npx playwright test --project=chromium
npx playwright test --project=mobile-chrome
npx playwright test --project=mobile-safari
```

**Test coverage:**
- Account CRUD (add, edit, delete)
- Import / Export JSON
- TOTP code display and clipboard
- Dark mode toggle
- Encryption (set password, lock/unlock)
- QR code modal
- Mobile responsive layout

## License

Based on original work by [Gerard Braad](https://github.com/nicedoc/gbraad-gauth). Licensed under the [GNU General Public License v3.0](LICENSE).
