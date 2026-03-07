# TOTP Authenticator

A lightweight, self-hosted TOTP authenticator web app. No server required — runs entirely in the browser.

## Features

- **Per-account TOTP** with configurable algorithm (SHA-1/256/512), period, and digits
- **Issuer field** (optional) for Google Authenticator compatibility
- **Auto-load accounts** from `accounts.json` on first visit
- **Import/Export** accounts as JSON or `otpauth://` URIs
- **QR code generation** for easy scanning into mobile authenticator apps
- **Click-to-copy** codes to clipboard
- **Responsive layout** — works on desktop and mobile
- **No dependencies** — pure HTML/CSS/JS, no build step

## Quick Start

Serve the files with any static HTTP server:

```bash
# Python
python3 -m http.server 8000

# Node
npx serve .

# BusyBox
busybox httpd -f -p 8000 -h .
```

Then open `http://localhost:8000` in your browser.

## Default Accounts

On first visit (empty localStorage), the app tries to load `accounts.json` from the server. If the file doesn't exist or is invalid, a random demo account is created.

To set up default accounts:

```bash
cp accounts.example.json accounts.json
```

Edit `accounts.json` with your real secrets. The file supports `//` and `#` comments.

> **Note:** `accounts.json` is in `.gitignore` — it contains real secrets and should never be committed.

## Account Format

```jsonc
[
  {
    "name": "user@example.com",  // Account name (required)
    "issuer": "GitHub",           // Service provider (optional)
    "secret": "4BVKJQZILWC46B2LT4CGT3ISFWZ4VYIP", // Base32 TOTP secret (required)
    "algorithm": "SHA-1",          // SHA-1, SHA-256, or SHA-512 (default: SHA-1)
    "period": 30,                  // Seconds: 30, 60, 300, 3600, 86400 (default: 30)
    "digits": 6,                   // 6 or 8 (default: 6)
    "url": "https://github.com"    // Optional link on account name
  }
]
```

## Google Authenticator Compatibility

For maximum compatibility with Google Authenticator and other mobile apps:

- Use **SHA-1** algorithm (default)
- Use **30-second** period (default)
- Use **6 digits** (default)
- Set the **issuer** field

## Storage

Accounts are stored in the browser's `localStorage`. Use the export button to back up your accounts.

## License

Based on original work by Gerard Braad. GPL-3.0.
