# Migration Guide

This guide explains how to migrate your accounts from other authenticator apps to TOTP Authenticator.

---

## Overview

TOTP Authenticator supports importing accounts via:
1. **JSON files** - Export from compatible apps or create manually
2. **otpauth:// URIs** - Standard format supported by most authenticators

---

## From Google Authenticator

### Method 1: Export via QR Code (Mobile)

1. Open Google Authenticator on your phone
2. Tap the **⋮** menu (Android) or **Edit** icon (iOS)
3. Select **Export accounts**
4. Choose accounts to export
5. A QR code will appear - **do not scan yet**
6. Take a screenshot or photo of the QR code
7. Use a QR code reader app to extract the `otpauth://` URI
8. Copy the URI to a text file (one per line)
9. In TOTP Authenticator:
   - Click **Edit** (⚙️) button
   - Click **Import** (↥) button
   - Select your text file

### Method 2: Manual Entry

For each account:
1. In TOTP Authenticator, click **Edit** (⚙️) → **+ Add Account**
2. Enter the issuer (e.g., "GitHub")
3. Enter the account name (e.g., "user@example.com")
4. Enter the secret key from Google Authenticator (tap the account to see setup key)
5. Click **Add**

---

## From Authy

### Export via Backup

Authy doesn't have a direct export feature, but you can:

1. **For each account:**
   - Open Authy on your phone
   - Tap the account
   - Look for "Setup Key" or "Export" option
   - Copy the secret key

2. Create a JSON file:
```json
[
  {
    "name": "user@example.com",
    "issuer": "GitHub",
    "secret": "YOUR_SECRET_HERE"
  }
]
```

3. In TOTP Authenticator:
   - Click **Edit** → **Import**
   - Select your JSON file

---

## From 1Password

### Export OTP Secrets

1. Open 1Password on desktop
2. Find an account with 2FA enabled
3. Click the **TOTP code** field
4. Click **Edit** → **Show Secret Key**
5. Copy the secret

6. Create a JSON file or enter manually:
   - Click **Edit** → **+ Add Account**
   - Fill in the details

**Note:** 1Password doesn't have bulk export for OTP secrets. You'll need to add accounts one by one.

---

## From Bitwarden

### Export Vault

1. Go to **Tools** → **Export Vault**
2. Choose **JSON** format
3. Export and open the file
4. Find entries with `totp` field
5. Create a new JSON file:

```json
[
  {
    "name": "Account Name",
    "issuer": "Service Name",
    "secret": "SECRET_FROM_TOTP_FIELD"
  }
]
```

6. Import into TOTP Authenticator

---

## From LastPass

### Export Authenticator Codes

LastPass doesn't provide easy export of TOTP secrets. You may need to:

1. Re-setup 2FA on each service
2. Scan the new QR code with TOTP Authenticator
3. Or manually enter the secret key

---

## From Microsoft Authenticator

### Manual Transfer

Microsoft Authenticator doesn't support export. For each account:

1. In TOTP Authenticator: **Edit** → **+ Add Account**
2. On the service's website, go to 2FA settings
3. Choose "I can't scan the QR code" or "Show secret key"
4. Copy the secret and enter it manually

---

## Import Format

### JSON Format

```json
[
  {
    "name": "user@example.com",
    "issuer": "GitHub",
    "secret": "BASE32SECRET",
    "algorithm": "SHA-1",
    "period": 30,
    "digits": 6,
    "url": "https://github.com"
  }
]
```

**Required fields:**
- `name` - Account name/label
- `secret` - Base32-encoded TOTP secret

**Optional fields:**
- `issuer` - Service provider name
- `algorithm` - SHA-1, SHA-256, or SHA-512 (default: SHA-1)
- `period` - Code validity in seconds (default: 30)
- `digits` - Code length: 6 or 8 (default: 6)
- `url` - Optional link for the account name

### otpauth:// URI Format

```
otpauth://totp/Issuer:Name?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
```

You can import a text file with one URI per line.

---

## Tips

- **Backup first:** Export your current accounts before migrating
- **Test each account:** Verify codes work before deleting old authenticator
- **Keep both apps:** Run both authenticators in parallel for a few days
- **Save secrets:** Store secret keys in a password manager as backup

---

## Troubleshooting

### Codes don't match
- Ensure system time is synchronized
- Check that the secret was entered correctly (no spaces, correct characters)
- Verify algorithm (SHA-1 vs SHA-256) matches

### Import fails
- Check JSON syntax (use a JSON validator)
- Ensure secrets are valid Base32 (A-Z, 2-7)
- Remove any comments or extra text from the file

### Missing accounts after import
- Check the browser console for errors
- Verify the file format matches the expected structure
- Try importing a smaller batch of accounts

---

*Last updated: April 2026*
