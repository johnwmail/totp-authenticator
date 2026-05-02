# Feature: Share URL - Encrypted Compressed Account Sharing

## Overview

Generate a shareable URL containing compressed and encrypted TOTP accounts. Recipients can decrypt and import accounts by entering the correct password.

### Goals

- Share TOTP accounts via URL (no server required)
- Password-protected encryption (AES-GCM + PBKDF2)
- Client-side compression (lz-string)
- URL stored in fragment (`#data=`) for privacy

### Data Flow

```
EXPORT:
accounts → lz-string.compress → AES-GCM.encrypt(password) → base64 → #data=...

IMPORT:
#data=... → base64 decode → AES-GCM.decrypt(password) → lz-string.decompress → merge accounts
```

## Tech Stack

| Component | Library | Reason |
|-----------|---------|--------|
| Compression | lz-string | Lightweight (~3KB), good for small data |
| Encryption | Web Crypto API (AES-GCM + PBKDF2) | Already used in app |
| Encoding | base64 | Standard, already used in app |

## Implementation Steps

### Step 1: Add lz-string Library

- [x] Download `lib/lz-string.min.js` from CDN/npm
- [x] Add script tag in `index.html`

### Step 2: Add Compression/Encryption Functions

- [x] `compressAndEncrypt(accounts, password)` → base64 string
  - Serialize accounts to JSON
  - Compress with lz-string
  - Encrypt with AES-GCM + PBKDF2 (310k iterations)
  - Return base64 string

- [x] `decompressAndDecrypt(data, password)` → accounts array
  - Decrypt base64 data with AES-GCM
  - Decompress with lz-string
  - Parse JSON and return accounts array

### Step 3: Add Share Modal UI

- [x] Add Share button in top bar (next to Export button)
- [x] Add Share modal HTML (index.html)
  - Password input field
  - Generate URL button
  - Read-only URL text field (clickable to copy)
- [x] Add Share modal controller (totp-auth.js)
  - Handle button click → show modal
  - Handle Generate URL → create URL
  - Handle URL click → copy to clipboard
  - Show toast "URL copied to clipboard"

### Step 4: Add URL Import on Page Load

- [x] In `init()`, check for `#data=` fragment
- [x] If present, show unlock modal with "Import Accounts" title
- [x] On successful decrypt, merge accounts
- [x] On failed decrypt, show error and increment attempt counter
- [x] After 3 failed attempts, clear URL and show message

### Step 5: Add Brute Force Protection

- [x] Track failed import attempts per session
- [x] After 3 failures:
  - Clear `#data=` from URL (history.replaceState)
  - Show message: "Too many failed attempts. Please request a new share URL."

## UI Specifications

### Share Modal

```
┌─────────────────────────────────────┐
│  Share Accounts                [X]  │
├─────────────────────────────────────┤
│  Password                           │
│  ┌─────────────────────────────┐     │
│  │ •••••••••••                 │     │
│  └─────────────────────────────┘     │
│                                     │
│  [      Generate URL      ]         │
│                                     │
│  ┌─────────────────────────────┐     │
│  │ https://app.com/#data=…    │ ← click to copy
│  └─────────────────────────────┘     │
│                                     │
│              [ Close ]               │
└─────────────────────────────────────┘
```

### Flow: Export

1. User clicks "Share" in settings menu
2. Share modal appears
3. User enters password
4. User clicks "Generate URL"
5. URL appears in text field
6. User clicks URL to copy
7. User shares URL

### Flow: Import

1. Recipient opens URL with `#data=...`
2. App detects fragment, shows unlock modal
3. User enters password
4. On success: accounts merge, toast "Accounts imported"
5. On failure: show error, allow retry (max 3 attempts)
6. After 3 failures: URL cleared, message shown

## File Changes

| File | Changes |
|------|---------|
| `lib/lz-string.min.js` | Add library |
| `index.html` | Add lz-string script, Share button, Share modal HTML |
| `js/totp-auth.js` | Add `compressAndEncrypt()`, `decompressAndDecrypt()`, URL detection, Share modal logic |
| `tests/unit/totp.test.js` | Add unit tests for compression/encryption functions |
| `tests/e2e/e2e.spec.js` | Add e2e tests for share/export/import flows |

## Test Cases

### Unit Tests

1. **compressAndEncrypt**
   - Given accounts array and password → returns base64 string
   - Different passwords produce different outputs
   - Empty accounts array → still produces valid output

2. **decompressAndDecrypt**
   - Given valid base64 data and correct password → returns original accounts
   - Given wrong password → throws error
   - Given corrupted data → throws error

3. **Roundtrip**
   - compress → decompress with same password → original data
   - Large accounts array maintains data integrity

### E2E Tests

1. **Share flow**
   - [x] Top bar has Share button (visible in edit mode)
   - [x] Click Share → modal opens
   - [x] Enter password → Generate URL button enabled
   - [x] Generate URL → URL appears with #data=
   - [x] Click URL → copies to clipboard
   - [x] Close modal → reopens with empty password

2. **Import flow (correct password)**
   - [x] Navigate to URL with `#data=...`
   - [x] Unlock/Import modal appears automatically
   - [x] Enter correct password → accounts merge
   - [x] URL fragment is cleared after success

3. **Import flow (wrong password)**
   - [x] Navigate to URL with `#data=...`
   - [x] Unlock/Import modal appears automatically
   - [x] Enter wrong password → error shown
   - [x] Retry → error shown again
   - [x] Third failure → URL cleared, message shown

4. **Import flow (merge behavior)**
   - [x] Existing accounts + imported accounts → all present
   - [x] No duplicates (by secret key)

## Security Considerations

- Same AES-GCM + PBKDF2 (310k iterations) as existing encryption
- IV generated fresh per encryption
- URL fragment never sent to server (CSP allows fragment-src: 'self')
- After 3 failed attempts, URL is cleared to prevent brute force
- Password is never stored, only used for key derivation

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Empty accounts | Allow share (generate empty URL) |
| Very large accounts | URL may exceed browser limits (~32KB Chrome) |
| No password entered | Generate button disabled |
| Network offline | Works (fully client-side) |
| Self-hosted clone | Works on any domain |

## Future Improvements (Out of Scope)

- QR code sharing option
- Expiration timestamp in URL
- Custom domain support
- Selective account sharing
