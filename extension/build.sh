#!/usr/bin/env bash
set -euo pipefail

# TOTP Authenticator - Extension Build Script
# Builds distributable Chrome and Firefox extensions

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$SCRIPT_DIR/dist"

echo "=== TOTP Authenticator Extension Build ==="
echo ""

# Preserve existing private key for CRX signing
KEY_FILE="$DIST_DIR/chrome.pem"
[ -f "$KEY_FILE" ] && cp "$KEY_FILE" /tmp/chrome-build-key.pem
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"
[ -f /tmp/chrome-build-key.pem ] && mv /tmp/chrome-build-key.pem "$KEY_FILE"

# Build Chrome
echo "--- Chrome MV3 ---"
CHROME_DIR="$DIST_DIR/chrome"
mkdir -p "$CHROME_DIR/popup/js" "$CHROME_DIR/popup/lib" "$CHROME_DIR/icons"

cp -r "$SCRIPT_DIR/popup/index.html" "$CHROME_DIR/popup/"
cp -r "$SCRIPT_DIR/popup/favicon.ico" "$CHROME_DIR/popup/"
cp -r "$SCRIPT_DIR/popup/js/totp-auth.js" "$CHROME_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/js/app-init.js" "$CHROME_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/lib/"* "$CHROME_DIR/popup/lib/"
cp -r "$SCRIPT_DIR/icons/"* "$CHROME_DIR/icons/"
cp "$SCRIPT_DIR/background.js" "$CHROME_DIR/"
cp "$SCRIPT_DIR/chrome-manifest.json" "$CHROME_DIR/manifest.json"

# Create zip with manifest at root level for clean extraction
cd "$CHROME_DIR"
zip -qr "$DIST_DIR/totp-authenticator-chrome.zip" .
cd "$SCRIPT_DIR"
echo "  -> $DIST_DIR/totp-authenticator-chrome.zip  ($(du -h "$DIST_DIR/totp-authenticator-chrome.zip" | cut -f1))"

# Build Firefox
echo ""
echo "--- Firefox MV2 ---"
FIREFOX_DIR="$DIST_DIR/firefox"
mkdir -p "$FIREFOX_DIR/popup/js" "$FIREFOX_DIR/popup/lib" "$FIREFOX_DIR/icons"

cp -r "$SCRIPT_DIR/popup/index.html" "$FIREFOX_DIR/popup/"
cp -r "$SCRIPT_DIR/popup/favicon.ico" "$FIREFOX_DIR/popup/"
cp -r "$SCRIPT_DIR/popup/js/totp-auth.js" "$FIREFOX_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/js/app-init.js" "$FIREFOX_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/lib/"* "$FIREFOX_DIR/popup/lib/"
cp -r "$SCRIPT_DIR/icons/"* "$FIREFOX_DIR/icons/"
cp "$SCRIPT_DIR/background.js" "$FIREFOX_DIR/"
cp "$SCRIPT_DIR/firefox-manifest.json" "$FIREFOX_DIR/manifest.json"

# Create xpi (store-only compression — safest for Firefox)
cd "$FIREFOX_DIR"
zip -0r "$DIST_DIR/totp-authenticator-firefox.zip" .
cp "$DIST_DIR/totp-authenticator-firefox.zip" "$DIST_DIR/totp-authenticator-firefox.xpi"
cd "$SCRIPT_DIR"
echo "  -> $DIST_DIR/totp-authenticator-firefox.xpi  ($(du -h "$DIST_DIR/totp-authenticator-firefox.xpi" | cut -f1))"

# Build Chrome CRX (packed extension for drag-and-drop install)
echo ""
echo "--- Chrome CRX ---"
if [ -f "$KEY_FILE" ]; then
    chromium --pack-extension="$CHROME_DIR" \
             --pack-extension-key="$KEY_FILE" \
             --no-sandbox --no-message-box 2>/dev/null || \
    echo "  (chromium not available, skipping CRX)"
else
    chromium --pack-extension="$CHROME_DIR" \
             --no-sandbox --no-message-box 2>/dev/null || \
    echo "  (chromium not available, skipping CRX)"
    if [ -f "$CHROME_DIR.pem" ]; then
        mv "$CHROME_DIR.pem" "$KEY_FILE"
    fi
fi

if [ -f "$CHROME_DIR.crx" ] && [ "$CHROME_DIR.crx" != "$DIST_DIR/chrome.crx" ]; then
    mv "$CHROME_DIR.crx" "$DIST_DIR/chrome.crx"
fi
if [ -f "$DIST_DIR/chrome.crx" ]; then
    echo "  -> $DIST_DIR/chrome.crx  ($(du -h "$DIST_DIR/chrome.crx" | cut -f1))"
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "CHROME (drag & drop):"
echo "  $DIST_DIR/chrome.crx"
echo ""
echo "CHROME (unpacked):"
echo "  1. Unzip $DIST_DIR/totp-authenticator-chrome.zip"
echo "  2. chrome://extensions → Developer mode → Load unpacked"
echo ""
echo "FIREFOX (drag & drop):"
echo "  $DIST_DIR/totp-authenticator-firefox.xpi"
echo "  Or: about:debugging → This Firefox → Load Temporary Add-on"
echo ""
echo "NOTE: For permanent installation you'll need to sign the extension:"
echo "  Chrome: https://developer.chrome.com/docs/webstore/publish/"
echo "  Firefox: https://addons.mozilla.org/developers/"
