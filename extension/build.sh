#!/usr/bin/env bash
set -euo pipefail

# TOTP Authenticator - Extension Build Script
# Builds distributable Chrome and Firefox extensions

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$SCRIPT_DIR/dist"

echo "=== TOTP Authenticator Extension Build ==="
echo ""

# Clean previous builds
rm -rf "$DIST_DIR"

# Build Chrome
echo "--- Chrome MV3 ---"
CHROME_DIR="$DIST_DIR/chrome"
mkdir -p "$CHROME_DIR/popup/js" "$CHROME_DIR/popup/lib" "$CHROME_DIR/icons"

cp -r "$SCRIPT_DIR/popup/index.html" "$CHROME_DIR/popup/"
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
cp -r "$SCRIPT_DIR/popup/js/totp-auth.js" "$FIREFOX_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/js/app-init.js" "$FIREFOX_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/lib/"* "$FIREFOX_DIR/popup/lib/"
cp -r "$SCRIPT_DIR/icons/"* "$FIREFOX_DIR/icons/"
cp "$SCRIPT_DIR/background.js" "$FIREFOX_DIR/"
cp "$SCRIPT_DIR/firefox-manifest.json" "$FIREFOX_DIR/manifest.json"

# Create xpi/zip with manifest at root level
cd "$FIREFOX_DIR"
zip -qr "$DIST_DIR/totp-authenticator-firefox.zip" .
cp "$DIST_DIR/totp-authenticator-firefox.zip" "$DIST_DIR/totp-authenticator-firefox.xpi"
cd "$SCRIPT_DIR"
echo "  -> $DIST_DIR/totp-authenticator-firefox.xpi  ($(du -h "$DIST_DIR/totp-authenticator-firefox.xpi" | cut -f1))"

echo ""
echo "=== Build Complete ==="
echo ""
echo "CHROME (file://$DIST_DIR/totp-authenticator-chrome.zip)"
echo "  1. Unzip the file to a folder"
echo "  2. Go to chrome://extensions"
echo "  3. Enable 'Developer mode' (top-right)"
echo "  4. Click 'Load unpacked' and select the unzipped folder"
echo ""
echo "FIREFOX (file://$DIST_DIR/totp-authenticator-firefox.xpi)"
echo "  Drag and drop the .xpi file into Firefox"
echo "  Or: about:debugging -> This Firefox -> Load Temporary Add-on"
echo ""
echo "NOTE: For permanent installation on both browsers,"
echo "you'll need to sign the extension. See:"
echo "  Chrome: https://developer.chrome.com/docs/webstore/publish/"
echo "  Firefox: https://addons.mozilla.org/developers/"
