#!/usr/bin/env bash
set -euo pipefail

# TOTP Authenticator - Extension Build Script
# Builds distributable Chrome and Firefox extensions from source

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$SCRIPT_DIR/dist"

echo "=== TOTP Authenticator Extension Build ==="
echo "Source: $SCRIPT_DIR"
echo "Output: $DIST_DIR"

# Clean previous builds
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Common files (shared between Chrome and Firefox)
COMMON_DIR="$DIST_DIR/_common"
mkdir -p "$COMMON_DIR/popup/js" "$COMMON_DIR/popup/lib" "$COMMON_DIR/icons"

# Copy popup assets
cp -r "$SCRIPT_DIR/popup/index.html" "$COMMON_DIR/popup/"
cp -r "$SCRIPT_DIR/popup/js/totp-auth.js" "$COMMON_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/js/app-init.js" "$COMMON_DIR/popup/js/"
cp -r "$SCRIPT_DIR/popup/lib/"* "$COMMON_DIR/popup/lib/"

# Copy icons
cp -r "$SCRIPT_DIR/icons/"* "$COMMON_DIR/icons/"

# Copy background script
cp "$SCRIPT_DIR/background.js" "$COMMON_DIR/"

echo ""
echo "--- Building Chrome MV3 Extension ---"
CHROME_DIR="$DIST_DIR/chrome"
mkdir -p "$CHROME_DIR"
cp -r "$COMMON_DIR/"* "$CHROME_DIR/"
cp "$SCRIPT_DIR/chrome-manifest.json" "$CHROME_DIR/manifest.json"
echo "Chrome extension ready at: $CHROME_DIR"

echo ""
echo "--- Building Firefox MV2 Extension ---"
FIREFOX_DIR="$DIST_DIR/firefox"
mkdir -p "$FIREFOX_DIR"
cp -r "$COMMON_DIR/"* "$FIREFOX_DIR/"
cp "$SCRIPT_DIR/firefox-manifest.json" "$FIREFOX_DIR/manifest.json"
echo "Firefox extension ready at: $FIREFOX_DIR"

# Clean up common directory
rm -rf "$COMMON_DIR"

echo ""
echo "=== Build Complete ==="
echo "  Chrome:  $CHROME_DIR"
echo "  Firefox: $FIREFOX_DIR"
echo ""
echo "To load in Chrome:"
echo "  1. Go to chrome://extensions"
echo "  2. Enable 'Developer mode'"
echo "  3. Click 'Load unpacked' and select $CHROME_DIR"
echo ""
echo "To load in Firefox:"
echo "  1. Go to about:debugging#/runtime/this-firefox"
echo "  2. Click 'Load Temporary Add-on'"
echo "  3. Select $FIREFOX_DIR/manifest.json"
