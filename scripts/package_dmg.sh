#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==> 1. Ensuring SWGBar.app is built..."
"$SCRIPT_DIR/build_app.sh"

echo "==> 2. Preparing DMG and ZIP staging..."
STAGING_DIR="$REPO_ROOT/build/dmg_staging"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

cp -R "$REPO_ROOT/build/SWGBar.app" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"

DMG_OUTPUT="$REPO_ROOT/build/SWGBar-Installer.dmg"
ZIP_OUTPUT="$REPO_ROOT/build/SWGBar-macOS.zip"

rm -f "$DMG_OUTPUT" "$ZIP_OUTPUT"

echo "==> 3. Creating DMG ($DMG_OUTPUT)..."
hdiutil create -volname "SWGBar Installer" -srcfolder "$STAGING_DIR" -ov -format UDZO "$DMG_OUTPUT"

echo "==> 4. Creating ZIP ($ZIP_OUTPUT)..."
(cd "$REPO_ROOT/build" && zip -r -y "SWGBar-macOS.zip" "SWGBar.app")

rm -rf "$STAGING_DIR"

echo "==> Packaging complete!"
echo "    - DMG: $DMG_OUTPUT"
echo "    - ZIP: $ZIP_OUTPUT"
