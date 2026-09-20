#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

./scripts/build_app.sh

APP_DIR="build/SWGBar.app"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_DIR/Contents/Info.plist")"
ARCH="$(uname -m)"
STAGING_DIR="build/installer-root"
COMPONENTS="build/installer-components.plist"
PACKAGE="SWGBar-macOS-$ARCH.pkg"

rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/Applications"
# Copy only the bundle contents, without source Finder metadata or resource forks.
ditto --noextattr --norsrc --noqtn "$APP_DIR" "$STAGING_DIR/Applications/SWGBar.app"

pkgbuild --analyze --root "$STAGING_DIR" "$COMPONENTS"
# Always install in /Applications, even if another copy exists in a build directory.
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$COMPONENTS"

pkgbuild \
    --root "$STAGING_DIR" \
    --component-plist "$COMPONENTS" \
    --install-location / \
    --identifier com.swgbar.app \
    --version "$VERSION" \
    "build/$PACKAGE"

(cd build && shasum -a 256 "$PACKAGE" > SHA256SUMS.txt)
echo "Installer: build/$PACKAGE"
echo "Checksums: build/SHA256SUMS.txt"
echo "This package is not Developer ID signed or notarized."
