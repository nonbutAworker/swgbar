#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p build

echo "==> 1. Building Go CoreWorker..."
cd coreworker
go build -trimpath -o ../build/coreworker main.go
cd ..

echo "==> 2. Building Swift Release Executable..."
swift build -c release \
    -Xswiftc -file-prefix-map -Xswiftc "$REPO_ROOT=." \
    -Xswiftc -debug-prefix-map -Xswiftc "$REPO_ROOT=." \
    -Xlinker -S

echo "==> 3. Assembling SWGBar.app bundle..."
APP_DIR="build/SWGBar.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Copy executables
cp .build/release/SWGBarApp "$MACOS_DIR/SWGBarApp"
cp build/coreworker "$MACOS_DIR/coreworker"
chmod +x "$MACOS_DIR/SWGBarApp" "$MACOS_DIR/coreworker"

# Copy app icon
cp Resources/AppIcon.icns "$RESOURCES_DIR/AppIcon.icns"

# Create Info.plist with LSUIElement=true
cat << 'EOF' > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>SWGBarApp</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.swgbar.app</string>
    <key>CFBundleName</key>
    <string>SWGBar</string>
    <key>CFBundleDisplayName</key>
    <string>SWGBar</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.6.0</string>
    <key>CFBundleVersion</key>
    <string>2</string>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleLocalizations</key>
    <array>
        <string>en</string>
    </array>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
EOF

echo "==> 4. Ad-hoc Codesigning SWGBar.app..."
codesign --force --deep --sign - "$APP_DIR"

echo "==> 5. Verification..."
codesign --verify --deep --strict "$APP_DIR"
echo "==> SUCCESS! SWGBar.app successfully built and signed at: $APP_DIR"
