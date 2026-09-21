#!/bin/bash
set -euo pipefail

readonly repository_url="https://github.com/nonbutAworker/swgbar"
readonly package_name="SWGBar-macOS-arm64.pkg"
readonly target_directory="${HOME:?}/Applications"

if [[ "$(/usr/bin/uname -s)" != "Darwin" ]]; then
    echo "SWGBar supports macOS only." >&2
    exit 1
fi
if [[ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || true)" != "1" ]]; then
    echo "SWGBar currently supports Apple Silicon Macs only." >&2
    exit 1
fi
macos_version="$(/usr/bin/sw_vers -productVersion)"
if (( ${macos_version%%.*} < 14 )); then
    echo "SWGBar requires macOS 14 or later." >&2
    exit 1
fi
if [[ "$EUID" -eq 0 ]]; then
    echo "Run this command as your normal user, without sudo." >&2
    exit 1
fi
if /usr/bin/pgrep -x SWGBarApp >/dev/null; then
    echo "Quit SWGBar before installing, then run this command again." >&2
    exit 1
fi

temporary_directory="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/swgbar-install.XXXXXX")"
trap '/bin/rm -rf "$temporary_directory"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Finding the latest SWGBar release..."
release_url="$(/usr/bin/curl --proto '=https' --fail --silent --show-error --location --head \
    --output /dev/null --write-out '%{url_effective}' "$repository_url/releases/latest")"
case "$release_url" in
    "$repository_url/releases/tag/"?*) ;;
    *) echo "Could not find the latest SWGBar release." >&2; exit 1 ;;
esac
release_tag="${release_url#"$repository_url/releases/tag/"}"
release_base="$repository_url/releases/download/$release_tag"

echo "Downloading SWGBar..."
/usr/bin/curl --proto '=https' --fail --location --silent --show-error --retry 3 \
    "$release_base/$package_name" --output "$temporary_directory/$package_name"
/usr/bin/curl --proto '=https' --fail --location --silent --show-error --retry 3 \
    "$release_base/SHA256SUMS.txt" --output "$temporary_directory/SHA256SUMS.txt"

expected_checksum="$(/usr/bin/awk -v package="$package_name" \
    '$2 == package { print $1 }' "$temporary_directory/SHA256SUMS.txt")"
actual_checksum="$(/usr/bin/shasum -a 256 "$temporary_directory/$package_name" | /usr/bin/awk '{ print $1 }')"
if [[ ! "$expected_checksum" =~ ^[[:xdigit:]]{64}$ || "$actual_checksum" != "$expected_checksum" ]]; then
    echo "Checksum verification failed. Nothing was installed. Please try again later." >&2
    exit 1
fi

echo "Checksum verified. Extracting SWGBar..."
/usr/sbin/pkgutil --expand-full "$temporary_directory/$package_name" "$temporary_directory/expanded"
source_app="$temporary_directory/expanded/Payload/Applications/SWGBar.app"
/usr/bin/codesign --verify --deep --strict "$source_app"

echo "Installing SWGBar in $target_directory..."
/bin/mkdir -p "$target_directory"
/usr/bin/ditto "$source_app" "$target_directory/SWGBar.app"
/usr/bin/codesign --verify --deep --strict "$target_directory/SWGBar.app"

echo "SWGBar is installed at $target_directory/SWGBar.app. Open it when you are ready."
