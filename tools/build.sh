#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode-16.4.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode-16.4.app/Contents/Developer
fi
/usr/bin/python3 -I -B tools/fetch_router_core.py --verify-file "$PWD/.build/router-core/mihomo"
# Cursor/agent sandboxes often block SwiftPM's sandbox-exec; disable nested sandbox.
swift build -c release --disable-sandbox
APP="$PWD/dist/Claude Launcher.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# Generate every standard macOS icon representation from the checked-in master.
ICON_SOURCE="$PWD/assets/app-icon/AppIcon-full-bleed.png"
ICONSET="$PWD/.build/AppIcon.iconset"
ICON_CATALOG="$PWD/.build/ClaudeDetector.xcassets"
mkdir -p "$ICONSET" "$ICON_CATALOG/ClaudeDetector.appiconset"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  sips -z "$((size * 2))" "$((size * 2))" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
cp "$ICONSET/"*.png "$ICON_CATALOG/ClaudeDetector.appiconset/"
cp assets/app-icon/Contents.json "$ICON_CATALOG/ClaudeDetector.appiconset/Contents.json"
xcrun actool "$ICON_CATALOG" --compile "$APP/Contents/Resources" --platform macosx \
  --minimum-deployment-target 13.0 --app-icon ClaudeDetector \
  --output-partial-info-plist "$PWD/.build/AppIcon-info.plist"
iconutil --convert icns --output "$APP/Contents/Resources/ClaudeDetector.icns" "$ICONSET"
cp .build/release/ClaudeLauncher "$APP/Contents/MacOS/ClaudeLauncher"
cp .build/release/launcher-tool "$APP/Contents/MacOS/launcher-tool"
cp .build/release/router-runtime "$APP/Contents/MacOS/router-runtime"
# Keep upstream executable bytes/signature intact; never deep-sign the resource.
cp .build/router-core/mihomo "$APP/Contents/Resources/mihomo"
chmod 700 "$APP/Contents/Resources/mihomo"
cp docs/licenses/mihomo-GPL-3.0.txt "$APP/Contents/Resources/mihomo-GPL-3.0.txt"
cp tools/console_probe.py tools/providers.py tools/connector_service.py tools/browser_install.py tools/retire_legacy.py tools/install.py \
  tools/claude_protect_privileged.py tools/claude_protect_pf.py tools/claude_protect_guard.py tools/claude_protect_root_hook.py tools/router_pf_root_hook.py \
  "$APP/Contents/Resources/"
mkdir -p "$APP/Contents/Resources/tools"
cp tools/claude_protect_pf.py tools/claude_protect_guard.py "$APP/Contents/Resources/tools/"
cp docs/third-party-notices.md "$APP/Contents/Resources/third-party-notices.md"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.crazymax.claude-launcher</string>
<key>CFBundleName</key><string>Claude 环境检测</string>
<key>CFBundleExecutable</key><string>ClaudeLauncher</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIconFile</key><string>ClaudeDetector.icns</string>
<key>CFBundleIconName</key><string>ClaudeDetector</string>
<key>CFBundleShortVersionString</key><string>0.16.16</string>
<key>CFBundleVersion</key><string>61</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$APP/Contents/MacOS/launcher-tool"
codesign --force --sign - "$APP/Contents/MacOS/router-runtime"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
/usr/bin/python3 -I -B tools/fetch_router_core.py --verify-file "$APP/Contents/Resources/mihomo"
printf '%s\n' "$APP"
