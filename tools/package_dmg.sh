#!/bin/bash
# 打试用版 DMG：把 dist 里的 App 装进可拖拽安装的磁盘镜像。
# 当前是 ad-hoc 签名，适合自用/熟人试用；陌生人可能要右键 → 打开。
# 用法：
#   bash tools/package_dmg.sh           # 用已有 dist/*.app
#   bash tools/package_dmg.sh --build   # 先 release 构建再打包
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--build" ]]; then
  bash tools/build.sh
fi

APP="$PWD/dist/Claude Launcher.app"
if [[ ! -d "$APP" ]]; then
  echo "找不到 App：$APP" >&2
  echo "先运行：bash tools/build.sh" >&2
  exit 1
fi

/usr/bin/codesign --verify --deep --strict "$APP"

VERSION="$(/usr/bin/defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "0.0.0")"
BUILD="$(/usr/bin/defaults read "$APP/Contents/Info" CFBundleVersion 2>/dev/null || echo "0")"
SAFE_NAME="Claude-Launcher-${VERSION}-${BUILD}"
OUT_DIR="$PWD/dist"
STAGE="$PWD/.build/dmg-stage"
RW_DMG="$PWD/.build/${SAFE_NAME}-rw.dmg"
FINAL_DMG="$OUT_DIR/${SAFE_NAME}.dmg"
VOL="Claude 环境检测"

rm -rf "$STAGE"
mkdir -p "$STAGE" "$OUT_DIR"
/bin/cp -R "$APP" "$STAGE/"
/bin/ln -s /Applications "$STAGE/Applications"

rm -f "$RW_DMG" "$FINAL_DMG"
/usr/bin/hdiutil create \
  -volname "$VOL" \
  -srcfolder "$STAGE" \
  -ov \
  -format UDRW \
  "$RW_DMG" >/dev/null

# 压缩成常见的只读 DMG
/usr/bin/hdiutil convert "$RW_DMG" -format UDZO -imagekey zlib-level=9 -o "$FINAL_DMG" >/dev/null
rm -f "$RW_DMG"
rm -rf "$STAGE"

/usr/bin/shasum -a 256 "$FINAL_DMG" | /usr/bin/tee "$FINAL_DMG.sha256"
printf '%s\n' "$FINAL_DMG"
echo "试用版 DMG 已就绪。打开后把「Claude Launcher」拖到 Applications 即可。"
echo "若系统提示无法验证开发者：选中 App → 右键 → 打开。"
