#!/system/bin/sh
# 作者：jx小新
# 在 Android 原生终端或 MT 的 Root 执行模式运行此脚本。
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CSCAN_BIN="$PROJECT_DIR/bin/cscan-android-arm64"
if [ ! -x "$CSCAN_BIN" ]; then
  echo "无法执行 $CSCAN_BIN；请解压到允许执行的位置，并设置执行权限。" >&2
  exit 1
fi
# /proc/self/status reflects kernel credentials even when a container rewrites id/getuid.
if ! "$CSCAN_BIN" runtime | /system/bin/grep -q '"root": true'; then
  echo '当前不是 Android 原生 Root 环境。请退出 proot/容器，在手机终端执行 su，或在 MT 中选择 Root 执行，再运行本脚本。' >&2
  exit 1
fi
exec "$CSCAN_BIN" serve --data "$PROJECT_DIR/data" --port 18760
