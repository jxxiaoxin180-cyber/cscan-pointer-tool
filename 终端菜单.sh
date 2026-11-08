#!/system/bin/sh
# 作者：jx小新
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x /system/bin/linker64 ]; then
    CSCAN_BIN="$PROJECT_DIR/bin/cscan-android-arm64"
elif [ -x "$PROJECT_DIR/bin/cscan-linux-arm64" ]; then
    CSCAN_BIN="$PROJECT_DIR/bin/cscan-linux-arm64"
else
    echo '本仓库仅附带 Android ARM64 成品；Linux 请先运行 bash scripts/build-host.sh。' >&2
    exit 1
fi
exec "$CSCAN_BIN" menu --data "$PROJECT_DIR/data"
