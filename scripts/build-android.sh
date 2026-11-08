#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NDK_DIR="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK_DIR" || ! -f "$NDK_DIR/build/cmake/android.toolchain.cmake" ]]; then
  echo '请用 ANDROID_NDK_HOME 指向已安装的 Android NDK。' >&2
  exit 1
fi
cmake -S "$PROJECT_DIR" -B "$PROJECT_DIR/build-android" -G Ninja \
 -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$NDK_DIR/build/cmake/android.toolchain.cmake" \
 -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 -DANDROID_STL=c++_static
cmake --build "$PROJECT_DIR/build-android" -j "${CSCAN_BUILD_JOBS:-3}"
mkdir -p "$PROJECT_DIR/bin"
CSCAN_STAGING="$PROJECT_DIR/bin/.cscan-android-arm64.$$.part"
trap 'rm -f -- "$CSCAN_STAGING"' EXIT
cp "$PROJECT_DIR/build-android/cscan" "$CSCAN_STAGING"
STRIP_TOOL="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
if [[ -x "$STRIP_TOOL" ]]; then "$STRIP_TOOL" --strip-unneeded "$CSCAN_STAGING"; fi
chmod +x "$CSCAN_STAGING"
mv -f -- "$CSCAN_STAGING" "$PROJECT_DIR/bin/cscan-android-arm64"
sha256sum "$PROJECT_DIR/bin/cscan-android-arm64"
