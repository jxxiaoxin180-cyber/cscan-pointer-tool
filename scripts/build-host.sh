#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cmake -S "$PROJECT_DIR" -B "$PROJECT_DIR/build-host" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$PROJECT_DIR/build-host" -j "${CSCAN_BUILD_JOBS:-3}"
ctest --test-dir "$PROJECT_DIR/build-host" --output-on-failure
mkdir -p "$PROJECT_DIR/bin"
CSCAN_STAGING="$PROJECT_DIR/bin/.cscan-linux-arm64.$$.part"
trap 'rm -f -- "$CSCAN_STAGING"' EXIT
cp "$PROJECT_DIR/build-host/cscan" "$CSCAN_STAGING"
chmod +x "$CSCAN_STAGING"
mv -f -- "$CSCAN_STAGING" "$PROJECT_DIR/bin/cscan-linux-arm64"
