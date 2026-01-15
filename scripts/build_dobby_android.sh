#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOBBY_DIR="$ROOT_DIR/app/src/main/cpp/dobby"
OUT_DIR="$ROOT_DIR/out/dobby"

NDK_ROOT="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-}}"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"

if [ -z "$NDK_ROOT" ]; then
  echo "[错误] 未设置 ANDROID_NDK_ROOT 或 ANDROID_NDK_HOME"
  exit 1
fi

API_LEVEL=24
ABI=arm64-v8a

if [ -z "$SDK_ROOT" ]; then
  CMAKE_BIN="cmake"
else
  if [ -d "$SDK_ROOT/cmake" ]; then
    CMAKE_BIN="$(find "$SDK_ROOT/cmake" -type f -path '*/bin/cmake' | sort | tail -n1)"
  else
    CMAKE_BIN="cmake"
  fi
fi

if [ -z "$CMAKE_BIN" ]; then
  CMAKE_BIN="cmake"
fi

echo "ROOT_DIR = $ROOT_DIR"
echo "DOBBY_DIR = $DOBBY_DIR"
echo "NDK_ROOT = $NDK_ROOT"
echo "SDK_ROOT = $SDK_ROOT"
echo "CMAKE_BIN = $CMAKE_BIN"

BUILD_DIR="$OUT_DIR/build-$ABI"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

"$CMAKE_BIN" -G Ninja \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API_LEVEL" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_GENERATE_SHARED=ON \
  -DDOBBY_DEBUG=OFF \
  "$DOBBY_DIR" \
  -B"$BUILD_DIR"

"$CMAKE_BIN" --build "$BUILD_DIR" --target dobby

SO_PATH="$(find "$BUILD_DIR" -name 'libdobby.so' | head -n1)"
if [ -z "$SO_PATH" ]; then
  echo "[错误] 未在 $BUILD_DIR 下找到 libdobby.so"
  exit 1
fi

DEST_ASSET_DIR="$ROOT_DIR/app/src/main/assets"
mkdir -p "$DEST_ASSET_DIR"
cp -f "$SO_PATH" "$DEST_ASSET_DIR/libdobby.so"
echo "✅ 已将 libdobby.so 同步到: $DEST_ASSET_DIR/libdobby.so"
