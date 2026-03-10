#!/bin/bash
#
# ReSignPro - Native 库构建脚本
#
# 使用 NDK 编译 librepack_native.so（所有支持的 ABI）
# 输出到 app/src/main/assets/nativeLibs/ 供运行时注入
#
# 用法: ./scripts/build_native.sh [debug|release]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TYPE="${1:-release}"

echo "=========================================="
echo "  ReSignPro Native Builder"
echo "  Build type: $BUILD_TYPE"
echo "=========================================="

# NDK 路径
if [ -z "$ANDROID_NDK_HOME" ]; then
    if [ -z "$ANDROID_HOME" ]; then
        if [ -d "$HOME/Android/Sdk" ]; then
            export ANDROID_HOME="$HOME/Android/Sdk"
        elif [ -d "$HOME/Library/Android/sdk" ]; then
            export ANDROID_HOME="$HOME/Library/Android/sdk"
        fi
    fi
    # 查找最新的 NDK
    NDK_DIR=$(ls -d "$ANDROID_HOME/ndk/"* 2>/dev/null | sort -V | tail -1)
    if [ -z "$NDK_DIR" ]; then
        echo "ERROR: NDK not found. Set ANDROID_NDK_HOME or install NDK via SDK Manager."
        exit 1
    fi
    export ANDROID_NDK_HOME="$NDK_DIR"
fi

echo "  NDK: $ANDROID_NDK_HOME"

CMAKE_BIN="$ANDROID_NDK_HOME/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin/cmake"
if [ ! -f "$CMAKE_BIN" ]; then
    CMAKE_BIN=$(which cmake)
fi

if [ ! -x "$CMAKE_BIN" ]; then
    echo "ERROR: cmake not found"
    exit 1
fi

echo "  CMake: $CMAKE_BIN"

CMAKE_TOOLCHAIN="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
CPP_DIR="$PROJECT_DIR/app/src/main/cpp"
NATIVE_ASSETS_DIR="$PROJECT_DIR/app/src/main/assets/nativeLibs"

# 支持的 ABI 列表
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")

# CMake build type
if [ "$BUILD_TYPE" = "debug" ]; then
    CMAKE_BUILD_TYPE="Debug"
else
    CMAKE_BUILD_TYPE="Release"
fi

echo ""

for ABI in "${ABIS[@]}"; do
    echo "[Building $ABI]"

    BUILD_DIR="$PROJECT_DIR/build/native/$ABI"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    OUTPUT_DIR="$NATIVE_ASSETS_DIR/$ABI"
    mkdir -p "$OUTPUT_DIR"

    # CMake configure
    "$CMAKE_BIN" \
        -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN" \
        -DANDROID_ABI="$ABI" \
        -DANDROID_PLATFORM=android-21 \
        -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
        -S "$CPP_DIR" \
        -B "$BUILD_DIR" \
        > /dev/null 2>&1

    # Build
    "$CMAKE_BIN" --build "$BUILD_DIR" --config "$CMAKE_BUILD_TYPE" -j$(nproc) > /dev/null 2>&1

    # Copy output
    SO_FILE=$(find "$BUILD_DIR" -name "librepack_native.so" -type f | head -1)
    if [ -n "$SO_FILE" ]; then
        cp "$SO_FILE" "$OUTPUT_DIR/librepack_native.so"
        SIZE=$(du -h "$OUTPUT_DIR/librepack_native.so" | cut -f1)
        echo "  -> $OUTPUT_DIR/librepack_native.so ($SIZE)"
    else
        echo "  ERROR: librepack_native.so not found for $ABI"
        exit 1
    fi
done

echo ""
echo "=========================================="
echo "  Native build complete!"
echo "  Outputs in: $NATIVE_ASSETS_DIR/"

for ABI in "${ABIS[@]}"; do
    FILE="$NATIVE_ASSETS_DIR/$ABI/librepack_native.so"
    if [ -f "$FILE" ]; then
        echo "    $ABI: $(du -h "$FILE" | cut -f1)"
    fi
done

echo "=========================================="
