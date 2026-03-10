#!/bin/bash
#
# ReSignPro - 完整构建脚本
#
# 按顺序执行：
# 1. 构建 payload DEX
# 2. 构建 native SO（所有 ABI）
# 3. 构建 Android APK（Gradle）
#
# 用法: ./build.sh [debug|release]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TYPE="${1:-release}"

echo "============================================================"
echo "  ReSignPro Full Build"
echo "  Type: $BUILD_TYPE"
echo "  Time: $(date)"
echo "============================================================"
echo ""

# Step 1: Build Payload DEX
echo ">>> Step 1/3: Building Payload DEX..."
echo ""
bash "$SCRIPT_DIR/scripts/build_payload.sh" "$BUILD_TYPE"
echo ""

# Step 2: Build Native Libraries
echo ">>> Step 2/3: Building Native Libraries..."
echo ""
bash "$SCRIPT_DIR/scripts/build_native.sh" "$BUILD_TYPE"
echo ""

# Step 3: Build APK via Gradle
echo ">>> Step 3/3: Building APK via Gradle..."
echo ""

if [ "$BUILD_TYPE" = "debug" ]; then
    GRADLE_TASK="assembleDebug"
else
    GRADLE_TASK="assembleRelease"
fi

if [ -f "$SCRIPT_DIR/gradlew" ]; then
    chmod +x "$SCRIPT_DIR/gradlew"
    "$SCRIPT_DIR/gradlew" "$GRADLE_TASK" --no-daemon
else
    echo "WARNING: gradlew not found, trying system gradle..."
    gradle "$GRADLE_TASK" --no-daemon
fi

echo ""
echo "============================================================"
echo "  Build Complete!"
echo ""

# 查找输出 APK
APK_PATH=""
if [ "$BUILD_TYPE" = "debug" ]; then
    APK_PATH=$(find "$SCRIPT_DIR/app/build/outputs/apk/debug" -name "*.apk" 2>/dev/null | head -1)
else
    APK_PATH=$(find "$SCRIPT_DIR/app/build/outputs/apk/release" -name "*.apk" 2>/dev/null | head -1)
fi

if [ -n "$APK_PATH" ]; then
    echo "  APK: $APK_PATH"
    echo "  Size: $(du -h "$APK_PATH" | cut -f1)"
else
    echo "  APK output not found (check Gradle output above)"
fi

echo ""
echo "============================================================"
