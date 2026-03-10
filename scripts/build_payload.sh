#!/bin/bash
#
# ReSignPro - Payload 构建脚本
#
# 将 payload 相关的 Java 文件编译为 DEX，打包到 assets 中
# 供 PackEngine 在重打包时注入到目标 APK
#
# 用法: ./scripts/build_payload.sh [debug|release]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_TYPE="${1:-release}"

echo "=========================================="
echo "  ReSignPro Payload Builder"
echo "  Build type: $BUILD_TYPE"
echo "=========================================="

# 目录定义
PAYLOAD_SRC_DIR="$PROJECT_DIR/payload"
PAYLOAD_BUILD_DIR="$PROJECT_DIR/build/payload"
PAYLOAD_CLASSES_DIR="$PAYLOAD_BUILD_DIR/classes"
PAYLOAD_OUTPUT_DIR="$PROJECT_DIR/app/src/main/assets/payload"

# 清理
rm -rf "$PAYLOAD_BUILD_DIR"
mkdir -p "$PAYLOAD_CLASSES_DIR"
mkdir -p "$PAYLOAD_OUTPUT_DIR"

# 检查必要工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 not found. Please ensure Android SDK/Build Tools are in PATH."
        exit 1
    fi
}

# 查找 Android SDK 路径
if [ -z "$ANDROID_HOME" ]; then
    if [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    else
        echo "ERROR: ANDROID_HOME not set and SDK not found in default locations."
        exit 1
    fi
fi

echo "[1/4] Finding build tools..."

# 查找最新的 build-tools
BUILD_TOOLS_DIR=$(ls -d "$ANDROID_HOME/build-tools/"* 2>/dev/null | sort -V | tail -1)
if [ -z "$BUILD_TOOLS_DIR" ]; then
    echo "ERROR: No build-tools found in $ANDROID_HOME/build-tools/"
    exit 1
fi
echo "  Build tools: $BUILD_TOOLS_DIR"

D8="$BUILD_TOOLS_DIR/d8"
AAPT2="$BUILD_TOOLS_DIR/aapt2"

# 查找 android.jar
PLATFORM_DIR=$(ls -d "$ANDROID_HOME/platforms/android-"* 2>/dev/null | sort -V | tail -1)
ANDROID_JAR="$PLATFORM_DIR/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
    echo "ERROR: android.jar not found"
    exit 1
fi
echo "  Android JAR: $ANDROID_JAR"

# 查找 Pine 依赖 JAR（从 Gradle 缓存或本地 libs 目录）
PINE_JAR=""
PINE_XPOSED_JAR=""
LIBS_DIR="$PROJECT_DIR/app/libs"
if [ -d "$LIBS_DIR" ]; then
    PINE_JAR=$(find "$LIBS_DIR" -name "pine-core-*.jar" -o -name "pine*.jar" 2>/dev/null | head -1)
    PINE_XPOSED_JAR=$(find "$LIBS_DIR" -name "pine-xposed*.jar" 2>/dev/null | head -1)
fi

CLASSPATH="$ANDROID_JAR"
if [ -n "$PINE_JAR" ]; then
    CLASSPATH="$CLASSPATH:$PINE_JAR"
    echo "  Pine JAR: $PINE_JAR"
fi
if [ -n "$PINE_XPOSED_JAR" ]; then
    CLASSPATH="$CLASSPATH:$PINE_XPOSED_JAR"
fi

echo ""
echo "[2/4] Compiling payload Java sources..."

# 收集所有 payload Java 文件
JAVA_FILES=$(find "$PAYLOAD_SRC_DIR" -name "*.java" -type f)
JAVA_COUNT=$(echo "$JAVA_FILES" | wc -l)
echo "  Found $JAVA_COUNT Java file(s)"

# 编译
javac \
    -source 11 -target 11 \
    -cp "$CLASSPATH" \
    -d "$PAYLOAD_CLASSES_DIR" \
    -Xlint:none \
    $JAVA_FILES

echo "  Compilation successful"

echo ""
echo "[3/4] Converting to DEX..."

# 使用 d8 将 class 文件转换为 DEX
CLASS_FILES=$(find "$PAYLOAD_CLASSES_DIR" -name "*.class" -type f)

"$D8" \
    --min-api 21 \
    --output "$PAYLOAD_BUILD_DIR" \
    $CLASS_FILES

# 重命名为 payload.dex
mv "$PAYLOAD_BUILD_DIR/classes.dex" "$PAYLOAD_OUTPUT_DIR/payload.dex"

echo "  DEX created: $PAYLOAD_OUTPUT_DIR/payload.dex"
echo "  Size: $(du -h "$PAYLOAD_OUTPUT_DIR/payload.dex" | cut -f1)"

echo ""
echo "[4/4] Verifying..."

# 基本验证
if [ ! -f "$PAYLOAD_OUTPUT_DIR/payload.dex" ]; then
    echo "ERROR: payload.dex not created!"
    exit 1
fi

# 检查 DEX magic
MAGIC=$(xxd -l 4 -p "$PAYLOAD_OUTPUT_DIR/payload.dex")
if [ "$MAGIC" != "6465780a" ]; then
    echo "ERROR: Invalid DEX magic: $MAGIC"
    exit 1
fi

echo "  DEX verification passed"
echo ""
echo "=========================================="
echo "  Payload build complete!"
echo "  Output: $PAYLOAD_OUTPUT_DIR/payload.dex"
echo "=========================================="
