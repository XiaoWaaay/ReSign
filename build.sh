#!/usr/bin/env bash
set -euo pipefail

CURDIR="$(cd "$(dirname "$0")" && pwd)"
JAVA_FILE="HookApplication.Java"
OUT_DIR="$CURDIR/out"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
PLATFORM_JAR=""

if [ -n "$SDK" ] && [ -d "$SDK/platforms" ]; then
  while IFS= read -r plat; do
    if [ -f "$SDK/platforms/$plat/android.jar" ]; then
      PLATFORM_JAR="$SDK/platforms/$plat/android.jar"
      break
    fi
  done < <(ls -1 "$SDK/platforms" | sort -t- -k2,2nr)
fi

D8=""
if [ -d "$SDK/build-tools" ]; then
  while IFS= read -r ver; do
    if [ -f "$SDK/build-tools/$ver/d8" ]; then
      D8="$SDK/build-tools/$ver/d8"
      break
    fi
  done < <(ls -1 "$SDK/build-tools" | sort -r)
fi

if [ -z "$SDK" ]; then
  echo "[错误] 未设置 ANDROID_SDK_ROOT 或 ANDROID_HOME"
  exit 1
fi

if [ -z "$D8" ]; then
  echo "[错误] 未找到 d8，請檢查 Android SDK 是否安装。"
  exit 1
fi

if [ ! -f "$PLATFORM_JAR" ]; then
  echo "[错误] 未找到 $PLATFORM_JAR"
  echo "请修改此脚本中的 PLATFORM_JAR 对应 API 版本"
  exit 1
fi

echo "当前目录: $CURDIR"
echo "使用 android.jar: $PLATFORM_JAR"
echo "使用 d8: $D8"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/classes"
mkdir -p "$OUT_DIR/dex"

echo "编译 Java 源码中..."
set +e
JAVA_SRC="$OUT_DIR/HookApplication.java"
cp "$CURDIR/$JAVA_FILE" "$JAVA_SRC"

javac -encoding UTF-8 -source 1.8 -target 1.8 -bootclasspath "$PLATFORM_JAR" -classpath "$PLATFORM_JAR" -d "$OUT_DIR/classes" "$JAVA_SRC"
JAVAC_EXIT=$?
set -e
if [ $JAVAC_EXIT -ne 0 ]; then
  echo "[错误] 编译失败！"
  exit 1
fi

echo "打包为 JAR..."
jar cf "$OUT_DIR/hook.jar" -C "$OUT_DIR/classes" .

echo "转换为 DEX..."
"$D8" --min-api 21 --output "$OUT_DIR/dex" --lib "$PLATFORM_JAR" "$OUT_DIR/hook.jar"

if [ -f "$OUT_DIR/dex/classes.dex" ]; then
  echo
  echo "✅ 编译成功！"
  echo "输出文件: $OUT_DIR/dex/classes.dex"
else
  echo "❌ 未生成 classes.dex，请检查输出。"
  exit 1
fi
