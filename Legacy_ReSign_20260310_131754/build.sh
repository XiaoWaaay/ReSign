#!/usr/bin/env bash
set -euo pipefail

CURDIR="$(cd "$(dirname "$0")" && pwd)"
JAVA_FILE="HookApplication.Java"
OUT_DIR="$CURDIR/out"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
PLATFORM_JAR=""

if [ -z "$SDK" ] && [ -f "$CURDIR/local.properties" ]; then
  SDK="$(sed -n 's/^sdk.dir=//p' "$CURDIR/local.properties" | tail -n 1)"
fi

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

DEPS_DIR="$CURDIR/app/build/payload-deps"
EXTRA_CP=""
EXTRA_D8_INPUTS=()

if [ ! -d "$DEPS_DIR" ] || ! ls "$DEPS_DIR"/*.jar >/dev/null 2>&1; then
  if [ -f "$CURDIR/gradlew" ]; then
    JAVA_MAJOR=""
    if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME:-}/bin/java" ]; then
      JAVA_MAJOR="$("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1 | sed -n 's/.*version \"\\([0-9][0-9]*\\)\\..*/\\1/p')"
      if [ -z "$JAVA_MAJOR" ]; then
        JAVA_MAJOR="$("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1 | sed -n 's/.*version \"1\\.\\([0-9][0-9]*\\)\\..*/\\1/p')"
      fi
    fi

    if [ -z "${JAVA_HOME:-}" ] || [ -z "$JAVA_MAJOR" ] || [ "$JAVA_MAJOR" -lt 17 ] || [ "$JAVA_MAJOR" -gt 21 ]; then
      CAND="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
      if [ -d "$CAND" ]; then
        export JAVA_HOME="$CAND"
        export PATH="$JAVA_HOME/bin:$PATH"
      fi
    fi

    "$CURDIR/gradlew" :app:preparePayloadDeps
  fi
fi

if [ -d "$DEPS_DIR" ] && ls "$DEPS_DIR"/*.jar >/dev/null 2>&1; then
  for j in "$DEPS_DIR"/*.jar; do
    EXTRA_CP="${EXTRA_CP:+$EXTRA_CP:}$j"
    EXTRA_D8_INPUTS+=("$j")
  done
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/classes"
mkdir -p "$OUT_DIR/dex"

echo "编译 Java 源码中..."
set +e
JAVA_SRC="$OUT_DIR/HookApplication.java"
cp "$CURDIR/$JAVA_FILE" "$JAVA_SRC"

CP="$PLATFORM_JAR"
if [ -n "$EXTRA_CP" ]; then
  CP="$PLATFORM_JAR:$EXTRA_CP"
fi

javac -encoding UTF-8 -source 1.8 -target 1.8 -bootclasspath "$PLATFORM_JAR" -classpath "$CP" -d "$OUT_DIR/classes" "$JAVA_SRC"
JAVAC_EXIT=$?
set -e
if [ $JAVAC_EXIT -ne 0 ]; then
  echo "[错误] 编译失败！"
  exit 1
fi

echo "打包为 JAR..."
jar cf "$OUT_DIR/hook.jar" -C "$OUT_DIR/classes" .

echo "转换为 DEX..."
"$D8" --min-api 21 --output "$OUT_DIR/dex" --lib "$PLATFORM_JAR" "$OUT_DIR/hook.jar" "${EXTRA_D8_INPUTS[@]}"

if [ -f "$OUT_DIR/dex/classes.dex" ]; then
  echo
  echo "✅ 编译成功！"
  echo "输出文件: $OUT_DIR/dex/classes.dex"

  ASSET_DIR="$CURDIR/app/src/main/assets"
  if [ -d "$ASSET_DIR" ]; then
    cp -f "$OUT_DIR/dex/classes.dex" "$ASSET_DIR/classesx.dex"
    echo "已同步到 assets: $ASSET_DIR/classesx.dex"
  fi
else
  echo "❌ 未生成 classes.dex，请检查输出。"
  exit 1
fi
