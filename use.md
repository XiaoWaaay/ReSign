# ReSign 使用文档

## 1. 环境搭建

### 1.1 必备软件

- Android Studio（推荐用其内置 JBR 作为 JAVA_HOME）
- Android SDK（至少包含 build-tools、platforms）
- ADB（Android SDK platform-tools）

### 1.2 环境变量（macOS 示例）

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
export ANDROID_SDK_ROOT="/Users/bytedance/Library/Android/sdk"
```

如果你使用 Homebrew 的 JDK，可能出现 Gradle/Kotlin 对过新 Java 版本不兼容的问题；优先使用 Android Studio 自带的 JBR 可以规避。

## 2. 构建与安装

### 2.1 构建 Debug 包

```bash
./gradlew :app:assembleDebug :app:lintDebug
```

（可选）跑单测/仪器测试：

```bash
./gradlew :app:testDebugUnitTest :app:connectedDebugAndroidTest
```

### 2.2 安装到手机

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## 3. 产物准备（payload dex / so）

### 3.1 更新注入用 dex（HookApplication.Java -> assets/classesx.dex）

```bash
bash build.sh
```

该脚本会编译仓库根目录的 HookApplication.Java，并把输出同步到 app/src/main/assets/classesx.dex。

### 3.2（可选）编译并同步 libdobby.so（-> assets/libdobby.so）

如果你需要 Dobby 后端（nativeBackend=auto/dobby），需要准备 libdobby.so：

```bash
ANDROID_SDK_ROOT=/path/to/sdk ANDROID_NDK_ROOT=/path/to/ndk scripts/build_dobby_android.sh
```

## 4. 功能操作指南

### 4.1 选择模式

在 App 首页顶部 Tabs 选择：

- 普通模式：输出重打包后的 APK（自用/调试）
- 爱加密模式（AIJIAMI）：输出“用于送加固”的 base 产物以及相关中间文件

### 4.2 AIJIAMI 模式参数

- 加固前 Application（可选）：填写“加固前真实 Application 全类名”
  - 不填：默认从原 Manifest 读取并写入委托链

### 4.3 功能选项（可切换）

重打包前可以在页面里配置：

- 启用 Java Hook：主要用于 Java 层签名/PM 相关逻辑一致性
- 启用 Native Hook：主要用于底层 IO/SVC 重定向
- 启用 IO/SVC 重定向：是否启用 open/readlink 等路径视图重定向
- 启用资源重定向（实验）：向 AssetManager 追加资源路径，默认关闭
- Native 后端（auto/dobby/seccomp/off）：
  - auto：优先 Dobby，失败自动回退到 seccomp
  - dobby：只允许 Dobby（加载失败即不启用 native 重定向）
  - seccomp：强制走 seccomp + SIGSYS（不加载 dobby）
  - off：关闭 native 重定向
- 启用解包缓存：复用 “dex/manifest 解包结果”，减少重复解包耗时
- 启用 payload dex 缓存：复用“已写入占位符的 classesx.dex”，减少 baksmali/smali 耗时

## 5. 输出文件说明

### 5.1 普通模式

输出文件位于 App 私有目录与/或下载目录（以实际日志与 UI 提示为准），主要包含：

- 重打包后的 base.apk（已注入 dex、Manifest 入口、必要 so/assets）

### 5.2 AIJIAMI 模式

导出目录形如：

`Android/data/<your.resig.package>/files/Download/resign_export/<pkg>/<runId>/`

包含：

- `<pkg>_packed_base.apk`：原始 base 备份
- `<pkg>_aijiami_repacked_base.apk`：已注入 dex/so/assets，并替换 Manifest 入口类的 base 产物
- `splits/`：split APK 备份（如目标应用存在 splits）

## 6. 常见问题（FAQ）

### 6.1 构建时报 Kotlin daemon “Operation not permitted”

这是本机环境对 Kotlin daemon 临时文件目录的权限限制导致。当前构建会自动回退到 “Compile without Kotlin daemon”，不影响产物生成。

### 6.2 为什么改成“只改 Manifest 入口”而不改目标 dex？

目标 dex 反编译/回编译会引入兼容性与稳定性风险（DEX 格式、壳延迟加载、混淆差异等）。替换 Manifest 入口（Application + AppComponentFactory）更稳定，并能通过委托链把生命周期与组件创建正确交接给原始实现。

### 6.3 资源重定向为什么默认是“实验”

不同 Android 版本/ROM 对 AssetManager/Resources 的内部实现差异较大。该能力默认关闭，仅在明确验证通过的目标范围内启用。
