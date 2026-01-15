# Pine 与 ReSign 使用与开发说明

## 1. 这份文档覆盖什么

本文档包含两部分：

- Pine：框架能力、常用 API、在 Android 运行期的注意事项、以及在本项目中的接入方式与示例。
- ReSign：项目架构（pack-time / run-time）、实现功能介绍、如何使用、如何扩展（尤其是基于 Pine 扩展 Java Hook）。

本仓库里 Pine 项目地址：https://github.com/canyie/pine/tree/master

---

## 2. Pine 概览

### 2.1 Pine 是什么

Pine 是运行在 ART 上的动态 Java 方法 Hook 框架，可以在当前进程内拦截几乎所有 Java 方法调用，并在调用前/后修改参数、返回值、异常等。Pine 还提供了 Xposed 风格的 Hook API（仅 Java 方法 Hook，资源 Hook 等特性不在支持范围内）。

### 2.2 Pine 的关键特性（与你关心的点对应）

- Hook 粒度：Method/Constructor 级别。
- Hook 形态：
  - before/after：观察、改参、改返回值。
  - replacement：直接替换实现（例如强制返回、直接 no-op）。
- Xposed 支持：可使用 `de.robv.android.xposed.*` 风格的 API 来写 Hook 逻辑。
- 进程范围：Hook 仅对当前进程生效；如果目标应用多进程，需要保证你的 payload 在对应进程也会执行。

### 2.3 兼容性提示（框架已知约束）

（基于 Pine 项目说明）

- Android 4.4(仅 ART) ~ Android 15 Beta 4
- 支持 thumb-2/arm64 架构
- Android 9.0+ 会默认处理 hidden api 限制策略
- Android 6.0 arm32/thumb-2 可能存在参数异常的已知问题

---

## 3. ReSign 项目架构（你需要知道的整体脉络）

ReSign 将“重打包”和“运行期能力”分为两个阶段：

### 3.1 pack-time（重打包阶段）

目标：在不改业务源码的前提下，把必要的 payload 注入到目标 APK，并修改 Manifest 入口以确保 payload 能在目标应用启动时执行。

关键动作：

- 解包：提取 dex 与 AndroidManifest.xml
- 修改 Manifest：把 Application 与 AppComponentFactory 指向 payload 的入口类，并写入 meta-data 作为运行期开关
- payload dex 注入：将 `classesx.dex` 作为新的 `classesN.dex` 注入到目标 APK
- so / assets 注入：
  - 注入 `libkillsignture.so`
  - 注入 `assets/KillSig/origin.apk`（备份原始 base.apk，用于运行期路径视图一致）
- ZIP 增量写入：通过 zip4j 进行 remove+add，避免全量重压缩

入口代码主要在：

- `app/src/main/java/com/xwaaa/resig/Core.java`：重打包主流程

### 3.2 run-time（payload 运行期）

目标：在目标应用进程中执行 payload，按配置启用能力，然后把生命周期/组件创建交接给原始实现，尽量不影响业务。

入口代码主要在：

- 仓库根目录 `HookApplication.Java`：payload Application + DelegatingAppComponentFactory（会被编译为 dex 注入目标 APK）

运行期能力大致分为两类：

- Java Hook（签名一致性）：现在由 Pine 统一承载（本文档第 6 章）
- Native Hook（路径视图一致）：由 `libkillsignture.so` 实现，使用 seccomp + SIGSYS 方式对 open/readlinkat 等进行重定向

---

## 4. 这个项目实现了哪些功能

### 4.1 签名一致性（Java）

目标：当目标应用或其 SDK 通过 PackageManager / IPackageManager 查询自身签名时，返回 payload 注入的“伪签名”，从而与重打包后的签名视图保持一致。

当前实现方式：使用 Pine Hook（详见第 6 章）。

### 4.2 路径视图一致（Native）

目标：当目标应用读取自身 base.apk 或通过 `/proc/self/fd/*` 反查路径时，视图一致地指向“原始 APK（origin.apk）”或预期路径，减少路径类检测。

当前实现方式：seccomp + SIGSYS 拦截路径相关 syscall，并按规则重定向。

### 4.3 入口交接（稳定性）

目标：即便替换了 Manifest 入口，也尽量把 Application 生命周期与组件创建交还给原始实现，避免业务逻辑断链。

实现方式：

- Application 委托：payload Application 内部保存并转发到原 Application
- AppComponentFactory 委托：尽量调用原 factory 创建 Activity/Service/Receiver/Provider

---

## 5. 如何使用 ReSign（面向使用者）

### 5.1 构建与运行

- 打开 Android Studio，构建 `app` 模块并安装到设备
- 在 UI 中选择目标应用并点击“重打包”

### 5.2 常用开关（运行期由 meta-data 下发）

meta-data 键（在 Manifest 中写入）：

- `resig.enableJavaHook`：是否启用 Java Hook（签名一致性）
- `resig.enableNativeHook`：是否启用 Native Hook
- `resig.enableIoRedirect`：是否启用 IO 重定向（native 子能力）
- `resig.enableResourceRedirect`：是否启用资源重定向（实验）
- `resig.debugLog`：是否输出调试日志

---

## 6. 本项目里 Pine 是如何使用的（签名一致性重写方案）

### 6.1 目标与设计策略

目标：让“签名一致性”的核心逻辑尽可能集中在 Java 方法 Hook 上，减少对 Binder/Parcel 代理链路的侵入与维护成本。

策略：

- 以 Pine（Xposed 风格 Hook）为主，在关键返回点统一 patch `PackageInfo` / `SigningInfo`
- 覆盖典型查询路径：
  - `PackageManager` 侧的 `getPackageInfo/getInstalledPackages/getPackageArchiveInfo`
  - `IPackageManager` 的 Stub Proxy（如果在当前系统中可见）
  - `PackageInfo.CREATOR` / `SigningInfo.CREATOR` 的 `createFromParcel`（兜底：无论结果从何处来，只要进程里反序列化出对象就 patch）

### 6.2 Hook 安装入口

Hook 安装发生在 payload 的初始化流程中：

- `HookApplication.initSignatureHookInternal(...)` 会根据 meta-data 判断是否启用 Java Hook
- 启用后调用 `killPM(...)`，由它触发 `installPineSignatureHooksIfPossible(...)` 安装 Pine Hook

对应实现文件：

- `HookApplication.Java`

### 6.3 Hook 点清单（当前实现）

以下 hook 会在当前进程生效：

1) `android.content.pm.PackageInfo.CREATOR.createFromParcel(Parcel)`

- afterHook：若返回的 `PackageInfo.packageName == targetPkg`，则 patch `signatures` 与 `signingInfo` 内可见的签名字段

2) `android.content.pm.SigningInfo.CREATOR.createFromParcel(Parcel)`（Android 9+）

- afterHook：对创建出的 `SigningInfo` 进行 patch，确保其内部的 signer 相关字段与 fakeSig 一致

3) `android.app.ApplicationPackageManager` 的典型 API

- `getPackageInfo(String, int)`
- `getPackageInfoAsUser(String, int, int)`
- `getPackageArchiveInfo(String, int)`
- Android 13+ 还会尝试 hook：
  - `getPackageInfo(String, PackageInfoFlags)`
  - `getPackageInfoAsUser(String, PackageInfoFlags, int)`
  - `getPackageArchiveInfo(String, PackageInfoFlags)`
- `getInstalledPackages(int)` 与 `getInstalledPackages(PackageInfoFlags)`：afterHook 遍历并 patch 返回列表中的目标包名条目

4) `android.content.pm.IPackageManager$Stub$Proxy`（如果存在）

- 按方法名扫描并 hook 返回 `PackageInfo` 的方法，如 `getPackageInfo/getPackageInfoAsUser/getPackageInfoVersioned`
- 按方法名扫描并 hook 返回包列表的方法，如 `getInstalledPackages`

说明：不同 Android 版本 / ROM 的方法签名可能不同，所以实现采用“存在则 hook”的策略，不存在不会中断启动。

---

## 7. Pine 在本项目中的“正确打包方式”（非常关键）

### 7.1 为什么不能只加 Gradle implementation

本项目的 payload dex（`classesx.dex`）不是由 Android Gradle 插件直接打进应用的 classpath，而是通过根目录脚本 `build.sh` 用 `javac + d8` 单独产出。

因此必须确保 Pine 的 classes 最终进入 `classesx.dex`，否则目标应用运行期会出现找不到 Pine/Xposed 类的问题。

### 7.2 当前实现：preparePayloadDeps + build.sh 自动合并

实现流程：

1) `:app:preparePayloadDeps`

- 解析 AAR 依赖（Pine core / xposed / enhances）
- 抽取每个 AAR 的 `classes.jar`
- 输出到：`app/build/payload-deps/*.jar`

2) `build.sh`

- 编译 `HookApplication.Java`
- d8 时把 `hook.jar` + `app/build/payload-deps/*.jar` 一起作为输入
- 输出 dex 同步到：`app/src/main/assets/classesx.dex`

---

## 8. 如何基于 Pine 扩展更多 Hook（面向开发者）

### 8.1 推荐写法：集中在 payload 初始化路径

建议把 Hook 安装集中在：

- `HookApplication.initSignatureHookInternal(...)` 的 Java Hook 分支

原因：

- 入口足够早（更容易覆盖到目标应用早期的调用）
- 运行期开关统一由 meta-data 控制

### 8.2 Hook 的工程化建议

- Hook 失败要容错：目标系统的类/方法不存在时直接跳过
- Hook 逻辑尽量轻：不要在 afterHook 里做重 IO 或复杂反射
- 只 patch 目标包名：避免误伤系统/其他包导致副作用

---

## 9. 常见问题与排查

### 9.1 build.sh 能编译，但 assembleDebug 报 JDK 版本异常

如果默认 JDK 过新（例如 25.x），Gradle/Kotlin 可能直接报错。建议使用 Android Studio 自带 JBR（17~21）。

### 9.2 Kotlin daemon 连接失败 / tmp 文件权限问题

这类问题通常与系统权限/沙盒有关，Gradle 会自动 fallback 到非 daemon 编译模式，但构建依然能完成。

### 9.3 Hook 没生效

排查顺序建议：

- 确认 meta-data 里 `resig.enableJavaHook=true`
- 确认 payload dex 已更新：重新运行 `./build.sh` 并重新重打包目标 APK
- 打开 `resig.debugLog=true` 观察日志里 Pine hook 的安装结果
- 目标应用是否多进程：如果检查发生在非主进程，确保 payload 在该进程也会执行

---

## 10. 参考入口（源码导航）

- payload：`HookApplication.Java`
- pack-time：`app/src/main/java/com/xwaaa/resig/Core.java`
- native：`app/src/main/cpp/killsignture.cpp`
- build：`build.sh` + `:app:preparePayloadDeps`
