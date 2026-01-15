# ReSign 项目说明文档

## 1. 项目背景

ReSign 是一个 Android 侧的“重打包与运行期一致性修复”工具，用于在不改业务源码的前提下，对目标 APK 做可配置的注入与调整，并在运行期通过可选的 Java/Native 框架实现一致性能力（例如签名相关信息一致、路径视图一致等）。

本项目将“重打包（pack-time）”与“运行期初始化（run-time）”拆分为两个层面：

- pack-time：把 payload dex / so / assets 注入到目标 APK，并修改 Manifest 入口与 meta-data 配置
- run-time：由 payload 入口类读取配置，按策略初始化 Java/Native 能力，并把生命周期与组件创建交接给原始实现

## 2. 设计目标

- 稳定性优先：避免对目标 dex 做反编译/插桩，优先通过 Manifest 入口类替换完成注入
- 可配置、可回退：Java hook / Native hook / IO 重定向 / 资源重定向均可选择开关与后端
- 性能可控：重打包流程引入缓存复用，减少重复解包与 payload dex 重写的开销
- 可维护：模块边界清晰，关键路径有注释与文档，便于交接

## 3. 架构设计（高层）

### 3.1 pack-time（重打包侧）

入口主要在 [Core.java](file:///Users/bytedance/Desktop/GithubProject/ReSign/app/src/main/java/com/xwaaa/resig/Core.java)：

- 输入解析：读取目标应用的 base.apk 路径与 splits 列表
- 解包阶段：提取 dex 与 AndroidManifest.xml，并支持缓存复用
- Manifest 修改：写入新的入口类（Application + AppComponentFactory）与 meta-data 配置
- payload dex 注入：把 classesx.dex 写入占位符（包名/签名/原始入口类信息），并作为新的 classesN.dex 加入 APK
- so / assets 注入：写入 libkillsignture.so 与 assets/KillSig/origin.apk 等
- ZIP 更新：使用 zip4j 做增量写入（remove + add），避免全量重压缩

### 3.2 run-time（payload 运行期）

入口主要在仓库根目录的 [HookApplication.Java](file:///Users/bytedance/Desktop/GithubProject/ReSign/HookApplication.Java)（会被编译为 payload dex）：

- 读取 meta-data 配置（resig.*），决定是否启用 Java/Native/IO/资源能力
- 初始化顺序：
  - Java Hook：PackageManager / 签名信息一致性
  - Native Hook：open/readlink 重定向（seccomp + SIGSYS）+ maps 过滤（best-effort）
- 交接机制：
  - Application 委托：把 attachBaseContext/onCreate 转发到原 Application
  - AppComponentFactory 委托：把 Activity/Service/Receiver/Provider 的创建尽量转发给原 factory，保持组件创建链路稳定

Native 侧能力位于 [killsignture.cpp](file:///Users/bytedance/Desktop/GithubProject/ReSign/app/src/main/cpp/killsignture.cpp)。
payload 会把 `assets/KillSig/origin.apk` 原子落盘到 `files/origin.apk`，避免半写入导致循环崩溃。

## 4. 技术选型

- UI：Jetpack Compose（配置模式与功能开关、触发重打包）
- APK/Manifest 修改：wind-meditor（在 Android 环境修改二进制 AXML）
- ZIP 增量更新：zip4j（remove + add，默认 STORE）
- payload dex 生成：d8（见 build.sh）
- Java hook：Pine
- Native hook：seccomp + SIGSYS

## 5. 模块划分

- app/src/main/java/com/xwaaa/resig/Core.java：重打包主流程 + 缓存复用
- app/src/main/java/com/xwaaa/resig/Inject.kt：Manifest 修改与 payload dex 占位符写入
- app/src/main/java/com/xwaaa/resig/FileUtils.kt：文件拷贝、解包、zip 增量更新
- HookApplication.Java：payload 入口、运行期配置、能力编排与交接
- app/src/main/cpp/killsignture.cpp：Native 重定向后端实现
- app/src/main/java/com/xwaaa/resig/MainActivity.kt：UI（模式选择、功能开关、触发重打包）

## 6. 使用方式（面向使用者）

### 6.1 构建与安装 ReSign App

- Android Studio：直接构建并安装 `app` 模块
- 命令行：仓库根目录执行 `bash build_project --debug`（输出 apk 路径会打印）
- Lint：`bash build_project --debug --lint`（需要 JDK 17~21；若系统默认是 JDK 25+，请先切换 JAVA_HOME）

### 6.2 重打包产物位置

重打包完成后，产物会输出到应用专属目录（适配 Android 11+ 的存储模型）：

- `${getExternalFilesDir(DIRECTORY_DOWNLOADS)}/resign_export/<包名>/<runId>/`
  - `<包名>_repacked_base.apk`
  - `splits/`（如目标应用有 split APK，会一并导出到该目录）

### 6.3 重要说明（签名与 split）

- 本项目会修改 zip 内容（dex/manifest/so/assets），会破坏原 APK 签名；输出的 base.apk 默认不做签名闭环，需要你在后续流程中自行签名（或通过外部工具安装）。
- 对 split APK 应用：当前输出为 “base + splits 目录”的交付形态；如需“一键可安装”，建议后续接入 PackageInstaller session 或打包为 .apks。

## 7. 运行期配置（meta-data）

pack-time 会写入 meta-data，run-time payload 会读取并决定是否启用能力：

- `resig.enableJavaHook`：是否启用 Java Hook（签名一致性）
- `resig.enableNativeHook`：是否启用 Native Hook（seccomp + SIGSYS）
- `resig.enableIoRedirect`：是否启用 IO 重定向（base.apk → origin.apk）
- `resig.enableMapsHide`：是否启用 maps 过滤与痕迹隐藏（实验）
- `resig.enableResourceRedirect`：是否启用资源重定向（实验）
- `resig.debugLog`：是否启用 payload 调试日志

## 8. 开发流程与质量保障

- 本地构建：优先使用 Android Studio 的 JBR（见 use.md）
- 变更策略：
  - 先保持入口链路稳定（Manifest 入口替换 + 交接）
  - 再扩展能力（Java/Native/资源重定向）并保证可降级
  - 再做性能优化（缓存复用）
- 验证：
  - assembleDebug + lintDebug
  - 真机回归：多 Android 版本 + 多 ROM（建议形成固定回归矩阵）

## 9. 版本控制策略（建议）

- 分支：
  - main：稳定分支，仅合入已回归的功能
  - develop：日常开发集成分支
  - feature/*：功能开发分支
  - hotfix/*：线上修复分支
- 版本号：
  - 建议遵循语义化版本（SemVer）：MAJOR.MINOR.PATCH
  - 每次发布记录变更点与兼容性影响

## 10. 未来扩展方向

- 更细粒度的配置下发：按进程/按组件类型启用能力（减少非主进程风险）
- 资源重定向增强：在可控的 Android 版本范围内实现更完整的 Resources 重建与回退
- 重打包性能进一步优化：更彻底的增量处理与更精细的缓存键
- 自动化回归：接入设备农场/云真机，自动跑启动与基础功能用例

## 11. 安全与合规说明

本项目定位为工程化的重打包与一致性修复工具。仓库当前包含对 `/proc/<pid>/maps` 的 best-effort 过滤（用于降低注入库字符串暴露风险），建议仅在测试/研究环境使用，并在目标环境评估合规与风险。
