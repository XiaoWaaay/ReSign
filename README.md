# ReSignPro

一个高兼容性的 Android APK 重打包签名工具，参考 LSPatch、MT Manager、NP Manager 等工具的技术方案，实现全面的签名绕过能力。

## 架构

三层架构设计：

### Layer 1: Pack-Time Engine（打包时引擎）
- `PackEngine` - 重打包流程编排（10步流水线）
- `ApkParser` - APK 深度解析（Manifest/DEX/ABI/签名块）
- `ApkSigner` - V1 签名实现（MANIFEST.MF/SF/RSA）
- `ApkSigningBlock` - V2/V3 签名块解析/保留/伪造
- `DexInjector` - DEX 占位符替换注入（dexlib2 DexRewriter）
- `ManifestEditor` - AXML 二进制编辑器
- `SoInjector` - 多 ABI SO 注入
- `SplitApkHandler` - Split APK 处理

### Layer 2: Runtime Signature Engine（运行时签名引擎）
- `HookEntry` - Payload 入口（Pine 框架 Java Hook）
  - SAFE/STANDARD/AGGRESSIVE 三级 Hook 模式
  - PackageManager/Parcelable CREATOR/SigningInfo/Binder IPC 全链路 Hook
  - Application 代理 + Deep Hide + AppComponentFactory 代理
  - 自动降级机制
- `NativeBridge` - JNI 桥接层

### Layer 3: Anti-Detection Engine（反检测引擎）
- **Native C++ 引擎**:
  - `io_redirect` - IO 重定向（openat/fstatat/faccessat/readlinkat/statx）
  - `plt_hook` - ELF GOT/PLT Hook 引擎
  - `maps_hide` - /proc/self/maps 内容过滤（memfd_create）
  - `seccomp_filter` - seccomp + BPF + SIGSYS 系统调用拦截
  - 四架构支持: aarch64, arm, x86_64, i386
  - 三后端模式: PLT Hook / Seccomp / Hybrid
- **Java 反检测**:
  - `AntiDetection` - 安装器伪装/调试标志隐藏/框架痕迹清除/Build字段伪装
  - `TraceHider` - 文件系统/ClassLoader/环境变量/Native 层痕迹隐藏

## 相比原版 ReSign 的改进

| 能力 | 原版 ReSign | ReSignPro |
|------|------------|-----------|
| 签名方案 | 仅 V1 | V1 + V2/V3 签名块保留/伪造 |
| Hook 层级 | 单一模式 | SAFE/STANDARD/AGGRESSIVE 三级 |
| Native 后端 | 仅 seccomp | PLT Hook + Seccomp + Hybrid |
| IO 重定向 | 部分 syscall | openat/fstatat/faccessat/readlinkat/statx/openat2 |
| Maps 隐藏 | 简单过滤 | memfd_create + 动态过滤 + 字符串替换 |
| Split APK | 不支持 | 完整支持 (ABI/Locale/Density/Feature) |
| 架构支持 | arm64 + arm | arm64 + arm + x86_64 + x86 |
| Application 代理 | 基本 | Deep Hide + AppComponentFactory |
| API 兼容 | ≤ Android 13 | Android 5.0 ~ 15 (API 21-35) |
| ContentProvider | 时序问题 | attachBaseContext 中完成 Hook |
| IPC 检测 | 不处理 | Binder 动态代理拦截 |
| 自动降级 | 无 | 异常时自动从 AGGRESSIVE→STANDARD→SAFE |

## 构建

```bash
# 完整构建
./build.sh release

# 仅构建 Payload DEX
./scripts/build_payload.sh

# 仅构建 Native SO
./scripts/build_native.sh

# Gradle 构建
./gradlew assembleRelease
```

## 依赖

- Pine Hook Framework (top.canyie.pine)
- dexlib2 / smali (com.android.tools.smali)
- zip4j (net.lingala.zip4j)
- Jetpack Compose (Material 3)

## 最低要求

- Android 5.0+ (API 21)
- Target SDK: 34
- NDK: r25+
- Gradle: 8.2+
- AGP: 8.2.2+

## License

仅供学习研究使用。
