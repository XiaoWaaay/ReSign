# 2026-01-13 Java Hook 覆盖排查与签名修复记录

## 目标

- 增加 Java 层关键路径日志，定位“后续流程覆盖/未生效”的具体位置
- 修正并验证“签名获取与 HookApplication 注入写入”链路
- 保持原有功能行为不变（PM 重定向、Binder 代理、SVC 能力默认启用）

## 变更概览

### HookApplication（payload 运行期）

- 增加 debugLog 开关：通过 Manifest meta-data `resig.debugLog` 控制（默认开启）
- 在 initSignatureHook / killPM / installPmBinderProxyIfPossible / PmBinderProxy.transact 关键位置输出参数、状态与结果
- 在 attachBaseContext 与 onCreate 额外触发 initSignatureHook（由原有 AtomicBoolean 去重），降低“时机过早导致缓存/代理未补齐”的概率

相关文件：

- HookApplication.Java

### 重打包侧（ReSign App）

- 在重打包时输出：
  - 修改后的 Manifest 入口类是否写入成功（application / appComponentFactory）
  - 读取到的签名 byte 长度、base64 长度与 sha256
  - payload dex 生成路径与大小

相关文件：

- app/src/main/java/com/xwaaa/resig/Core.java

### Native（Dobby 依赖问题修复）

- killsignture 不再链接到 dobby target，避免 DT_NEEDED 导致“未选 Dobby 也要求 libdobby.so”而崩溃

相关文件：

- app/src/main/cpp/CMakeLists.txt

## 验证清单

- 重新生成 payload dex：
  - `bash build.sh`（同步到 app/src/main/assets/classesx.dex）
- 重新构建并安装 ReSign：
  - `./gradlew :app:assembleDebug`
  - `adb install -r app/build/outputs/apk/debug/app-debug.apk`
- 重新重打包并安装目标 app 后，用 logcat 关注：
  - `initSignatureHook enter/done`
  - `killPM enter/done`
  - `installPmBinderProxyIfPossible patched ...`
  - `PmBinderProxy.transact getPackageInfo / checkSignatures / hasSigningCertificate`
  - `PmBinderProxy patched PackageInfo for <pkg>`

