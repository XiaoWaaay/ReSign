# ReSign V3 — 三层递进式签名绕过

## V2 为什么失败了？

### 根本原因

V2 的 PLT Hook 方案从原理上就无法拦截签名校验，因为签名数据**不走文件 IO**：

```
App 获取签名的真实路径:
native-lib.cpp JNI_OnLoad
  → ActivityThread.currentApplication()     // 拿到 Application Context
  → context.getPackageManager()             // 返回 ApplicationPackageManager
  → pm.getPackageInfo(pkgName, 64)          // 内部调用 IPackageManager (Binder IPC)
  → system_server 通过 Binder 返回 PackageInfo  // 经过 Parcel 反序列化
  → PackageInfo.signatures                   // 签名数据在这里
```

PLT Hook 只能拦截 libc 的 `openat/fopen/stat` 等文件 IO 函数，而签名数据通过 **Binder IPC** 传输，根本不经过文件系统。所以 PLT Hook 对签名校验完全无效。

### SVC 拦截无效的原因

即使用 seccomp 拦截了 SVC 系统调用，也只能控制文件 IO 相关的系统调用（openat/fstatat 等）。Binder IPC 走的是 `ioctl` 系统调用（操作 `/dev/binder`），拦截 ioctl 然后解析 Binder 协议难度极高且不可靠。

## V3 方案（参考 KC Tool 过签思路）

### 三层架构

| 层 | 技术 | 拦截目标 | 覆盖场景 |
|---|---|---|---|
| Layer 1 | CREATOR 替换 | Parcel 反序列化 | 所有通过 Binder 返回的 PackageInfo |
| Layer 2 | IPackageManager 动态代理 | Binder 调用 | getPackageInfo/checkSignatures 等 |
| Layer 3 | Dobby Inline Hook + Seccomp | Native IO | 直接读取 APK 文件解析签名块 |

### Layer 1: CREATOR 替换

替换 `PackageInfo.CREATOR` 静态字段。当任何 Binder 调用返回 PackageInfo 对象时，Parcel 反序列化会调用 `CREATOR.createFromParcel()`，我们在这里替换 `signatures` 字段。

三重降级策略替换 `static final` 字段：
1. `Field.set()` 直接修改
2. `sun.misc.Unsafe.putObject()` 绕过访问控制
3. 修改 `Field.accessFlags` 移除 FINAL 标志

### Layer 2: Binder IPC 代理

用 Java 动态代理包装 `IPackageManager` 接口：
- 代理 `ActivityThread.sPackageManager` → 全局入口
- 代理 `ApplicationPackageManager.mPM` → Context 级别入口

拦截方法：`getPackageInfo`, `checkSignatures`, `checkUidSignatures`, `hasSigningCertificate`

**这是解决你的问题的关键**：native 代码通过 `getApplication().getPackageManager().getPackageInfo()` 获取签名时，实际调用的是被代理过的 `IPackageManager`，代理会在返回值中替换签名。

### Layer 3: Native IO + Dobby + Seccomp

防御直接读取 APK 文件解析签名块的场景：
- Dobby Inline Hook 替代 PLT Hook（可拦截任意函数调用，不限于 PLT 导入）
- IO 重定向：base.apk → 原始 APK 备份
- Maps 隐藏：过滤 `/proc/self/maps` 中的 hook 痕迹
- Seccomp BPF：拦截内联 SVC 指令

## 初始化时序

```
App 进程启动
  ↓
Application.attachBaseContext()
  ↓
SignatureKillerProvider.onCreate() [initOrder=999]
  ├── Layer 1: CREATOR 替换 (PackageInfo/Signature/SigningInfo)
  ├── Layer 2: IPackageManager 代理 (sPackageManager + mPM)
  └── Layer 3: Native (Dobby + Seccomp + Maps)
  ↓
Application.onCreate()
  ↓
MainActivity 类加载 → static { System.loadLibrary("native-lib"); }
  → JNI_OnLoad → getApplication() → getPackageInfo(64) → 代理拦截 → 返回原始签名 ✓
  ↓
MainActivity.onCreate() → stringFromJNI() → "signature is valid" ✓
```

## 项目结构

```
app/src/main/
├── AndroidManifest.xml              # 含 SignatureKillerProvider (initOrder=999)
├── java/com/xiao/resign/
│   ├── MainActivity.java            # 原始签名校验界面
│   └── killsig/
│       ├── SignatureKillerProvider.java  # ContentProvider 初始化入口
│       ├── SignatureKiller.java          # 三层绕过核心 (Layer 1 + 2)
│       └── NativeSignatureKiller.java   # Native JNI 桥接 (Layer 3)
├── cpp/
│   ├── CMakeLists.txt               # CMake (含 Dobby FetchContent)
│   ├── common.h                     # 公共定义
│   ├── native-lib.cpp               # 原始签名校验库 (测试目标)
│   ├── native_killer.cpp            # Dobby inline hook 入口
│   ├── io_redirect.cpp              # IO 路径重定向
│   ├── maps_hide.cpp                # /proc/self/maps 过滤
│   └── seccomp_handler.cpp          # Seccomp BPF + SIGSYS
└── res/
    ├── layout/activity_main.xml
    └── values/ (strings, colors, themes)
```

## 使用方式

### 直接编译测试
1. Android Studio 打开项目
2. Build → Run
3. 查看界面显示 "signature is valid" 或 "signature is not valid"

### 集成到重打包工具
1. 将 `killsig/` 下的 3 个 Java 文件注入目标 APK 的 dex
2. 在 AndroidManifest.xml 中添加 SignatureKillerProvider
3. 将 libnative_killer.so 放入 lib/ 目录
4. 将原始签名 Base64 写入 `SignatureKiller.ORIGINAL_SIGNATURES_BASE64`
5. 重签名 APK
