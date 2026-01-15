# Android App 签名校验方案汇总（Java / SO / 读文件）

本文汇总当前安卓生态中常见的“签名校验/验签”方案，覆盖：

- Java 层通过系统 API 获取并比对签名/证书指纹
- 通过读取 APK 文件（base.apk / split APK）解析证书或校验签名块
- SO（Native）层做同类校验（含 JNI / 直接读文件）
- 适配 Android 版本差异（尤其是 API 28+ 的 SigningInfo）
- 工程化落地建议与常见绕过点

## 0. 先统一概念：你到底要“校验”什么

安卓里常见有三类目标，混在一起会导致方案选错：

- **校验签名证书是谁**：判断当前安装包是否由“预期证书”签发（最常见）
- **校验 APK 是否被篡改**：判断 base.apk / splits 是否被改动（需要读文件、做哈希或校验签名块）
- **校验运行环境可信**：防 Hook/注入/重打包的对抗（签名校验只是其中一个信号）

多数业务只需要第一类（证书指纹比对）。第二类更偏完整性校验；第三类需要综合策略（本地 + 服务端/平台能力）。

## 1. Java 层：通过 PackageManager 获取签名/证书

### 1.1 API 演进与推荐用法

Android 对“签名”相关字段的演进要点：

- **API < 28（Android 9 之前）**：`PackageInfo.signatures` 可用（已弃用但仍存在）
- **API >= 28（Android 9+）**：推荐 `PackageInfo.signingInfo`（`SigningInfo`）
- **多签/轮换**：`SigningInfo` 可能返回多个证书（签名轮换或历史签名），校验时要明确策略

常用 flags：

- 旧：`PackageManager.GET_SIGNATURES`
- 新：`PackageManager.GET_SIGNING_CERTIFICATES`

### 1.2 关键 API 清单（Java）

获取本包信息：

- `Context.getPackageName()`
- `Context.getPackageManager()`
- `PackageManager.getPackageInfo(String packageName, int flags)`
- `PackageInfo.signatures`（旧）
- `PackageInfo.signingInfo`（新）
- `SigningInfo.getApkContentsSigners()`
- `SigningInfo.getSigningCertificateHistory()`

把 `Signature` 转为证书并做指纹：

- `Signature.toByteArray()`
- `java.security.cert.CertificateFactory.getInstance("X.509")`
- `java.security.cert.X509Certificate`
- `java.security.MessageDigest.getInstance("SHA-256")`（也可 SHA-1，但不建议新项目用）
- `android.util.Base64` 或手写 hex 编码

获取 APK 路径（用于“读文件校验”）：

- `Context.getApplicationInfo()`
- `ApplicationInfo.sourceDir`
- `ApplicationInfo.publicSourceDir`
- `ApplicationInfo.splitSourceDirs`
- `Context.getPackageCodePath()`

### 1.3 示例：取本包证书 SHA-256 指纹并比对（兼容 28+/旧版）

```java
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class SignatureCheck {
  public static boolean isExpectedCertSha256(Context context, String expectedUpperHexSha256) throws Exception {
    PackageManager pm = context.getPackageManager();
    String pkg = context.getPackageName();

    PackageInfo pi;
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
      Signature[] signatures = pi.signingInfo != null ? pi.signingInfo.getApkContentsSigners() : null;
      return containsExpected(signatures, expectedUpperHexSha256);
    } else {
      pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
      return containsExpected(pi.signatures, expectedUpperHexSha256);
    }
  }

  private static boolean containsExpected(Signature[] signatures, String expectedUpperHexSha256) throws Exception {
    if (signatures == null || signatures.length == 0) return false;
    for (Signature s : signatures) {
      String sha256 = certSha256UpperHex(s.toByteArray());
      if (expectedUpperHexSha256.equals(sha256)) return true;
    }
    return false;
  }

  private static String certSha256UpperHex(byte[] signatureBytes) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(signatureBytes));
    byte[] encoded = cert.getEncoded();

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(encoded);
    return toUpperHex(digest);
  }

  private static String toUpperHex(byte[] bytes) {
    char[] hex = "0123456789ABCDEF".toCharArray();
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      out[i * 2] = hex[v >>> 4];
      out[i * 2 + 1] = hex[v & 0x0F];
    }
    return new String(out);
  }
}
```

落地建议：

- 指纹建议用 **SHA-256**（SHA-1 仍常见，但新项目尽量不用）
- expected 值建议来自你的正式证书（release keystore）导出的证书指纹
- 对多签（`signatures.length > 1`）要明确策略：任一命中即通过，或必须包含某个集合

### 1.4 校验“历史签名”与“签名轮换”的注意点（API 28+）

`SigningInfo` 有两个不同概念：

- `getApkContentsSigners()`：当前 APK 内容对应的签名证书集合
- `getSigningCertificateHistory()`：签名历史（可能包含轮换前证书）

如果你的产品经历过“签名证书轮换”，可能需要：

- 允许历史证书之一命中，或
- 允许“当前证书”命中，且“历史链”满足预期

业务上一般用 `getApkContentsSigners()` 作为“当前安装包签名”更直观；是否允许历史证书需要你明确安全策略。

### 1.5 通过 PackageManager 校验的优缺点

优点：

- 实现简单、性能好、兼容性高
- 不需要解析 APK 结构

缺点（对抗场景）：

- 结果来自系统服务/框架层，可能被 Hook（Xposed/LSPosed、Frida 等）或虚拟化环境伪造
- 无法直接回答“APK 文件是否被篡改”（它回答的是“系统认为它的签名是谁”）

## 2. Java 层：读取 APK 文件进行校验（base.apk / split APK）

读文件校验主要用来做两件事：

- 直接从 APK 中提取证书/签名信息并比对（绕开对 PackageManager 的依赖）
- 做完整性校验（hash/签名块校验）以检测篡改

### 2.1 获取 APK 路径（含 Split APK）

```java
import android.content.Context;
import android.content.pm.ApplicationInfo;

public final class ApkPaths {
  public static String[] getAllApkPaths(Context context) {
    ApplicationInfo ai = context.getApplicationInfo();
    if (ai.splitSourceDirs == null || ai.splitSourceDirs.length == 0) {
      return new String[] { ai.sourceDir };
    }
    String[] out = new String[1 + ai.splitSourceDirs.length];
    out[0] = ai.sourceDir;
    System.arraycopy(ai.splitSourceDirs, 0, out, 1, ai.splitSourceDirs.length);
    return out;
  }
}
```

注意：

- 现代应用常见 split（base + config/abi/language splits），若你做“完整性校验”，不能只校验 base.apk
- “只校验证书指纹”的话通常校验 base.apk 足够，但在对抗场景仍建议至少把 split 纳入一致性检查

### 2.2 方案 A：用 Jar 验签（v1/JAR 签名体系）

适用性：

- 主要对应 APK v1（JAR）签名体系
- 对 v2/v3/v4 签名：APK 仍可能兼容存在 META-INF，但只靠 Jar 验签并不覆盖所有情况

思路：

- 用 `java.util.jar.JarFile` 读取 `classes.dex` 等 entry
- 触发 `JarEntry` 读取以校验签名（JAR 验签机制）
- 从 entry 的 `getCertificates()` 取证书链，做指纹比对

关键类：

- `java.util.jar.JarFile`
- `java.util.jar.JarEntry`
- `java.security.cert.Certificate`

示例（简化版，展示核心流程）：

```java
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class JarV1CertReader {
  public static String readAnyCertSha256UpperHex(String apkPath) throws Exception {
    JarFile jarFile = new JarFile(apkPath);
    try {
      Enumeration<JarEntry> entries = jarFile.entries();
      while (entries.hasMoreElements()) {
        JarEntry e = entries.nextElement();
        if (e.isDirectory()) continue;
        if (e.getName().startsWith("META-INF/")) continue;

        try (InputStream is = jarFile.getInputStream(e)) {
          byte[] buffer = new byte[8192];
          while (is.read(buffer) != -1) {}
        }

        Certificate[] certs = e.getCertificates();
        if (certs != null && certs.length > 0) {
          X509Certificate x509 = (X509Certificate) certs[0];
          MessageDigest md = MessageDigest.getInstance("SHA-256");
          byte[] digest = md.digest(x509.getEncoded());
          return toUpperHex(digest);
        }
      }
      return null;
    } finally {
      jarFile.close();
    }
  }

  private static String toUpperHex(byte[] bytes) {
    char[] hex = "0123456789ABCDEF".toCharArray();
    char[] out = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int v = bytes[i] & 0xFF;
      out[i * 2] = hex[v >>> 4];
      out[i * 2 + 1] = hex[v & 0x0F];
    }
    return new String(out);
  }
}
```

风险点：

- 有些 APK 可能没有 v1 签名（仅 v2/v3），这时 `JarEntry.getCertificates()` 可能拿不到
- 对抗场景中，攻击者也可能针对你的读取逻辑做定向欺骗（Hook JarFile/IO）

### 2.3 方案 B：解析 APK Signing Block（v2/v3/v4）

适用性：

- 想覆盖 v2/v3（以及更现代签名体系）时，需要解析 APK Signing Block
- 这是“更接近真相”的文件级校验方式，但实现复杂度明显更高

现实落地常见做法：

- 直接使用 AOSP 的 apksig 实现（在 Gradle/Java 里引入并不总是方便）
- 或参考 apksig 的算法自己实现（工程量大，且要适配格式细节）
- Android 系统内部存在一些相关实现类（例如 `android.util.apk.*`），但很多是隐藏 API，反射使用在新系统上受限制

你如果确实要走这条路，建议目标明确：

- **只要证书指纹**：从 v2/v3 block 解析 signer 的证书并做 SHA-256 指纹
- **要完整性校验**：校验签名块并验证所有摘要与签名

### 2.4 方案 C：简单完整性校验（文件哈希/分段哈希）

适用性：

- 你只关心“被改过没有”，不必严格遵循 APK 签名规范

思路：

- 对 `base.apk`（及 splits）做 SHA-256
- 将 hash 与内置/服务端下发的期望值比对

优点：

- 实现简单，跨版本稳定

缺点：

- 每次版本升级都要更新期望 hash
- 对“合法更新”不友好（hash 必然变化）
- 在强对抗环境下容易被 patch 掉比对逻辑

工程常见折中：

- 只对关键文件做 hash（如 `classes.dex`、特定 so、关键资源）
- 组合多点校验（Java + Native + 文件）提高改动成本

## 3. SO（Native）层验签：JNI / 读文件 / 反调试结合

Native 层验签的核心价值通常不是“能力更强”，而是：

- 让攻击者需要同时处理 Java 与 Native 两侧的校验逻辑，提高成本
- 配合反调试/反注入（ptrace、检测 frida-gadget 等）形成链路

### 3.1 Native 层可用的常见入口

Native 可以做的事情大体分三类：

- **JNI 调 Java API**：在 C/C++ 里调用 `Context -> PackageManager -> getPackageInfo`，逻辑与 Java 等价，但对抗成本更高
- **直接读 APK 文件**：用 `open/read/mmap` 读 `sourceDir`，做 v1/v2/v3 解析或 hash
- **校验自身 so/内存**：校验 `libxxx.so` 文件 hash、ELF 段 hash、关键函数代码段校验，作为“篡改检测”的补充

### 3.2 JNI 调用 PackageManager 的思路（伪代码级别）

典型 JNI 链路：

- 从传入的 `Context` 获取 `getPackageManager()`、`getPackageName()`
- 调用 `getPackageInfo(pkg, flags)`
- 分支处理：
  - API 28+：`PackageInfo.signingInfo.getApkContentsSigners()`
  - 旧：`PackageInfo.signatures`
- 对 `Signature.toByteArray()` 得到证书 bytes
- Native 里做 SHA-256（OpenSSL/BoringSSL/自实现）或回调 Java `MessageDigest`

关键点：

- Android 9+ 的隐藏 API 限制不会直接影响你用公开 API，但反射隐藏类会更难
- Native 里如果引入 OpenSSL 等三方库，要注意体积与兼容性；也可以自己实现 SHA-256（代码短但要保证正确）

### 3.3 Native 直接读 base.apk 并做 hash（示例思路）

做法：

- Java 侧把 `ApplicationInfo.sourceDir` 字符串传给 JNI
- Native 侧 `open()` 文件并 `mmap()`，对整个文件做 SHA-256
- 与内置期望值比对

这种方式更像“完整性校验”，不是签名规范意义上的验签，但实现容易、覆盖面稳定。

### 3.4 Native 做证书指纹 vs 做文件完整性：选型建议

- 如果你的目标是“识别是不是我签的”：优先证书指纹（Java API 或 v2/v3 解析）
- 如果你的目标是“检测被改过”：优先文件完整性（hash / 分段 hash / so 段校验），并把 split 也纳入

## 4. 读取文件校验的工程陷阱与兼容性

### 4.1 Split APK、动态特性与资源拆分

- `ApplicationInfo.splitSourceDirs` 可能存在多个路径
- 某些动态特性模块安装后才出现对应 split（取决于 Play Feature Delivery）
- 如果你做完整性校验，建议将“当前存在的所有 APK 路径”都纳入校验

### 4.2 多进程与多 ABI

- 不同进程启动时机不同，校验触发点要避免导致 ANR
- 对大 APK 做全量 hash 可能很慢，建议异步 + 缓存结果（存到内存或持久化）

### 4.3 运行时环境可能影响读取路径

- 虚拟化/多开环境可能改变 `sourceDir` 的意义或返回值
- Hook 框架可能拦截文件 IO 或 Java 方法返回值

## 5. 对抗绕过：签名校验常见被绕过方式与加固策略

### 5.1 常见绕过手段

- Hook `PackageManager.getPackageInfo` / `SigningInfo` / `Signature.toByteArray` 直接伪造指纹
- Patch 你的比对逻辑：把 “if (!ok) exit” 改成永远 ok
- 重打包后修改你的 expected 指纹常量或配置
- 在虚拟化环境中由宿主统一伪造签名信息

结论：

- **单点本地验签不是强安全边界**，更像“篡改成本提升器”

### 5.2 工程落地建议（更现实有效）

- 多点校验：Java API + 读文件 + Native 至少两条链路
- 分散触发：启动、关键业务点、后台周期性抽检（避免只在 Application.onCreate）
- 结果使用策略：不要只“弹框”，最好与关键功能开关绑定，并做服务端风控联动
- 服务端参与：客户端上报证书指纹/安装来源/设备信息做风控（注意上报可伪造，需交叉验证）
- 平台能力：结合 Play Integrity API（或厂商设备完整性能力）提高对抗强度

## 6. 常用“期望值”获取方式（证书指纹怎么来）

你通常需要把“你的 release 证书”的 SHA-256 指纹放进代码或配置。

常见来源：

- 从 keystore 导出证书再算 SHA-256
- 从已发布 APK 提取证书指纹（确保来源可信）
- 若使用 Play App Signing，需要区分：
  - 上传证书（Upload key）
  - 应用签名证书（App signing key，最终分发 APK 的签名）

如果你的目标是校验“商店下发的安装包”，应以“最终分发签名证书”作为期望值。

## 7. 方案对比（快速选型）

- **只想判断是不是你签的（一般业务）**：Java `SigningInfo`/`signatures` 指纹比对
- **担心 Java API 被 Hook**：加上读取 APK（v1 Jar 验签或 hash），并在 Native 再做一次
- **要严格覆盖 v2/v3**：实现/引入 apksig 级别的 signing block 解析与校验
- **要做篡改检测**：hash（base + splits）+ so 段校验 + 分散触发点

## 8. 你可以直接复用的“组合式策略”（推荐默认）

推荐一套工程上性价比高的组合（按强度递增）：

1. Java：`SigningInfo.getApkContentsSigners()` 做证书 SHA-256 指纹比对（兼容旧版用 `signatures`）
2. Java：读取 `sourceDir` 对 `base.apk` 做 SHA-256（缓存结果）
3. Native：再对 `base.apk` 做一次 SHA-256 或对关键 so 段做校验
4. 关键链路：校验失败时触发业务降级 + 上报服务端风控

这套策略不保证“无法绕过”，但能显著提高重打包/Hook 的工作量，并降低误伤。

