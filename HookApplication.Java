// package com.xwaaa.hook;

// import android.app.Application;
// import android.content.Context;
// import android.content.pm.PackageInfo;
// import android.content.pm.PackageManager;
// import android.content.pm.Signature;
// import android.os.Build;
// import android.os.Environment;
// import android.util.Base64;
// import android.util.Log;

// import java.io.BufferedReader;
// import java.io.File;
// import java.io.FileOutputStream;
// import java.io.FileReader;
// import java.io.InputStream;
// import java.io.OutputStream;
// import java.lang.reflect.Constructor;
// import java.lang.reflect.Field;
// import java.lang.reflect.InvocationHandler;
// import java.lang.reflect.Method;
// import java.lang.reflect.Proxy;
// import java.util.concurrent.atomic.AtomicBoolean;
// import java.util.zip.ZipEntry;
// import java.util.zip.ZipFile;

// public class HookApplication extends Application {
//     public static final String TAG = "HookApplication";

//     // 由外部注入
//     public static String packageName   = "xwaaa.package";
//     public static String signatureData = "xwaaa resig";

//     // 状态位
//     private static final AtomicBoolean INIT_ONCE           = new AtomicBoolean(false);
//     private static final AtomicBoolean PM_PROXY_INSTALLED  = new AtomicBoolean(false);
//     private static final AtomicBoolean APP_PM_PATCHED      = new AtomicBoolean(false);
//     private static final AtomicBoolean OPEN_HOOKED         = new AtomicBoolean(false);

//     public static native void hookApkPath(String sourceApkPath, String redirectedApkPath);
//     public static native void cleanup();

//     // 全局上下文与 PM 相关状态
//     private static volatile Context sAppContext;
//     private static volatile Object sGlobalPmProxy;  // 兼容原有命名
//     private static volatile Object sRawIPM;         // 系统原始 IPackageManager
//     private static volatile Object sPmProxy;        // 我们的代理 IPackageManager
//     private static volatile boolean sProxyInstalled = false;

//     // =============== 静态初始化 ===============
//     static {
//         Log.d(TAG, "=== HookApplication <clinit> ===");
//         try {
//             if (shouldRunInThisProcess() && INIT_ONCE.compareAndSet(false, true)) {
//                 try {
//                     installGlobalPmProxy(packageName, signatureData);
//                 } catch (Throwable t) {
//                     Log.e(TAG, "installGlobalPmProxy failed: " + t.getMessage(), t);
//                 }
//             } else {
//                 Log.d(TAG, "skip: not main process or already inited");
//             }
//         } catch (Throwable e) {
//             Log.e(TAG, "static init error: " + e.getMessage(), e);
//         }
//     }

//     private static boolean shouldRunInThisProcess() {
//         String current = null;
//         try {
//             if (Build.VERSION.SDK_INT >= 28) current = Application.getProcessName();
//             else {
//                 BufferedReader br = new BufferedReader(new FileReader("/proc/self/cmdline"));
//                 String line = br.readLine();
//                 br.close();
//                 current = (line != null) ? line.trim() : null;
//             }
//         } catch (Throwable ignore) {}
//         return current == null || current.equals(packageName);
//     }

//     // =============== IPackageManager 全局代理 ===============
//     private static void installGlobalPmProxy(final String targetPkg, final String fakeSigBase64) throws Exception {
//         if (PM_PROXY_INSTALLED.get()) return;

//         final Signature fakeSig = new Signature(Base64.decode(fakeSigBase64, Base64.DEFAULT));

//         Class<?> atClz = Class.forName("android.app.ActivityThread");
//         Object activityThread = atClz.getMethod("currentActivityThread").invoke(null);
//         Field fSPM = atClz.getDeclaredField("sPackageManager");
//         fSPM.setAccessible(true);
//         final Object rawIPM = fSPM.get(activityThread); // 原始 IPackageManager

//         // 记录原始对象，供切换用
//         sRawIPM = rawIPM;

//         final Class<?> iPmClz = Class.forName("android.content.pm.IPackageManager");

//         InvocationHandler h = new InvocationHandler() {
//             @Override
//             public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
//                 String name = method.getName();

//                 // 特殊：一些框架通过这些方法探测代理对象身份，做“隐身”处理
//                 if ("getClass".equals(name)) {
//                     return rawIPM.getClass();
//                 }
//                 if ("toString".equals(name)) {
//                     return rawIPM.toString();
//                 }
//                 if ("hashCode".equals(name)) {
//                     return rawIPM.hashCode();
//                 }
//                 if ("equals".equals(name) && args != null && args.length == 1) {
//                     return rawIPM.equals(args[0]);
//                 }

//                 // 拦 getPackageInfo / getPackageInfoAsUser，改写签名
//                 if ("getPackageInfo".equals(name) || "getPackageInfoAsUser".equals(name)) {
//                     Object out = method.invoke(rawIPM, args);
//                     if (out instanceof PackageInfo) {
//                         PackageInfo pi = (PackageInfo) out;
//                         if (targetPkg.equals(pi.packageName)) {
//                             // 旧字段：signatures
//                             try {
//                                 Field fSigs = PackageInfo.class.getDeclaredField("signatures");
//                                 fSigs.setAccessible(true);
//                                 fSigs.set(pi, new Signature[]{ fakeSig });
//                             } catch (Throwable e) {
//                                 Log.d(TAG, "替换 signatures 失败: " + e.getMessage());
//                             }

//                             // 新字段：signingInfo (API 28+)
//                             if (Build.VERSION.SDK_INT >= 28) {
//                                 try {
//                                     Field fSI = PackageInfo.class.getDeclaredField("signingInfo");
//                                     fSI.setAccessible(true);
//                                     Object si = fSI.get(pi);
//                                     if (si != null) {
//                                         // 构造新的 SigningDetails 并替换 SigningInfo 的 mSigningDetails
//                                         Class<?> sdClz = Class.forName("android.content.pm.SigningDetails");
//                                         Constructor<?> c =
//                                                 sdClz.getDeclaredConstructor(Signature[].class, int.class);
//                                         c.setAccessible(true);
//                                         Object details = c.newInstance(new Signature[]{ fakeSig }, 2);
//                                         Field fDetails = Class.forName("android.content.pm.SigningInfo")
//                                                 .getDeclaredField("mSigningDetails");
//                                         fDetails.setAccessible(true);
//                                         fDetails.set(si, details);
//                                     }
//                                 } catch (Throwable e) {
//                                     Log.d(TAG, "替换 signingInfo 失败: " + e.getMessage());
//                                 }
//                             }
//                         }
//                     }
//                     return out;
//                 }

//                 // 放过签名与证书检测结果（强制放行）
//                 if ("checkSignatures".equals(name) || "checkSignaturesAsUser".equals(name)) {
//                     Object result = method.invoke(rawIPM, args);
//                     if (result instanceof Integer) {
//                         int originalResult = (Integer) result;
//                         if (originalResult != PackageManager.SIGNATURE_MATCH) {
//                             return PackageManager.SIGNATURE_MATCH;
//                         }
//                     }
//                     return result;
//                 }
//                 if ("hasSigningCertificate".equals(name) || "hasSigningCertificateAsUser".equals(name)) {
//                     Object result = method.invoke(rawIPM, args);
//                     if (result instanceof Boolean) {
//                         boolean originalResult = (Boolean) result;
//                         if (!originalResult) {
//                             return true;
//                         }
//                     }
//                     return result;
//                 }

//                 // 其他方法直接转发
//                 return method.invoke(rawIPM, args);
//             }
//         };

//         Object proxy = Proxy.newProxyInstance(iPmClz.getClassLoader(), new Class[]{ iPmClz }, h);
//         fSPM.set(activityThread, proxy);

//         // 记录代理，并标记安装完成
//         sGlobalPmProxy = proxy;
//         sPmProxy = proxy;
//         sProxyInstalled = true;
//         PM_PROXY_INSTALLED.set(true);

//         Log.d(TAG, "Global IPackageManager proxy installed (stealth mode)");

//         // 验证代理是否正确安装
//         verifyProxyInstallation(activityThread, fSPM);
//     }

//     /** 验证代理安装 */
//     private static void verifyProxyInstallation(Object activityThread, Field fSPM) {
//         try {
//             Object currentPm = fSPM.get(activityThread);
//             Log.d(TAG, "验证代理安装 - 当前 sPackageManager: " + currentPm.getClass().getName());

//             // 测试 getClass() 拦截
//             Class<?> pmClass = currentPm.getClass();
//             Log.d(TAG, "验证 getClass() - 返回: " + pmClass.getName());
//         } catch (Exception e) {
//             Log.e(TAG, "验证代理安装失败: " + e.getMessage());
//         }
//     }

//     // =============== 把应用侧 PackageManager.mPM 指到同一代理 ===============
//     private static void patchAppPmIfNeeded(Context ctx) {
//         if (ctx == null || sGlobalPmProxy == null || APP_PM_PATCHED.get()) return;
//         try {
//             PackageManager pm = ctx.getPackageManager();
//             Field fMPM = pm.getClass().getDeclaredField("mPM");
//             fMPM.setAccessible(true);
//             fMPM.set(pm, sGlobalPmProxy);
//             APP_PM_PATCHED.set(true);
//             Log.d(TAG, "ApplicationPackageManager.mPM patched");

//             // 验证伪装效果
//             verifyStealthEffect(pm);
//         } catch (Throwable t) {
//             Log.e(TAG, "patchAppPmIfNeeded failed: " + t.getMessage(), t);
//         }
//     }

//     /** 验证伪装效果 */
//     private static void verifyStealthEffect(PackageManager pm) {
//         try {
//             Field fMPM = pm.getClass().getDeclaredField("mPM");
//             fMPM.setAccessible(true);
//             Object currentPm = fMPM.get(pm);

//             String className = currentPm.getClass().getName();
//             Log.d(TAG, "当前 mPM 实际类名: " + className);

//             // 调用 getClass() 验证伪装
//             Class<?> reportedClass = currentPm.getClass();
//             Log.d(TAG, "getClass() 报告类名: " + reportedClass.getName());

//             boolean isStealth = reportedClass.getName().contains("IPackageManager$Stub$Proxy");
//             Log.d(TAG, "伪装检测结果: " + (isStealth ? "成功" : "失败"));

//         } catch (Exception e) {
//             Log.e(TAG, "验证伪装效果失败: " + e.getMessage());
//         }
//     }

//     /** 将应用侧 PackageManager.mPM 切到“原始”对象（用于过类名/反射检测） */
//     public static boolean setAppPmToRaw(Context ctx) {
//         if (ctx == null || sRawIPM == null) return false;
//         try {
//             PackageManager pm = ctx.getPackageManager();
//             Field fMPM = pm.getClass().getDeclaredField("mPM");
//             fMPM.setAccessible(true);
//             fMPM.set(pm, sRawIPM);
//             return true;
//         } catch (Throwable t) {
//             Log.e(TAG, "setAppPmToRaw failed: " + t.getMessage(), t);
//             return false;
//         }
//     }

//     /** 将应用侧 PackageManager.mPM 切回“代理”对象（恢复改签名能力） */
//     public static boolean setAppPmToProxy(Context ctx) {
//         if (ctx == null || sPmProxy == null) return false;
//         try {
//             PackageManager pm = ctx.getPackageManager();
//             Field fMPM = pm.getClass().getDeclaredField("mPM");
//             fMPM.setAccessible(true);
//             fMPM.set(pm, sPmProxy);
//             return true;
//         } catch (Throwable t) {
//             Log.e(TAG, "setAppPmToProxy failed: " + t.getMessage(), t);
//             return false;
//         }
//     }

//     /** 在回调执行期间切到“原始 mPM”，结束后切回“代理 mPM” */
//     public static void runWithRawPm(Context ctx, Runnable r) {
//         boolean switched = setAppPmToRaw(ctx);
//         try { r.run(); } finally {
//             if (switched) setAppPmToProxy(ctx);
//         }
//     }

//     // =============== 公开的 PM Hook 入口 ===============
//     public static void killPM(final String pkg, String sigBase64) {
//         Log.d(TAG, "执行 killPM");
//         try {
//             installGlobalPmProxy(pkg, sigBase64);
//         } catch (Throwable t) {
//             Log.e(TAG, "killPM: installGlobalPmProxy failed: " + t.getMessage(), t);
//         }
//         if (sAppContext != null) {
//             patchAppPmIfNeeded(sAppContext);
//         } else {
//             Log.e(TAG, "killPM: sAppContext is null");
//         }
//     }

//     // =============== native 层 open/readlinkat 重定向 ===============
//     public static void killOpen(String pkg) {
//         if (OPEN_HOOKED.get()) return;
//         try {
//             System.loadLibrary("killsignture");

//             String apkPath = findSelfApkPath(pkg);
//             if (apkPath == null) {
//                 Log.e(TAG, "未找到自身 base.apk 路径");
//                 return;
//             }
//             File apkFile = new File(apkPath);
//             File dataDir = ensureDataDir(pkg);
//             File redirected = new File(dataDir, "origin.apk");

//             try (ZipFile zip = new ZipFile(apkFile)) {
//                 ZipEntry entry = zip.getEntry("assets/KillSig/origin.apk");
//                 if (entry == null) {
//                     Log.e(TAG, "未找到 assets/KillSig/origin.apk");
//                     return;
//                 }
//                 if (!redirected.exists() || redirected.length() != entry.getSize()) {
//                     try (InputStream is = zip.getInputStream(entry);
//                          OutputStream os = new FileOutputStream(redirected)) {
//                         byte[] buf = new byte[64 * 1024];
//                         int n;
//                         while ((n = is.read(buf)) != -1) os.write(buf, 0, n);
//                     }
//                     Log.d(TAG, "已解压 origin.apk -> " + redirected.getAbsolutePath());
//                 }
//             }
//             hookApkPath(apkFile.getAbsolutePath(), redirected.getAbsolutePath());
//             OPEN_HOOKED.set(true);
//             Log.d(TAG, "killOpen: io重定向 完成");
//         } catch (Throwable t) {
//             Log.e(TAG, "killOpen failed: " + t.getMessage(), t);
//         }
//     }



//     // =============== 其余辅助方法 ===============
//     public static String findSelfApkPath(String pkg) {
//         try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
//             String line;
//             while ((line = reader.readLine()) != null) {
//                 int sp = line.lastIndexOf(' ');
//                 if (sp <= 0) continue;
//                 String path = line.substring(sp + 1);
//                 if (isApkPathOf(pkg, path)) return path;
//             }
//         } catch (Throwable e) {
//             Log.e(TAG, "findSelfApkPath 失败: " + e.getMessage());
//         }
//         return null;
//     }

//     public static boolean isApkPathOf(String pkg, String path) {
//         if (path == null) return false;
//         path = path.trim();
//         if (!path.startsWith("/") || !path.endsWith(".apk")) return false;
//         if (path.contains("/data/app/") && path.endsWith("/base.apk") && path.contains("/" + pkg + "-")) return true;
//         if (path.contains("/mnt/expand/") && path.endsWith("/base.apk") && path.contains("/" + pkg)) return true;
//         return false;
//     }

//     public static File ensureDataDir(String pkg) {
//         String username = Environment.getExternalStorageDirectory().getName();
//         File dir;
//         if (username != null && username.matches("\\d+")) {
//             dir = new File("/data/user/" + username + "/" + pkg);
//             if (!dir.canWrite()) dir = new File("/data/data/" + pkg);
//         } else {
//             dir = new File("/data/data/" + pkg);
//         }
//         if (!dir.exists()) dir.mkdirs();
//         return dir;
//     }

//     // =============== 初始化入口 ===============
//     public static void initSignatureHook() {
//         try {
//             Log.d(TAG, "开始初始化签名 Hook...");
//             Log.d(TAG, "包名: " + packageName);
//             Log.d(TAG, "签名(Base64): " + signatureData);

//             killPM(packageName, signatureData);
//             killOpen(packageName);

//             Log.d(TAG, "签名 Hook 初始化完成!");
//         } catch (Throwable e) {
//             Log.e(TAG, "初始化失败: " + e.getMessage(), e);
//         }
//     }

//     // =============== 生命周期 ===============
//     @Override protected void attachBaseContext(Context base) {
//         super.attachBaseContext(base);
//         sAppContext = base.getApplicationContext();
//         Log.d(TAG, "attachBaseContext: sAppContext set");
//         patchAppPmIfNeeded(sAppContext);
//     }

//     @Override public void onCreate() {
//         super.onCreate();
//         if (sAppContext == null) sAppContext = getApplicationContext();
//         Log.d(TAG, "onCreate: sAppContext checked");
//         patchAppPmIfNeeded(sAppContext);
//     }
// }


package com.xwaaa.hook;

import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class HookApplication extends Application {
    private static final String TAG = "HookApplication";

    // 由外部注入替换
    static String packageName = "xwaaa.package";
    static String signatureData = "xwaaa resig";

    // 只初始化一次（整个进程）
    private static final AtomicBoolean INIT_ONCE = new AtomicBoolean(false);
    private static final AtomicBoolean PM_HOOKED = new AtomicBoolean(false);
    private static final AtomicBoolean OPEN_HOOKED = new AtomicBoolean(false);

    private static volatile Object sRawIPM;
    private static volatile Object sProxyIPM;

    // 改成你实际的 so 名（lib<这里>.so）
    private static final String LIB_NAME = "killsignture";

    private static native void hookApkPath(String sourceApkPath, String redirectedApkPath);
    private static native void cleanup(); // 如需释放资源再调用

    // 静态初始化：只在主进程且仅一次
    static {
        Log.d(TAG, "=== HookApplication 静态块开始 ===");
        try {
            if (shouldRunInThisProcess() && INIT_ONCE.compareAndSet(false, true)) {
                initSignatureHook();
            } else {
                Log.d(TAG, "跳过初始化：非主进程或已初始化过");
            }
        } catch (Throwable e) {
            Log.e(TAG, "静态块初始化失败: " + e.getMessage(), e);
        }
        Log.d(TAG, "=== HookApplication 静态块结束 ===");
    }

    private static boolean shouldRunInThisProcess() {
        String current;
        try {
            if (Build.VERSION.SDK_INT >= 28) {
                current = Application.getProcessName();
            } else {
                try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/cmdline"))) {
                    String line = br.readLine();
                    current = line != null ? line.trim() : null;
                }
            }
        } catch (Throwable t) {
            current = null;
        }
        // 没拿到就默认允许；拿到了就要求与目标包名一致（目标包名会被注入替换）
        return current == null || current.equals(packageName);
    }

    /** 初始化：一次性 **/
    private static void initSignatureHook() {
        try {
            Log.d(TAG, "开始初始化签名 Hook...");
            Log.d(TAG, "成功提取包名: " + packageName);
            Log.d(TAG, "成功提取签名: " + signatureData);

            // 1) Java 层 PM Hook（只装一次）
            if (PM_HOOKED.compareAndSet(false, true)) {
                killPM(packageName, signatureData);
            } else {
                Log.d(TAG, "PM Hook 已安装，跳过");
            }

            // 2) native 层 open/readlinkat SVC 重定向（只装一次）
            if (OPEN_HOOKED.compareAndSet(false, true)) {
                killOpen(packageName);
            } else {
                Log.d(TAG, "Open Hook 已安装，跳过");
            }

            Log.d(TAG, "签名 Hook 初始化完成!");
            // 如需释放 native 缓存可延后在合适的时机调用 cleanup();
        } catch (Throwable e) {
            Log.e(TAG, "初始化签名 Hook 失败: " + e.getMessage(), e);
        }
    }

    /** PackageManager Hook（Java 层） **/
    private static void killPM(final String pkg, String sigBase64) {
        try {
            Log.d(TAG, "执行 PackageManager Binder Hook...");
            Object proxy = installPackageManagerBinderHook(pkg, sigBase64);
            sProxyIPM = proxy;
            patchActivityThreadPackageManager(proxy);
            patchApplicationPackageManager(proxy);
            clearPackageManagerInfoCache();
            Log.d(TAG, "PackageManager Binder Hook 安装完成");
        } catch (Throwable e) {
            Log.e(TAG, "PackageManager Hook 失败: " + e.getMessage(), e);
        }
    }

    private static Object installPackageManagerBinderHook(final String targetPkg, String sigBase64) throws Throwable {
        final Signature fakeSig = new Signature(Base64.decode(sigBase64, Base64.DEFAULT));

        Class<?> smClz = Class.forName("android.os.ServiceManager");
        Method getService = smClz.getDeclaredMethod("getService", String.class);
        getService.setAccessible(true);
        IBinder rawBinder = (IBinder) getService.invoke(null, "package");

        Class<?> iPmClz = Class.forName("android.content.pm.IPackageManager");
        Class<?> stubClz = Class.forName("android.content.pm.IPackageManager$Stub");
        Method asInterface = stubClz.getDeclaredMethod("asInterface", IBinder.class);
        asInterface.setAccessible(true);

        final Object rawIPM = asInterface.invoke(null, rawBinder);
        sRawIPM = rawIPM;

        final InvocationHandler ipmHandler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                String name = method.getName();

                if ("getClass".equals(name)) return rawIPM.getClass();
                if ("toString".equals(name)) return rawIPM.toString();
                if ("hashCode".equals(name)) return rawIPM.hashCode();
                if ("equals".equals(name) && args != null && args.length == 1) return rawIPM.equals(args[0]);

                if ("getPackageInfo".equals(name)
                        || "getPackageInfoAsUser".equals(name)
                        || "getPackageInfoVersioned".equals(name)
                        || "getPackageInfoVersionedAsUser".equals(name)) {
                    Object out = invokeOriginal(rawIPM, method, args);
                    if (out instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) out;
                        if (targetPkg.equals(pi.packageName)) {
                            patchPackageInfoSignatures(pi, fakeSig);
                        }
                    }
                    return out;
                }

                if ("checkSignatures".equals(name) || "checkSignaturesAsUser".equals(name)) {
                    Object result = invokeOriginal(rawIPM, method, args);
                    if (result instanceof Integer) {
                        int originalResult = (Integer) result;
                        if (originalResult != PackageManager.SIGNATURE_MATCH) return PackageManager.SIGNATURE_MATCH;
                    }
                    return result;
                }

                if ("hasSigningCertificate".equals(name) || "hasSigningCertificateAsUser".equals(name)) {
                    Object result = invokeOriginal(rawIPM, method, args);
                    if (result instanceof Boolean) {
                        boolean originalResult = (Boolean) result;
                        if (!originalResult) return true;
                    }
                    return result;
                }

                return invokeOriginal(rawIPM, method, args);
            }
        };

        final Object proxyIPM = Proxy.newProxyInstance(HookApplication.class.getClassLoader(), new Class[]{iPmClz}, ipmHandler);

        IBinder hookedBinder = (IBinder) Proxy.newProxyInstance(
                HookApplication.class.getClassLoader(),
                new Class[]{IBinder.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        if ("queryLocalInterface".equals(method.getName())
                                && args != null
                                && args.length == 1
                                && "android.content.pm.IPackageManager".equals(args[0])) {
                            return proxyIPM;
                        }
                        return invokeOriginal(rawBinder, method, args);
                    }
                }
        );

        @SuppressWarnings("unchecked")
        Map<String, IBinder> cache = (Map<String, IBinder>) findField(smClz, "sCache").get(null);
        cache.put("package", hookedBinder);

        return proxyIPM;
    }

    private static Object invokeOriginal(Object receiver, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(receiver, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause != null) throw cause;
            throw e;
        }
    }

    private static void patchPackageInfoSignatures(PackageInfo pi, Signature fakeSig) {
        try {
            Field fSigs = findField(PackageInfo.class, "signatures");
            fSigs.set(pi, new Signature[]{fakeSig});
        } catch (Throwable ignored) {
        }

        if (Build.VERSION.SDK_INT < 28) return;

        try {
            Field fSigningInfo = findField(PackageInfo.class, "signingInfo");
            Object signingInfo = fSigningInfo.get(pi);
            if (signingInfo == null) return;

            Class<?> signingInfoClz = Class.forName("android.content.pm.SigningInfo");
            Field fDetails;
            try {
                fDetails = signingInfoClz.getDeclaredField("mSigningDetails");
            } catch (NoSuchFieldException e) {
                fDetails = signingInfoClz.getDeclaredField("signingDetails");
            }
            fDetails.setAccessible(true);
            Object details = fDetails.get(signingInfo);

            if (details == null) {
                try {
                    Class<?> sdClz = Class.forName("android.content.pm.SigningDetails");
                    try {
                        details = sdClz.getDeclaredConstructor(Signature[].class, int.class).newInstance(new Signature[]{fakeSig}, 2);
                    } catch (NoSuchMethodException ignored) {
                        details = sdClz.getDeclaredConstructor().newInstance();
                    }
                    fDetails.set(signingInfo, details);
                } catch (Throwable ignored) {
                    return;
                }
            }

            try {
                Field fDetailSigs;
                try {
                    fDetailSigs = details.getClass().getDeclaredField("signatures");
                } catch (NoSuchFieldException e) {
                    fDetailSigs = details.getClass().getDeclaredField("mSignatures");
                }
                fDetailSigs.setAccessible(true);
                fDetailSigs.set(details, new Signature[]{fakeSig});
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }
    }

    private static void patchActivityThreadPackageManager(Object proxyIPM) {
        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method cur = atClz.getDeclaredMethod("currentActivityThread");
            cur.setAccessible(true);
            Object at = cur.invoke(null);
            if (at == null) return;

            Field fSPM;
            try {
                fSPM = atClz.getDeclaredField("sPackageManager");
            } catch (NoSuchFieldException e) {
                return;
            }
            fSPM.setAccessible(true);
            Object old = fSPM.get(at);
            if (old != proxyIPM) fSPM.set(at, proxyIPM);
        } catch (Throwable ignored) {
        }
    }

    private static void patchApplicationPackageManager(Object proxyIPM) {
        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method curApp = atClz.getDeclaredMethod("currentApplication");
            curApp.setAccessible(true);
            Object app = curApp.invoke(null);
            if (!(app instanceof Application)) return;
            PackageManager pm = ((Application) app).getPackageManager();
            Field fMPM = findField(pm.getClass(), "mPM");
            Object old = fMPM.get(pm);
            if (old != proxyIPM) fMPM.set(pm, proxyIPM);
        } catch (Throwable ignored) {
        }
    }

    /** native 层 open/readlinkat 重定向（一次性） **/
    private static void killOpen(String pkg) {
        Log.d(TAG, "killOpen: 去除 Open 检测，将重定向到 assets 内的 origin.apk");
        try {
            // 1) 加载 so（名称要和你编译出的 lib<name>.so 一致）
            System.loadLibrary(LIB_NAME);

            // 2) 找到当前 APK 的 base.apk 路径
            String apkPath = findSelfApkPath(pkg);
            if (apkPath == null) {
                Log.e(TAG, "未找到自身 base.apk 路径");
                return;
            }
            File apkFile = new File(apkPath);

            // 3) 准备 /data/data/<pkg>/origin.apk
            File dataDir = ensureDataDir(pkg);
            File redirected = new File(dataDir, "origin.apk");

            // 4) 若不存在或大小不一致，则从 assets/KillSig/origin.apk 解压一份
            try (ZipFile zip = new ZipFile(apkFile)) {
                ZipEntry entry = zip.getEntry("assets/KillSig/origin.apk");
                if (entry == null) {
                    Log.e(TAG, "未找到 assets/KillSig/origin.apk");
                    return;
                }
                if (!redirected.exists() || redirected.length() != entry.getSize()) {
                    try (InputStream is = zip.getInputStream(entry);
                         OutputStream os = new FileOutputStream(redirected)) {
                        byte[] buf = new byte[64 * 1024];
                        int n;
                        while ((n = is.read(buf)) != -1) {
                            os.write(buf, 0, n);
                        }
                    }
                }
            }

            // 5) 安装 SVC 拦截（把 base.apk 重定向到 /data/data/.../origin.apk）
            hookApkPath(apkFile.getAbsolutePath(), redirected.getAbsolutePath());
            Log.d(TAG, "killOpen: io重定向 完成");
        } catch (Throwable t) {
            Log.e(TAG, "加载/安装 native 重定向失败: " + t.getMessage(), t);
        }
    }

    /** 读取 /proc/self/maps 寻找自身 base.apk 路径 */
    private static String findSelfApkPath(String pkg) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int sp = line.lastIndexOf(' ');
                if (sp <= 0) continue;
                String path = line.substring(sp + 1);
                if (isApkPathOf(pkg, path)) {
                    return path;
                }
            }
        } catch (Throwable e) {
            Log.e(TAG, "findSelfApkPath 失败: " + e.getMessage());
        }
        return null;
    }

    /** 判断是否是该包的 base.apk */
    private static boolean isApkPathOf(String pkg, String path) {
        if (path == null) return false;
        path = path.trim();
        if (!path.startsWith("/") || !path.endsWith(".apk")) return false;
        // 常见：/data/app/<something>/<pkg>-<...>/base.apk
        if (path.contains("/data/app/") && path.endsWith("/base.apk") && path.contains("/" + pkg + "-")) {
            return true;
        }
        // 兼容 mnt/expand 等情况
        if (path.contains("/mnt/expand/") && path.endsWith("/base.apk") && path.contains("/" + pkg)) {
            return true;
        }
        return false;
    }

    /** 返回 /data/data/<pkg>（若 /data/user/<n>/<pkg> 可写则优先用它） */
    private static File ensureDataDir(String pkg) {
        String username = Environment.getExternalStorageDirectory().getName();
        File dir;
        if (username != null && username.matches("\\d+")) {
            dir = new File("/data/user/" + username + "/" + pkg);
            if (!dir.canWrite()) dir = new File("/data/data/" + pkg);
        } else {
            dir = new File("/data/data/" + pkg);
        }
        if (!dir.exists()) {
            // 尽量创建；失败也不致命
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        return dir;
    }

    /** 清理 PackageManager 缓存（可能被隐藏 API 限制拦截，忽略异常即可） */
    private static void clearPackageManagerInfoCache() {
        try {
            Object cache = findField(PackageManager.class, "sPackageInfoCache").get(null);
            if (cache != null) {
                cache.getClass().getMethod("clear").invoke(cache);
            }
        } catch (Throwable ignored) {
        }
    }

    private static Field findField(Class<?> c, String name) throws Exception {
        Class<?> cur = c;
        while (cur != null) {
            try {
                Field f = cur.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignore) {
                cur = cur.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name + " in " + c.getName());
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "HookApplication onCreate()");
        // 这里不再重复 init；静态块已做一次性保护
    }
}
