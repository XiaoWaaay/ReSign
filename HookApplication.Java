package com.xwaaa.hook;

import android.app.Activity;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Parcel;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import top.canyie.pine.Pine;
import top.canyie.pine.PineConfig;
import top.canyie.pine.callback.MethodHook;

/**
 * 修复版 HookApplication
 * 1. 优化 Pine 初始化时机。
 * 2. 修复 Android 13+ (API 33) PackageInfoFlags 兼容性。
 * 3. 增强签名替换逻辑，深度反射 SigningInfo。
 * 4. 移除不稳定的 Proxy Hook，专注于 ApplicationPackageManager。
 */
public class HookApplication extends Application {
    private static final String TAG = "HookApplication";
    private static final String PAYLOAD_ID = "payload-2026-01-13-FIXED";

    static String packageName = "xwaaa.package";
    static String signatureData = "xwaaa resig";
    static String originalApplicationClass = "xwaaa.original_app";
    static String originalAppComponentFactoryClass = "xwaaa.original_factory";

    private static final AtomicBoolean INIT_ONCE = new AtomicBoolean(false);
    private static final AtomicBoolean PM_HOOKED = new AtomicBoolean(false);
    private static final AtomicBoolean PINE_INITED = new AtomicBoolean(false);
    private static final AtomicBoolean NATIVE_INITED = new AtomicBoolean(false);

    private static final ConcurrentHashMap<String, Boolean> HOOKED_METHODS = new ConcurrentHashMap<>();

    private static volatile Signature sFakeSig;
    private static volatile X509Certificate sFakeCert;
    private static volatile int sTargetUid = -1;

    private static final String LIB_NAME = "killsignture";

    private static native void hookApkPath(String sourceApkPath, String redirectedApkPath);

    private static native void hookApkPathWithBackend(String sourceApkPath, String redirectedApkPath, int backend);

    private static native int getRedirectBackend();

    private static native void setMapsHideEnabled(boolean enabled);

    private static volatile Application sDelegateApp;
    private static volatile Object sDelegateFactory;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        log("attachBaseContext: " + base.getPackageName());

        initPine();
        initSignatureData(base);
        initHooks(base);
        handleDelegateAttach(base);
        hideManifestTraces(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        log("onCreate");

        if (sDelegateApp != null) {
            hideDeepTraces(getBaseContext());
            log("Calling delegate onCreate: " + sDelegateApp.getClass().getName());
            sDelegateApp.onCreate();
            hideDeepTraces(getBaseContext());
        }
    }

    private void initPine() {
        if (PINE_INITED.compareAndSet(false, true)) {
            try {
                PineConfig.debug = true;
                PineConfig.debuggable = true;
                PineConfig.disableHiddenApiPolicy = true;
                PineConfig.disableHiddenApiPolicyForPlatformDomain = true;
                PineConfig.antiChecks = true;

                Pine.ensureInitialized();
                Pine.disableHiddenApiPolicy(true, true);
            } catch (Throwable e) {
                Log.e(TAG, "Pine init failed", e);
            }
        }
    }

    private void initSignatureData(Context context) {
        try {
            byte[] bytes = null;
            if (signatureData != null && !signatureData.isEmpty()) {
                try {
                    bytes = Base64.decode(signatureData, Base64.DEFAULT);
                } catch (Throwable ignored) {
                }
            }

            if (bytes == null || bytes.length == 0) {
                File originApk = ensureOriginApkExtracted(context);
                if (originApk != null && originApk.exists()) {
                    bytes = readFirstX509CertFromApk(originApk.getAbsolutePath());
                }
            }

            if (bytes == null || bytes.length == 0) return;

            sFakeSig = new Signature(bytes);

            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            sFakeCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));

            sTargetUid = Process.myUid();
            log("Signature data loaded. Length: " + bytes.length);
        } catch (Throwable e) {
            Log.e(TAG, "Failed to parse signature data", e);
        }
    }

    private void initHooks(Context context) {
        if (!INIT_ONCE.compareAndSet(false, true)) return;

        if (sFakeSig != null) {
            boolean success = installPackageManagerHooks(context);
            PM_HOOKED.set(success);
            log("PM Hook installed: " + success);
        }

        installNativeHooks(context);
    }

    private void installNativeHooks(Context context) {
        if (!NATIVE_INITED.compareAndSet(false, true)) return;
        if (context == null) return;

        boolean enableNativeHook = getBooleanMeta(context, "resig.enableNativeHook", true);
        boolean enableIoRedirect = getBooleanMeta(context, "resig.enableIoRedirect", true);
        if (!enableNativeHook || !enableIoRedirect) return;

        try {
            System.loadLibrary(LIB_NAME);
        } catch (Throwable t) {
            Log.e(TAG, "Load native library failed: " + LIB_NAME, t);
            return;
        }

        String sourceApkPath = null;
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if (ai != null) sourceApkPath = ai.sourceDir;
        } catch (Throwable ignored) {
        }

        if (sourceApkPath == null || sourceApkPath.isEmpty()) return;

        File repFile = ensureOriginApkExtracted(context);
        if (repFile == null || !repFile.exists() || repFile.length() <= 0) return;

        try {
            boolean enableMapsHide = getBooleanMeta(context, "resig.enableMapsHide", true);
            try {
                setMapsHideEnabled(enableMapsHide);
            } catch (Throwable ignored) {
            }
            hookApkPath(sourceApkPath, repFile.getAbsolutePath());
            log("Native hook installed. backend=" + getRedirectBackend());
        } catch (Throwable t) {
            Log.e(TAG, "Native hook install failed", t);
        }
    }

    private void hideManifestTraces(Context base) {
        if (base == null) return;
        try {
            Object loadedApk = null;
            try {
                Field mPackageInfoField = Class.forName("android.app.ContextImpl").getDeclaredField("mPackageInfo");
                mPackageInfoField.setAccessible(true);
                loadedApk = mPackageInfoField.get(base);
            } catch (Throwable ignored) {
            }

            ApplicationInfo appInfo = null;
            try {
                appInfo = base.getApplicationInfo();
            } catch (Throwable ignored) {
            }
            if (appInfo == null) return;

            if (originalApplicationClass != null && !originalApplicationClass.isEmpty()) {
                forceSetField(ApplicationInfo.class, appInfo, "className", originalApplicationClass);
                if (loadedApk != null) {
                    try {
                        forceSetField(loadedApk.getClass(), loadedApk, "mAppClassName", originalApplicationClass);
                    } catch (Throwable ignored) {
                    }
                }
            }

            if (Build.VERSION.SDK_INT >= 28
                    && originalAppComponentFactoryClass != null
                    && !originalAppComponentFactoryClass.isEmpty()) {
                try {
                    forceSetField(ApplicationInfo.class, appInfo, "appComponentFactory", originalAppComponentFactoryClass);
                } catch (Throwable ignored) {
                }
            }

            Log.d(TAG, "Traces hidden: className restored to " + appInfo.className);
        } catch (Throwable e) {
            Log.e(TAG, "Failed to hide traces", e);
        }
    }

    /**
     * 深度隐藏痕迹：替换 ActivityThread 和 LoadedApk 中的对象引用
     */
    private void hideDeepTraces(Context context) {
        try {
            // 1. 获取 ActivityThread 实例
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentAtMethod = atClass.getDeclaredMethod("currentActivityThread");
            currentAtMethod.setAccessible(true);
            Object activityThread = currentAtMethod.invoke(null);

            // 2. 获取 LoadedApk (即 mPackageInfo)
            // 这是系统用来维护当前包信息的核心对象
            Object loadedApk = null;
            try {
                Field mPackageInfoField = context.getClass().getDeclaredField("mPackageInfo");
                mPackageInfoField.setAccessible(true);
                loadedApk = mPackageInfoField.get(context);
            } catch (Throwable t) {
                // 备用：部分系统 ContextImpl 可能有所不同，这里忽略错误
            }

            if (loadedApk == null) return;

            // =======================================================
            // 步骤 A: 替换 Application 实例
            // 解决 application.getClass().getName() 暴露的问题
            // =======================================================
            if (sDelegateApp != null) {
                // 1. 修改 ActivityThread.mInitialApplication
                Field mInitialAppField = atClass.getDeclaredField("mInitialApplication");
                mInitialAppField.setAccessible(true);
                mInitialAppField.set(activityThread, sDelegateApp);

                // 2. 修改 ActivityThread.mAllApplications 列表
                Field mAllAppsField = atClass.getDeclaredField("mAllApplications");
                mAllAppsField.setAccessible(true);
                java.util.ArrayList<?> allApps = (java.util.ArrayList<?>) mAllAppsField.get(activityThread);
                if (allApps != null) {
                    for (int i = 0; i < allApps.size(); i++) {
                        // 找到列表中的“壳”对象 (即 this)，替换为“真身”
                        if (allApps.get(i) == this) {
                            //noinspection unchecked
                            ((java.util.ArrayList<Object>) allApps).set(i, sDelegateApp);
                        }
                    }
                }

                // 3. 修改 LoadedApk.mApplication
                Field mAppField = loadedApk.getClass().getDeclaredField("mApplication");
                mAppField.setAccessible(true);
                mAppField.set(loadedApk, sDelegateApp);
            }

            // =======================================================
            // 步骤 B: 隐藏类名字符串 (ApplicationInfo)
            // 解决 getApplicationInfo().className 暴露的问题
            // =======================================================
            if (originalApplicationClass != null && !originalApplicationClass.isEmpty()) {
                // 1. 修改 ApplicationInfo.className
                ApplicationInfo appInfo = context.getApplicationInfo();
                Field classNameField = ApplicationInfo.class.getDeclaredField("className");
                classNameField.setAccessible(true);
                classNameField.set(appInfo, originalApplicationClass);

                // 2. 修改 LoadedApk.mAppClassName
                Field mAppClassNameField = loadedApk.getClass().getDeclaredField("mAppClassName");
                mAppClassNameField.setAccessible(true);
                mAppClassNameField.set(loadedApk, originalApplicationClass);
            }

            // =======================================================
            // 步骤 C: 替换 Factory 实例
            // 解决 getAppComponentFactory() 暴露的问题
            // =======================================================
            if (Build.VERSION.SDK_INT >= 28 && originalAppComponentFactoryClass != null && !originalAppComponentFactoryClass.isEmpty()) {
                // 1. 修改 ApplicationInfo 中的字符串
                ApplicationInfo appInfo = context.getApplicationInfo();
                Field factoryStrField = ApplicationInfo.class.getDeclaredField("appComponentFactory");
                factoryStrField.setAccessible(true);
                factoryStrField.set(appInfo, originalAppComponentFactoryClass);

                // 2. 【关键】替换 LoadedApk.mAppComponentFactory 对象实例
                // 系统检测代码通常是检查这个对象的类型
                try {
                    Field mFactoryField = loadedApk.getClass().getDeclaredField("mAppComponentFactory");
                    mFactoryField.setAccessible(true);

                    // 如果还没初始化过原始 Factory，现在反射创建一个
                    if (sDelegateFactory == null) {
                        Class<?> factoryCls = Class.forName(originalAppComponentFactoryClass);
                        Constructor<?> constructor = factoryCls.getConstructor();
                        sDelegateFactory = constructor.newInstance();
                    }

                    // 强行替换
                    mFactoryField.set(loadedApk, sDelegateFactory);
                } catch (Throwable t) {
                    Log.e(TAG, "Replace Factory failed", t);
                }
            }

        } catch (Throwable e) {
            Log.e(TAG, "Hide traces failed", e);
        }
    }

    private void swapApplicationInstance() {
        if (sDelegateApp == null) return;

        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentAt = atClass.getDeclaredMethod("currentActivityThread");
            currentAt.setAccessible(true);
            Object activityThread = currentAt.invoke(null);
            if (activityThread == null) return;

            try {
                Field mInitialAppField = atClass.getDeclaredField("mInitialApplication");
                mInitialAppField.setAccessible(true);
                mInitialAppField.set(activityThread, sDelegateApp);
            } catch (Throwable ignored) {
            }

            try {
                Field mAllAppsField = atClass.getDeclaredField("mAllApplications");
                mAllAppsField.setAccessible(true);
                Object listObj = mAllAppsField.get(activityThread);
                if (listObj instanceof ArrayList) {
                    ArrayList<?> allApps = (ArrayList<?>) listObj;
                    for (int i = 0; i < allApps.size(); i++) {
                        if (allApps.get(i) == this) {
                            ((ArrayList) allApps).set(i, sDelegateApp);
                        }
                    }
                }
            } catch (Throwable ignored) {
            }

            try {
                Context base = getBaseContext();
                if (base != null) {
                    Field mPackageInfoField = Class.forName("android.app.ContextImpl").getDeclaredField("mPackageInfo");
                    mPackageInfoField.setAccessible(true);
                    Object loadedApk = mPackageInfoField.get(base);
                    if (loadedApk != null) {
                        Field mApplicationField = loadedApk.getClass().getDeclaredField("mApplication");
                        mApplicationField.setAccessible(true);
                        mApplicationField.set(loadedApk, sDelegateApp);
                    }
                }
            } catch (Throwable ignored) {
            }

            Log.d(TAG, "Application instance swapped to original");
        } catch (Throwable e) {
            Log.e(TAG, "Failed to swap application instance", e);
        }
    }

    private void forceSetField(Class<?> clazz, Object target, String fieldName, Object value) throws Exception {
        Field f = clazz.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    private boolean installPackageManagerHooks(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            if (pm != null) {
                Class<?> pmClass = pm.getClass();
                log("Hooking PackageManager class: " + pmClass.getName());
                hookMethodsInPackageManager(pmClass);
            }

            try {
                Class<?> atClass = Class.forName("android.app.ActivityThread");
                Method getPm = atClass.getDeclaredMethod("getPackageManager");
                safeHook(getPm, new MethodHook() {
                    @Override
                    public void afterCall(Pine.CallFrame callFrame) throws Throwable {
                        Object result = callFrame.getResult();
                        if (result != null) {
                            log("ActivityThread.getPackageManager returned: " + result.getClass().getName());
                        }
                    }
                });
            } catch (Throwable ignored) {
            }

            hookParcelableCreators();

            return true;
        } catch (Throwable e) {
            Log.e(TAG, "installPackageManagerHooks failed", e);
            return false;
        }
    }

    private void hookMethodsInPackageManager(Class<?> pmClass) {
        Set<String> targetMethods = new HashSet<>(Arrays.asList(
                "getPackageInfo",
                "getPackageInfoAsUser",
                "getInstalledPackages",
                "getInstalledPackagesAsUser",
                "getPackageArchiveInfo"
        ));

        Method[] methods = pmClass.getDeclaredMethods();
        List<Method> allMethods = new ArrayList<>(Arrays.asList(methods));
        try {
            allMethods.addAll(Arrays.asList(pmClass.getMethods()));
        } catch (Throwable ignored) {
        }

        for (Method method : allMethods) {
            String name = method.getName();
            if (!targetMethods.contains(name)) continue;
            if (method.isBridge() || method.isSynthetic()) continue;

            if (name.startsWith("getPackageInfo")) {
                Class<?>[] params = method.getParameterTypes();
                if (method.getReturnType() != PackageInfo.class) continue;
                if (params.length > 0 && params[0] == String.class) {
                    safeHook(method, new PackageInfoHook());
                } else if (Build.VERSION.SDK_INT >= 33 && params.length > 0 && params[0] == String.class) {
                    safeHook(method, new PackageInfoHook());
                }
            } else if (name.startsWith("getInstalledPackages")) {
                if (method.getReturnType() == List.class) {
                    safeHook(method, new InstalledPackagesHook());
                }
            } else if (name.equals("getPackageArchiveInfo")) {
                if (method.getReturnType() == PackageInfo.class) {
                    safeHook(method, new ArchiveInfoHook());
                }
            }
        }
    }

    private void hookParcelableCreators() {
        try {
            Field creatorField = PackageInfo.class.getField("CREATOR");
            Object creator = creatorField.get(null);
            if (creator != null) {
                Method createFromParcel = creator.getClass().getMethod("createFromParcel", Parcel.class);
                safeHook(createFromParcel, new MethodHook() {
                    @Override
                    public void afterCall(Pine.CallFrame callFrame) {
                        Object result = callFrame.getResult();
                        if (result instanceof PackageInfo) {
                            PackageInfo pi = (PackageInfo) result;
                            if (shouldPatch(pi.packageName)) {
                                patchPackageInfo(pi);
                            }
                        }
                    }
                });
            }
        } catch (Throwable e) {
            Log.w(TAG, "Hook PackageInfo.CREATOR failed: " + e.getMessage());
        }

        if (Build.VERSION.SDK_INT >= 28) {
            try {
                Class<?> signingInfoClass = Class.forName("android.content.pm.SigningInfo");
                Field creatorField = signingInfoClass.getField("CREATOR");
                Object creator = creatorField.get(null);
                if (creator != null) {
                    Method createFromParcel = creator.getClass().getMethod("createFromParcel", Parcel.class);
                    safeHook(createFromParcel, new MethodHook() {
                        @Override
                        public void afterCall(Pine.CallFrame callFrame) {
                            Object result = callFrame.getResult();
                            if (result != null) {
                                patchSigningInfo(result);
                            }
                        }
                    });
                }
            } catch (Throwable e) {
                Log.w(TAG, "Hook SigningInfo.CREATOR failed: " + e.getMessage());
            }
        }
    }

    private class PackageInfoHook extends MethodHook {
        @Override
        public void afterCall(Pine.CallFrame callFrame) throws Throwable {
            Object result = callFrame.getResult();
            if (result instanceof PackageInfo) {
                PackageInfo pi = (PackageInfo) result;
                String reqPkg = null;
                if (callFrame.args.length > 0 && callFrame.args[0] instanceof String) {
                    reqPkg = (String) callFrame.args[0];
                }

                if (shouldPatch(reqPkg) || shouldPatch(pi.packageName)) {
                    log("Patching getPackageInfo for: " + pi.packageName);
                    patchPackageInfo(pi);
                }
            }
        }
    }

    private class ArchiveInfoHook extends MethodHook {
        @Override
        public void afterCall(Pine.CallFrame callFrame) {
            Object result = callFrame.getResult();
            if (result instanceof PackageInfo) {
                patchPackageInfo((PackageInfo) result);
            }
        }
    }

    private class InstalledPackagesHook extends MethodHook {
        @Override
        public void afterCall(Pine.CallFrame callFrame) {
            Object result = callFrame.getResult();
            if (result instanceof List) {
                List<?> list = (List<?>) result;
                for (Object item : list) {
                    if (item instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) item;
                        if (shouldPatch(pi.packageName)) {
                            patchPackageInfo(pi);
                        }
                    }
                }
            }
        }
    }

    private void patchPackageInfo(PackageInfo pi) {
        if (pi == null || sFakeSig == null) return;

        if (pi.signatures != null && pi.signatures.length > 0) {
            pi.signatures[0] = sFakeSig;
            for (int i = 1; i < pi.signatures.length; i++) {
                pi.signatures[i] = sFakeSig;
            }
        } else {
            pi.signatures = new Signature[]{sFakeSig};
        }

        if (Build.VERSION.SDK_INT >= 28) {
            if (pi.signingInfo != null) {
                patchSigningInfo(pi.signingInfo);
            }
        }
    }

    private void patchSigningInfo(Object signingInfo) {
        if (signingInfo == null) return;
        try {
            Class<?> clazz = signingInfo.getClass();
            Field mSigningDetailsField = findFieldRecursive(clazz, "mSigningDetails");

            if (mSigningDetailsField != null) {
                Object signingDetails = mSigningDetailsField.get(signingInfo);
                if (signingDetails != null) {
                    Class<?> detailsClass = signingDetails.getClass();
                    Field signaturesField = findFieldRecursive(detailsClass, "signatures");
                    if (signaturesField != null) {
                        signaturesField.set(signingDetails, new Signature[]{sFakeSig});
                    }

                    Field pastSignaturesField = findFieldRecursive(detailsClass, "pastSigningCertificates");
                    if (pastSignaturesField != null) {
                        pastSignaturesField.set(signingDetails, new Signature[]{sFakeSig});
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private boolean shouldPatch(String pkgName) {
        if (pkgName == null) return false;
        return pkgName.equals(packageName) || pkgName.equals(sTargetPkg);
    }

    private static String sTargetPkg = packageName;

    private void safeHook(Method method, MethodHook hook) {
        if (method == null) return;
        String key = method.getDeclaringClass().getName() + "#" + method.getName() + Arrays.toString(method.getParameterTypes());

        if (HOOKED_METHODS.containsKey(key)) return;

        try {
            Pine.hook(method, hook);
            HOOKED_METHODS.put(key, true);
            log("Hook success: " + key);
        } catch (Throwable e) {
            Log.e(TAG, "Hook failed: " + key + " Error: " + e.getMessage());
        }
    }

    private Field findFieldRecursive(Class<?> clazz, String fieldName) {
        Class<?> curr = clazz;
        while (curr != null && curr != Object.class) {
            try {
                Field f = curr.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException e) {
                curr = curr.getSuperclass();
            }
        }
        return null;
    }

    private void log(String msg) {
        if (PineConfig.debug) {
            Log.d(TAG, msg);
        }
    }

    private static boolean getBooleanMeta(Context context, String key, boolean defValue) {
        try {
            ApplicationInfo ai = context.getPackageManager().getApplicationInfo(
                    context.getPackageName(),
                    PackageManager.GET_META_DATA
            );
            if (ai != null && ai.metaData != null && ai.metaData.containsKey(key)) {
                Object v = ai.metaData.get(key);
                if (v instanceof Boolean) return (Boolean) v;
                if (v instanceof String) return Boolean.parseBoolean((String) v);
                if (v instanceof Integer) return ((Integer) v) != 0;
            }
        } catch (Throwable ignored) {
        }
        return defValue;
    }

    private static File ensureOriginApkExtracted(Context context) {
        if (context == null) return null;
        try {
            File out = new File(context.getFilesDir(), "origin.apk");
            if (out.exists() && out.length() > 0) return out;

            File temp = new File(context.getFilesDir(), "origin.apk.tmp");
            try {
                if (temp.exists()) temp.delete();
            } catch (Throwable ignored) {
            }

            InputStream is = null;
            OutputStream os = null;
            try {
                is = context.getAssets().open("KillSig/origin.apk");
                os = new FileOutputStream(temp);
                byte[] buf = new byte[1024 * 128];
                while (true) {
                    int len = is.read(buf);
                    if (len == -1) break;
                    os.write(buf, 0, len);
                }
                os.flush();
                try {
                    ((FileOutputStream) os).getFD().sync();
                } catch (Throwable ignored) {
                }

                if (temp.renameTo(out)) return out;
                try {
                    if (out.exists() && out.delete()) {
                        if (temp.renameTo(out)) return out;
                    }
                } catch (Throwable ignored) {
                }
                return out;
            } finally {
                try {
                    if (os != null) os.close();
                } catch (Throwable ignored) {
                }
                try {
                    if (is != null) is.close();
                } catch (Throwable ignored) {
                }
                try {
                    if (temp.exists()) temp.delete();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static byte[] readFirstX509CertFromApk(String apkPath) throws Exception {
        ZipFile zip = new ZipFile(new File(apkPath));
        try {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry == null) continue;
                String name = entry.getName();
                if (name == null) continue;
                if (!name.startsWith("META-INF/")) continue;
                if (!(name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) continue;

                InputStream is = zip.getInputStream(entry);
                try {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(is);
                    return x509.getEncoded();
                } finally {
                    try {
                        is.close();
                    } catch (Throwable ignored) {
                    }
                }
            }
            return null;
        } finally {
            try {
                zip.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private void handleDelegateAttach(Context base) {
        if (originalApplicationClass == null || originalApplicationClass.isEmpty()) return;
        if (originalApplicationClass.equals(this.getClass().getName())) return;

        try {
            Class<?> delegateClass = Class.forName(originalApplicationClass);
            Constructor<?> constructor = delegateClass.getConstructor();
            sDelegateApp = (Application) constructor.newInstance();

            Method attachMethod = ContextWrapper.class.getDeclaredMethod("attachBaseContext", Context.class);
            attachMethod.setAccessible(true);
            attachMethod.invoke(sDelegateApp, base);

            log("Delegate app attached: " + originalApplicationClass);
        } catch (Throwable e) {
            Log.e(TAG, "Failed to create/attach delegate application", e);
        }
    }

    public static class DelegatingAppComponentFactory extends android.app.AppComponentFactory {
        private android.app.AppComponentFactory mOrigin;

        private android.app.AppComponentFactory getOrigin() {
            if (mOrigin == null && originalAppComponentFactoryClass != null && !originalAppComponentFactoryClass.isEmpty()) {
                try {
                    Class<?> cls = Class.forName(originalAppComponentFactoryClass);
                    mOrigin = (android.app.AppComponentFactory) cls.newInstance();
                } catch (Throwable e) {
                    Log.e(TAG, "Failed to instantiate origin factory", e);
                }
            }
            return mOrigin;
        }

        @Override
        public Application instantiateApplication(ClassLoader cl, String className)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            return super.instantiateApplication(cl, className);
        }

        @Override
        public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            if (getOrigin() != null) return getOrigin().instantiateActivity(cl, className, intent);
            return super.instantiateActivity(cl, className, intent);
        }

        @Override
        public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            if (getOrigin() != null) return getOrigin().instantiateReceiver(cl, className, intent);
            return super.instantiateReceiver(cl, className, intent);
        }

        @Override
        public Service instantiateService(ClassLoader cl, String className, Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            if (getOrigin() != null) return getOrigin().instantiateService(cl, className, intent);
            return super.instantiateService(cl, className, intent);
        }

        @Override
        public ContentProvider instantiateProvider(ClassLoader cl, String className)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            if (getOrigin() != null) return getOrigin().instantiateProvider(cl, className);
            return super.instantiateProvider(cl, className);
        }
    }
}
