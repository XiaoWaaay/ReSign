package com.resign.pro.payload;

import android.app.Activity;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import top.canyie.pine.Pine;
import top.canyie.pine.callback.MethodHook;
import top.canyie.pine.callback.MethodReplacement;

/**
 * ReSignPro Payload 入口类
 * 
 * 替换目标应用的Application，在运行时安装签名伪装hook链
 * 编译为独立DEX后注入到目标APK中
 * 
 * 核心能力：
 * 1. 签名伪装（Java层 PackageManager/Parcelable/Binder 全链路）
 * 2. Native库加载与IO重定向
 * 3. Application/AppComponentFactory生命周期委托
 * 4. Deep Hide（替换系统持有的Application引用）
 * 5. 自动降级（AGGRESSIVE -> STANDARD -> SAFE）
 */
public class HookEntry extends Application {

    private static final String TAG = "ReSignPro";

    // ========== 占位符字段（pack-time由DexInjector填充） ==========
    private static final String TARGET_PKG            = "$$RESIGN_PKG$$";
    private static final String SIGNATURE_HEX         = "$$RESIGN_SIG$$";
    private static final String ORIGINAL_APP_CLASS    = "$$RESIGN_APP_CLASS$$";
    private static final String ORIGINAL_FACTORY_CLASS= "$$RESIGN_FACTORY$$";
    private static final String CFG_JAVA_HOOK         = "$$RESIGN_JAVA_HOOK$$";
    private static final String CFG_NATIVE_HOOK       = "$$RESIGN_NATIVE_HOOK$$";
    private static final String CFG_IO_REDIRECT       = "$$RESIGN_IO_REDIRECT$$";
    private static final String CFG_MAPS_HIDE         = "$$RESIGN_MAPS_HIDE$$";
    private static final String CFG_DEEP_HIDE         = "$$RESIGN_DEEP_HIDE$$";
    private static final String CFG_DEBUG             = "$$RESIGN_DEBUG$$";
    private static final String CFG_HOOK_MODE         = "$$RESIGN_HOOK_MODE$$";
    private static final String CFG_NATIVE_BACKEND    = "$$RESIGN_NATIVE_BACKEND$$";

    // ========== 运行时状态 ==========
    private static boolean sDebug = false;
    private static HookMode sHookMode = HookMode.STANDARD;
    private static Signature[] sCachedSignatures;
    private static Application sOriginalApp;
    private static String sOriginApkPath;
    private static boolean sJavaHookInstalled = false;
    private static boolean sNativeLoaded = false;

    /** Hook模式 */
    public enum HookMode {
        SAFE,       // 仅PackageManager.getPackageInfo
        STANDARD,   // PM + Parcelable CREATOR + SigningInfo + 路径重定向
        AGGRESSIVE  // 全量: Binder层 + 归档签名 + checkSignatures + Deep Hide
    }

    // ==================== Application 生命周期 ====================

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        long t0 = System.currentTimeMillis();

        try {
            // 1. 解析配置
            parseConfig();
            logd("=== ReSignPro payload init ===");
            logd("pkg=" + TARGET_PKG + ", mode=" + sHookMode + ", debug=" + sDebug);

            // 2. 提取origin.apk（必须在hook前完成，ContentProvider可能先于onCreate执行）
            extractOriginApk(base);

            // 3. 安装Java层签名hook（越早越好，Provider初始化前）
            if (bool(CFG_JAVA_HOOK)) {
                installJavaHooks(base);
            }

            // 4. 加载Native库
            if (bool(CFG_NATIVE_HOOK)) {
                loadNativeEngine(base);
            }

            // 5. 创建并委托原始Application
            sOriginalApp = createOriginalApp(base);
            if (sOriginalApp != null) {
                invokeAttachBaseContext(sOriginalApp, base);
            }

            logd("init完成, 耗时: " + (System.currentTimeMillis() - t0) + "ms");

        } catch (Throwable t) {
            loge("attachBaseContext异常", t);
            // 尝试降级
            tryDowngrade(t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            // Deep Hide: 替换系统持有的Application引用
            if (bool(CFG_DEEP_HIDE) && sHookMode == HookMode.AGGRESSIVE) {
                performDeepHide();
            }

            // 委托原始Application.onCreate
            if (sOriginalApp != null) {
                sOriginalApp.onCreate();
            }
        } catch (Throwable t) {
            loge("onCreate异常", t);
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (sOriginalApp != null) sOriginalApp.onConfigurationChanged(newConfig);
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (sOriginalApp != null) sOriginalApp.onLowMemory();
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (sOriginalApp != null) sOriginalApp.onTrimMemory(level);
    }

    // ==================== 配置解析 ====================

    private void parseConfig() {
        sDebug = bool(CFG_DEBUG);
        try {
            sHookMode = HookMode.valueOf(CFG_HOOK_MODE);
        } catch (Exception e) {
            sHookMode = HookMode.STANDARD;
        }

        // 解析签名hex -> Signature[]
        sCachedSignatures = parseSignatures(SIGNATURE_HEX);
    }

    /** 解析hex编码的签名数据（多个签名用|分隔） */
    private static Signature[] parseSignatures(String hex) {
        if (hex == null || hex.isEmpty() || hex.startsWith("$$")) {
            return new Signature[0];
        }
        String[] parts = hex.split("\\|");
        Signature[] sigs = new Signature[parts.length];
        for (int i = 0; i < parts.length; i++) {
            sigs[i] = new Signature(hexToBytes(parts[i]));
        }
        return sigs;
    }

    // ==================== Origin APK 提取 ====================

    /** 从assets提取origin.apk到files目录（原子写入） */
    private void extractOriginApk(Context ctx) {
        try {
            File target = new File(ctx.getFilesDir(), "origin.apk");
            sOriginApkPath = target.getAbsolutePath();

            if (target.exists() && target.length() > 0) {
                logd("origin.apk已存在: " + sOriginApkPath);
                return;
            }

            File tmp = new File(ctx.getFilesDir(), "origin.apk.tmp");
            try (InputStream is = ctx.getAssets().open("resign_pro/origin.apk");
                 FileOutputStream fos = new FileOutputStream(tmp)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = is.read(buf)) != -1) {
                    fos.write(buf, 0, n);
                }
                fos.getFD().sync();
            }

            // 原子rename
            if (!tmp.renameTo(target)) {
                // rename失败则copy
                copyFile(tmp, target);
                tmp.delete();
            }

            logd("origin.apk提取完成: " + target.length() + " bytes");
        } catch (Throwable t) {
            loge("提取origin.apk失败", t);
        }
    }

    // ==================== Java签名Hook ====================

    /** 安装Java层签名hook（分级） */
    private void installJavaHooks(Context ctx) {
        if (sJavaHookInstalled || sCachedSignatures == null || sCachedSignatures.length == 0) {
            return;
        }

        try {
            // SAFE级: PackageManager.getPackageInfo签名替换
            installSafeHooks(ctx);

            if (sHookMode.ordinal() >= HookMode.STANDARD.ordinal()) {
                // STANDARD级: CREATOR替换 + 更多PM方法 + 路径重定向
                installStandardHooks(ctx);
            }

            if (sHookMode == HookMode.AGGRESSIVE) {
                // AGGRESSIVE级: Binder层 + 归档签名 + checkSignatures
                installAggressiveHooks(ctx);
            }

            sJavaHookInstalled = true;
            logd("Java hook安装完成, 模式=" + sHookMode);

        } catch (Throwable t) {
            loge("Java hook安装异常, 尝试降级", t);
            tryDowngrade(t);
        }
    }

    // -------- SAFE级Hook --------

    private void installSafeHooks(Context ctx) throws Throwable {
        // Hook PackageManager.getPackageInfo(String, int)
        Method getPackageInfo = PackageManager.class.getDeclaredMethod(
                "getPackageInfo", String.class, int.class);
        Pine.hook(getPackageInfo, new MethodHook() {
            @Override
            public void afterCall(Pine.CallFrame callFrame) {
                PackageInfo pi = (PackageInfo) callFrame.getResult();
                if (pi != null && TARGET_PKG.equals(pi.packageName)) {
                    patchPackageInfoSignatures(pi);
                }
            }
        });
        logd("SAFE: hook getPackageInfo(String,int)");

        // API 33+ 重载: getPackageInfo(String, PackageManager.PackageInfoFlags)
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                Class<?> flagsClass = Class.forName("android.content.pm.PackageManager$PackageInfoFlags");
                Method getPackageInfoFlags = PackageManager.class.getDeclaredMethod(
                        "getPackageInfo", String.class, flagsClass);
                Pine.hook(getPackageInfoFlags, new MethodHook() {
                    @Override
                    public void afterCall(Pine.CallFrame callFrame) {
                        PackageInfo pi = (PackageInfo) callFrame.getResult();
                        if (pi != null && TARGET_PKG.equals(pi.packageName)) {
                            patchPackageInfoSignatures(pi);
                        }
                    }
                });
                logd("SAFE: hook getPackageInfo(String,PackageInfoFlags)");
            } catch (Throwable t) {
                logd("SAFE: API33重载hook跳过: " + t.getMessage());
            }
        }
    }

    // -------- STANDARD级Hook --------

    private void installStandardHooks(Context ctx) throws Throwable {
        // 1. Hook PackageInfo的Parcelable CREATOR
        hookParcelableCreator(PackageInfo.class, "PackageInfo");

        // 2. Hook Signature的Parcelable CREATOR
        hookParcelableCreator(Signature.class, "Signature");

        // 3. API 28+: Hook SigningInfo CREATOR
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                hookParcelableCreator(SigningInfo.class, "SigningInfo");
            } catch (Throwable t) {
                logd("STANDARD: SigningInfo CREATOR hook跳过: " + t.getMessage());
            }
        }

        // 4. Hook getPackageResourcePath / getPackageCodePath
        try {
            Method getResPath = Context.class.getDeclaredMethod("getPackageResourcePath");
            Pine.hook(getResPath, new MethodReplacement() {
                @Override
                public Object replaceCall(Pine.CallFrame callFrame) {
                    if (sOriginApkPath != null) return sOriginApkPath;
                    return callFrame.thisObject != null ?
                            ((Context) callFrame.thisObject).getApplicationInfo().sourceDir : null;
                }
            });

            Method getCodePath = Context.class.getDeclaredMethod("getPackageCodePath");
            Pine.hook(getCodePath, new MethodReplacement() {
                @Override
                public Object replaceCall(Pine.CallFrame callFrame) {
                    if (sOriginApkPath != null) return sOriginApkPath;
                    return callFrame.thisObject != null ?
                            ((Context) callFrame.thisObject).getApplicationInfo().sourceDir : null;
                }
            });
            logd("STANDARD: hook getPackageResourcePath/getPackageCodePath");
        } catch (Throwable t) {
            logd("STANDARD: 路径hook跳过: " + t.getMessage());
        }

        // 5. Hook ApplicationPackageManager内部方法
        try {
            Class<?> apmClass = Class.forName("android.app.ApplicationPackageManager");

            // getPackageInfoAsUser
            for (Method m : apmClass.getDeclaredMethods()) {
                if ("getPackageInfoAsUser".equals(m.getName())) {
                    Pine.hook(m, new MethodHook() {
                        @Override
                        public void afterCall(Pine.CallFrame callFrame) {
                            PackageInfo pi = (PackageInfo) callFrame.getResult();
                            if (pi != null && TARGET_PKG.equals(pi.packageName)) {
                                patchPackageInfoSignatures(pi);
                            }
                        }
                    });
                    logd("STANDARD: hook " + m.getName());
                }
            }
        } catch (Throwable t) {
            logd("STANDARD: APM hook跳过: " + t.getMessage());
        }
    }

    // -------- AGGRESSIVE级Hook --------

    private void installAggressiveHooks(Context ctx) throws Throwable {
        // 1. Hook getPackageArchiveInfo
        try {
            Method archiveInfo = PackageManager.class.getDeclaredMethod(
                    "getPackageArchiveInfo", String.class, int.class);
            Pine.hook(archiveInfo, new MethodHook() {
                @Override
                public void afterCall(Pine.CallFrame callFrame) {
                    PackageInfo pi = (PackageInfo) callFrame.getResult();
                    if (pi != null && TARGET_PKG.equals(pi.packageName)) {
                        patchPackageInfoSignatures(pi);
                    }
                }
            });
            logd("AGGRESSIVE: hook getPackageArchiveInfo");
        } catch (Throwable t) {
            logd("AGGRESSIVE: getPackageArchiveInfo hook跳过: " + t.getMessage());
        }

        // 2. Hook checkSignatures
        try {
            Method checkSig = PackageManager.class.getDeclaredMethod(
                    "checkSignatures", String.class, String.class);
            Pine.hook(checkSig, new MethodReplacement() {
                @Override
                public Object replaceCall(Pine.CallFrame callFrame) throws Throwable {
                    String pkg1 = (String) callFrame.args[0];
                    String pkg2 = (String) callFrame.args[1];
                    if (TARGET_PKG.equals(pkg1) || TARGET_PKG.equals(pkg2)) {
                        return PackageManager.SIGNATURE_MATCH;
                    }
                    return callFrame.invokeOriginalMethod();
                }
            });
            logd("AGGRESSIVE: hook checkSignatures");
        } catch (Throwable t) {
            logd("AGGRESSIVE: checkSignatures hook跳过: " + t.getMessage());
        }

        // 3. API 28+: Hook hasSigningCertificate
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                Method hasSigCert = PackageManager.class.getDeclaredMethod(
                        "hasSigningCertificate", String.class, byte[].class, int.class);
                Pine.hook(hasSigCert, new MethodReplacement() {
                    @Override
                    public Object replaceCall(Pine.CallFrame callFrame) throws Throwable {
                        String pkg = (String) callFrame.args[0];
                        if (TARGET_PKG.equals(pkg)) return true;
                        return callFrame.invokeOriginalMethod();
                    }
                });
                logd("AGGRESSIVE: hook hasSigningCertificate");
            } catch (Throwable t) {
                logd("AGGRESSIVE: hasSigningCertificate hook跳过: " + t.getMessage());
            }
        }

        // 4. Binder层 IPackageManager 代理
        installBinderProxy(ctx);
    }

    // ==================== Binder代理 ====================

    /** 通过动态代理拦截IPackageManager的Binder调用 */
    private void installBinderProxy(Context ctx) {
        try {
            // 获取ActivityThread中的sPackageManager字段
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentAT = atClass.getDeclaredMethod("currentActivityThread");
            currentAT.setAccessible(true);
            Object at = currentAT.invoke(null);

            Field spmField = atClass.getDeclaredField("sPackageManager");
            spmField.setAccessible(true);
            Object originalPM = spmField.get(at);

            if (originalPM == null) {
                logd("Binder代理: sPackageManager为null, 跳过");
                return;
            }

            // 获取IPackageManager接口
            Class<?> ipmClass = Class.forName("android.content.pm.IPackageManager");

            // 创建动态代理
            Object proxy = Proxy.newProxyInstance(
                    ipmClass.getClassLoader(),
                    new Class[]{ipmClass},
                    new PMBinderProxy(originalPM)
            );

            // 替换sPackageManager
            spmField.set(at, proxy);

            // 替换ApplicationPackageManager中的mPM
            PackageManager pm = ctx.getPackageManager();
            Field mPMField = pm.getClass().getDeclaredField("mPM");
            mPMField.setAccessible(true);
            mPMField.set(pm, proxy);

            logd("Binder代理安装完成");
        } catch (Throwable t) {
            logd("Binder代理安装失败: " + t.getMessage());
        }
    }

    /** IPackageManager动态代理 */
    private class PMBinderProxy implements InvocationHandler {
        private final Object original;

        PMBinderProxy(Object original) {
            this.original = original;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object result = method.invoke(original, args);

            String name = method.getName();

            // 拦截返回PackageInfo的方法
            if (result instanceof PackageInfo) {
                PackageInfo pi = (PackageInfo) result;
                if (TARGET_PKG.equals(pi.packageName)) {
                    patchPackageInfoSignatures(pi);
                }
            }

            // 拦截checkSignatures
            if ("checkSignatures".equals(name) && args != null && args.length >= 2) {
                if (TARGET_PKG.equals(args[0]) || TARGET_PKG.equals(args[1])) {
                    return PackageManager.SIGNATURE_MATCH;
                }
            }

            // 拦截hasSigningCertificate
            if ("hasSigningCertificate".equals(name) && args != null && args.length >= 1) {
                if (TARGET_PKG.equals(args[0])) {
                    return true;
                }
            }

            return result;
        }
    }

    // ==================== Parcelable CREATOR Hook ====================

    /** 通用的Parcelable CREATOR hook */
    @SuppressWarnings("unchecked")
    private void hookParcelableCreator(Class<?> clazz, String label) {
        try {
            Field creatorField = clazz.getDeclaredField("CREATOR");
            creatorField.setAccessible(true);

            Parcelable.Creator<?> originalCreator = (Parcelable.Creator<?>) creatorField.get(null);

            Parcelable.Creator<?> hookedCreator = new Parcelable.Creator<Parcelable>() {
                @Override
                public Parcelable createFromParcel(Parcel source) {
                    Parcelable obj = ((Parcelable.Creator<Parcelable>) originalCreator)
                            .createFromParcel(source);
                    if (obj instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) obj;
                        if (TARGET_PKG.equals(pi.packageName)) {
                            patchPackageInfoSignatures(pi);
                        }
                    }
                    return obj;
                }

                @Override
                public Parcelable[] newArray(int size) {
                    return ((Parcelable.Creator<Parcelable>) originalCreator).newArray(size);
                }
            };

            // 使用反射修改static final CREATOR字段
            setStaticFinalField(creatorField, hookedCreator);

            // 同步Parcel中的CREATOR缓存
            syncParcelCreatorCache(clazz, hookedCreator);

            logd("STANDARD: hook " + label + " CREATOR");
        } catch (Throwable t) {
            logd(label + " CREATOR hook失败: " + t.getMessage());
        }
    }

    /** 设置static final字段 */
    private static void setStaticFinalField(Field field, Object value) throws Exception {
        field.setAccessible(true);

        // 尝试直接set（某些VM允许）
        try {
            field.set(null, value);
            return;
        } catch (IllegalAccessException ignored) {}

        // 使用Unsafe（如果可用）
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);

            Method staticFieldOffset = unsafeClass.getDeclaredMethod("staticFieldOffset", Field.class);
            Method putObject = unsafeClass.getDeclaredMethod("putObject", Object.class, long.class, Object.class);
            Method staticFieldBase = unsafeClass.getDeclaredMethod("staticFieldBase", Field.class);

            long offset = (Long) staticFieldOffset.invoke(unsafe, field);
            Object base = staticFieldBase.invoke(unsafe, field);
            putObject.invoke(unsafe, base, offset, value);
        } catch (Exception e) {
            // 最后手段：修改modifiers
            try {
                Field modifiersField = Field.class.getDeclaredField("modifiers");
                modifiersField.setAccessible(true);
                modifiersField.setInt(field, field.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
                field.set(null, value);
            } catch (Exception e2) {
                throw new Exception("无法修改static final字段: " + field, e2);
            }
        }
    }

    /** 同步Parcel内部的CREATOR缓存映射 */
    private static void syncParcelCreatorCache(Class<?> clazz, Parcelable.Creator<?> newCreator) {
        try {
            Field cacheField = Parcel.class.getDeclaredField("sPairedCreators");
            cacheField.setAccessible(true);
            Object cache = cacheField.get(null);
            if (cache instanceof Map) {
                // HashMap<ClassLoader, HashMap<String, Creator>>
                for (Object inner : ((Map<?, ?>) cache).values()) {
                    if (inner instanceof Map) {
                        ((Map<String, Object>) inner).put(clazz.getName(), newCreator);
                    }
                }
            }
        } catch (Throwable ignored) {
            // sPairedCreators可能不存在于所有Android版本
            try {
                Field mCreators = Parcel.class.getDeclaredField("mCreators");
                mCreators.setAccessible(true);
                Object cache = mCreators.get(null);
                if (cache instanceof Map) {
                    for (Object inner : ((Map<?, ?>) cache).values()) {
                        if (inner instanceof Map) {
                            ((Map<String, Object>) inner).put(clazz.getName(), newCreator);
                        }
                    }
                }
            } catch (Throwable ignored2) {}
        }
    }

    // ==================== 签名数据修补 ====================

    /** 修补PackageInfo中的签名信息 */
    private static void patchPackageInfoSignatures(PackageInfo pi) {
        if (pi == null || sCachedSignatures == null || sCachedSignatures.length == 0) return;

        // 修补 signatures 字段 (V1)
        pi.signatures = sCachedSignatures.clone();

        // 修补 signingInfo 字段 (V2/V3, API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && pi.signingInfo != null) {
            patchSigningInfo(pi.signingInfo);
        }
    }

    /** 修补SigningInfo中的签名 */
    private static void patchSigningInfo(SigningInfo si) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || si == null) return;
        try {
            // SigningInfo -> mSigningDetails
            Field detailsField = SigningInfo.class.getDeclaredField("mSigningDetails");
            detailsField.setAccessible(true);
            Object details = detailsField.get(si);
            if (details == null) return;

            // SigningDetails.signatures
            Field sigsField = details.getClass().getDeclaredField("signatures");
            sigsField.setAccessible(true);
            sigsField.set(details, sCachedSignatures.clone());

            // SigningDetails.pastSigningCertificates
            try {
                Field pastField = details.getClass().getDeclaredField("pastSigningCertificates");
                pastField.setAccessible(true);
                pastField.set(details, sCachedSignatures.clone());
            } catch (NoSuchFieldException ignored) {}

        } catch (Throwable t) {
            logd("patchSigningInfo异常: " + t.getMessage());
        }
    }

    // ==================== 原Application委托 ====================

    /** 反射创建原始Application实例 */
    private Application createOriginalApp(Context base) {
        if (ORIGINAL_APP_CLASS == null || ORIGINAL_APP_CLASS.isEmpty()
                || ORIGINAL_APP_CLASS.startsWith("$$")) {
            logd("无原始Application类, 跳过委托");
            return null;
        }
        try {
            ClassLoader cl = base.getClassLoader();
            Class<?> appClass = cl.loadClass(ORIGINAL_APP_CLASS);
            Application app = (Application) appClass.newInstance();
            logd("原始Application创建成功: " + ORIGINAL_APP_CLASS);
            return app;
        } catch (Throwable t) {
            loge("创建原始Application失败: " + ORIGINAL_APP_CLASS, t);
            return null;
        }
    }

    /** 反射调用Application.attachBaseContext */
    private static void invokeAttachBaseContext(Application app, Context base) {
        try {
            Method attach = Application.class.getDeclaredMethod("attach", Context.class);
            attach.setAccessible(true);
            attach.invoke(app, base);
        } catch (NoSuchMethodException e) {
            // 某些ROM上方法名不同，尝试attachBaseContext
            try {
                Method abc = android.content.ContextWrapper.class.getDeclaredMethod(
                        "attachBaseContext", Context.class);
                abc.setAccessible(true);
                abc.invoke(app, base);
            } catch (Throwable t2) {
                loge("invokeAttachBaseContext失败", t2);
            }
        } catch (Throwable t) {
            loge("invokeAttachBaseContext失败", t);
        }
    }

    // ==================== Deep Hide ====================

    /** 替换ActivityThread/LoadedApk中持有的Application引用 */
    private void performDeepHide() {
        if (sOriginalApp == null) return;
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentAT = atClass.getDeclaredMethod("currentActivityThread");
            currentAT.setAccessible(true);
            Object at = currentAT.invoke(null);

            // 替换mInitialApplication
            Field initAppField = atClass.getDeclaredField("mInitialApplication");
            initAppField.setAccessible(true);
            Application current = (Application) initAppField.get(at);
            if (current == this) {
                initAppField.set(at, sOriginalApp);
                logd("DeepHide: mInitialApplication替换成功");
            }

            // 替换mAllApplications列表中的引用
            Field allAppsField = atClass.getDeclaredField("mAllApplications");
            allAppsField.setAccessible(true);
            @SuppressWarnings("unchecked")
            ArrayList<Application> allApps = (ArrayList<Application>) allAppsField.get(at);
            if (allApps != null) {
                for (int i = 0; i < allApps.size(); i++) {
                    if (allApps.get(i) == this) {
                        allApps.set(i, sOriginalApp);
                    }
                }
            }

            // 替换LoadedApk中的mApplication
            Field boundAppField = atClass.getDeclaredField("mBoundApplication");
            boundAppField.setAccessible(true);
            Object boundApp = boundAppField.get(at);
            if (boundApp != null) {
                Field infoField = boundApp.getClass().getDeclaredField("info");
                infoField.setAccessible(true);
                Object loadedApk = infoField.get(boundApp);
                if (loadedApk != null) {
                    Field mAppField = loadedApk.getClass().getDeclaredField("mApplication");
                    mAppField.setAccessible(true);
                    if (mAppField.get(loadedApk) == this) {
                        mAppField.set(loadedApk, sOriginalApp);
                        logd("DeepHide: LoadedApk.mApplication替换成功");
                    }
                }
            }

        } catch (Throwable t) {
            logd("DeepHide异常: " + t.getMessage());
        }
    }

    // ==================== Native引擎加载 ====================

    private void loadNativeEngine(Context ctx) {
        try {
            System.loadLibrary("native_engine");
            sNativeLoaded = true;
            logd("Native引擎加载成功");

            // 初始化Native引擎
            String backend = CFG_NATIVE_BACKEND.startsWith("$$") ? "PLT" : CFG_NATIVE_BACKEND;
            String origApkPath = sOriginApkPath != null ? sOriginApkPath : "";
            String baseApkPath = ctx.getApplicationInfo().sourceDir;

            nativeInit(backend, baseApkPath, origApkPath,
                    bool(CFG_IO_REDIRECT), bool(CFG_MAPS_HIDE), sDebug);
            logd("Native引擎初始化完成, backend=" + backend);
        } catch (Throwable t) {
            loge("Native引擎加载失败", t);
        }
    }

    // Native方法声明
    private static native void nativeInit(String backend, String baseApkPath,
                                           String originApkPath, boolean ioRedirect,
                                           boolean mapsHide, boolean debug);

    // ==================== 自动降级 ====================

    private void tryDowngrade(Throwable error) {
        if (sHookMode == HookMode.AGGRESSIVE) {
            logd("AGGRESSIVE模式失败, 降级到STANDARD");
            sHookMode = HookMode.STANDARD;
        } else if (sHookMode == HookMode.STANDARD) {
            logd("STANDARD模式失败, 降级到SAFE");
            sHookMode = HookMode.SAFE;
        }
    }

    // ==================== AppComponentFactory代理 ====================

    /**
     * 委托AppComponentFactory
     * 将组件创建转发给原始Factory，保持ClassLoader/ClassInfo链路正确
     */
    public static class DelegatingFactory extends android.app.AppComponentFactory {

        private android.app.AppComponentFactory originalFactory;

        private android.app.AppComponentFactory getOriginal(ClassLoader cl) {
            if (originalFactory != null) return originalFactory;
            if (ORIGINAL_FACTORY_CLASS == null || ORIGINAL_FACTORY_CLASS.isEmpty()
                    || ORIGINAL_FACTORY_CLASS.startsWith("$$")) {
                return null;
            }
            try {
                Class<?> factClass = cl.loadClass(ORIGINAL_FACTORY_CLASS);
                originalFactory = (android.app.AppComponentFactory) factClass.newInstance();
            } catch (Throwable t) {
                logd("创建原始Factory失败: " + t.getMessage());
            }
            return originalFactory;
        }

        @Override
        public Activity instantiateActivity(ClassLoader cl, String className, android.content.Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            android.app.AppComponentFactory orig = getOriginal(cl);
            if (orig != null) {
                try { return orig.instantiateActivity(cl, className, intent); }
                catch (Throwable ignored) {}
            }
            return super.instantiateActivity(cl, className, intent);
        }

        @Override
        public Application instantiateApplication(ClassLoader cl, String className)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            android.app.AppComponentFactory orig = getOriginal(cl);
            if (orig != null) {
                try { return orig.instantiateApplication(cl, className); }
                catch (Throwable ignored) {}
            }
            return super.instantiateApplication(cl, className);
        }

        @Override
        public android.app.Service instantiateService(ClassLoader cl, String className, android.content.Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            android.app.AppComponentFactory orig = getOriginal(cl);
            if (orig != null) {
                try { return orig.instantiateService(cl, className, intent); }
                catch (Throwable ignored) {}
            }
            return super.instantiateService(cl, className, intent);
        }

        @Override
        public android.content.BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, android.content.Intent intent)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            android.app.AppComponentFactory orig = getOriginal(cl);
            if (orig != null) {
                try { return orig.instantiateReceiver(cl, className, intent); }
                catch (Throwable ignored) {}
            }
            return super.instantiateReceiver(cl, className, intent);
        }

        @Override
        public android.content.ContentProvider instantiateProvider(ClassLoader cl, String className)
                throws InstantiationException, IllegalAccessException, ClassNotFoundException {
            android.app.AppComponentFactory orig = getOriginal(cl);
            if (orig != null) {
                try { return orig.instantiateProvider(cl, className); }
                catch (Throwable ignored) {}
            }
            return super.instantiateProvider(cl, className);
        }
    }

    // ==================== 工具方法 ====================

    private static boolean bool(String val) {
        return "true".equalsIgnoreCase(val);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static void copyFile(File src, File dst) throws java.io.IOException {
        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) fos.write(buf, 0, n);
            fos.getFD().sync();
        }
    }

    private static void logd(String msg) {
        if (sDebug) Log.d(TAG, msg);
    }

    private static void loge(String msg, Throwable t) {
        Log.e(TAG, msg, t);
    }
}
