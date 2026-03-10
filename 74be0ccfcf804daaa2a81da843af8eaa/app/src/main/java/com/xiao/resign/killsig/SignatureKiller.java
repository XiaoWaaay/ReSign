package com.xiao.resign.killsig;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

/**
 * SignatureKiller V3 — 完整的三层递进式签名绕过核心
 *
 * ===== 为什么 V2 失败了？ =====
 *
 * V2 的问题在于 Hook 时机和覆盖面不够：
 *
 * 1. native-lib.cpp 在 JNI_OnLoad 时通过 ActivityThread.currentApplication() 拿 Context
 *    然后直接调用 context.getPackageManager().getPackageInfo()
 *    这个调用链实际上是：
 *    ActivityThread.currentApplication() → Application 对象
 *    → Application.getPackageManager() → 返回 ApplicationPackageManager
 *    → ApplicationPackageManager.getPackageInfo()
 *    → 内部调用 mPM.getPackageInfo() (mPM 就是 IPackageManager Binder 代理)
 *    → 通过 Binder IPC 到 system_server
 *    → 返回 PackageInfo (通过 Parcel 反序列化)
 *
 * 2. V2 只替换了一部分路径，遗漏了几个关键环节：
 *    a) ActivityThread.sPackageManager 可能和 ApplicationPackageManager.mPM 是同一个对象，
 *       但某些 ROM 上不一定
 *    b) 不同 Context 实例（Application vs Activity）的 mPM 可能不同
 *    c) CREATOR 替换后没有清理 Parcel 缓存
 *
 * ===== V3 方案（参考 KC Tool） =====
 *
 * 第一层：PackageInfo.CREATOR 替换
 *   - 拦截所有通过 Binder Parcel 反序列化的 PackageInfo
 *   - 在 createFromParcel 中替换 signatures 字段
 *
 * 第二层：IPackageManager Binder 代理
 *   - 代理 ActivityThread.sPackageManager
 *   - 代理所有已创建的 ApplicationPackageManager.mPM
 *   - 拦截 getPackageInfo / checkSignatures 等方法
 *
 * 第三层：Native IO 重定向 + Dobby Inline Hook + Seccomp
 *   - 拦截 openat/fopen 等函数，重定向 APK 文件读取
 *   - seccomp BPF 拦截内联 SVC 指令
 *   - /proc/self/maps 过滤
 */
public class SignatureKiller {

    private static final String TAG = "SigKiller";

    // ===== 原始签名数据 =====
    // 在打包时注入，Base64 编码的签名字节
    // 工具在重打包时应该将原始 APK 的签名 Base64 填入此处
    private static final String ORIGINAL_SIGNATURES_BASE64 = "$ORIG_SIGNATURES$";

    // 运行时解析出的原始签名
    private static Signature[] sOriginalSignatures = null;
    private static String sPackageName = null;
    private static boolean sInstalled = false;

    /**
     * 安装签名绕过（主入口）
     *
     * 必须在 Application.attachBaseContext 或 ContentProvider.onCreate 中调用
     * 越早越好，确保在任何业务代码/native 库加载之前完成
     */
    public static void install(Context context) {
        if (sInstalled) {
            Log.w(TAG, "Already installed, skip");
            return;
        }

        sPackageName = context.getPackageName();
        Log.i(TAG, "Installing for package: " + sPackageName);

        // 解析原始签名
        sOriginalSignatures = parseOriginalSignatures(context);
        if (sOriginalSignatures == null || sOriginalSignatures.length == 0) {
            Log.e(TAG, "No original signatures available!");
            return;
        }
        Log.i(TAG, "Original signatures loaded: " + sOriginalSignatures.length);

        try {
            // === Layer 1: CREATOR 替换 ===
            hookPackageInfoCreator();
            Log.i(TAG, "Layer 1: PackageInfo.CREATOR hooked");

            hookSignatureCreator();
            Log.i(TAG, "Layer 1: Signature.CREATOR hooked");

            if (Build.VERSION.SDK_INT >= 28) {
                hookSigningInfoCreator();
                Log.i(TAG, "Layer 1: SigningInfo.CREATOR hooked");
            }

            // === Layer 2: Binder IPC 代理 ===
            hookActivityThreadPM();
            Log.i(TAG, "Layer 2: ActivityThread.sPackageManager proxied");

            hookApplicationPM(context);
            Log.i(TAG, "Layer 2: ApplicationPackageManager.mPM proxied");

            // === Layer 3: Native 层 ===
            try {
                NativeSignatureKiller.install(context, sOriginalSignatures);
                Log.i(TAG, "Layer 3: Native layer installed");
            } catch (Throwable t) {
                Log.w(TAG, "Layer 3 failed (non-fatal): " + t.getMessage());
            }

            sInstalled = true;
            Log.i(TAG, "=== SignatureKiller V3 installed successfully ===");

        } catch (Throwable t) {
            Log.e(TAG, "Install failed", t);
        }
    }

    // ========================================================================
    //  签名解析
    // ========================================================================

    /**
     * 解析原始签名
     *
     * 优先使用注入的 Base64 签名，如果不可用则读取当前签名（首次安装前）
     */
    private static Signature[] parseOriginalSignatures(Context context) {
        // 尝试解析注入的签名
        if (!ORIGINAL_SIGNATURES_BASE64.equals("$ORIG_SIGNATURES$")
                && !ORIGINAL_SIGNATURES_BASE64.isEmpty()) {
            try {
                // 支持多签名，用 "|" 分隔
                String[] parts = ORIGINAL_SIGNATURES_BASE64.split("\\|");
                Signature[] sigs = new Signature[parts.length];
                for (int i = 0; i < parts.length; i++) {
                    byte[] sigBytes = Base64.decode(parts[i], Base64.NO_WRAP);
                    sigs[i] = new Signature(sigBytes);
                }
                Log.i(TAG, "Parsed " + sigs.length + " injected signatures");
                return sigs;
            } catch (Exception e) {
                Log.e(TAG, "Failed to parse injected signatures", e);
            }
        }

        // 降级：读取当前 app 签名（这在未重签时有效，重签后这里拿到的是新签名）
        try {
            @SuppressWarnings("deprecation")
            PackageInfo pi = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi.signatures != null && pi.signatures.length > 0) {
                Log.i(TAG, "Using current signatures (not re-signed yet or placeholder)");
                return pi.signatures;
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get current signatures", e);
        }

        return null;
    }

    // ========================================================================
    //  Layer 1: CREATOR 替换
    // ========================================================================

    /**
     * 替换 PackageInfo.CREATOR
     *
     * PackageInfo 通过 Binder IPC 返回时，会经过 Parcel.readParcelable()
     * → 查找 PackageInfo.CREATOR → 调用 CREATOR.createFromParcel()
     *
     * 我们替换这个 CREATOR，在 createFromParcel 返回后替换 signatures 字段
     */
    private static void hookPackageInfoCreator() throws Exception {
        final Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;

        Parcelable.Creator<PackageInfo> fakeCreator = new Parcelable.Creator<PackageInfo>() {
            @Override
            public PackageInfo createFromParcel(Parcel source) {
                PackageInfo pi = originalCreator.createFromParcel(source);
                modifyPackageInfo(pi);
                return pi;
            }

            @Override
            public PackageInfo[] newArray(int size) {
                return originalCreator.newArray(size);
            }
        };

        replaceCreatorField(PackageInfo.class, "CREATOR", fakeCreator);
        syncParcelCreatorCache(PackageInfo.class, fakeCreator);
    }

    /**
     * 替换 Signature.CREATOR
     *
     * 防止某些代码直接从 Parcel 反序列化 Signature 对象
     */
    @SuppressWarnings("unchecked")
    private static void hookSignatureCreator() throws Exception {
        final Parcelable.Creator<Signature> originalCreator = Signature.CREATOR;

        Parcelable.Creator<Signature> fakeCreator = new Parcelable.Creator<Signature>() {
            @Override
            public Signature createFromParcel(Parcel source) {
                // 直接返回原始签名
                if (sOriginalSignatures != null && sOriginalSignatures.length > 0) {
                    // 读取并丢弃 parcel 中的数据（保持 parcel 位置正确）
                    Signature dummy = originalCreator.createFromParcel(source);
                    return sOriginalSignatures[0];
                }
                return originalCreator.createFromParcel(source);
            }

            @Override
            public Signature[] newArray(int size) {
                return originalCreator.newArray(size);
            }
        };

        replaceCreatorField(Signature.class, "CREATOR", fakeCreator);
        syncParcelCreatorCache(Signature.class, fakeCreator);
    }

    /**
     * 替换 SigningInfo.CREATOR (API 28+)
     */
    @SuppressWarnings("unchecked")
    private static void hookSigningInfoCreator() {
        if (Build.VERSION.SDK_INT < 28) return;

        try {
            final Parcelable.Creator<SigningInfo> originalCreator = SigningInfo.CREATOR;

            Parcelable.Creator<SigningInfo> fakeCreator = new Parcelable.Creator<SigningInfo>() {
                @Override
                public SigningInfo createFromParcel(Parcel source) {
                    SigningInfo si = originalCreator.createFromParcel(source);
                    modifySigningInfo(si);
                    return si;
                }

                @Override
                public SigningInfo[] newArray(int size) {
                    return originalCreator.newArray(size);
                }
            };

            replaceCreatorField(SigningInfo.class, "CREATOR", fakeCreator);
            syncParcelCreatorCache(SigningInfo.class, fakeCreator);
        } catch (Throwable t) {
            Log.w(TAG, "hookSigningInfoCreator failed: " + t.getMessage());
        }
    }

    /**
     * 替换 static final CREATOR 字段
     *
     * static final 字段正常情况下无法通过反射修改。
     * 我们用三种策略尝试：
     * 1. 直接 Field.set (某些 VM 允许)
     * 2. 使用 Unsafe.putObject 绕过
     * 3. 移除 FINAL 修饰符后 set
     */
    private static void replaceCreatorField(Class<?> clazz, String fieldName,
                                            Object newValue) throws Exception {
        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);

        // 策略 1: 直接 set
        try {
            field.set(null, newValue);
            Log.d(TAG, "CREATOR replaced via direct set for " + clazz.getSimpleName());
            return;
        } catch (Exception e) {
            Log.d(TAG, "Direct set failed for " + clazz.getSimpleName() + ", trying Unsafe");
        }

        // 策略 2: Unsafe
        try {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Object unsafe = theUnsafe.get(null);

            Method staticFieldOffset = unsafeClass.getMethod("staticFieldOffset", Field.class);
            long offset = (Long) staticFieldOffset.invoke(unsafe, field);

            Method putObject = unsafeClass.getMethod("putObject", Object.class, long.class, Object.class);
            // 对于 static 字段，base 应该通过 staticFieldBase 获取
            Method staticFieldBase = unsafeClass.getMethod("staticFieldBase", Field.class);
            Object base = staticFieldBase.invoke(unsafe, field);
            putObject.invoke(unsafe, base, offset, newValue);
            Log.d(TAG, "CREATOR replaced via Unsafe for " + clazz.getSimpleName());
            return;
        } catch (Exception e) {
            Log.d(TAG, "Unsafe set failed for " + clazz.getSimpleName() + ", trying accessFlags");
        }

        // 策略 3: 移除 FINAL 标志
        try {
            Field accessFlagsField = Field.class.getDeclaredField("accessFlags");
            accessFlagsField.setAccessible(true);
            int flags = accessFlagsField.getInt(field);
            // 移除 FINAL (0x10)
            accessFlagsField.setInt(field, flags & ~0x10);
            field.set(null, newValue);
            Log.d(TAG, "CREATOR replaced via accessFlags for " + clazz.getSimpleName());
        } catch (Exception e) {
            Log.e(TAG, "All CREATOR replacement strategies failed for " + clazz.getSimpleName(), e);
            throw e;
        }
    }

    /**
     * 同步 Parcel 内部的 CREATOR 缓存
     *
     * Parcel 内部有缓存 Map，缓存了 className -> CREATOR 的映射。
     * 替换完 CREATOR 后必须同步更新这个缓存，否则 Parcel.readParcelable 会用旧的。
     *
     * Android 13 (API 33) 之前：Parcel.sPairedCreators (ArrayMap<ClassLoader, ArrayMap<String, Creator>>)
     * Android 13+ : Parcel.mCreators (same structure but instance field on Parcel)
     *
     * 但实际上不同 Android 版本的字段名和结构可能不同。
     * 最可靠的方式是清空缓存（让下次读取时重新查找 CREATOR）。
     */
    @SuppressWarnings("unchecked")
    private static void syncParcelCreatorCache(Class<?> targetClass, Object newCreator) {
        String className = targetClass.getName();

        // 尝试 Android 13+ 的 mCreators
        try {
            Field mCreators = Parcel.class.getDeclaredField("mCreators");
            mCreators.setAccessible(true);
            // mCreators 是一个 static Map<ClassLoader, Map<String, Creator>>
            Object map = mCreators.get(null);
            if (map instanceof Map) {
                // 遍历所有 ClassLoader 的缓存
                for (Object entry : ((Map<?, ?>) map).values()) {
                    if (entry instanceof Map) {
                        ((Map<String, Object>) entry).put(className, newCreator);
                    }
                }
                Log.d(TAG, "Parcel.mCreators synced for " + targetClass.getSimpleName());
                return;
            }
        } catch (NoSuchFieldException e) {
            // 不是 Android 13+，尝试旧版本
        } catch (Exception e) {
            Log.d(TAG, "mCreators sync failed: " + e.getMessage());
        }

        // 尝试旧版本的 sPairedCreators
        try {
            Field sPairedCreators = Parcel.class.getDeclaredField("sPairedCreators");
            sPairedCreators.setAccessible(true);
            Object map = sPairedCreators.get(null);
            if (map instanceof Map) {
                for (Object entry : ((Map<?, ?>) map).values()) {
                    if (entry instanceof Map) {
                        ((Map<String, Object>) entry).put(className, newCreator);
                    }
                }
                Log.d(TAG, "Parcel.sPairedCreators synced for " + targetClass.getSimpleName());
                return;
            }
        } catch (NoSuchFieldException e) {
            // 可能更旧的版本
        } catch (Exception e) {
            Log.d(TAG, "sPairedCreators sync failed: " + e.getMessage());
        }

        // 再尝试 sCreators (某些 AOSP 版本)
        try {
            Field sCreators = Parcel.class.getDeclaredField("sCreators");
            sCreators.setAccessible(true);
            Object map = sCreators.get(null);
            if (map instanceof Map) {
                for (Object entry : ((Map<?, ?>) map).values()) {
                    if (entry instanceof Map) {
                        ((Map<String, Object>) entry).put(className, newCreator);
                    }
                }
                Log.d(TAG, "Parcel.sCreators synced for " + targetClass.getSimpleName());
            }
        } catch (Exception e) {
            Log.d(TAG, "sCreators sync failed (non-fatal): " + e.getMessage());
        }
    }

    // ========================================================================
    //  Layer 2: Binder IPC 代理
    // ========================================================================

    /**
     * 代理 ActivityThread.sPackageManager
     *
     * 这是全局的 IPackageManager 引用，大部分签名查询最终都走这里。
     * 包括 native 层通过 getApplication().getPackageManager() 发起的调用。
     */
    private static void hookActivityThreadPM() throws Exception {
        // 获取 ActivityThread 实例
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Field sCurrentActivityThread = atClass.getDeclaredField("sCurrentActivityThread");
        sCurrentActivityThread.setAccessible(true);
        Object activityThread = sCurrentActivityThread.get(null);

        // 获取 sPackageManager
        Field sPM = atClass.getDeclaredField("sPackageManager");
        sPM.setAccessible(true);
        Object originalPM = sPM.get(null);

        if (originalPM == null) {
            Log.w(TAG, "sPackageManager is null, try getPackageManager()");
            // 某些情况下 sPackageManager 还没初始化，手动触发
            Method getSystemContext = atClass.getDeclaredMethod("getSystemContext");
            getSystemContext.setAccessible(true);
            Object systemContext = getSystemContext.invoke(activityThread);
            if (systemContext != null) {
                Method getPm = systemContext.getClass().getMethod("getPackageManager");
                getPm.invoke(systemContext);
                originalPM = sPM.get(null);
            }
        }

        if (originalPM == null) {
            Log.e(TAG, "Cannot get sPackageManager");
            return;
        }

        // 获取 IPackageManager 接口
        Class<?> ipmClass = Class.forName("android.content.pm.IPackageManager");

        // 创建动态代理
        Object proxyPM = Proxy.newProxyInstance(
                ipmClass.getClassLoader(),
                new Class[]{ipmClass},
                new PackageManagerProxy(originalPM)
        );

        // 替换 sPackageManager
        sPM.set(null, proxyPM);
        Log.i(TAG, "ActivityThread.sPackageManager proxied");
    }

    /**
     * 代理 ApplicationPackageManager.mPM
     *
     * 每个 Context (Application/Activity) 的 getPackageManager() 返回的
     * ApplicationPackageManager 内部有 mPM 字段，这也需要被代理。
     *
     * 关键：native 代码通过 getApplication().getPackageManager() 获取的就是这个
     */
    private static void hookApplicationPM(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            if (pm == null) return;

            // 找到 ApplicationPackageManager.mPM 字段
            Field mPMField = pm.getClass().getDeclaredField("mPM");
            mPMField.setAccessible(true);
            Object originalMPM = mPMField.get(pm);

            if (originalMPM == null) return;

            // 检查是否已经是代理
            if (Proxy.isProxyClass(originalMPM.getClass())) {
                Log.d(TAG, "mPM is already proxied");
                return;
            }

            // 获取 IPackageManager 接口
            Class<?> ipmClass = Class.forName("android.content.pm.IPackageManager");

            // 创建代理
            Object proxyMPM = Proxy.newProxyInstance(
                    ipmClass.getClassLoader(),
                    new Class[]{ipmClass},
                    new PackageManagerProxy(originalMPM)
            );

            // 替换 mPM
            mPMField.set(pm, proxyMPM);
            Log.i(TAG, "ApplicationPackageManager.mPM proxied for " + context.getClass().getName());

        } catch (Throwable t) {
            Log.w(TAG, "hookApplicationPM failed: " + t.getMessage());
        }

        // 同时 hook Application 的 PackageManager（如果 context 不是 Application）
        try {
            Context appContext = context.getApplicationContext();
            if (appContext != null && appContext != context) {
                PackageManager appPm = appContext.getPackageManager();
                if (appPm != null) {
                    Field mPMField2 = appPm.getClass().getDeclaredField("mPM");
                    mPMField2.setAccessible(true);
                    Object originalMPM2 = mPMField2.get(appPm);
                    if (originalMPM2 != null && !Proxy.isProxyClass(originalMPM2.getClass())) {
                        Class<?> ipmClass = Class.forName("android.content.pm.IPackageManager");
                        Object proxyMPM2 = Proxy.newProxyInstance(
                                ipmClass.getClassLoader(),
                                new Class[]{ipmClass},
                                new PackageManagerProxy(originalMPM2)
                        );
                        mPMField2.set(appPm, proxyMPM2);
                        Log.i(TAG, "ApplicationPackageManager.mPM proxied for ApplicationContext");
                    }
                }
            }
        } catch (Throwable t) {
            Log.d(TAG, "hookApplicationPM for app context: " + t.getMessage());
        }
    }

    // ========================================================================
    //  PackageManager 代理 (InvocationHandler)
    // ========================================================================

    /**
     * IPackageManager 动态代理处理器
     *
     * 拦截以下方法：
     * 1. getPackageInfo → 替换返回值中的 signatures
     * 2. checkSignatures → 涉及自身包名时返回 MATCH
     * 3. checkUidSignatures → 涉及自身 UID 时返回 MATCH
     * 4. hasSigningCertificate → 比对原始签名返回 true
     * 5. getPackageArchiveInfo → 替换 APK 解析出的签名
     */
    private static class PackageManagerProxy implements InvocationHandler {

        private final Object mOriginal;

        PackageManagerProxy(Object original) {
            this.mOriginal = original;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            try {
                return handleMethod(method, args);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getTargetException();
            }
        }

        private Object handleMethod(Method method, Object[] args) throws Throwable {
            String methodName = method.getName();

            switch (methodName) {
                case "getPackageInfo": {
                    Object result = method.invoke(mOriginal, args);
                    if (result instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) result;
                        // 检查是否是查询自身包名
                        if (sPackageName != null && sPackageName.equals(pi.packageName)) {
                            modifyPackageInfo(pi);
                            Log.d(TAG, "[Proxy] getPackageInfo: signatures replaced");
                        }
                    }
                    return result;
                }

                case "checkSignatures": {
                    // checkSignatures(String pkg1, String pkg2)
                    if (args != null && args.length >= 2) {
                        String pkg1 = args[0] instanceof String ? (String) args[0] : null;
                        String pkg2 = args[1] instanceof String ? (String) args[1] : null;
                        if (sPackageName != null &&
                                (sPackageName.equals(pkg1) || sPackageName.equals(pkg2))) {
                            return PackageManager.SIGNATURE_MATCH; // 0
                        }
                    }
                    return method.invoke(mOriginal, args);
                }

                case "checkUidSignatures": {
                    // checkUidSignatures(int uid1, int uid2)
                    // 为安全起见，如果涉及自身 UID 就返回 MATCH
                    try {
                        int myUid = android.os.Process.myUid();
                        if (args != null && args.length >= 2) {
                            if ((args[0] instanceof Integer && (int) args[0] == myUid) ||
                                    (args[1] instanceof Integer && (int) args[1] == myUid)) {
                                return PackageManager.SIGNATURE_MATCH;
                            }
                        }
                    } catch (Exception e) {
                        // ignore
                    }
                    return method.invoke(mOriginal, args);
                }

                case "hasSigningCertificate": {
                    // hasSigningCertificate(String packageName, byte[] certificate, int type)
                    if (args != null && args.length >= 1) {
                        if (sPackageName != null && sPackageName.equals(args[0])) {
                            return true;
                        }
                    }
                    return method.invoke(mOriginal, args);
                }

                case "getPackageArchiveInfo":
                case "getPackageArchiveInfoWithFlags": {
                    Object result = method.invoke(mOriginal, args);
                    if (result instanceof PackageInfo) {
                        modifyPackageInfo((PackageInfo) result);
                    }
                    return result;
                }

                default:
                    return method.invoke(mOriginal, args);
            }
        }
    }

    // ========================================================================
    //  PackageInfo / SigningInfo 修改
    // ========================================================================

    /**
     * 修改 PackageInfo 中的签名信息
     */
    @SuppressWarnings("deprecation")
    private static void modifyPackageInfo(PackageInfo pi) {
        if (pi == null || sOriginalSignatures == null) return;

        // 只修改自身包名的信息
        if (sPackageName != null && !sPackageName.equals(pi.packageName)) return;

        // 替换 signatures (GET_SIGNATURES 结果)
        if (pi.signatures != null && pi.signatures.length > 0) {
            pi.signatures = sOriginalSignatures.clone();
        }

        // 替换 signingInfo (GET_SIGNING_CERTIFICATES 结果, API 28+)
        if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
            modifySigningInfo(pi.signingInfo);
        }
    }

    /**
     * 修改 SigningInfo 内部的签名
     *
     * SigningInfo 内部有 SigningDetails 对象，包含：
     * - mSignatures: 当前签名
     * - mPastSigningCertificates: 历史签名
     *
     * 这些字段不直接暴露公共 API，需要反射修改
     */
    private static void modifySigningInfo(SigningInfo si) {
        if (si == null || sOriginalSignatures == null) return;

        try {
            // 获取 SigningInfo 内部的 mSigningDetails
            Field signingDetailsField = SigningInfo.class.getDeclaredField("mSigningDetails");
            signingDetailsField.setAccessible(true);
            Object signingDetails = signingDetailsField.get(si);

            if (signingDetails != null) {
                // 修改 mSignatures
                try {
                    Field signaturesField = signingDetails.getClass().getDeclaredField("signatures");
                    signaturesField.setAccessible(true);
                    signaturesField.set(signingDetails, sOriginalSignatures.clone());
                } catch (NoSuchFieldException e) {
                    // 可能字段名不同
                    try {
                        Field signaturesField = signingDetails.getClass().getDeclaredField("mSignatures");
                        signaturesField.setAccessible(true);
                        signaturesField.set(signingDetails, sOriginalSignatures.clone());
                    } catch (Exception e2) {
                        Log.d(TAG, "Cannot find signatures field in SigningDetails");
                    }
                }

                // 修改 mPastSigningCertificates
                try {
                    Field pastField = signingDetails.getClass().getDeclaredField("pastSigningCertificates");
                    pastField.setAccessible(true);
                    pastField.set(signingDetails, sOriginalSignatures.clone());
                } catch (NoSuchFieldException e) {
                    try {
                        Field pastField = signingDetails.getClass().getDeclaredField("mPastSigningCertificates");
                        pastField.setAccessible(true);
                        pastField.set(signingDetails, sOriginalSignatures.clone());
                    } catch (Exception e2) {
                        // OK, might not exist
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "modifySigningInfo failed: " + e.getMessage());
        }
    }

    // ========================================================================
    //  公共接口
    // ========================================================================

    public static Signature[] getOriginalSignatures() {
        return sOriginalSignatures;
    }

    public static void setOriginalSignatures(Signature[] signatures) {
        sOriginalSignatures = signatures;
    }

    public static boolean isInstalled() {
        return sInstalled;
    }
}
