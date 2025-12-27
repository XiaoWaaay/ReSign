package com.xwaaa.hook;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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

    private static volatile Application sApp;
    private static volatile String sTargetPkg;
    private static volatile Signature sFakeSig;
    private static final AtomicBoolean PATCHER_STARTED = new AtomicBoolean(false);

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

            signatureData = normalizeSignatureBase64(signatureData);

            try {
                sTargetPkg = packageName;
                sFakeSig = new Signature(Base64.decode(signatureData, Base64.DEFAULT));
            } catch (Throwable ignored) {
            }

            startStealthSignaturePatcherIfPossible();

            // 1) Java 层 PM Hook（只装一次）
            if (!PM_HOOKED.get()) {
                boolean ok = killPM(packageName, signatureData);
                PM_HOOKED.set(ok);
                if (!ok) {
                    Log.e(TAG, "PM Hook 安装失败，将在下次尝试重试");
                }
            } else Log.d(TAG, "PM Hook 已安装，跳过");

            // 2) native 层 open/readlinkat SVC 重定向（只装一次）
            if (!OPEN_HOOKED.get()) {
                boolean ok = killOpen(packageName);
                OPEN_HOOKED.set(ok);
                if (!ok) {
                    Log.e(TAG, "Open Hook 安装失败，将在下次尝试重试");
                }
            } else Log.d(TAG, "Open Hook 已安装，跳过");

            Log.d(TAG, "签名 Hook 初始化完成!");
            // 如需释放 native 缓存可延后在合适的时机调用 cleanup();
        } catch (Throwable e) {
            Log.e(TAG, "初始化签名 Hook 失败: " + e.getMessage(), e);
        }
    }

    private static String normalizeSignatureBase64(String in) {
        if (in == null) return null;
        if (in.indexOf('\\') < 0) return in;
        String out = in;
        out = out.replace("\\n", "\n");
        out = out.replace("\\r", "\r");
        return out;
    }

    /** PackageManager Hook（Java 层） **/
    private static boolean killPM(final String pkg, String sigBase64) {
        try {
            Log.d(TAG, "执行 PackageManager Stealth Patch...");

            sigBase64 = normalizeSignatureBase64(sigBase64);
            final Signature fakeSig = new Signature(Base64.decode(sigBase64, Base64.DEFAULT));

            sTargetPkg = pkg;
            sFakeSig = fakeSig;

            installPmBinderProxyIfPossible(pkg, fakeSig);

            Application app = sApp;
            if (app != null) {
                warmAndPatchPackageInfo(app, pkg, fakeSig);
                patchPackageInfoCachesNoEvict(pkg, fakeSig);
            }
            startStealthSignaturePatcherIfPossible();
            Log.d(TAG, "PackageManager Stealth Patch 安装完成");
            return true;
        } catch (Throwable e) {
            Log.e(TAG, "PackageManager Hook 失败: " + e.getMessage(), e);
            return false;
        }
    }

    private static void startStealthSignaturePatcherIfPossible() {
        if (PATCHER_STARTED.get()) return;
        final String targetPkg = sTargetPkg;
        final Signature fakeSig = sFakeSig;
        if (targetPkg == null || fakeSig == null) return;
        if (!PATCHER_STARTED.compareAndSet(false, true)) return;

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 60; i++) {
                    try {
                        Application app = sApp;
                        if (app == null) {
                            app = resolveCurrentApplication();
                            if (app != null) sApp = app;
                        }

                        installPmBinderProxyIfPossible(targetPkg, fakeSig);
                        if (app != null) {
                            warmAndPatchPackageInfo(app, targetPkg, fakeSig);
                            patchPackageInfoCachesNoEvict(targetPkg, fakeSig);
                        }
                        try {
                            Thread.sleep(50);
                        } catch (InterruptedException ignored) {
                            return;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }, "sig-patcher");
        try {
            t.setDaemon(true);
        } catch (Throwable ignored) {
        }
        t.start();
    }

    private static Application resolveCurrentApplication() {
        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method m = atClz.getDeclaredMethod("currentApplication");
            m.setAccessible(true);
            Object app = m.invoke(null);
            if (app instanceof Application) return (Application) app;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void warmAndPatchPackageInfo(Context ctx, String targetPkg, Signature fakeSig) {
        if (ctx == null || targetPkg == null || fakeSig == null) return;
        try {
            PackageManager pm = ctx.getPackageManager();
            if (pm == null) return;

            PackageInfo pi = null;

            try {
                pi = pm.getPackageInfo(targetPkg, PackageManager.GET_SIGNATURES);
            } catch (Throwable ignored) {
            }

            if (pi == null && Build.VERSION.SDK_INT >= 33) {
                try {
                    Method m = pm.getClass().getMethod("getPackageInfo", String.class, PackageManager.PackageInfoFlags.class);
                    Method of = PackageManager.PackageInfoFlags.class.getMethod("of", long.class);
                    Object flags = of.invoke(null, (long) PackageManager.GET_SIGNATURES);
                    Object out = m.invoke(pm, targetPkg, flags);
                    if (out instanceof PackageInfo) pi = (PackageInfo) out;
                } catch (Throwable ignored) {
                }
            }

            if (pi != null && targetPkg.equals(pi.packageName)) {
                patchPackageInfoSignatures(pi, fakeSig);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void patchPackageInfoCachesNoEvict(String targetPkg, Signature fakeSig) {
        tryPatchCacheNoEvictFromStaticField(PackageManager.class, "sPackageInfoCache", targetPkg, fakeSig);
        try {
            Class<?> apmClz = Class.forName("android.app.ApplicationPackageManager");
            tryPatchCacheNoEvictFromStaticField(apmClz, "sPackageInfoCache", targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }

        try {
            Application app = sApp;
            if (app != null) {
                PackageManager pm = app.getPackageManager();
                tryPatchCacheNoEvictFromInstanceField(pm, "mPackageInfoCache", targetPkg, fakeSig);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void tryPatchCacheNoEvictFromStaticField(Class<?> clz, String fieldName, String targetPkg, Signature fakeSig) {
        try {
            Object cache = findField(clz, fieldName).get(null);
            patchCacheObjectNoEvict(cache, targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }
    }

    private static void tryPatchCacheNoEvictFromInstanceField(Object instance, String fieldName, String targetPkg, Signature fakeSig) {
        if (instance == null) return;
        try {
            Object cache = findField(instance.getClass(), fieldName).get(instance);
            patchCacheObjectNoEvict(cache, targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }
    }

    private static void patchCacheObjectNoEvict(Object cache, String targetPkg, Signature fakeSig) {
        if (cache == null) return;

        try {
            if (cache instanceof Map) {
                for (Object v : ((Map<?, ?>) cache).values()) {
                    if (v instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) v;
                        if (targetPkg.equals(pi.packageName)) patchPackageInfoSignatures(pi, fakeSig);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Method snapshot = cache.getClass().getMethod("snapshot");
            Object snap = snapshot.invoke(cache);
            if (snap instanceof Map) {
                for (Object v : ((Map<?, ?>) snap).values()) {
                    if (v instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) v;
                        if (targetPkg.equals(pi.packageName)) patchPackageInfoSignatures(pi, fakeSig);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }


    private static void patchExistingIpmRemoteBinder(IBinder hookedBinder) {
        if (hookedBinder == null) return;
        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method cur = atClz.getDeclaredMethod("currentActivityThread");
            cur.setAccessible(true);
            Object at = cur.invoke(null);
            if (at != null) {
                try {
                    Field fSPM = atClz.getDeclaredField("sPackageManager");
                    fSPM.setAccessible(true);
                    Object ipm = fSPM.get(at);
                    tryPatchIpmRemoteBinder(ipm, hookedBinder);
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method curApp = atClz.getDeclaredMethod("currentApplication");
            curApp.setAccessible(true);
            Object app = curApp.invoke(null);
            if (app instanceof Application) {
                PackageManager pm = ((Application) app).getPackageManager();
                try {
                    Field fMPM = findField(pm.getClass(), "mPM");
                    Object ipm = fMPM.get(pm);
                    tryPatchIpmRemoteBinder(ipm, hookedBinder);
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void tryPatchIpmRemoteBinder(Object ipm, IBinder hookedBinder) {
        if (ipm == null || hookedBinder == null) return;
        try {
            Field fRemote = findField(ipm.getClass(), "mRemote");
            Object cur = fRemote.get(ipm);
            if (cur != hookedBinder) fRemote.set(ipm, hookedBinder);
        } catch (Throwable ignored) {
        }
    }

    private static void installPmBinderProxyIfPossible(String targetPkg, Signature fakeSig) {
        if (targetPkg == null || fakeSig == null) return;

        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method cur = atClz.getDeclaredMethod("currentActivityThread");
            cur.setAccessible(true);
            Object at = cur.invoke(null);
            if (at != null) {
                Field fSPM = atClz.getDeclaredField("sPackageManager");
                fSPM.setAccessible(true);
                Object ipm = fSPM.get(at);
                IBinder baseBinder = extractIpmRemoteBinder(ipm);
                if (baseBinder != null) {
                    IBinder hooked = (baseBinder instanceof PmBinderProxy)
                            ? baseBinder
                            : new PmBinderProxy(baseBinder, targetPkg, fakeSig);
                    patchExistingIpmRemoteBinder(hooked);
                    patchServiceManagerPackageBinder(hooked);
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Application app = sApp;
            if (app != null) {
                PackageManager pm = app.getPackageManager();
                if (pm != null) {
                    Field fMPM = findField(pm.getClass(), "mPM");
                    Object ipm = fMPM.get(pm);
                    IBinder baseBinder = extractIpmRemoteBinder(ipm);
                    if (baseBinder != null) {
                        IBinder hooked = (baseBinder instanceof PmBinderProxy)
                                ? baseBinder
                                : new PmBinderProxy(baseBinder, targetPkg, fakeSig);
                        tryPatchIpmRemoteBinder(ipm, hooked);
                        patchServiceManagerPackageBinder(hooked);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static IBinder extractIpmRemoteBinder(Object ipm) {
        if (ipm == null) return null;
        try {
            Field fRemote = findField(ipm.getClass(), "mRemote");
            Object v = fRemote.get(ipm);
            if (v instanceof IBinder) return (IBinder) v;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void patchServiceManagerPackageBinder(IBinder hookedBinder) {
        if (hookedBinder == null) return;
        try {
            Class<?> smClz = Class.forName("android.os.ServiceManager");
            Field fCache = findField(smClz, "sCache");
            Object cache = fCache.get(null);
            if (cache instanceof Map) {
                Object cur = ((Map<?, ?>) cache).get("package");
                if (cur != hookedBinder && cur instanceof IBinder) {
                    ((Map) cache).put("package", hookedBinder);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void patchPackageInfoCaches(String targetPkg, Signature fakeSig) {
        tryPatchCacheFromStaticField(PackageManager.class, "sPackageInfoCache", targetPkg, fakeSig);
        try {
            Class<?> apmClz = Class.forName("android.app.ApplicationPackageManager");
            tryPatchCacheFromStaticField(apmClz, "sPackageInfoCache", targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }

        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method curApp = atClz.getDeclaredMethod("currentApplication");
            curApp.setAccessible(true);
            Object app = curApp.invoke(null);
            if (app instanceof Application) {
                PackageManager pm = ((Application) app).getPackageManager();
                tryPatchCacheFromInstanceField(pm, "mPackageInfoCache", targetPkg, fakeSig);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void tryPatchCacheFromStaticField(Class<?> clz, String fieldName, String targetPkg, Signature fakeSig) {
        try {
            Object cache = findField(clz, fieldName).get(null);
            patchCacheObject(cache, targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }
    }

    private static void tryPatchCacheFromInstanceField(Object instance, String fieldName, String targetPkg, Signature fakeSig) {
        if (instance == null) return;
        try {
            Object cache = findField(instance.getClass(), fieldName).get(instance);
            patchCacheObject(cache, targetPkg, fakeSig);
        } catch (Throwable ignored) {
        }
    }

    private static void patchCacheObject(Object cache, String targetPkg, Signature fakeSig) {
        if (cache == null) return;

        try {
            if (cache instanceof Map) {
                for (Object v : ((Map<?, ?>) cache).values()) {
                    if (v instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) v;
                        if (targetPkg.equals(pi.packageName)) patchPackageInfoSignatures(pi, fakeSig);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Method snapshot = cache.getClass().getMethod("snapshot");
            Object snap = snapshot.invoke(cache);
            if (snap instanceof Map) {
                for (Object v : ((Map<?, ?>) snap).values()) {
                    if (v instanceof PackageInfo) {
                        PackageInfo pi = (PackageInfo) v;
                        if (targetPkg.equals(pi.packageName)) patchPackageInfoSignatures(pi, fakeSig);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Method evictAll = cache.getClass().getMethod("evictAll");
            evictAll.invoke(cache);
        } catch (Throwable ignored) {
        }
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

    private static final class PmBinderProxy implements IBinder {
        private final IBinder base;
        private final String targetPkg;
        private final Signature fakeSig;

        private final int codeGetPackageInfo;
        private final int codeGetPackageInfoAsUser;
        private final int codeGetPackageInfoVersioned;
        private final int codeGetPackageInfoVersionedAsUser;
        private final int codeCheckSignatures;
        private final int codeCheckSignaturesAsUser;
        private final int codeHasSigningCertificate;
        private final int codeHasSigningCertificateAsUser;

        PmBinderProxy(IBinder base, String targetPkg, Signature fakeSig) {
            this.base = base;
            this.targetPkg = targetPkg;
            this.fakeSig = fakeSig;

            int gp = -1;
            int gpa = -1;
            int gpv = -1;
            int gpva = -1;
            int cs = -1;
            int csa = -1;
            int hsc = -1;
            int hsca = -1;
            try {
                Class<?> stubClz = Class.forName("android.content.pm.IPackageManager$Stub");
                gp = readStaticIntSafely(stubClz, "TRANSACTION_getPackageInfo");
                gpa = readStaticIntSafely(stubClz, "TRANSACTION_getPackageInfoAsUser");
                gpv = readStaticIntSafely(stubClz, "TRANSACTION_getPackageInfoVersioned");
                gpva = readStaticIntSafely(stubClz, "TRANSACTION_getPackageInfoVersionedAsUser");
                cs = readStaticIntSafely(stubClz, "TRANSACTION_checkSignatures");
                csa = readStaticIntSafely(stubClz, "TRANSACTION_checkSignaturesAsUser");
                hsc = readStaticIntSafely(stubClz, "TRANSACTION_hasSigningCertificate");
                hsca = readStaticIntSafely(stubClz, "TRANSACTION_hasSigningCertificateAsUser");
            } catch (Throwable ignored) {
            }
            this.codeGetPackageInfo = gp;
            this.codeGetPackageInfoAsUser = gpa;
            this.codeGetPackageInfoVersioned = gpv;
            this.codeGetPackageInfoVersionedAsUser = gpva;
            this.codeCheckSignatures = cs;
            this.codeCheckSignaturesAsUser = csa;
            this.codeHasSigningCertificate = hsc;
            this.codeHasSigningCertificateAsUser = hsca;
        }

        @Override
        public String getInterfaceDescriptor() throws RemoteException {
            return base.getInterfaceDescriptor();
        }

        @Override
        public boolean pingBinder() {
            return base.pingBinder();
        }

        @Override
        public boolean isBinderAlive() {
            return base.isBinderAlive();
        }

        @Override
        public IInterface queryLocalInterface(String descriptor) {
            return base.queryLocalInterface(descriptor);
        }

        @Override
        public void dump(FileDescriptor fd, String[] args) throws RemoteException {
            base.dump(fd, args);
        }

        @Override
        public void dumpAsync(FileDescriptor fd, String[] args) throws RemoteException {
            base.dumpAsync(fd, args);
        }

        @Override
        public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            boolean result = base.transact(code, data, reply, flags);
            if (reply == null) return result;

            if (code == codeCheckSignatures || code == codeCheckSignaturesAsUser) {
                if (!replyHasNoException(reply)) return result;
                reply.setDataPosition(0);
                reply.setDataSize(0);
                reply.writeNoException();
                reply.writeInt(PackageManager.SIGNATURE_MATCH);
                reply.setDataPosition(0);
                return result;
            }

            if (code == codeHasSigningCertificate || code == codeHasSigningCertificateAsUser) {
                if (!replyHasNoException(reply)) return result;
                reply.setDataPosition(0);
                reply.setDataSize(0);
                reply.writeNoException();
                reply.writeInt(1);
                reply.setDataPosition(0);
                return result;
            }

            if (code == codeGetPackageInfo
                    || code == codeGetPackageInfoAsUser
                    || code == codeGetPackageInfoVersioned
                    || code == codeGetPackageInfoVersionedAsUser) {
                patchPackageInfoReplyIfPresent(reply);
                return result;
            }

            if (codeGetPackageInfo == -1
                    || codeGetPackageInfoAsUser == -1
                    || codeGetPackageInfoVersioned == -1
                    || codeGetPackageInfoVersionedAsUser == -1) {
                if (looksLikeIPackageManagerCall(data)) {
                    patchPackageInfoReplyIfPresent(reply);
                }
            }

            if (looksLikeIPackageManagerCall(data)) {
                patchPackageInfoReplyIfPresent(reply);
            }

            return result;
        }

        @Override
        public void linkToDeath(DeathRecipient recipient, int flags) throws RemoteException {
            base.linkToDeath(recipient, flags);
        }

        @Override
        public boolean unlinkToDeath(DeathRecipient recipient, int flags) {
            return base.unlinkToDeath(recipient, flags);
        }

        private boolean replyHasNoException(Parcel reply) {
            try {
                reply.setDataPosition(0);
                reply.readException();
                return true;
            } catch (Throwable ignored) {
                return false;
            }
        }

        private void patchPackageInfoReplyIfPresent(Parcel reply) {
            try {
                reply.setDataPosition(0);
                reply.readException();

                int present = reply.readInt();
                if (present == 0) {
                    reply.setDataPosition(0);
                    return;
                }

                PackageInfo pi = PackageInfo.CREATOR.createFromParcel(reply);
                if (pi == null) {
                    reply.setDataPosition(0);
                    return;
                }

                if (!targetPkg.equals(pi.packageName)) {
                    reply.setDataPosition(0);
                    return;
                }

                patchPackageInfoSignatures(pi, fakeSig);

                reply.setDataPosition(0);
                reply.setDataSize(0);
                reply.writeNoException();
                reply.writeInt(1);
                pi.writeToParcel(reply, 0);
                reply.setDataPosition(0);
            } catch (Throwable ignored) {
                try {
                    reply.setDataPosition(0);
                } catch (Throwable ignored2) {
                }
            }
        }

        private boolean looksLikeIPackageManagerCall(Parcel data) {
            if (data == null) return false;
            try {
                int pos = data.dataPosition();
                data.setDataPosition(0);
                String token = data.readString();
                data.setDataPosition(pos);
                return "android.content.pm.IPackageManager".equals(token);
            } catch (Throwable ignored) {
                return false;
            }
        }

        private static int readStaticIntSafely(Class<?> c, String fieldName) {
            try {
                Field f = c.getDeclaredField(fieldName);
                f.setAccessible(true);
                Object v = f.get(null);
                if (v instanceof Integer) return (Integer) v;
            } catch (Throwable ignored) {
            }
            return -1;
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

    /** native 层 open/readlinkat 重定向（一次性） **/
    private static boolean killOpen(String pkg) {
        Log.d(TAG, "killOpen: 去除 Open 检测，将重定向到 assets 内的 origin.apk");
        try {
            // 1) 加载 so（名称要和你编译出的 lib<name>.so 一致）
            System.loadLibrary(LIB_NAME);

            // 2) 找到当前 APK 的 base.apk 路径
            String apkPath = findSelfApkPath(pkg);
            if (apkPath == null) {
                Log.e(TAG, "未找到自身 base.apk 路径");
                return false;
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
                    return false;
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
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "加载/安装 native 重定向失败: " + t.getMessage(), t);
            return false;
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
        tryClearStaticCache(PackageManager.class, "sPackageInfoCache");

        try {
            Class<?> apmClz = Class.forName("android.app.ApplicationPackageManager");
            tryClearStaticCache(apmClz, "sPackageInfoCache");
        } catch (Throwable ignored) {
        }

        try {
            Class<?> atClz = Class.forName("android.app.ActivityThread");
            Method curApp = atClz.getDeclaredMethod("currentApplication");
            curApp.setAccessible(true);
            Object app = curApp.invoke(null);
            if (app instanceof Application) {
                PackageManager pm = ((Application) app).getPackageManager();
                tryClearInstanceCache(pm, "mPackageInfoCache");
            }
        } catch (Throwable ignored) {
        }
    }

    private static void tryClearStaticCache(Class<?> clz, String fieldName) {
        try {
            Object cache = findField(clz, fieldName).get(null);
            if (cache != null) {
                cache.getClass().getMethod("clear").invoke(cache);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void tryClearInstanceCache(Object instance, String fieldName) {
        if (instance == null) return;
        try {
            Object cache = findField(instance.getClass(), fieldName).get(instance);
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
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        sApp = this;
        startStealthSignaturePatcherIfPossible();
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sApp = this;
        startStealthSignaturePatcherIfPossible();
        Log.d(TAG, "HookApplication onCreate()");
        // 这里不再重复 init；静态块已做一次性保护
    }
}
