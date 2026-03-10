package com.xiao.resign.killsig;

import android.content.Context;
import android.content.pm.Signature;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

/**
 * NativeSignatureKiller — 第三层: Native IO 重定向 + Inline Hook + Seccomp
 *
 * 功能：
 * 1. Dobby Inline Hook 拦截 libc IO 函数（openat/fopen/stat 等）
 * 2. 将 base.apk 读取重定向到原始 APK 备份（签名正确的）
 * 3. Seccomp BPF 拦截内联 SVC 指令
 * 4. /proc/self/maps 过滤，隐藏 hook 痕迹
 *
 * 这一层主要防御：
 * - Native 代码直接 fopen/mmap base.apk 解析签名块
 * - 通过内联 SVC 绕过 libc hook
 * - 检查 /proc/self/maps 发现 hook 库
 */
public class NativeSignatureKiller {

    private static final String TAG = "NativeSigKiller";
    private static boolean sLoaded = false;

    static {
        try {
            System.loadLibrary("native_killer");
            sLoaded = true;
            Log.i(TAG, "libnative_killer.so loaded");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load libnative_killer.so: " + e.getMessage());
        }
    }

    /**
     * 安装 Native 层签名绕过
     */
    public static void install(Context context, Signature[] originalSignatures) {
        if (!sLoaded) {
            Log.e(TAG, "Native library not loaded, skip");
            return;
        }

        String packageName = context.getPackageName();
        String apkPath = context.getApplicationInfo().sourceDir;
        String dataDir = context.getApplicationInfo().dataDir;

        // 原始 APK 备份路径
        String origApkBackup = dataDir + "/.resign_orig.apk";

        File origFile = new File(origApkBackup);
        if (!origFile.exists()) {
            // 如果没有备份，用当前 APK（依赖 Java 层 Hook）
            origApkBackup = apkPath;
            Log.w(TAG, "No original APK backup, IO redirect limited");
        } else {
            Log.i(TAG, "Original APK backup found: " + origApkBackup);
        }

        // 准备签名字节数组
        byte[][] sigBytesArray = new byte[originalSignatures.length][];
        for (int i = 0; i < originalSignatures.length; i++) {
            sigBytesArray[i] = originalSignatures[i].toByteArray();
        }

        // 调用 native 初始化
        try {
            int result = nativeInstall(packageName, apkPath, origApkBackup,
                    dataDir, sigBytesArray);
            if (result == 0) {
                Log.i(TAG, "Native install success");
            } else {
                Log.e(TAG, "Native install failed: " + result);
            }
        } catch (Throwable t) {
            Log.e(TAG, "nativeInstall exception", t);
        }

        // 安装 maps 隐藏
        try {
            nativeHideMaps(new String[]{
                    "native_killer", "dobby", "frida", "xposed",
                    "substrate", "resign", "hook", "killsig"
            });
        } catch (Throwable t) {
            Log.w(TAG, "Maps hide failed: " + t.getMessage());
        }
    }

    /**
     * 备份原始 APK
     */
    public static boolean backupOriginalApk(Context context, String originalApkPath) {
        String dataDir = context.getApplicationInfo().dataDir;
        String backupPath = dataDir + "/.resign_orig.apk";

        try {
            File dst = new File(backupPath);
            if (dst.exists()) return true;

            try (InputStream in = new FileInputStream(originalApkPath);
                 FileOutputStream out = new FileOutputStream(dst)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
            }
            dst.setReadable(true, false);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Backup failed", e);
            return false;
        }
    }

    // ===== Native 方法 =====

    private static native int nativeInstall(String packageName, String currentApkPath,
                                            String origApkPath, String dataDir,
                                            byte[][] signatures);

    private static native void nativeHideMaps(String[] filterKeywords);

    public static native void nativeAddRedirect(String srcPath, String dstPath);

    public static native boolean nativeIsActive();
}
