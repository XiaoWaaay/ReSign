/**
 * ReSignPro - NativeBridge
 *
 * JNI 桥接层：Java 与 Native 引擎之间的接口
 * 所有 native 方法声明集中在此类
 */
package com.resign.pro.payload;

public class NativeBridge {

    private static final String TAG = "NativeBridge";
    private static boolean sLoaded = false;
    private static boolean sInitialized = false;

    /**
     * 加载 native 库
     *
     * @param libDir 包含 librepack_native.so 的目录路径
     * @return true 如果加载成功
     */
    public static synchronized boolean loadLibrary(String libDir) {
        if (sLoaded) return true;

        try {
            // 优先从指定目录加载
            if (libDir != null) {
                String soPath = libDir + "/librepack_native.so";
                System.load(soPath);
                sLoaded = true;
                return true;
            }
        } catch (UnsatisfiedLinkError e1) {
            // Fallback: 从默认路径加载
            try {
                System.loadLibrary("repack_native");
                sLoaded = true;
                return true;
            } catch (UnsatisfiedLinkError e2) {
                android.util.Log.e(TAG, "Failed to load native library", e2);
            }
        }

        return false;
    }

    /**
     * 初始化 native 引擎
     *
     * @param origApkPath   原始 APK 路径（重打包后的 APK 实际位置）
     * @param fakeApkPath   伪装 APK 路径（原始未修改的 APK，用于签名验证时返回）
     * @param origPkgName   原始包名
     * @param dataDir       应用数据目录
     * @param nativeBackend hook 后端: "plt_hook" / "seccomp" / "hybrid"
     * @return 0 成功, 负数失败
     */
    public static synchronized int init(String origApkPath, String fakeApkPath,
                                        String origPkgName, String dataDir,
                                        String nativeBackend) {
        if (!sLoaded) {
            android.util.Log.e(TAG, "Native library not loaded");
            return -100;
        }
        if (sInitialized) return 0;

        int ret = nativeInit(origApkPath, fakeApkPath, origPkgName, dataDir, nativeBackend);
        if (ret == 0) {
            sInitialized = true;
        }
        return ret;
    }

    /**
     * 添加路径重定向规则
     */
    public static boolean addRedirect(String fromPath, String toPath) {
        if (!sLoaded) return false;
        return nativeAddRedirect(fromPath, toPath);
    }

    /**
     * 添加 maps 过滤关键词
     */
    public static void addMapsFilter(String keyword) {
        if (!sLoaded) return;
        nativeAddMapsFilter(keyword);
    }

    /**
     * 设置 maps 字符串替换
     */
    public static void setMapsReplace(String oldStr, String newStr) {
        if (!sLoaded) return;
        nativeSetMapsReplace(oldStr, newStr);
    }

    /**
     * 获取引擎状态（JSON）
     */
    public static String getStatus() {
        if (!sLoaded) return "{\"initialized\":false,\"error\":\"not_loaded\"}";
        return nativeGetStatus();
    }

    /**
     * 启用反调试
     */
    public static void enableAntiDebug() {
        if (!sLoaded) return;
        nativeAntiDebug();
    }

    /**
     * 隐藏注入痕迹
     */
    public static void hideInjection() {
        if (!sLoaded) return;
        nativeHideInjection();
    }

    public static boolean isLoaded() {
        return sLoaded;
    }

    public static boolean isInitialized() {
        return sInitialized;
    }

    // ==================== Native 方法声明 ====================

    private static native int nativeInit(String origApkPath, String fakeApkPath,
                                          String origPkgName, String dataDir,
                                          String nativeBackend);

    private static native boolean nativeAddRedirect(String fromPath, String toPath);

    private static native void nativeAddMapsFilter(String keyword);

    private static native void nativeSetMapsReplace(String oldStr, String newStr);

    private static native String nativeGetStatus();

    private static native void nativeAntiDebug();

    private static native void nativeHideInjection();
}
