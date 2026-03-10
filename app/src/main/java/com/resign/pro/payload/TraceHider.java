/**
 * ReSignPro - TraceHider
 *
 * 痕迹隐藏模块：清除重打包的文件级和进程级痕迹
 * 配合 AntiDetection 使用，提供更深层的隐藏能力
 */
package com.resign.pro.payload;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TraceHider {

    private static final String TAG = "TraceHider";

    /**
     * 隐藏所有重打包痕迹
     */
    public static void hideAll(Context context, String origPkgName) {
        hideFileTraces(context);
        hideClassLoaderTraces(context);
        hideSystemPropertyTraces();
        hideEnvironmentTraces();
        hideNativeTraces(origPkgName);
    }

    /**
     * 隐藏文件系统痕迹
     *
     * 重打包后可能在以下位置留下痕迹：
     * - /data/data/<pkg>/resign_pro/
     * - /data/data/<pkg>/cache/payload.dex
     * - /data/data/<pkg>/lib/ 中的额外 so
     */
    private static void hideFileTraces(Context context) {
        try {
            File dataDir = context.getDataDir();
            if (dataDir == null) return;

            // 将 resign_pro 目录设为隐藏（以 . 开头）
            File resignDir = new File(dataDir, "resign_pro");
            File hiddenDir = new File(dataDir, ".rsp");
            if (resignDir.exists() && !hiddenDir.exists()) {
                resignDir.renameTo(hiddenDir);
            }

            // 清除可能的临时文件
            File cacheDir = context.getCacheDir();
            if (cacheDir != null) {
                cleanTempFiles(cacheDir, new String[]{
                    "payload", "resign", "hook", "inject", "patch"
                });
            }

        } catch (Throwable t) {
            Log.w(TAG, "hideFileTraces failed", t);
        }
    }

    /**
     * 清理目录中匹配关键词的临时文件
     */
    private static void cleanTempFiles(File dir, String[] keywords) {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            String name = file.getName().toLowerCase();
            for (String keyword : keywords) {
                if (name.contains(keyword) && !name.endsWith(".dex") && !name.endsWith(".apk")) {
                    // 只删除明确的临时文件，不删除关键的 dex/apk
                    if (file.isFile() && name.endsWith(".tmp")) {
                        file.delete();
                    }
                    break;
                }
            }
        }
    }

    /**
     * 隐藏 ClassLoader 痕迹
     *
     * 重打包注入的 payload 可能使用额外的 DexClassLoader
     * 某些检测会遍历 ClassLoader 链寻找异常的 ClassLoader
     */
    private static void hideClassLoaderTraces(Context context) {
        try {
            // 获取当前 ClassLoader 链
            ClassLoader cl = context.getClassLoader();
            ClassLoader parent = cl.getParent();

            // 检查是否有注入的 DexClassLoader
            // 正常链: PathClassLoader -> BootClassLoader
            // 注入后: PathClassLoader -> DexClassLoader -> BootClassLoader
            // 需要跳过中间的注入 ClassLoader

            // 这里通过反射检查 ClassLoader 类型
            while (parent != null) {
                String clName = parent.getClass().getName();
                if (clName.contains("InMemoryDexClassLoader") ||
                    clName.contains("DexClassLoader") &&
                    !clName.equals("dalvik.system.PathClassLoader")) {

                    // 尝试修改 parent 链跳过此 ClassLoader
                    try {
                        Field parentField = ClassLoader.class.getDeclaredField("parent");
                        parentField.setAccessible(true);
                        ClassLoader grandParent = parent.getParent();
                        parentField.set(cl, grandParent);
                        Log.i(TAG, "Bypassed injected ClassLoader: " + clName);
                        break;
                    } catch (Throwable t) {
                        Log.w(TAG, "Failed to bypass ClassLoader", t);
                    }
                }
                cl = parent;
                parent = cl.getParent();
            }
        } catch (Throwable t) {
            Log.w(TAG, "hideClassLoaderTraces failed", t);
        }
    }

    /**
     * 隐藏系统属性痕迹
     */
    private static void hideSystemPropertyTraces() {
        // 某些检测通过反射读取系统属性检查框架
        List<String> suspiciousProps = new ArrayList<>();
        suspiciousProps.add("ro.resign.pro");
        suspiciousProps.add("persist.resign.pro");
        suspiciousProps.add("ro.debuggable");

        for (String prop : suspiciousProps) {
            try {
                // 通过反射调用 SystemProperties.set 清除属性
                // 注意：非 root 环境下可能无法修改
                Class<?> sysPropClass = Class.forName("android.os.SystemProperties");
                Method setMethod = sysPropClass.getDeclaredMethod("set", String.class, String.class);
                setMethod.setAccessible(true);
                setMethod.invoke(null, prop, "");
            } catch (Throwable ignored) {
                // 非 root 下预期失败
            }
        }
    }

    /**
     * 隐藏环境变量痕迹
     */
    private static void hideEnvironmentTraces() {
        try {
            // 检查 CLASSPATH 环境变量是否包含可疑路径
            String classpath = System.getenv("CLASSPATH");
            if (classpath != null && (classpath.contains("xposed") ||
                                      classpath.contains("lsposed") ||
                                      classpath.contains("resign"))) {
                // 尝试修改环境变量
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, String> envMap = (Map<String, String>)
                        Class.forName("java.lang.ProcessEnvironment")
                             .getDeclaredMethod("getenv")
                             .invoke(null);
                    if (envMap != null) {
                        // 过滤掉可疑的 CLASSPATH 条目
                        String cleaned = cleanClasspath(classpath);
                        // ProcessEnvironment 的 map 通常是不可变的，需要反射修改
                        // 这里仅做尝试
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {
            Log.w(TAG, "hideEnvironmentTraces failed", t);
        }
    }

    /**
     * 清理 CLASSPATH 中的可疑路径
     */
    private static String cleanClasspath(String classpath) {
        if (classpath == null) return "";
        String[] parts = classpath.split(":");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            String lower = part.toLowerCase();
            if (!lower.contains("xposed") && !lower.contains("lsposed") &&
                !lower.contains("resign") && !lower.contains("edxp")) {
                if (sb.length() > 0) sb.append(":");
                sb.append(part);
            }
        }
        return sb.toString();
    }

    /**
     * Native 层痕迹隐藏
     */
    private static void hideNativeTraces(String origPkgName) {
        // 已在 NativeBridge.hideInjection() 中处理 maps 过滤
        // 这里添加额外的包名相关过滤

        if (origPkgName != null && !origPkgName.isEmpty()) {
            // 在 maps 中将 resign_pro 相关路径替换为原始包名相关路径
            NativeBridge.addMapsFilter("resign_pro");
            NativeBridge.addMapsFilter("com.resign.pro");
        }

        // 隐藏常见 hook 框架的 so
        String[] hookSoNames = {
            "libsubstrate", "libfrida", "libgadget",
            "libredirect", "libhook", "libinject"
        };
        for (String soName : hookSoNames) {
            NativeBridge.addMapsFilter(soName);
        }
    }
}
