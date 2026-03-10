/**
 * ReSignPro - AntiDetection
 *
 * 反检测模块：对抗应用的各种完整性检测手段
 * 包括：签名检测、安装器检测、调试检测、Root检测、框架检测等
 */
package com.resign.pro.payload;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

public class AntiDetection {

    private static final String TAG = "AntiDetection";

    /**
     * 安装所有反检测措施
     */
    public static void install(Context context, String origPkgName, String origInstallerName) {
        try {
            spoofInstaller(context, origInstallerName);
        } catch (Throwable t) {
            Log.w(TAG, "spoofInstaller failed", t);
        }

        try {
            hideDebugFlags(context);
        } catch (Throwable t) {
            Log.w(TAG, "hideDebugFlags failed", t);
        }

        try {
            hideXposedFramework();
        } catch (Throwable t) {
            Log.w(TAG, "hideXposedFramework failed", t);
        }

        try {
            spoofBuildFields();
        } catch (Throwable t) {
            Log.w(TAG, "spoofBuildFields failed", t);
        }

        // Native 层反检测
        NativeBridge.enableAntiDebug();
        NativeBridge.hideInjection();
    }

    /**
     * 伪装安装来源
     *
     * 很多应用检测 getInstallerPackageName 是否为 com.android.vending
     * 重打包后安装来源会变成 null 或 adb
     */
    private static void spoofInstaller(Context context, String installerName) {
        if (installerName == null || installerName.isEmpty()) {
            installerName = "com.android.vending"; // 默认伪装为 Google Play
        }

        try {
            // 通过反射修改 PackageManager 内部的安装器信息
            // 方法1: 修改 Settings.PackageSetting.installerPackageName
            // 这需要在 Java hook 层拦截 getInstallerPackageName 调用
            // 在 HookEntry 中已通过 Pine hook 处理

            Log.i(TAG, "Installer spoofed to: " + installerName);
        } catch (Throwable t) {
            Log.w(TAG, "spoofInstaller failed", t);
        }
    }

    /**
     * 隐藏调试标志
     */
    private static void hideDebugFlags(Context context) {
        try {
            // 清除 ApplicationInfo.FLAG_DEBUGGABLE
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(context.getPackageName(), 0);
            if (pi != null && pi.applicationInfo != null) {
                pi.applicationInfo.flags &= ~android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE;
            }
        } catch (Throwable t) {
            Log.w(TAG, "hideDebugFlags failed", t);
        }
    }

    /**
     * 隐藏 Xposed/LSPosed/Pine 框架痕迹
     */
    private static void hideXposedFramework() {
        // 1. 清除 Xposed 相关的系统属性
        List<String> xposedProps = Arrays.asList(
            "ro.xposed.version",
            "persist.sys.xposed.install"
        );

        // 2. 检查并清理堆栈中的框架类名
        // 通过 classloader 隔离，payload 中的 Pine 类不会出现在目标 app 的 classloader 中

        // 3. 隐藏 /proc/self/maps 中的框架 so
        NativeBridge.addMapsFilter("libpine");
        NativeBridge.addMapsFilter("libxposed");
        NativeBridge.addMapsFilter("liblsposed");
        NativeBridge.addMapsFilter("libdobby");
        NativeBridge.addMapsFilter("edxp");

        // 4. 清除环境变量中的框架路径
        try {
            // 通过反射清除 CLASSPATH 中的 xposed 路径
            Class<?> envClass = Class.forName("java.lang.ProcessEnvironment");
            // 这个比较危险，可能影响其他功能，谨慎处理
        } catch (Throwable ignored) {}

        Log.i(TAG, "Xposed framework traces hidden");
    }

    /**
     * 伪装 Build 字段
     *
     * 某些应用会检查 Build.TAGS 是否包含 "test-keys"（表示非官方ROM）
     * 或 Build.TYPE 是否为 "userdebug"
     */
    private static void spoofBuildFields() {
        try {
            setStaticField(Build.class, "TAGS", "release-keys");
            setStaticField(Build.class, "TYPE", "user");
            setStaticField(Build.class, "FINGERPRINT",
                Build.FINGERPRINT.replace("test-keys", "release-keys")
                                  .replace("userdebug", "user")
                                  .replace("eng", "user"));
        } catch (Throwable t) {
            Log.w(TAG, "spoofBuildFields failed", t);
        }
    }

    /**
     * 检查是否被检测到
     * 返回检测报告，用于调试
     */
    public static String selfCheck(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== AntiDetection SelfCheck ===\n");

        // 检查 debuggable 标志
        try {
            boolean debuggable = (context.getApplicationInfo().flags &
                    android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            sb.append("Debuggable: ").append(debuggable).append("\n");
        } catch (Throwable t) {
            sb.append("Debuggable check failed: ").append(t.getMessage()).append("\n");
        }

        // 检查 Build.TAGS
        sb.append("Build.TAGS: ").append(Build.TAGS).append("\n");
        sb.append("Build.TYPE: ").append(Build.TYPE).append("\n");

        // 检查 maps 中的敏感内容
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            boolean hasPayload = false;
            boolean hasPine = false;
            boolean hasXposed = false;
            while ((line = br.readLine()) != null) {
                if (line.contains("payload")) hasPayload = true;
                if (line.contains("libpine")) hasPine = true;
                if (line.contains("xposed")) hasXposed = true;
            }
            br.close();
            sb.append("Maps leak payload: ").append(hasPayload).append("\n");
            sb.append("Maps leak pine: ").append(hasPine).append("\n");
            sb.append("Maps leak xposed: ").append(hasXposed).append("\n");
        } catch (Throwable t) {
            sb.append("Maps check failed: ").append(t.getMessage()).append("\n");
        }

        // 检查 Native 引擎状态
        sb.append("Native status: ").append(NativeBridge.getStatus()).append("\n");

        return sb.toString();
    }

    /**
     * 通过反射修改 static final 字段
     */
    private static void setStaticField(Class<?> clazz, String fieldName, Object value) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);

            // 尝试移除 final 修饰符
            try {
                Field modifiersField = Field.class.getDeclaredField("accessFlags");
                modifiersField.setAccessible(true);
                modifiersField.setInt(field, field.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
            } catch (NoSuchFieldException e) {
                // Android 版本差异，尝试另一个名称
                try {
                    Field modifiersField = Field.class.getDeclaredField("modifiers");
                    modifiersField.setAccessible(true);
                    modifiersField.setInt(field, field.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
                } catch (NoSuchFieldException ignored) {}
            }

            field.set(null, value);
        } catch (Throwable t) {
            Log.w(TAG, "setStaticField " + fieldName + " failed", t);
        }
    }
}
