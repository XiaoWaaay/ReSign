package com.resign.pro.core;

import android.content.pm.ApplicationInfo;

import com.resign.pro.util.FileUtils;
import com.resign.pro.util.Logger;
import com.resign.pro.util.ZipUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Split APK处理器
 * 
 * 处理多APK应用（App Bundle / Split APK）的重打包：
 * 1. 识别Split APK类型（config.abi, config.locale, config.density, feature模块）
 * 2. 对base APK执行完整注入流程
 * 3. 对split APK进行必要的签名处理
 * 4. 确保所有APK使用一致的签名
 * 
 * Split APK类型：
 * - split_config.<abi>.apk    : ABI相关配置
 * - split_config.<locale>.apk : 语言相关配置
 * - split_config.<dpi>.apk    : 屏幕密度相关配置
 * - split_<feature>.apk       : 动态Feature模块
 */
public class SplitApkHandler {

    private static final String TAG = "SplitApkHandler";

    /**
     * Split APK信息
     */
    public static class SplitInfo {
        public final File file;
        public final String name;
        public final SplitType type;
        public final String qualifier; // abi名/语言/密度/feature名

        public SplitInfo(File file, String name, SplitType type, String qualifier) {
            this.file = file;
            this.name = name;
            this.type = type;
            this.qualifier = qualifier;
        }
    }

    public enum SplitType {
        ABI,        // split_config.arm64_v8a.apk
        LOCALE,     // split_config.zh.apk
        DENSITY,    // split_config.xxhdpi.apk
        FEATURE,    // split_feature_xxx.apk
        UNKNOWN
    }

    /**
     * 解析Split APK列表
     */
    public static List<SplitInfo> parseSplits(String[] splitPaths) {
        List<SplitInfo> splits = new ArrayList<>();
        if (splitPaths == null) return splits;

        for (String path : splitPaths) {
            File file = new File(path);
            String name = file.getName();
            SplitType type = SplitType.UNKNOWN;
            String qualifier = "";

            // 解析split类型
            if (name.startsWith("split_config.")) {
                String configName = name.replace("split_config.", "")
                        .replace(".apk", "");

                if (isAbiQualifier(configName)) {
                    type = SplitType.ABI;
                    qualifier = normalizeAbi(configName);
                } else if (isLocaleQualifier(configName)) {
                    type = SplitType.LOCALE;
                    qualifier = configName;
                } else if (isDensityQualifier(configName)) {
                    type = SplitType.DENSITY;
                    qualifier = configName;
                }
            } else if (name.startsWith("split_")) {
                type = SplitType.FEATURE;
                qualifier = name.replace("split_", "").replace(".apk", "");
            }

            splits.add(new SplitInfo(file, name, type, qualifier));
            Logger.d(TAG, "Split: " + name + " -> " + type + "(" + qualifier + ")");
        }

        return splits;
    }

    /**
     * 处理所有Split APK
     * 
     * 对于split APK，主要需要：
     * 1. 对ABI split：可能需要注入对应ABI的SO
     * 2. 对所有split：确保与base APK签名一致
     */
    public static void processSplits(List<SplitInfo> splits, File outputDir,
                                      android.content.Context context) throws Exception {
        File splitsOutDir = new File(outputDir, "splits");
        splitsOutDir.mkdirs();

        for (SplitInfo split : splits) {
            File outputSplit = new File(splitsOutDir, split.name);
            FileUtils.copyFile(split.file, outputSplit);

            // 对ABI split注入SO
            if (split.type == SplitType.ABI && !split.qualifier.isEmpty()) {
                if (!"arm64-v8a".equals(split.qualifier)) {
                    continue;
                }
                try {
                    SoInjector injector = new SoInjector(context);
                    injector.inject(outputSplit, split.qualifier, "libnative_engine.so");
                    Logger.i(TAG, "ABI split SO注入成功: " + split.name);
                } catch (Exception e) {
                    Logger.w(TAG, "ABI split SO注入失败: " + split.name + " - " + e.getMessage());
                }
            }

            // 重签名（使用与base相同的签名）
            try {
                ApkSigner.sign(outputSplit, context);
                Logger.i(TAG, "Split签名完成: " + split.name);
            } catch (Exception e) {
                Logger.w(TAG, "Split签名失败: " + split.name + " - " + e.getMessage());
            }
        }
    }

    /**
     * 获取目标应用需要的ABI列表（基于其split配置）
     */
    public static String[] getRequiredAbis(List<SplitInfo> splits) {
        List<String> abis = new ArrayList<>();
        for (SplitInfo split : splits) {
            if (split.type == SplitType.ABI) {
                abis.add(split.qualifier);
            }
        }
        return abis.toArray(new String[0]);
    }

    // ========== 内部辅助方法 ==========

    private static boolean isAbiQualifier(String name) {
        switch (name.toLowerCase()) {
            case "arm64_v8a":
            case "armeabi_v7a":
            case "armeabi":
            case "x86":
            case "x86_64":
            case "mips":
            case "mips64":
                return true;
            default:
                return false;
        }
    }

    private static String normalizeAbi(String name) {
        // split文件名使用下划线，ABI目录使用连字符
        switch (name.toLowerCase()) {
            case "arm64_v8a": return "arm64-v8a";
            case "armeabi_v7a": return "armeabi-v7a";
            case "x86_64": return "x86_64";
            case "x86": return "x86";
            default: return name.replace('_', '-');
        }
    }

    private static boolean isLocaleQualifier(String name) {
        // 语言限定符通常是2-3个小写字母，可能带区域后缀
        return name.matches("[a-z]{2,3}([-_][A-Za-z]{2,3})?");
    }

    private static boolean isDensityQualifier(String name) {
        switch (name.toLowerCase()) {
            case "ldpi":
            case "mdpi":
            case "hdpi":
            case "xhdpi":
            case "xxhdpi":
            case "xxxhdpi":
            case "tvdpi":
            case "anydpi":
            case "nodpi":
                return true;
            default:
                return false;
        }
    }
}
