package com.resign.pro.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.util.Log;

import com.resign.pro.util.FileUtils;
import com.resign.pro.util.ZipUtils;
import com.resign.pro.util.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * 重打包主引擎
 * 
 * 核心流程：
 * 1. 解析目标APK（base + splits）
 * 2. 创建工作目录
 * 3. 提取原始签名信息
 * 4. 准备payload DEX（填充占位符：包名、签名、原始入口类）
 * 5. 修改AndroidManifest.xml（替换Application/AppComponentFactory入口）
 * 6. 注入payload DEX为classesN.dex
 * 7. 注入Native SO（多ABI）
 * 8. 注入origin.apk到assets
 * 9. 处理APK Signing Block（保留/伪造V2/V3签名）
 * 10. 输出最终APK
 */
public class PackEngine {

    private static final String TAG = "PackEngine";

    // 配置选项
    public static class Config {
        public boolean enableJavaHook = true;
        public boolean enableNativeHook = true;
        public boolean enableIoRedirect = true;
        public boolean enableMapsHide = true;
        public boolean enableResourceRedirect = false;
        public boolean enableDeepHide = true;
        public boolean debugLog = false;
        public HookMode hookMode = HookMode.STANDARD;
        public NativeBackend nativeBackend = NativeBackend.PLT;
        public boolean handleSplits = true;
        public boolean preserveSigningBlock = false;
    }

    public enum HookMode {
        SAFE,       // 仅基础PackageManager hook
        STANDARD,   // PM + Parcelable CREATOR + Binder
        AGGRESSIVE  // 全量hook + Deep Hide + Maps隐藏
    }

    public enum NativeBackend {
        PLT,        // PLT hook（兼容性最好）
        DOBBY,      // Inline hook（性能最好）
        SECCOMP,    // seccomp+SIGSYS（最底层）
        HYBRID      // PLT + seccomp组合
    }

    // 进度回调
    public interface ProgressCallback {
        void onProgress(int step, int total, String message);
        void onError(String error);
        void onComplete(String outputPath);
    }

    private final Context context;
    private final Config config;
    private ProgressCallback callback;

    // 内部状态
    private File workDir;
    private String targetPackage;
    private String targetApkPath;
    private String[] splitApkPaths;
    private byte[][] originalSignatures;
    private String originalAppClass;
    private String originalFactoryClass;
    private int existingDexCount;

    public PackEngine(Context context, Config config) {
        this.context = context;
        this.config = config;
    }

    public void setProgressCallback(ProgressCallback callback) {
        this.callback = callback;
    }

    /**
     * 执行重打包
     * @param packageName 目标包名
     * @return 输出APK路径
     */
    public String repack(String packageName) throws Exception {
        final int TOTAL_STEPS = 10;
        int step = 0;

        try {
            // Step 1: 解析目标应用
            progress(++step, TOTAL_STEPS, "解析目标应用...");
            resolveTarget(packageName);

            // Step 2: 创建工作目录
            progress(++step, TOTAL_STEPS, "创建工作目录...");
            createWorkDir();

            // Step 3: 拷贝APK到工作目录
            progress(++step, TOTAL_STEPS, "拷贝APK文件...");
            File baseApk = copyApkToWork();

            // Step 4: 提取签名和Manifest信息
            progress(++step, TOTAL_STEPS, "提取签名信息...");
            extractSignatureAndManifest(baseApk);

            // Step 5: 准备并注入payload DEX
            progress(++step, TOTAL_STEPS, "注入payload DEX...");
            injectPayloadDex(baseApk);

            // Step 6: 修改Manifest
            progress(++step, TOTAL_STEPS, "修改AndroidManifest.xml...");
            modifyManifest(baseApk);

            // Step 7: 注入Native SO
            progress(++step, TOTAL_STEPS, "注入Native库...");
            injectNativeSo(baseApk);

            // Step 8: 注入origin.apk到assets
            progress(++step, TOTAL_STEPS, "注入原始APK...");
            injectOriginApk(baseApk);

            // Step 9: 处理签名
            progress(++step, TOTAL_STEPS, "处理APK签名...");
            handleSigning(baseApk);

            // Step 10: 输出到最终位置
            progress(++step, TOTAL_STEPS, "导出产物...");
            String outputPath = exportResult(baseApk);

            if (callback != null) callback.onComplete(outputPath);
            return outputPath;

        } catch (Exception e) {
            Logger.e(TAG, "重打包失败", e);
            if (callback != null) callback.onError(e.getMessage());
            throw e;
        } finally {
            // 清理工作目录（可选保留用于调试）
            if (!config.debugLog && workDir != null && workDir.exists()) {
                FileUtils.deleteRecursive(workDir);
            }
        }
    }

    /**
     * 解析目标应用信息
     */
    private void resolveTarget(String packageName) throws Exception {
        this.targetPackage = packageName;

        PackageManager pm = context.getPackageManager();
        int flags = PackageManager.GET_META_DATA;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }

        PackageInfo pi = pm.getPackageInfo(packageName, flags);
        ApplicationInfo ai = pi.applicationInfo;

        this.targetApkPath = ai.sourceDir;

        // 获取split APK路径
        if (ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0) {
            this.splitApkPaths = ai.splitSourceDirs;
            Logger.i(TAG, "检测到Split APK: " + splitApkPaths.length + "个");
        }

        // 获取原始签名
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && pi.signingInfo != null) {
            Signature[] sigs = pi.signingInfo.getApkContentsSigners();
            if (sigs != null && sigs.length > 0) {
                originalSignatures = new byte[sigs.length][];
                for (int i = 0; i < sigs.length; i++) {
                    originalSignatures[i] = sigs[i].toByteArray();
                }
            }
        } else if (pi.signatures != null && pi.signatures.length > 0) {
            originalSignatures = new byte[pi.signatures.length][];
            for (int i = 0; i < pi.signatures.length; i++) {
                originalSignatures[i] = pi.signatures[i].toByteArray();
            }
        }

        if (originalSignatures == null || originalSignatures.length == 0) {
            throw new Exception("无法获取目标应用签名");
        }

        Logger.i(TAG, "目标: " + packageName + ", APK: " + targetApkPath
                + ", 签名数: " + originalSignatures.length);
    }

    /**
     * 创建工作目录
     */
    private void createWorkDir() {
        String runId = UUID.randomUUID().toString().substring(0, 8);
        File baseDir = new File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS),
                "resign_pro/" + targetPackage + "/" + runId);
        baseDir.mkdirs();
        this.workDir = baseDir;
        Logger.i(TAG, "工作目录: " + workDir.getAbsolutePath());
    }

    /**
     * 拷贝APK到工作目录
     */
    private File copyApkToWork() throws IOException {
        File destApk = new File(workDir, "base.apk");
        FileUtils.copyFile(new File(targetApkPath), destApk);

        // 拷贝split APKs
        if (config.handleSplits && splitApkPaths != null) {
            File splitsDir = new File(workDir, "splits");
            splitsDir.mkdirs();
            for (String splitPath : splitApkPaths) {
                File src = new File(splitPath);
                File dst = new File(splitsDir, src.getName());
                FileUtils.copyFile(src, dst);
            }
        }

        return destApk;
    }

    /**
     * 提取签名和Manifest信息
     */
    private void extractSignatureAndManifest(File apk) throws Exception {
        // 解析Manifest获取原始Application和AppComponentFactory
        ApkParser parser = new ApkParser(apk);
        ApkParser.ManifestInfo info = parser.parseManifest();

        this.originalAppClass = info.applicationClass;
        this.originalFactoryClass = info.appComponentFactory;
        this.existingDexCount = parser.countDexFiles();

        Logger.i(TAG, "原始Application: " + (originalAppClass != null ? originalAppClass : "null"));
        Logger.i(TAG, "原始AppComponentFactory: " + (originalFactoryClass != null ? originalFactoryClass : "null"));
        Logger.i(TAG, "现有DEX数量: " + existingDexCount);

        parser.close();
    }

    /**
     * 注入payload DEX
     */
    private void injectPayloadDex(File apk) throws Exception {
        // 从assets读取payload DEX模板
        InputStream is = context.getAssets().open("resign_pro/classesx.dex");
        File tempDex = new File(workDir, "classesx.dex.tmp");
        FileUtils.copyStream(is, new FileOutputStream(tempDex));
        is.close();

        // 使用DexInjector填充占位符
        DexInjector injector = new DexInjector();

        // 序列化签名为hex
        StringBuilder sigHex = new StringBuilder();
        for (int i = 0; i < originalSignatures.length; i++) {
            if (i > 0) sigHex.append("|");
            sigHex.append(bytesToHex(originalSignatures[i]));
        }

        DexInjector.PatchConfig patchConfig = new DexInjector.PatchConfig();
        patchConfig.packageName = targetPackage;
        patchConfig.signatureData = sigHex.toString();
        patchConfig.originalAppClass = originalAppClass != null ? originalAppClass : "";
        patchConfig.originalFactoryClass = originalFactoryClass != null ? originalFactoryClass : "";
        patchConfig.enableJavaHook = config.enableJavaHook;
        patchConfig.enableNativeHook = config.enableNativeHook;
        patchConfig.enableIoRedirect = config.enableIoRedirect;
        patchConfig.enableMapsHide = config.enableMapsHide;
        patchConfig.enableDeepHide = config.enableDeepHide;
        patchConfig.debugLog = config.debugLog;
        patchConfig.hookMode = config.hookMode.name();
        patchConfig.nativeBackend = config.nativeBackend.name();

        File patchedDex = new File(workDir, "payload.dex");
        injector.patchPayloadDex(tempDex, patchedDex, patchConfig);

        // 作为classesN+1.dex注入APK
        String dexName = "classes" + (existingDexCount + 1) + ".dex";
        ZipUtils.addFileToApk(apk, patchedDex, dexName);

        // 清理临时文件
        tempDex.delete();
        patchedDex.delete();

        Logger.i(TAG, "Payload DEX注入完成: " + dexName);
    }

    /**
     * 修改AndroidManifest.xml
     */
    private void modifyManifest(File apk) throws Exception {
        ManifestEditor editor = new ManifestEditor(apk, workDir);

        // payload入口类名（编译到payload DEX中的HookEntry）
        String hookEntryClass = "com.resign.pro.payload.HookEntry";
        String hookFactoryClass = "com.resign.pro.payload.HookEntry$DelegatingFactory";

        ManifestEditor.EditConfig editConfig = new ManifestEditor.EditConfig();
        editConfig.newApplicationClass = hookEntryClass;

        // 只在API 28+时设置AppComponentFactory
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            editConfig.newAppComponentFactory = hookFactoryClass;
        }

        // 写入meta-data配置
        editConfig.metaData.put("resignpro.package", targetPackage);
        editConfig.metaData.put("resignpro.originalApp", originalAppClass != null ? originalAppClass : "");
        editConfig.metaData.put("resignpro.originalFactory", originalFactoryClass != null ? originalFactoryClass : "");
        editConfig.metaData.put("resignpro.enableJavaHook", String.valueOf(config.enableJavaHook));
        editConfig.metaData.put("resignpro.enableNativeHook", String.valueOf(config.enableNativeHook));
        editConfig.metaData.put("resignpro.enableIoRedirect", String.valueOf(config.enableIoRedirect));
        editConfig.metaData.put("resignpro.enableMapsHide", String.valueOf(config.enableMapsHide));
        editConfig.metaData.put("resignpro.enableResourceRedirect", String.valueOf(config.enableResourceRedirect));
        editConfig.metaData.put("resignpro.enableDeepHide", String.valueOf(config.enableDeepHide));
        editConfig.metaData.put("resignpro.debugLog", String.valueOf(config.debugLog));
        editConfig.metaData.put("resignpro.hookMode", config.hookMode.name());
        editConfig.metaData.put("resignpro.nativeBackend", config.nativeBackend.name());

        editor.edit(editConfig);

        Logger.i(TAG, "Manifest修改完成");
    }

    /**
     * 注入Native SO
     */
    private void injectNativeSo(File apk) throws Exception {
        SoInjector injector = new SoInjector(context);
        String[] targetAbis = getTargetAbis(apk);

        for (String abi : targetAbis) {
            if (!"arm64-v8a".equals(abi)) {
                continue;
            }
            try {
                injector.inject(apk, abi, "libnative_engine.so");
            } catch (Exception e) {
                Logger.w(TAG, "注入 " + abi + "/libnative_engine.so 失败: " + e.getMessage());
            }
        }

        Logger.i(TAG, "Native SO注入完成, ABIs: " + Arrays.toString(targetAbis));
    }

    /**
     * 获取目标APK支持的ABI列表
     */
    private String[] getTargetAbis(File apk) throws Exception {
        ApkParser parser = new ApkParser(apk);
        String[] abis = parser.getAbis();
        parser.close();

        if (abis == null || abis.length == 0) {
            // 如果APK没有native库，使用设备的ABI
            abis = Build.SUPPORTED_ABIS;
            // 限制为我们支持的ABI
            List<String> supported = new ArrayList<>();
            List<String> ourAbis = Arrays.asList("arm64-v8a", "armeabi-v7a", "x86_64", "x86");
            for (String abi : abis) {
                if (ourAbis.contains(abi)) {
                    supported.add(abi);
                    break; // 只注入primary ABI
                }
            }
            if (supported.isEmpty()) {
                supported.add("arm64-v8a"); // 默认
            }
            abis = supported.toArray(new String[0]);
        }

        return abis;
    }

    /**
     * 注入原始APK到assets目录
     */
    private void injectOriginApk(File apk) throws Exception {
        // 将原始（未修改的）APK拷贝一份作为origin.apk
        File originApk = new File(workDir, "origin.apk");
        FileUtils.copyFile(new File(targetApkPath), originApk);

        // 注入到APK的assets/resign_pro/目录下
        ZipUtils.addFileToApk(apk, originApk, "assets/resign_pro/origin.apk");

        originApk.delete();
        Logger.i(TAG, "Origin APK注入完成");
    }

    /**
     * 处理APK签名
     * 
     * 策略：
     * 1. 如果配置保留Signing Block且目标有V2/V3签名 -> 尝试保留原始Signing Block
     * 2. 否则使用测试签名重新签名（V1）
     */
    private void handleSigning(File apk) throws Exception {
        if (config.preserveSigningBlock) {
            try {
                ApkSigningBlock.preserveSigningBlock(new File(targetApkPath), apk);
                Logger.i(TAG, "APK Signing Block已插入（仅用于欺骗存在性检测）");
            } catch (Exception e) {
                Logger.w(TAG, "Signing Block插入失败: " + e.getMessage());
            }
        }

        ApkSigner.sign(apk, context);
        Logger.i(TAG, "签名完成");
    }

    /**
     * 导出产物到最终位置
     */
    private String exportResult(File baseApk) throws IOException {
        File exportDir = new File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS),
                "resign_pro_export/" + targetPackage);
        exportDir.mkdirs();

        File outputApk = new File(exportDir, targetPackage + "_repacked.apk");
        FileUtils.copyFile(baseApk, outputApk);

        // 如果有split APKs，也导出
        if (config.handleSplits && splitApkPaths != null) {
            File splitsDir = new File(workDir, "splits");
            if (splitsDir.exists()) {
                File outSplitsDir = new File(exportDir, "splits");
                outSplitsDir.mkdirs();
                File[] splits = splitsDir.listFiles();
                if (splits != null) {
                    for (File split : splits) {
                        FileUtils.copyFile(split, new File(outSplitsDir, split.getName()));
                    }
                }
            }
        }

        Logger.i(TAG, "产物导出到: " + outputApk.getAbsolutePath());
        return outputApk.getAbsolutePath();
    }

    // ========== 工具方法 ==========

    private void progress(int step, int total, String message) {
        Logger.i(TAG, "[" + step + "/" + total + "] " + message);
        if (callback != null) {
            callback.onProgress(step, total, message);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
