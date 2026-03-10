package com.resign.pro.core;

import android.content.Context;

import com.resign.pro.util.Logger;
import com.resign.pro.util.ZipUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Native SO注入器
 * 
 * 将预编译的Native库注入到目标APK中
 * 支持多ABI: arm64-v8a, armeabi-v7a, x86_64, x86
 * 
 * 注入策略：
 * 1. 检查目标APK已有的ABI目录
 * 2. 对每个目标ABI，将对应的SO文件注入到 lib/<abi>/目录
 * 3. SO文件来源：本应用的assets/resign_pro/lib/<abi>/目录
 */
public class SoInjector {

    private static final String TAG = "SoInjector";

    private static final String[] SUPPORTED_ABIS = {
            "arm64-v8a", "armeabi-v7a", "x86_64", "x86"
    };

    // SO资源在assets中的路径前缀
    private static final String ASSET_LIB_PREFIX = "resign_pro/lib/";

    private final Context context;

    public SoInjector(Context context) {
        this.context = context;
    }

    /**
     * 向APK注入指定ABI的SO文件
     * 
     * @param apk      目标APK文件
     * @param abi      目标ABI（如 "arm64-v8a"）
     * @param soName   SO文件名（如 "libnative_engine.so"）
     */
    public void inject(File apk, String abi, String soName) throws Exception {
        // 验证ABI是否支持
        boolean supported = false;
        for (String s : SUPPORTED_ABIS) {
            if (s.equals(abi)) {
                supported = true;
                break;
            }
        }
        if (!supported) {
            Logger.w(TAG, "不支持的ABI: " + abi + ", 跳过");
            return;
        }

        // 构建assets中的路径
        String assetPath = ASSET_LIB_PREFIX + abi + "/" + soName;
        
        // 尝试从assets读取SO
        byte[] soData = readAssetSafe(assetPath);
        
        if (soData == null) {
            // 尝试从应用自身的native libs目录读取
            soData = readFromNativeLibs(abi, soName);
        }

        if (soData == null) {
            Logger.w(TAG, "找不到SO文件: " + assetPath + ", 尝试从应用lib目录读取");
            // 从已安装的应用lib目录拷贝
            File nativeLibDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File soFile = new File(nativeLibDir, soName);
            if (soFile.exists()) {
                soData = readFileBytes(soFile);
            }
        }

        if (soData == null) {
            throw new Exception("找不到 " + abi + "/" + soName + " SO文件");
        }

        // 写入临时文件
        File tmpSo = File.createTempFile("inject_", ".so", context.getCacheDir());
        try {
            try (FileOutputStream fos = new FileOutputStream(tmpSo)) {
                fos.write(soData);
            }

            // 注入到APK的 lib/<abi>/目录
            String zipPath = "lib/" + abi + "/" + soName;
            ZipUtils.addFileToApk(apk, tmpSo, zipPath);

            Logger.i(TAG, "SO注入成功: " + zipPath + " (" + soData.length + " bytes)");
        } finally {
            tmpSo.delete();
        }
    }

    /**
     * 批量注入所有必需的SO到所有目标ABI
     */
    public void injectAll(File apk, String[] targetAbis) throws Exception {
        String[] soFiles = {"libnative_engine.so"};

        for (String abi : targetAbis) {
            for (String soName : soFiles) {
                try {
                    inject(apk, abi, soName);
                } catch (Exception e) {
                    Logger.w(TAG, "注入 " + abi + "/" + soName + " 失败: " + e.getMessage());
                    // 非关键SO允许失败
                }
            }
        }
    }

    /**
     * 从应用自身的native libs拷贝SO文件数据
     */
    private byte[] readFromNativeLibs(String targetAbi, String soName) {
        try {
            String nativeLibDir = context.getApplicationInfo().nativeLibraryDir;
            // nativeLibDir 通常指向设备的primary ABI目录
            // 如果目标ABI与设备ABI不同，需要从其他路径查找
            
            File soFile = new File(nativeLibDir, soName);
            if (soFile.exists()) {
                return readFileBytes(soFile);
            }
            
            // 尝试从base.apk中提取指定ABI的SO
            String apkPath = context.getApplicationInfo().sourceDir;
            return ZipUtils.extractEntryBytes(new File(apkPath), 
                    "lib/" + targetAbi + "/" + soName);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 安全读取asset文件
     */
    private byte[] readAssetSafe(String path) {
        try (InputStream is = context.getAssets().open(path)) {
            return readFully(is);
        } catch (IOException e) {
            return null;
        }
    }

    private static byte[] readFully(InputStream is) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static byte[] readFileBytes(File file) throws IOException {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
            return readFully(fis);
        }
    }
}
