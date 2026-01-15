package com.xwaaa.resig;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class Core {
    static String TAG = "去签 Core代码";
    Appinfos appinfo;
    Context context;
    Options options;

    public static class Options {
        public boolean enableJavaHook = true;
        public boolean enableNativeHook = true;
        public boolean enableIoRedirect = true;
        public boolean enableMapsHide = true;
        public boolean enableResourceRedirect = false;

        public boolean enableCache = true;
        public boolean enablePayloadDexCache = true;
    }

    private static final String HOOK_APPLICATION = "com.xwaaa.hook.HookApplication";
    private static final String HOOK_COMPONENT_FACTORY = "com.xwaaa.hook.HookApplication$DelegatingAppComponentFactory";

    private static final String META_ENABLE_JAVA_HOOK = "resig.enableJavaHook";
    private static final String META_ENABLE_NATIVE_HOOK = "resig.enableNativeHook";
    private static final String META_ENABLE_IO_REDIRECT = "resig.enableIoRedirect";
    private static final String META_ENABLE_MAPS_HIDE = "resig.enableMapsHide";
    private static final String META_ENABLE_RESOURCE_REDIRECT = "resig.enableResourceRedirect";
    private static final String META_DEBUG_LOG = "resig.debugLog";

    public Core(Appinfos appinfo, Context context) {
        this.appinfo = appinfo;
        this.context = context;
        this.options = new Options();
    }

    public Core(Appinfos appinfo, Context context, Options options) {
        this.appinfo = appinfo;
        this.context = context;
        this.options = options != null ? options : new Options();
    }
    public void begin(){
        File[] dex_s=null;
        String targetPackageName = this.appinfo.getPackageName();
        String targetPackagePath = this.appinfo.getPackagePath();

        boolean success = false;
        File workDirFile = null;
        String[] splitSourceDirs = null;

        if (targetPackageName == null || targetPackageName.isEmpty()) {
            throw new IllegalArgumentException("packageName is empty");
        }

        try {
            PackageManager pm = this.context.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfo(targetPackageName, 0);
            if (ai != null) {
                String p = ai.publicSourceDir;
                if (p == null || p.isEmpty()) p = ai.sourceDir;
                if (p != null && !p.isEmpty()) targetPackagePath = p;
                splitSourceDirs = ai.splitSourceDirs;
            }
        } catch (Throwable ignored) {
        }
        Log.d(TAG,"去签APP路径："+targetPackagePath+"\n去签APP的包名："+targetPackageName);

        //拼接一下目录路径
        String runId = String.valueOf(System.currentTimeMillis()) + "_" + UUID.randomUUID().toString().replace("-", "");
        String workDir=this.context.getFilesDir().getAbsolutePath()+'/'+targetPackageName+"/work_"+runId;
        workDirFile = new File(workDir);
        if (!workDirFile.exists()) {
            workDirFile.mkdirs();
        }
        Log.d(TAG,"工作路径："+workDir);

        try{
            //读取目标路径与工作目录，然后将其复制拷贝到工作目录
            try {
                FileUtils.INSTANCE.copyFile(targetPackagePath,workDir);
            } catch (Exception first) {
                Log.e("Error","将原文件复制到工作目录出错: "+targetPackagePath, first);
                String fallback = null;
                try {
                    if (targetPackageName != null && !targetPackageName.isEmpty()) {
                        PackageManager pm = this.context.getPackageManager();
                        ApplicationInfo ai = pm.getApplicationInfo(targetPackageName, 0);
                        if (ai != null) {
                            fallback = ai.sourceDir;
                            if (fallback == null || fallback.isEmpty()) fallback = ai.publicSourceDir;
                        }
                    }
                } catch (Throwable ignored) {
                }
                if (fallback != null && !fallback.isEmpty() && !fallback.equals(targetPackagePath)) {
                    targetPackagePath = fallback;
                    FileUtils.INSTANCE.copyFile(targetPackagePath, workDir);
                } else {
                    throw first;
                }
            }
            Log.d(TAG,"将原文件复制到工作目录成功");
            appinfo.ensureSignatures(context);
            Log.d(TAG,"调用appinfo去获取原始签名值");
//            Signature signature2 = this.appinfo.getSignatures()[0];  // ✅ 直接拿签名，不再重新计算
//            byte[] byteArray2 = signature2.toByteArray();
//            String Sig2 = Base64.encodeToString(byteArray2, 0); // 获取签名值
//            Log.d("签名1",Sig2);
            //拼接获取一下这个复制到的新文件
            String apkPath=workDir+"/base.apk";
            // 解包阶段：优先复用缓存，避免重复扫描/解压耗时
            try{
                String xmlPath=workDir+"/AndroidManifest.xml";
                try {
                    ensureExtractedWorkFiles(apkPath, workDir, xmlPath, options != null && options.enableCache);
                    //下面就是遍历dex了,接收所有的dex文件
                    File file=new File(workDir);
                    File[] files=file.listFiles(new FilenameFilter() {
                        @Override
                        public boolean accept(File dir,String name) {
                            return name.contains(".dex");
                        }
                    });
                    if (files == null) {
                        throw new IllegalStateException("list dex failed");
                    }
                    Log.d(TAG,"xml路径："+xmlPath);
                    String manifestPkg = Injector.Companion.getManifestPackageName(xmlPath);
                    String manifestApp = Injector.Companion.getApplicationName(xmlPath);
                    String manifestFactory = Injector.Companion.getAppComponentFactoryName(xmlPath);
                    String effectiveOriginalApp = normalizeClassName(manifestApp, manifestPkg);
                    String effectiveOriginalFactory = normalizeClassName(manifestFactory, manifestPkg);

                    // 先把原始 XML 值（原始 Application/Factory）写入 payload dex，再修改 Manifest 入口，
                    // 确保两者保持一致（任一失败都不会只改一半）。
                    Signature[] sigArr = this.appinfo.getSignatures();
                    if (sigArr == null || sigArr.length == 0) {
                        throw new IllegalStateException("signature missing");
                    }
                    Signature signature = sigArr[0];
                    byte[] byteArray = signature.toByteArray();
                    String Sig = Base64.encodeToString(byteArray, Base64.NO_WRAP);
                    Log.d(TAG, "Signature extracted: bytes=" + (byteArray == null ? -1 : byteArray.length) + " base64.len=" + (Sig == null ? -1 : Sig.length()) + " sha256=" + sha256String(Sig));
                    File payloadDex = ensurePatchedPayloadDex(
                            this.appinfo.getPackageName(),
                            Sig,
                            effectiveOriginalApp,
                            effectiveOriginalFactory,
                            options != null && options.enablePayloadDexCache
                    );
                    copyFile(payloadDex, new File(workDir, "classesx.dex"));
                    Log.d(TAG,"payload dex ready: " + payloadDex.getAbsolutePath() + " size=" + payloadDex.length());
                    int length = files.length;
                    Injector.Companion.renameFile(new File(workDir + "/classesx.dex"), new File(workDir + "/classes" + (length + 1) + ".dex"));

                    java.util.ArrayList<String> meta = buildRuntimeMetaData(options);
                    Injector.Companion.editManifestEntry(xmlPath, HOOK_APPLICATION, HOOK_COMPONENT_FACTORY, meta);
                    String patchedApp = Injector.Companion.getApplicationName(xmlPath);
                    String patchedFactory = Injector.Companion.getAppComponentFactoryName(xmlPath);
                    Log.d(TAG, "Manifest after patch: application=" + patchedApp + " appComponentFactory=" + patchedFactory);
                    try{
                        FileUtils.INSTANCE.copyFile(workDir + File.separator+ "base.apk", workDir + File.separator, "origin.apk");
                        Log.d(TAG, "injectDexCode: 拷贝base.apk to origin.apk");
                        Set<String> abis = collectApkAbis(new File(workDir, "base.apk"));
                        if (abis.isEmpty()) {
                            String[] supp = Build.SUPPORTED_ABIS;
                            if (supp != null) {
                                for (String a : supp) {
                                    if (a != null && !a.trim().isEmpty()) abis.add(a.trim());
                                }
                            }
                        }

                        File selfLibRoot = new File(workDir, "self_libs");
                        if (!selfLibRoot.exists()) {
                            selfLibRoot.mkdirs();
                        }

                        for (String abi : abis) {
                            if (abi == null || abi.trim().isEmpty()) continue;
                            String abiTrim = abi.trim();
                            File abiDir = new File(selfLibRoot, abiTrim);
                            abiDir.mkdirs();

                            File outPine = new File(abiDir, "libpine.so");
                            if (extractSelfNativeLib(this.context, abiTrim, "libpine.so", outPine)) {
                                try {
                                    FileUtils.INSTANCE.addToZip(outPine, workDir + "/base.apk", "lib/" + abiTrim + "/");
                                    Log.d(TAG, "begin: add libpine.so abi=" + abiTrim);
                                } catch (Throwable t) {
                                    Log.e(TAG, "add libpine.so failed abi=" + abiTrim, t);
                                }
                            } else {
                                Log.e(TAG, "libpine.so not found for abi=" + abiTrim);
                            }

                            File outKill = new File(abiDir, "libkillsignture.so");
                            if (extractSelfNativeLib(this.context, abiTrim, "libkillsignture.so", outKill)) {
                                try {
                                    FileUtils.INSTANCE.addToZip(outKill, workDir + "/base.apk", "lib/" + abiTrim + "/");
                                    Log.d(TAG, "begin: add libkillsignture.so abi=" + abiTrim);
                                } catch (Throwable t) {
                                    Log.e(TAG, "add libkillsignture.so failed abi=" + abiTrim, t);
                                }
                            } else {
                                try {
                                    FileUtils.INSTANCE.copyAssetToFile(this.context, "libkillsignture.so", abiDir.getAbsolutePath(), "libkillsignture.so");
                                    FileUtils.INSTANCE.addToZip(outKill, workDir + "/base.apk", "lib/" + abiTrim + "/");
                                    Log.d(TAG, "begin: add libkillsignture.so(assets fallback) abi=" + abiTrim);
                                } catch (Throwable t) {
                                    Log.e(TAG, "libkillsignture.so not found for abi=" + abiTrim, t);
                                }
                            }
                        }
                        File[] dex_s2 = new File(workDir).listFiles(new FilenameFilter() {
                            @Override // java.io.FilenameFilter
                            public boolean accept(File dir, String name) {
                                return name.contains(".dex");
                            }
                        });
                        int length2 = dex_s2.length;
                        int i = 0;
                        while (i < length2) {
                            String apkPath2 = apkPath;
                            File dex = dex_s2[i];
                            int i2 = length2;
                            try {
                                FileUtils.INSTANCE.addToZip(dex, workDir + "/base.apk", "");
                                dex_s = dex_s2;
                            } catch (Exception e) {
                                Log.e("Error","添加压缩文件报错", e);
                                throw new RuntimeException(e);
                            }
                            try {
                                Log.d(TAG, "begin: add dex " + dex.getName());
                                i++;
                                apkPath = apkPath2;
                                length2 = i2;
                                dex_s2 = dex_s;

                            } catch (Exception e5) {
                                Log.e("Error","添加压缩文件报错"+e5);
                                throw new RuntimeException(e5);
                            }
                        }

                        try{

                            FileUtils.INSTANCE.addToZip(new File(workDir + "/origin.apk"), workDir + "/base.apk", "assets/KillSig/");
                            Log.d(TAG, "begin: add origin");
                            FileUtils.INSTANCE.addToZip(new File(workDir + "/AndroidManifest.xml"), workDir + "/base.apk", "");
                            Log.d(TAG, "begin: add AndroidManifest");
                            Log.d(TAG, "完成");
                            File[] files1 = new File(workDir).listFiles(new FilenameFilter() { // from class: com.crack.sigkill.business.Core.3
                                @Override // java.io.FilenameFilter
                                public boolean accept(File dir, String name) {
                                    return !name.equals("base.apk");
                                }
                            });
                            int i3 = 0;
                            for (int length3 = files1.length; i3 < length3; length3 = length3) {
                                File file_2 = files1[i3];
                                file_2.delete();
                                Log.d(TAG, "删除文件：" + file_2.getName());
                                i3++;
                            }
                            String downloadPath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath();
                            File exportRoot = this.context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                            if (exportRoot == null) {
                                exportRoot = this.context.getFilesDir();
                            }
                            File exportDir = new File(exportRoot, "resign_export" + File.separator + targetPackageName + File.separator + runId);
                            if (!exportDir.exists()) {
                                exportDir.mkdirs();
                            }
                            File exportSplitsDir = new File(exportDir, "splits");
                            if (!exportSplitsDir.exists()) {
                                exportSplitsDir.mkdirs();
                            }

                            if (splitSourceDirs != null && splitSourceDirs.length > 0) {
                                for (String sp : splitSourceDirs) {
                                    try {
                                        if (sp == null || sp.isEmpty()) continue;
                                        File sFile = new File(sp);
                                        if (!sFile.exists()) continue;
                                        FileUtils.INSTANCE.copyFile(sp, exportSplitsDir.getAbsolutePath(), sFile.getName());
                                    } catch (Throwable ignored) {
                                    }
                                }
                            }

                            try {
                                FileUtils.INSTANCE.copyFile(workDir + "/base.apk", downloadPath, targetPackageName+"_去签.apk");
                                Log.d(TAG, "begin: 输出成功！  路径：" + downloadPath);
                                try {
                                    FileUtils.INSTANCE.copyFile(workDir + "/base.apk", exportDir.getAbsolutePath(), targetPackageName+"_repacked_base.apk");
                                } catch (Throwable ignored) {
                                }
                                success = true;
                            } catch (IOException e7) {
                                File fallbackDir = this.context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                                if (fallbackDir == null) {
                                    throw new RuntimeException(e7);
                                }
                                FileUtils.INSTANCE.copyFile(workDir + "/base.apk", fallbackDir.getAbsolutePath(), targetPackageName+"_去签.apk");
                                Log.d(TAG, "begin: 输出成功！  路径：" + fallbackDir.getAbsolutePath());
                                try {
                                    FileUtils.INSTANCE.copyFile(workDir + "/base.apk", exportDir.getAbsolutePath(), targetPackageName+"_repacked_base.apk");
                                } catch (Throwable ignored) {
                                }
                                success = true;
                            }

                        }catch (Exception e6){
                            Log.e("Error","压缩文件报错2"+e6);
                        }

                    }catch (Exception e4){
                        Log.e("Error","so注入报错"+e4);
                    }
                }catch (Exception e3){
                    Log.e("Error","从APK中解压xml文件报错"+e3);
                }
            }catch (Exception e2){
                Log.e("Error","解压dex文件出错", e2);
            }

        }catch (Exception e1){
            Log.e("Error","将原文件复制到工作目录出错，请检查是否有参数错误", e1);
        } finally {
            if (success && workDirFile != null) {
                try {
                    deleteRecursively(workDirFile);
                } catch (Throwable ignored) {
                }
            }
        }

    }

    private static String normalizeClassName(String raw, String manifestPackageName) {
        if (raw == null) return null;
        String v = raw.trim();
        if (v.isEmpty()) return v;
        String pkg = manifestPackageName != null ? manifestPackageName.trim() : "";
        if (v.startsWith(".")) {
            return pkg.isEmpty() ? v.substring(1) : (pkg + v);
        }
        if (v.contains(".")) return v;
        return pkg.isEmpty() ? v : (pkg + "." + v);
    }

    private static void deleteRecursively(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) {
                    deleteRecursively(c);
                }
            }
        }
        try {
            f.delete();
        } catch (Throwable ignored) {
        }
    }

    private java.util.ArrayList<String> buildRuntimeMetaData(Options opt) {
        Options o = opt != null ? opt : new Options();
        java.util.ArrayList<String> out = new java.util.ArrayList<String>(9);
        out.add(META_ENABLE_JAVA_HOOK + ":" + String.valueOf(o.enableJavaHook));
        out.add(META_ENABLE_NATIVE_HOOK + ":" + String.valueOf(o.enableNativeHook));
        out.add(META_ENABLE_IO_REDIRECT + ":" + String.valueOf(o.enableIoRedirect));
        out.add(META_ENABLE_MAPS_HIDE + ":" + String.valueOf(o.enableMapsHide));
        out.add(META_ENABLE_RESOURCE_REDIRECT + ":" + String.valueOf(o.enableResourceRedirect));
        out.add(META_DEBUG_LOG + ":" + String.valueOf(false));
        return out;
    }

    private void ensureExtractedWorkFiles(String apkPath, String workDir, String xmlPath, boolean enableCache) throws IOException {
        if (!enableCache) {
            FileUtils.INSTANCE.extractDexFile(apkPath, workDir);
            FileUtils.INSTANCE.extractXmlFile(apkPath, workDir);
            return;
        }

        File apkFile = new File(apkPath);
        String key = sha256File(apkFile);
        File cacheDir = new File(this.context.getCacheDir(), "resig_repack_cache" + File.separator + "extract" + File.separator + key);
        File cachedManifest = new File(cacheDir, "AndroidManifest.xml");

        if (cachedManifest.exists()) {
            copyFile(cachedManifest, new File(xmlPath));
            File[] cachedDex = cacheDir.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name != null && name.endsWith(".dex");
                }
            });
            if (cachedDex != null) {
                for (File dex : cachedDex) {
                    copyFile(dex, new File(workDir, dex.getName()));
                }
            }
            return;
        }

        FileUtils.INSTANCE.extractDexFile(apkPath, workDir);
        FileUtils.INSTANCE.extractXmlFile(apkPath, workDir);

        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }
        File manifest = new File(xmlPath);
        if (manifest.exists()) {
            copyFile(manifest, new File(cacheDir, "AndroidManifest.xml"));
        }
        File[] dexFiles = new File(workDir).listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name != null && name.endsWith(".dex");
            }
        });
        if (dexFiles != null) {
            for (File dex : dexFiles) {
                if ("classesx.dex".equalsIgnoreCase(dex.getName())) continue;
                copyFile(dex, new File(cacheDir, dex.getName()));
            }
        }
    }

    private File ensurePatchedPayloadDex(
            String pkg,
            String sigBase64,
            String originalApplication,
            String originalFactory,
            boolean enableCache
    ) throws IOException {
        File cacheRoot = new File(this.context.getCacheDir(), "resig_repack_cache" + File.separator + "payload");
        if (!cacheRoot.exists()) {
            cacheRoot.mkdirs();
        }

        String payloadAssetSha256 = null;
        try {
            payloadAssetSha256 = sha256Asset(this.context, "classesx.dex");
        } catch (Throwable ignored) {
        }
        Log.d(TAG, "payloadAsset.sha256=" + payloadAssetSha256);

        String key = sha256String(
                String.valueOf(pkg) + "|" +
                        String.valueOf(sigBase64) + "|" +
                        String.valueOf(originalApplication) + "|" +
                        String.valueOf(originalFactory) + "|" +
                        String.valueOf(payloadAssetSha256)
        );
        File dir = new File(cacheRoot, key);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        File out = new File(dir, "classesx.dex");
        if (enableCache && out.exists() && out.length() > 0) {
            return out;
        }

        FileUtils.INSTANCE.copyAssetToFile(this.context, "classesx.dex", dir.getAbsolutePath(), "classesx.dex");
        Injector.Companion.editShellDEX(out.getAbsolutePath(), pkg, sigBase64, originalApplication, originalFactory);
        return out;
    }

    private static String sha256Asset(Context context, String assetName) throws IOException {
        if (context == null) throw new IOException("sha256Asset: context is null");
        if (assetName == null || assetName.isEmpty()) throw new IOException("sha256Asset: assetName is empty");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InputStream is = context.getAssets().open(assetName);
            try {
                byte[] buf = new byte[256 * 1024];
                while (true) {
                    int n = is.read(buf);
                    if (n < 0) break;
                    if (n > 0) md.update(buf, 0, n);
                }
            } finally {
                try {
                    is.close();
                } catch (Throwable ignored) {
                }
            }
            return toHex(md.digest());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("sha256Asset failed: " + e.getMessage(), e);
        }
    }

    private static void copyFile(File src, File dst) throws IOException {
        if (src == null || dst == null) throw new IOException("copyFile: null");
        if (!src.exists() || !src.isFile()) throw new IOException("copyFile: missing src " + src.getAbsolutePath());
        File parent = dst.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        FileInputStream fis = new FileInputStream(src);
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream(dst);
            try {
                byte[] buf = new byte[256 * 1024];
                while (true) {
                    int n = fis.read(buf);
                    if (n < 0) break;
                    if (n > 0) fos.write(buf, 0, n);
                }
                try {
                    fos.getFD().sync();
                } catch (Throwable ignored) {
                }
            } finally {
                fos.close();
            }
        } finally {
            fis.close();
        }
    }

    private static String sha256File(File f) throws IOException {
        if (f == null || !f.exists() || !f.isFile()) throw new IOException("sha256File: invalid file");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            FileInputStream fis = new FileInputStream(f);
            try {
                byte[] buf = new byte[256 * 1024];
                while (true) {
                    int n = fis.read(buf);
                    if (n < 0) break;
                    if (n > 0) md.update(buf, 0, n);
                }
            } finally {
                fis.close();
            }
            return toHex(md.digest());
        } catch (Exception e) {
            throw new IOException("sha256File failed: " + e.getMessage(), e);
        }
    }

    private static String sha256String(String s) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (s != null) {
                md.update(s.getBytes("UTF-8"));
            }
            return toHex(md.digest());
        } catch (Exception e) {
            throw new IOException("sha256String failed: " + e.getMessage(), e);
        }
    }

    private static String toHex(byte[] bytes) {
        if (bytes == null) return "";
        char[] hex = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = hex[(v >>> 4) & 0x0F];
            out[i * 2 + 1] = hex[v & 0x0F];
        }
        return new String(out);
    }

    private static Set<String> collectApkAbis(File apk) {
        HashSet<String> out = new HashSet<String>(4);
        if (apk == null || !apk.exists() || !apk.isFile()) return out;
        try {
            ZipFile zip = new ZipFile(apk);
            try {
                Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e == null) continue;
                    String name = e.getName();
                    if (name == null) continue;
                    if (!name.startsWith("lib/")) continue;
                    int p = name.indexOf('/', 4);
                    if (p <= 4) continue;
                    String abi = name.substring(4, p);
                    if (abi != null && !abi.trim().isEmpty()) out.add(abi.trim());
                }
            } finally {
                zip.close();
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static boolean extractSelfNativeLib(Context ctx, String abi, String libName, File outFile) {
        if (ctx == null || abi == null || libName == null || outFile == null) return false;
        String abiTrim = abi.trim();
        if (abiTrim.isEmpty()) return false;
        String entryName = "lib/" + abiTrim + "/" + libName;

        ApplicationInfo ai;
        try {
            ai = ctx.getApplicationInfo();
        } catch (Throwable t) {
            return false;
        }
        if (ai == null) return false;

        if (tryExtractFromApk(ai.sourceDir, entryName, outFile)) return true;

        String[] splits = ai.splitSourceDirs;
        if (splits != null) {
            for (String sp : splits) {
                if (sp == null || sp.isEmpty()) continue;
                if (tryExtractFromApk(sp, entryName, outFile)) return true;
            }
        }
        return false;
    }

    private static boolean tryExtractFromApk(String apkPath, String entryName, File outFile) {
        if (apkPath == null || apkPath.isEmpty() || entryName == null || entryName.isEmpty() || outFile == null) return false;
        File apk = new File(apkPath);
        if (!apk.exists() || !apk.isFile()) return false;
        try {
            ZipFile zip = new ZipFile(apk);
            try {
                ZipEntry e = zip.getEntry(entryName);
                if (e == null) return false;
                InputStream is = zip.getInputStream(e);
                try {
                    File parent = outFile.getParentFile();
                    if (parent != null && !parent.exists()) parent.mkdirs();
                    java.io.FileOutputStream os = new java.io.FileOutputStream(outFile);
                    try {
                        byte[] buf = new byte[256 * 1024];
                        while (true) {
                            int n = is.read(buf);
                            if (n < 0) break;
                            if (n > 0) os.write(buf, 0, n);
                        }
                        try {
                            os.getFD().sync();
                        } catch (Throwable ignored) {
                        }
                    } finally {
                        os.close();
                    }
                } finally {
                    is.close();
                }
                return true;
            } finally {
                zip.close();
            }
        } catch (Throwable ignored) {
            return false;
        }
    }


}
