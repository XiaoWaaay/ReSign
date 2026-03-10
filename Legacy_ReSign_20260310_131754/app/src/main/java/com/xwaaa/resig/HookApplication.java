//package com.xwaaa.hook;
//
//import android.app.Application;
//import android.content.pm.PackageInfo;
//import android.content.pm.PackageManager;
//import android.content.pm.Signature;
//import android.os.Build;
//import android.os.Environment;
//import android.os.Parcel;
//import android.os.Parcelable;
//import android.util.Base64;
//import android.util.Log;
//
//import java.io.BufferedReader;
//import java.io.File;
//import java.io.FileOutputStream;
//import java.io.FileReader;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.lang.reflect.Field;
//import java.util.Map;
//import java.util.concurrent.atomic.AtomicBoolean;
//import java.util.zip.ZipEntry;
//import java.util.zip.ZipFile;
//
//public class HookApplication extends Application {
//    private static final String TAG = "HookApplication";
//    static String packageName = "xwaaa.package";
//    static String signatureData = "xwaaa resig";
//    private static final AtomicBoolean INIT_ONCE = new AtomicBoolean(false);
//
//    private static native void hookApkPath(String str, String str2);
//
//    private static native void cleanup();
//
//    // 静态块 - 在类加载时立即执行
//    static {
//        Log.d(TAG, "=== HookApplication 静态块开始 ===");
//        try {
//            initSignatureHook();
//        } catch (Exception e) {
//            Log.e(TAG, "静态块初始化失败: " + e.getMessage(), e);
//        }
//        Log.d(TAG, "=== HookApplication 静态块结束 ===");
//    }
//
//    /**
//     * 初始化签名 Hook
//     */
//    private static void initSignatureHook() {
//        try {
//            Log.d(TAG, "开始初始化签名 Hook...");
//
//            Log.d(TAG, "成功提取包名: " + packageName);
//            Log.d(TAG, "成功提取签名: " + signatureData);
//
//            // 3. 执行 Java层pm Hook
//            killPM(packageName, signatureData);
//
//            // 4、执行so层 open函数的hook
//            killOpen(packageName);
//
//            Log.d(TAG, "签名 Hook 初始化完成!");
//            //cleanup();
//
//        } catch (Exception e) {
//            Log.e(TAG, "初始化签名 Hook 失败: " + e.getMessage(), e);
//        }
//    }
//
//    // 核心 Hook 方法
//    private static void killPM(final String packageName, String signatureData) {
//        Log.d(TAG, "执行 PackageManager Hook...");
//
//        try {
//            final Signature fakeSignature = new Signature(Base64.decode(signatureData, 0));
//            final Parcelable.Creator<PackageInfo> originalCreator = PackageInfo.CREATOR;
//
//            // 创建替换的 CREATOR
//            Parcelable.Creator<PackageInfo> creator = new Parcelable.Creator<PackageInfo>() {
//                @Override
//                public PackageInfo createFromParcel(Parcel source) {
//                    PackageInfo packageInfo = (PackageInfo) originalCreator.createFromParcel(source);
//
//                    if (packageName.equals(packageInfo.packageName)) {
//                        // 替换 signatures
//                        if (packageInfo.signatures != null && packageInfo.signatures.length > 0) {
//                            packageInfo.signatures[0] = fakeSignature;
//                            Log.d(TAG, "已替换 signatures[0]");
//                        }
//
//                        // Android 9.0+ 替换 signingInfo
//                        if (Build.VERSION.SDK_INT >= 28 && packageInfo.signingInfo != null) {
//                            try {
//                                Signature[] apkSigners = packageInfo.signingInfo.getApkContentsSigners();
//                                if (apkSigners != null && apkSigners.length > 0) {
//                                    apkSigners[0] = fakeSignature;
//                                    Log.d(TAG, "已替换 signingInfo 签名");
//                                }
//                            } catch (Exception e) {
//                                Log.e(TAG, "替换 signingInfo 失败: " + e.getMessage());
//                            }
//                        }
//                    }
//                    return packageInfo;
//                }
//
//                @Override
//                public PackageInfo[] newArray(int size) {
//                    return originalCreator.newArray(size);
//                }
//            };
//
//            // 替换 PackageInfo.CREATOR
//            findField(PackageInfo.class, "CREATOR").set(null, creator);
//            Log.d(TAG, "成功替换 PackageInfo.CREATOR");
//
//            // 清理缓存
//            clearPackageManagerCaches();
//
//        } catch (Exception e) {
//            Log.e(TAG, "PackageManager Hook 失败: " + e.getMessage(), e);
//            throw new RuntimeException(e);
//        }
//    }
//
//    // 核心 hook so方法
//    private static void killOpen(String packageName2) {
//        Log.d(TAG, "killOpen: 去除 Open 检测，将重定向到assert下的目录中");
//        try {
//            // 首先加载so文件
//            System.loadLibrary("killsignture");
//            // 获取APK路径，也就是assert下的那个路径
//            String apkPath = getApkPath(packageName2);
//            if (apkPath == null) {
//                System.err.println("Get apk path failed");
//                return;
//            }
//            File apkFile = new File(apkPath);
//            File repFile = new File(getDataFile(packageName2), "origin.apk");
//            try {
//                ZipFile zipFile = new ZipFile(apkFile);
//                ZipEntry entry = zipFile.getEntry("assets/KillSig/origin.apk");
//                if (entry == null) {
//                    System.err.println("未找到: assets/KillSig/origin.apk");
//                    zipFile.close();
//                    return;
//                }
//                if (!repFile.exists() || repFile.length() != entry.getSize()) {
//                    InputStream is = zipFile.getInputStream(entry);
//                    OutputStream os = new FileOutputStream(repFile);
//                    try {
//                        byte[] buf = new byte[102400];
//                        while (true) {
//                            int len = is.read(buf);
//                            if (len == -1) {
//                                break;
//                            }
//                            os.write(buf, 0, len);
//                        }
//                        os.close();
//                        if (is != null) {
//                            is.close();
//                        }
//                    } catch (Throwable th) {
//                        try {
//                            os.close();
//                        } catch (Throwable th2) {
//                            th.addSuppressed(th2);
//                        }
//                        throw th;
//                    }
//                }
//                zipFile.close();
//                hookApkPath(apkFile.getAbsolutePath(), repFile.getAbsolutePath());
//                Log.d(TAG, "killOpen: io重定向 完成");
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        } catch (Throwable th3) {
//            System.err.println("Load signaturekill library failed");
//        }
//    }
//
//    private static String getApkPath(String packageName2) {
//        try {
//            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
//            while (true) {
//                String line = reader.readLine();
//                if (line != null) {
//                    String[] arr = line.split("\\s+");
//                    String path = arr[arr.length - 1];
//                    if (isApkPath(packageName2, path)) {
//                        reader.close();
//                        return path;
//                    }
//                } else {
//                    reader.close();
//                    return null;
//                }
//            }
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    private static boolean isApkPath(String packageName2, String path) {
//        if (!path.startsWith("/") || !path.endsWith(".apk")) {
//            return false;
//        }
//        String[] splitStr = path.substring(1).split("/", 6);
//        int splitCount = splitStr.length;
//        if (splitCount == 4 || splitCount == 5) {
//            if (splitStr[0].equals("data") && splitStr[1].equals("app")
//                    && splitStr[splitCount - 1].equals("base.apk")) {
//                return splitStr[splitCount - 2].startsWith(packageName2);
//            }
//            if (splitStr[0].equals("mnt") && splitStr[1].equals("asec") && splitStr[splitCount - 1].equals("pkg.apk")) {
//                return splitStr[splitCount - 2].startsWith(packageName2);
//            }
//        } else if (splitCount == 3) {
//            if (splitStr[0].equals("data") && splitStr[1].equals("app")) {
//                return splitStr[2].startsWith(packageName2);
//            }
//        } else if (splitCount == 6 && splitStr[0].equals("mnt") && splitStr[1].equals("expand")
//                && splitStr[3].equals("app") && splitStr[5].equals("base.apk")) {
//            return splitStr[4].endsWith(packageName2);
//        }
//        return false;
//    }
//
//    private static File getDataFile(String packageName2) {
//        String username = Environment.getExternalStorageDirectory().getName();
//        if (username.matches("\\d+")) {
//            File file = new File("/data/user/" + username + "/" + packageName2);
//            if (file.canWrite()) {
//                return file;
//            }
//        }
//        return new File("/data/data/" + packageName2);
//    }
//
//    // 清理 PackageManager 缓存
//    private static void clearPackageManagerCaches() {
//        String[] cacheFields = { "sPackageInfoCache", "mCreators", "sPairedCreators" };
//
//        for (String fieldName : cacheFields) {
//            try {
//                if (fieldName.equals("sPackageInfoCache")) {
//                    Object cache = findField(PackageManager.class, fieldName).get(null);
//                    cache.getClass().getMethod("clear").invoke(cache);
//                } else {
//                    Map<?, ?> cacheMap = (Map) findField(Parcel.class, fieldName).get(null);
//                    cacheMap.clear();
//                }
//                Log.d(TAG, "已清理缓存: " + fieldName);
//            } catch (Throwable e) {
//                Log.d(TAG, "清理缓存失败 " + fieldName + ": " + e.getMessage());
//            }
//        }
//    }
//
//    // 查找字段
//    private static Field findField(Class<?> clazz, String fieldName) throws Exception {
//        Class<?> current = clazz;
//        while (current != null) {
//            try {
//                Field field = current.getDeclaredField(fieldName);
//                field.setAccessible(true);
//                return field;
//            } catch (NoSuchFieldException e) {
//                current = current.getSuperclass();
//            }
//        }
//        throw new NoSuchFieldException(fieldName + " in " + clazz.getName());
//    }
//
//    @Override
//    public void onCreate() {
//        super.onCreate();
//        Log.d(TAG, "HookApplication onCreate()");
//    }
//}
