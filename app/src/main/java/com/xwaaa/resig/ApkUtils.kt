package com.xwaaa.resig

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException

class ApkUtils(private val context: Context) {

    companion object {
        private const val TAG = "ApkUtils"
        private const val ORIGIN_FILENAME = "origin.apk" // 如需用到可保留
    }

    // 获取包名（按应用显示名匹配，注意应用名可能重复）
    fun getPackageNameFromInstalledApp(appName: String): String? {
        val pm = context.packageManager
        return try {
            pm.getInstalledApplications(0).firstOrNull {
                it.loadLabel(pm).toString() == appName
            }?.packageName
        } catch (e: Exception) {
            Log.e(TAG, "getPackageNameFromInstalledApp error", e)
            null
        }
    }

    // 获取已安装应用的 APK 路径（ApplicationInfo.sourceDir）
    fun getApkPathFromPackageName(packageName: String): String? {
        return try {
            val pi = context.packageManager.getPackageInfo(packageName, 0)
            pi.applicationInfo.sourceDir
        } catch (e: Exception) {
            Log.e(TAG, "getApkPathFromPackageName error", e)
            null
        }
    }

    //复制目标文件到似有母鹿下
    fun copyApkToPrivateDir(
        context: Context,
        apkPath: String,
        destSubDir: String = "apks",
        outFileName: String? = null,
        overwrite: Boolean = true
    ): File {
        val src = File(apkPath)
        if (!src.exists() || !src.isFile) {
            throw FileNotFoundException("没有找到目标apk的地址: $apkPath")
        }

        val destDir = File(context.filesDir, destSubDir)
        if (!destDir.exists() && !destDir.mkdirs()) {
            throw IOException("未能成功打开该文件的私有目录: ${destDir.absolutePath}")
        }

        val dest = File(destDir, outFileName ?: src.name)
        if (dest.exists() && !overwrite) return dest

        FileInputStream(src).use { fis ->
            FileOutputStream(dest).use { fos ->
                val buf = ByteArray(8 * 1024)
                while (true) {
                    val n = fis.read(buf)
                    if (n == -1) break
                    fos.write(buf, 0, n)
                }
                fos.fd.sync()
            }
        }
        return dest
    }

}
