/**
 * ReSignPro - AppInfoHelper
 *
 * 应用信息获取辅助工具
 * 提供已安装应用列表、APK 信息解析等功能
 */
package com.resign.pro.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import java.io.File

object AppInfoHelper {

    private const val TAG = "AppInfoHelper"

    /**
     * 应用信息数据类
     */
    data class AppItem(
        val packageName: String,
        val appName: String,
        val versionName: String,
        val versionCode: Long,
        val apkPath: String,
        val splitApkPaths: List<String>,
        val isSystemApp: Boolean,
        val icon: Drawable?,
        val minSdkVersion: Int,
        val targetSdkVersion: Int,
        val signatureHash: String,
        val fileSize: Long,
        val hasSplits: Boolean
    )

    /**
     * 获取所有已安装应用（排除系统应用，除非 includeSystem=true）
     */
    fun getInstalledApps(context: Context, includeSystem: Boolean = false): List<AppItem> {
        val pm = context.packageManager
        val flags = PackageManager.GET_META_DATA or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    @Suppress("DEPRECATION")
                    PackageManager.GET_SIGNATURES
                }

        val packages = pm.getInstalledPackages(flags)
        val result = mutableListOf<AppItem>()

        for (pi in packages) {
            val ai = pi.applicationInfo ?: continue
            val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            if (!includeSystem && isSystem) continue

            result.add(packageInfoToAppItem(pm, pi))
        }

        return result.sortedBy { it.appName.lowercase() }
    }

    /**
     * 获取单个应用信息
     */
    fun getAppInfo(context: Context, packageName: String): AppItem? {
        return try {
            val pm = context.packageManager
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
            val pi = pm.getPackageInfo(packageName, flags)
            packageInfoToAppItem(pm, pi)
        } catch (e: PackageManager.NameNotFoundException) {
            Logger.w(TAG, "Package not found: $packageName")
            null
        }
    }

    /**
     * 从 APK 文件解析应用信息
     */
    fun getApkInfo(context: Context, apkPath: String): AppItem? {
        val pm = context.packageManager
        val pi = pm.getPackageArchiveInfo(apkPath, PackageManager.GET_META_DATA) ?: return null

        // PackageArchiveInfo 不设置 sourceDir，需要手动设置用于获取图标
        pi.applicationInfo?.let {
            it.sourceDir = apkPath
            it.publicSourceDir = apkPath
        }

        return packageInfoToAppItem(pm, pi)
    }

    /**
     * 获取应用的签名 SHA-256 哈希
     */
    fun getSignatureHash(context: Context, packageName: String): String? {
        return try {
            val pm = context.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                pi.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                pi.signatures
            }

            signatures?.firstOrNull()?.let {
                FileUtils.sha256(it.toByteArray())
            }
        } catch (e: Exception) {
            Logger.w(TAG, "Failed to get signature hash for $packageName", e)
            null
        }
    }

    /**
     * PackageInfo -> AppItem 转换
     */
    private fun packageInfoToAppItem(pm: PackageManager, pi: PackageInfo): AppItem {
        val ai = pi.applicationInfo
        val appName = ai?.let { pm.getApplicationLabel(it).toString() } ?: pi.packageName
        val icon = try { ai?.let { pm.getApplicationIcon(it) } } catch (e: Exception) { null }
        val apkPath = ai?.sourceDir ?: ""
        val fileSize = if (apkPath.isNotEmpty()) File(apkPath).length() else 0L

        val splitPaths = ai?.splitSourceDirs?.toList() ?: emptyList()

        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pi.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            pi.versionCode.toLong()
        }

        val sigHash = try {
            val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pi.signatures
            }
            sigs?.firstOrNull()?.let { FileUtils.sha256(it.toByteArray()) } ?: ""
        } catch (e: Exception) { "" }

        return AppItem(
            packageName = pi.packageName,
            appName = appName,
            versionName = pi.versionName ?: "unknown",
            versionCode = versionCode,
            apkPath = apkPath,
            splitApkPaths = splitPaths,
            isSystemApp = ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            icon = icon,
            minSdkVersion = ai?.minSdkVersion ?: 1,
            targetSdkVersion = ai?.targetSdkVersion ?: 1,
            signatureHash = sigHash,
            fileSize = fileSize,
            hasSplits = splitPaths.isNotEmpty()
        )
    }
}
