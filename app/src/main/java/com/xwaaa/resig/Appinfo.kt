package com.xwaaa.resig

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.util.Log
import com.xwaaa.resig.utils.IOUtils

class Appinfos(
    var name: String,
    var packageName: String,
    var packagePath: String,
    var signatures: Array<Signature>? = null
) {
    constructor() : this("", "", "", null)

    /**
     * 自动读取签名信息（当 signatures 为 null 时）
     */
    fun ensureSignatures(context: Context) {
        if (signatures != null) return

        try {
            val pm = context.packageManager
            val pkgInfo = if (android.os.Build.VERSION.SDK_INT >= 28) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }
            this.packageName = pkgInfo.packageName

            signatures = if (android.os.Build.VERSION.SDK_INT >= 28) {
                pkgInfo.signingInfo.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.signatures
            }

            Log.d("Appinfos", "签名已自动获取：${signatures?.size ?: 0} 个")
        } catch (e: Exception) {
            Log.e("Appinfos", "读取签名失败：${e.message}")
        }
    }

    override fun toString(): String {
        val signatureString = StringBuilder()
        signatures?.forEach { signature ->
            signatureString.append(signature.toCharsString())
                .append(IOUtils.LINE_SEPARATOR_UNIX)
        }
        return "Appinfo{name='$name', packageName='$packageName', packagePath='$packagePath', signatures='${signatureString.toString().trim()}'}"
    }
}
