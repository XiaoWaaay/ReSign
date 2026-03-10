package com.xwaaa.resig

import com.wind.meditor.core.ApkSigner
import com.wind.meditor.core.FileProcesser
import com.wind.meditor.property.AttributeItem
import com.wind.meditor.property.ModificationProperty
import com.wind.meditor.utils.FileTypeUtils
import com.wind.meditor.utils.Log
import com.wind.meditor.utils.NodeValue
import com.wind.meditor.utils.Utils
import java.io.File

/**
 * Android 工程内可直接调用的 Manifest / APK 修改器
 * 依赖 wind meditor 的核心库（FileProcesser、ModificationProperty 等）
 *
 * 用法：
 * val out = ManifestEditor.edit(
 *     inputPath = "/sdcard/Download/app.apk",
 *     options = ManifestEditor.Options(
 *         packageName = "com.example.newpkg",
 *         applicationName = "com.example.MyApp",
 *         debuggable = true,
 *         output = "/sdcard/Download/app-new-unsigned.apk",
 *         needSignApk = false,   // Android 环境下通常不要走 jarsigner
 *         forceOverwrite = true
 *     )
 * )
 */
object ManifestEditor {

    private const val ANDROID_NAMESPACE_PREFIX = "android-"
    private const val MULTI_NAME_SEPARATOR = ":"

    data class Options(
        // 输出文件路径（不传则按输入文件自动生成）
        val output: String? = null,

        // manifest 包名、版本
        val packageName: String? = null,
        val versionCode: Int? = null,
        val versionName: String? = null,

        // <application> 层属性
        val applicationName: String? = null,
        val debuggable: Boolean? = null,
        val extractNativeLibs: Boolean? = null,

        // 追加 uses-permission
        val usesPermissionList: List<String> = emptyList(),

        /**
         * 以下三类属性项的写法遵循命令行工具的习惯：
         *   - 若是 android 命名空间属性，name 请加前缀 "android-"
         *   - 形式为 "name:value"
         *   - 例如： "android-minSdkVersion:24"、"android-targetSdkVersion:34"
         */
        // <manifest> 层属性
        val manifestAttributeList: List<String> = emptyList(),
        // <application> 层属性
        val applicationAttributeList: List<String> = emptyList(),
        // <uses-sdk> 层属性
        val usesSdkAttributeList: List<String> = emptyList(),

        // <application><meta-data> 追加（"name:value"）
        val metaDataList: List<String> = emptyList(),
        // <application><meta-data> 删除（仅 name）
        val deleteMetaDataList: List<String> = emptyList(),

        // 文件覆盖与签名
        val forceOverwrite: Boolean = false,
        val needSignApk: Boolean = false   // Android 环境下一般设为 false
    )

    /**
     * 执行修改。返回最终输出文件路径。
     * @throws IllegalArgumentException 当入参非法
     * @throws IllegalStateException    当源文件不可处理
     */
    @JvmStatic
    fun edit(inputPath: String, options: Options): String {
        val srcFile = File(inputPath)
        require(srcFile.exists()) { "input file not found: $inputPath" }

        val isManifest = FileTypeUtils.isAndroidManifestFile(inputPath)
        val isApk = if (!isManifest) FileTypeUtils.isApkFile(inputPath) else false
        require(isManifest || isApk) { "input must be an AndroidManifest.xml or an .apk file" }

        // 计算输出路径
        val outputPath = options.output?.takeIf { it.isNotBlank() } ?: run {
            val base = getBaseName(inputPath)
            if (isManifest) "${base}-new.xml" else "${base}-unsigned.apk"
        }

        // 若需要“连签名”，预估签名后的输出路径
        val signedApkPath: String? = if (isApk && options.needSignApk) {
            options.output?.let { getBaseName(it) + "-signed.apk" } ?: (getBaseName(inputPath) + "-signed.apk")
        } else null

        val outFile = File(outputPath)
        if (outFile.exists() && !options.forceOverwrite) {
            throw IllegalStateException("$outputPath exists. Set forceOverwrite = true to overwrite.")
        }

        Log.i("output file path --> $outputPath")

        val property = composeProperty(options)

        if (isManifest) {
            Log.i("Start to process manifest file")
            FileProcesser.processManifestFile(inputPath, outputPath, property)
        } else {
            Log.i("Start to process apk")
            FileProcesser.processApkFile(inputPath, outputPath, property)

            if (options.needSignApk) {
                // ⚠️ jarsigner 方案在 Android 设备上不可用；通常只在桌面环境跑。
                // 若你在桌面 JVM 环境使用该库，此处可工作；在 Android 上请保持 needSignApk=false。
                try {
                    Log.i("Start to sign the apk (desktop-only).")
                    val parent = File(outputPath).parentFile
                    val keyStorePath = (parent?.absolutePath ?: "") + File.separator + "keystore"
                    Log.d(" parentPath=${parent?.absolutePath} keyStoreFilePath=$keyStorePath")
                    Log.i(" output unsigned apk path = $outputPath")
                    Log.i(" output signed apk path = $signedApkPath")

                    // 将打包内的测试 keystore 释放出来（wind meditor 的工具函数）
                    com.wind.meditor.utils.Utils.copyFileFromJar("assets/new_keystore", keyStorePath)
                    ApkSigner.signApk(outputPath, keyStorePath, signedApkPath)
                    // 清理
                    File(keyStorePath).takeIf { it.exists() }?.delete()
                } catch (t: Throwable) {
                    // 在 Android 环境这里多半会抛错，确保不会中断主流程
                    Log.e("Sign apk failed on this runtime: ${t.message}")
                }
            }
        }

        return if (options.needSignApk && isApk && signedApkPath != null) signedApkPath else outputPath
    }

    // -------------------- 内部工具 --------------------

    private fun composeProperty(opt: Options): ModificationProperty {
        val property = ModificationProperty()

        // manifest-level
        if (!opt.packageName.isNullOrEmpty()) {
            property.addManifestAttribute(
                AttributeItem(NodeValue.Manifest.PACKAGE, opt.packageName).setNamespace(null)
            )
        }
        opt.versionCode?.let { vc ->
            if (vc > 0) property.addManifestAttribute(
                AttributeItem(NodeValue.Manifest.VERSION_CODE, vc)
            )
        }
        opt.versionName?.let { vn ->
            if (vn.isNotEmpty()) property.addManifestAttribute(
                AttributeItem(NodeValue.Manifest.VERSION_NAME, vn)
            )
        }

        // application-level
        opt.debuggable?.let { db ->
            property.addApplicationAttribute(
                AttributeItem(NodeValue.Application.DEBUGGABLE, db)
            )
        }
        opt.extractNativeLibs?.let { en ->
            property.addApplicationAttribute(
                AttributeItem(NodeValue.Application.EXTRACTNATIVELIBS, en)
            )
        }
        opt.applicationName?.let { name ->
            if (name.isNotEmpty()) {
                property.addApplicationAttribute(AttributeItem("name", name))
            }
        }

        // uses-permission
        opt.usesPermissionList.forEach { perm ->
            if (perm.isNotBlank()) property.addUsesPermission(perm)
        }

        // manifest attributes (name:value)
        opt.manifestAttributeList.forEach { line ->
            val nameValue = line.split(MULTI_NAME_SEPARATOR, limit = 2)
            if (nameValue.size == 2) {
                val key = nameValue[0].trim()
                val value = nameValue[1].trim()
                if (key.startsWith(ANDROID_NAMESPACE_PREFIX)) {
                    property.addManifestAttribute(
                        AttributeItem(key.substring(ANDROID_NAMESPACE_PREFIX.length), value)
                    )
                } else {
                    property.addManifestAttribute(
                        AttributeItem(key, value).setNamespace(null)
                    )
                }
            }
        }

        // application attributes (name:value)
        opt.applicationAttributeList.forEach { line ->
            val nameValue = line.split(MULTI_NAME_SEPARATOR, limit = 2)
            if (nameValue.size == 2) {
                val key = nameValue[0].trim()
                val value = nameValue[1].trim()
                if (key.startsWith(ANDROID_NAMESPACE_PREFIX)) {
                    property.addApplicationAttribute(
                        AttributeItem(key.substring(ANDROID_NAMESPACE_PREFIX.length), value)
                    )
                } else {
                    property.addApplicationAttribute(
                        AttributeItem(key, value).setNamespace(null)
                    )
                }
            }
        }

        // uses-sdk attributes (name:value)
        opt.usesSdkAttributeList.forEach { line ->
            val nameValue = line.split(MULTI_NAME_SEPARATOR, limit = 2)
            if (nameValue.size == 2) {
                val key = nameValue[0].trim()
                val value = nameValue[1].trim()
                if (key.startsWith(ANDROID_NAMESPACE_PREFIX)) {
                    property.addUsesSdkAttribute(
                        AttributeItem(key.substring(ANDROID_NAMESPACE_PREFIX.length), value)
                    )
                } else {
                    property.addUsesSdkAttribute(
                        AttributeItem(key, value).setNamespace(null)
                    )
                }
            }
        }

        // meta-data add (name:value)
        opt.metaDataList.forEach { line ->
            val nameValue = line.split(MULTI_NAME_SEPARATOR, limit = 2)
            if (nameValue.size == 2) {
                property.addMetaData(
                    ModificationProperty.MetaData(nameValue[0], nameValue[1])
                )
            }
        }

        // meta-data delete (name)
        opt.deleteMetaDataList.forEach { name ->
            if (name.isNotBlank()) property.addDeleteMetaData(name)
        }

        return property
    }

    private fun getBaseName(path: String): String {
        val f = File(path)
        val parent = f.parentFile?.absolutePath ?: ""
        val name = f.name
        val dot = name.lastIndexOf('.')
        val stem = if (dot >= 0) name.substring(0, dot) else name
        return if (parent.isEmpty()) stem else (parent + File.separator + stem)
    }
}
