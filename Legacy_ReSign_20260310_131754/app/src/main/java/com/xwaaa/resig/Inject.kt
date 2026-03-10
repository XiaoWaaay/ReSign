package com.xwaaa.resig

import android.content.Context
import android.os.Build
import android.util.Log
import com.wind.meditor.ManifestEditorMain
import java.io.*
import java.nio.file.Files
import java.nio.file.Paths
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.ReferenceType
import org.jf.dexlib2.dexbacked.DexBackedDexFile
import org.jf.dexlib2.iface.instruction.Instruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.instruction.formats.Instruction21c
import org.jf.dexlib2.iface.instruction.formats.Instruction31c
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.iface.value.EncodedValue
import org.jf.dexlib2.iface.value.StringEncodedValue
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction31c
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.value.ImmutableStringEncodedValue
import org.jf.dexlib2.rewriter.DexRewriter
import org.jf.dexlib2.rewriter.Rewriter
import org.jf.dexlib2.rewriter.RewriterModule
import org.jf.dexlib2.rewriter.Rewriters
import org.jf.dexlib2.writer.io.FileDataStore
import org.jf.dexlib2.writer.pool.DexPool


class Injector {

    companion object {
        private const val TAG = "DexInjector"
        private const val MANIFEST_NAME = "AndroidManifest.xml"
        private const val HOOK_APPLICATION = "com.xwaaa.hook.HookApplication"
        private const val HOOK_COMPONENT_FACTORY = "com.xwaaa.hook.HookApplication\$DelegatingAppComponentFactory"
        // Manifest 入口替换模式：不对目标 dex 反编译/插桩，稳定性更高
        fun injectByManifest(xmlPath: String, metaDataList: List<String> = emptyList()) {
            Log.d(TAG, "开始注入（Manifest 入口替换模式）")
            editManifestEntry(xmlPath, HOOK_APPLICATION, HOOK_COMPONENT_FACTORY, metaDataList)
        }

        fun editManifestEntry(
            xmlPath: String,
            applicationClassName: String,
            appComponentFactoryClassName: String?,
            metaDataList: List<String> = emptyList()
        ) {
            val attrs = ArrayList<String>(2)
            attrs.add("android-name:$applicationClassName")
            if (!appComponentFactoryClassName.isNullOrBlank()) {
                attrs.add("android-appComponentFactory:$appComponentFactoryClassName")
            }
            val out = ManifestEditor.edit(
                xmlPath,
                ManifestEditor.Options(
                    output = "$xmlPath.bak",
                    applicationAttributeList = attrs,
                    metaDataList = metaDataList,
                    forceOverwrite = true,
                    needSignApk = false
                )
            )
            deleteDirectory(File(xmlPath))
            renameFile(File(out), File(xmlPath))
        }

        // ---------------- 获取 Application 名称 ----------------
        fun getApplicationName(filePath: String): String? {
            return getValue(filePath, "application", "android", "name")
        }

        fun getManifestPackageName(filePath: String): String? {
            return getValue(filePath, "manifest", "", "package")
        }

        fun getAppComponentFactoryName(filePath: String): String? {
            return getValue(filePath, "application", "android", "appComponentFactory")
        }

        private fun normalizeClassName(raw: String, manifestPackageName: String?): String {
            val v = raw.trim()
            if (v.isEmpty()) return v
            val pkg = manifestPackageName?.trim().orEmpty()

            if (v.startsWith(".")) {
                return if (pkg.isEmpty()) v.drop(1) else pkg + v
            }
            if (v.contains(".")) return v
            return if (pkg.isEmpty()) v else "$pkg.$v"
        }

        // ---------------- 通用属性读取函数 ----------------
        fun getValue(filePath: String, tag: String, ns: String, attrName: String): String? {
            try {
                val axmlData = readFileToBytes(filePath) ?: return null
                val parser = XmlParser(axmlData)

                while (true) {
                    val event = parser.next()
                    if (event == XmlParser.END_FILE) break

                    // ✅ 避免 NullPointerException：只在 START_TAG 时读取 name
                    if (event != XmlParser.START_TAG) continue

                    if (parser.getName() == tag && parser.getAttrCount() > 0) {
                        for (i in 0 until parser.getAttrCount()) {
                            val attrNameInXml = parser.getAttrName(i)
                            if (attrNameInXml == "$ns:$attrName" || attrNameInXml == attrName) {
                                val value = parser.getAttrValue(i)?.toString()
                                Log.d(TAG, "找到属性 $attrName = $value")
                                return value
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "解析 XML 失败: ${e.message}", e)
            }
            return null
        }

        // ---------------- 文件读取函数 ----------------
        @Throws(IOException::class)
        fun readFileToBytes(filePath: String?): ByteArray? {
            if (filePath.isNullOrEmpty()) return null

            val file = File(filePath)
            if (!file.exists()) throw IOException("文件不存在: $filePath")

            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Files.readAllBytes(Paths.get(filePath))
            } else {
                FileInputStream(file).use { it.readBytes() }
            }
        }

        //添加自定义的类
        fun editAName(file: String, newName: String?) {
            ManifestEditorMain.main(file, "-an", newName, "-o", "$file.bak")
            deleteDirectory(File(file))
            renameFile(File("$file.bak"), File(file))
        }

        //重新命名
        fun renameFile(oldFile: File, newFile: File): Boolean {
            if (newFile.exists()) {
                newFile.delete()
            }
            return oldFile.renameTo(newFile)
        }

        private fun deleteDirectory(dir: File) {
            if (!dir.exists()) return
            if (dir.isDirectory) {
                dir.listFiles()?.forEach { deleteDirectory(it) }
            }
            dir.delete()
        }

//        fun injectHookInit(smaliFilePath: String) {
//            val file = File(smaliFilePath)
//            if (!file.exists()) {
//                Log.e(TAG, "找不到 smali 文件: $smaliFilePath")
//                return
//            }
//
//            val content = file.readText()
//            val hookCode = """
//            |
//            |    # === 注入 HookApplication 初始化 ===
//            |    invoke-static {}, Lcom/xwaaa/hook/HookApplication;->initSignatureHook()V
//            |
        //修改注入的dex中的预设值
        fun editShellDEX(DexPath: String, packageName: String?, Sig: String) {
            editShellDEX(DexPath, packageName, Sig, null, null)
        }

        fun editShellDEX(DexPath: String, packageName: String?, Sig: String, originalApplicationClass: String?) {
            editShellDEX(DexPath, packageName, Sig, originalApplicationClass, null)
        }

        fun editShellDEX(
            DexPath: String,
            packageName: String?,
            Sig: String,
            originalApplicationClass: String?,
            originalAppComponentFactoryClass: String?
        ) {
            val file = File(DexPath)
            if (!file.exists() || !file.isFile) {
                Log.e(TAG, "❌ DexPath 不存在或不是文件: $DexPath")
                return
            }

            val pkg = packageName?.trim().orEmpty()
            val sig = Sig.trim()
            val origApp = originalApplicationClass?.trim().orEmpty()
            val origFactory = originalAppComponentFactoryClass?.trim().orEmpty()

            val inBytes = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    Files.readAllBytes(Paths.get(DexPath))
                } else {
                    FileInputStream(file).use { it.readBytes() }
                }
            } catch (e: Throwable) {
                Log.e(TAG, "❌ 读取 dex 失败: ${e.message}", e)
                return
            }

            val dexFile = try {
                DexBackedDexFile(Opcodes.getDefault(), inBytes)
            } catch (e: Throwable) {
                Log.e(TAG, "❌ 解析 dex 失败: ${e.message}", e)
                return
            }

            fun replacePlaceholder(s: String): String? {
                return when (s) {
                    "xwaaa.package" -> pkg
                    "xwaaa resig" -> sig
                    "xwaaa.original_app" -> origApp
                    "xwaaa.original_factory" -> origFactory
                    else -> null
                }
            }

            val module = object : RewriterModule() {
                override fun getInstructionRewriter(rewriters: Rewriters): Rewriter<Instruction> {
                    val base = super.getInstructionRewriter(rewriters)
                    return Rewriter { value ->
                        val ins = base.rewrite(value)
                        if (ins is ReferenceInstruction && ins.referenceType == ReferenceType.STRING) {
                            val ref = ins.reference
                            if (ref is StringReference) {
                                val replaced = replacePlaceholder(ref.string)
                                if (replaced != null) {
                                    if (ins is Instruction21c) {
                                        return@Rewriter ImmutableInstruction21c(ins.opcode, ins.registerA, ImmutableStringReference(replaced))
                                    }
                                    if (ins is Instruction31c) {
                                        return@Rewriter ImmutableInstruction31c(ins.opcode, ins.registerA, ImmutableStringReference(replaced))
                                    }
                                }
                            }
                        }
                        ins
                    }
                }

                override fun getEncodedValueRewriter(rewriters: Rewriters): Rewriter<EncodedValue> {
                    val base = super.getEncodedValueRewriter(rewriters)
                    return Rewriter { value ->
                        val v = base.rewrite(value)
                        if (v is StringEncodedValue) {
                            val replaced = replacePlaceholder(v.value)
                            if (replaced != null) {
                                return@Rewriter ImmutableStringEncodedValue(replaced)
                            }
                        }
                        v
                    }
                }
            }

            val rewriters = DexRewriter(module)
            val rewritten = rewriters.getDexFileRewriter().rewrite(dexFile)
            val tmpOut = File(file.parentFile, file.name + ".patched")
            try {
                val pool = DexPool(dexFile.opcodes)
                for (cls in rewritten.classes) {
                    pool.internClass(cls)
                }
                pool.writeTo(FileDataStore(tmpOut))
            } catch (e: Throwable) {
                Log.e(TAG, "❌ 写回 dex 失败: ${e.message}", e)
                try {
                    tmpOut.delete()
                } catch (_: Throwable) {
                }
                return
            }

            try {
                if (!tmpOut.renameTo(file)) {
                    FileInputStream(tmpOut).use { input ->
                        FileOutputStream(file).use { output ->
                            val buf = ByteArray(256 * 1024)
                            while (true) {
                                val n = input.read(buf)
                                if (n < 0) break
                                if (n > 0) output.write(buf, 0, n)
                            }
                            try {
                                output.fd.sync()
                            } catch (_: Throwable) {
                            }
                        }
                    }
                    tmpOut.delete()
                }
            } catch (e: Throwable) {
                Log.e(TAG, "❌ 覆盖 dex 失败: ${e.message}", e)
                try {
                    tmpOut.delete()
                } catch (_: Throwable) {
                }
                return
            }

            Log.d(TAG, "✅ editShellDEX 完成: ${file.absolutePath} size=${file.length()}")
        }

        //=============================================================================





    }
}
