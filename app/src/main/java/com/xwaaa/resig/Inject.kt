package com.xwaaa.resig

// 只保留 zip4j，避免 ZipFile 名称冲突

import android.content.Context
import android.os.Build
import android.util.Log
import com.wind.meditor.ManifestEditorMain
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.CompressionLevel
import net.lingala.zip4j.model.enums.CompressionMethod
import org.jf.baksmali.Main
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.dexbacked.DexBackedClassDef
import org.jf.dexlib2.dexbacked.DexBackedDexFile
import java.io.*
import java.nio.file.Files
import java.nio.file.Paths
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import org.jf.smali.Main as SmaliMain


class Injector {

    companion object {
        private const val TAG = "DexInjector"
        private const val MANIFEST_NAME = "AndroidManifest.xml"
        // ---------------- 入口函数 ----------------
        fun injectDex(dexDir: String, xmlPath: String) {
            Log.d(TAG, "开始注入 dex 代码")
            val appName = getApplicationName(xmlPath)
            if (appName == null) {
                editAName(xmlPath, "com.xwaaa.hook.HookApplication");
                Log.w(TAG, "未找到 application name，主动修改为com.xwaaa.hook.HookApplication")
                return
            }
            Log.d(TAG,"要修改的类是："+appName)

            val dest = appName.replace(".", "/")
            val targetClassPath = "L$dest;"
            Log.d(TAG, "🔍 目标 Application 类: $targetClassPath")
            val dexFiles = File(dexDir).listFiles(FileFilter { it.name.endsWith(".dex") }) ?: emptyArray()
            var targetDex: File? = null
            for (file in dexFiles) {
                val dexFile: DexBackedDexFile = DexFileFactory.loadDexFile(file, Opcodes.forApi(28))
                for (cls: DexBackedClassDef in dexFile.classes) {
                    if (cls.type == targetClassPath) {
                        targetDex = file
                        break
                    }
                }
                if (targetDex != null) break
            }

            if (targetDex == null) {
                Log.w(TAG, "❌ 未找到目标 dex 文件，无法注入")
                return
            }
            Log.d(TAG, "✅ 找到目标 dex: ${targetDex.name}")
            // 反编译 dex → smali 目录
            val smaliDir = File(targetDex.parentFile, "smali")
            Main.main(arrayOf("d", targetDex.absolutePath, "-o", smaliDir.absolutePath))
            Log.d(TAG, "✅ 已反编译到: ${smaliDir.absolutePath}")

            // 定位 smali 文件路径
            val smaliPath = File(smaliDir, "$dest.smali").absolutePath
            val smaliFile = File(smaliPath)
            if (!smaliFile.exists()) {
                Log.e(TAG, "❌ 找不到 smali 文件: $smaliPath")
                return
            }
            // 注入 Hook 初始化逻辑
            injectHookInit(smaliFile.absolutePath)

            // 回编译 smali → 新 dex
            val newDexFile = File(targetDex.parentFile, "out.dex")
            SmaliMain.main(arrayOf("a", smaliDir.absolutePath, "-o", newDexFile.absolutePath))
            Log.d(TAG, "✅ smali 回编译完成: ${newDexFile.absolutePath}")
            // 替换原 dex
            if (newDexFile.exists()) {
                targetDex.delete()
                newDexFile.renameTo(targetDex)
                Log.d(TAG, "✅ dex 文件替换完成: ${targetDex.name}")
            } else {
                Log.e(TAG, "❌ 新 dex 未生成，注入失败")
            }
            // 清理 smali 残留
            smaliDir.deleteRecursively()
            Log.d(TAG, "🧹 清理 smali 临时目录完成")

        }

        // ---------------- 获取 Application 名称 ----------------
        fun getApplicationName(filePath: String): String? {
            return getValue(filePath, "application", "android", "name")
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
        open fun editAName(file: String, newName: String?) {
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
//        """.trimMargin()
//
//            val pattern = Regex(""".method static constructor <clinit>\(\)V\s*\.registers\s+(\d+)""")
//            val match = pattern.find(content)
//
//            val modifiedContent = if (match != null) {
//                // 如果已有静态构造方法，则注入 hook 调用
//                val registers = match.groupValues[1].toInt().coerceAtLeast(1)
//                pattern.replace(content) {
//                    """
//                |.method static constructor <clinit>()V
//                |    .registers $registers
//                |$hookCode
//                """.trimMargin()
//                }
//            } else {
//                // 否则新增一个新的 <clinit>() 方法
//                """
//            |$content
//            |
//            |.method static constructor <clinit>()V
//            |    .registers 1
//            |$hookCode
//            |    return-void
//            |.end method
//            """.trimMargin()
//            }
//
//            file.writeText(modifiedContent)
//            Log.d(TAG, "✅ 已在 $smaliFilePath 注入 Hook 初始化代码")
//        }

        fun injectHookInit(smaliFilePath: String) {
            val file = File(smaliFilePath)
            if (!file.exists()) {
                Log.e(TAG, "找不到 smali 文件: $smaliFilePath")
                return
            }

            val content = file.readText()

            val hookCodeInExistingClinit = """
        |
        |    :resig_try_start
        |    const-string v0, "com.xwaaa.hook.HookApplication"
        |    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
        |    move-result-object v0
        |
        |    const-string v1, "initSignatureHook"
        |    const/4 v2, 0x0
        |    new-array v2, v2, [Ljava/lang/Class;
        |    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
        |    move-result-object v0
        |
        |    const/4 v1, 0x1
        |    invoke-virtual {v0, v1}, Ljava/lang/reflect/Method;->setAccessible(Z)V
        |
        |    const/4 v1, 0x0
        |    invoke-virtual {v0, v1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
        |    :resig_try_end
        |    .catch Ljava/lang/Exception; {:resig_try_start .. :resig_try_end} :resig_catch
        |
        |    goto :resig_after
        |
        |    :resig_catch
        |
        |    :resig_after
        |
    """.trimMargin()

            val hookCodeNewClinit = """
        |$hookCodeInExistingClinit
        |    return-void
        |
    """.trimMargin()

            val pattern = Regex(""".method static constructor <clinit>\(\)V\s*\.registers\s+(\d+)""")
            val match = pattern.find(content)

            val modifiedContent = if (match != null) {
                // 如果已有静态构造方法，则注入 hook 调用
                val registers = match.groupValues[1].toInt()
                val neededRegisters = 3 // v0, v1, v2
                val finalRegisters = if (registers < neededRegisters) neededRegisters else registers

                pattern.replace(content) {
                    """
            |.method static constructor <clinit>()V
            |    .registers $finalRegisters
            |$hookCodeInExistingClinit
            """.trimMargin()
                }
            } else {
                // 否则新增一个新的 <clinit>() 方法
                """
        |$content
        |
        |.method static constructor <clinit>()V
        |    .registers 3
        |$hookCodeNewClinit
        |.end method
        """.trimMargin()
            }

            file.writeText(modifiedContent)
            Log.d(TAG, "✅ 已在 $smaliFilePath 注入 Hook 初始化代码")
        }

        //修改注入的dex中的预设值
        open fun editShellDEX(DexPath: String, packageName: String?, Sig: String) {
            val file = File(DexPath)
            Log.d(TAG, "开始 dex → smali 转换: $DexPath")
            // 1️⃣ 反编译 dex 为 smali
            Main.main(
                arrayOf(
                    "d",
                    DexPath,
                    "-o",
                    file.parent + File.separator + "smali"
                )
            )

            Log.d(TAG, "✅ dex 转 smali 执行完成，开始检查目录结构")

            val smaliDir = File(file.parent, "smali")
            if (!smaliDir.exists()) {
                Log.e(TAG, "❌ smali 目录未生成，反编译失败")
                return
            }

            // 2️⃣ 打印反编译输出目录（调试用）
            smaliDir.walkTopDown().forEach {
                Log.d(TAG, "反编译输出: ${it.absolutePath}")
            }

            // 3️⃣ 自动搜索 App.smali（避免包名写死）
            // 自动寻找 HookApplication 或 App.smali
            val appSmaliFile = smaliDir.walkTopDown()
                .firstOrNull { it.isFile && (it.name == "App.smali" || it.name == "HookApplication.smali") }

            if (appSmaliFile == null) {
                Log.e(TAG, "❌ 未找到 HookApplication.smali 或 App.smali，请检查反编译输出")
                smaliDir.walkTopDown().forEach {
                    Log.d(TAG, "反编译输出: ${it.absolutePath}")
                }
                return
            }

            Log.d(TAG, "✅ 找到目标 smali 文件: ${appSmaliFile.absolutePath}")


            // 4️⃣ 替换签名与包名
            val Sig2: String = Sig.replace("\n", "\\n")
            replaceInFile(appSmaliFile.absolutePath, "xwaaa.package", packageName)
            replaceInFile(appSmaliFile.absolutePath, "xwaaa resig", Sig2)
            Log.d(TAG, "✅ 已修改包名与签名值")

            // 5️⃣ 将 smali 重新编译为 dex
            Log.d(TAG, "开始 smali → dex 重编译")
            org.jf.smali.Main.main(
                arrayOf(
                    "a",
                    smaliDir.absolutePath,
                    "-o",
                    file.parent + File.separator + "out.dex"
                )
            )

            // 6️⃣ 等待 out.dex 生成
            val outDex = File(file.parent, "out.dex")
            var waited = 0
            while (!outDex.exists() && waited < 15000) {
                Thread.sleep(1000L)
                waited += 1000
            }

            if (!outDex.exists()) {
                Log.e(TAG, "❌ 等待 out.dex 超时，smali 编译失败")
                return
            }

            Log.d(TAG, "✅ out.dex 生成完成: ${outDex.absolutePath}")

            // 7️⃣ 删除临时 smali 目录
            deleteDirectory(smaliDir)
            Log.d(TAG, "🧹 清理 smali 临时文件完成")

            // 8️⃣ 替换原 dex
            val success = renameFile(outDex, file)
            if (success) {
                Log.d(TAG, "✅ 替换原 dex 成功: ${file.absolutePath}")
            } else {
                Log.e(TAG, "❌ 替换原 dex 失败")
            }

            Log.d(TAG, "✅ editShellDEX 流程完成")
        }

        //替换文件
        fun replaceInFile(filePath: String?, target: String?, replacement: String?) {
            val file = File(filePath)
            val fileContent = StringBuilder()
            try {
                val reader = BufferedReader(FileReader(file))
                while (true) {
                    val line = reader.readLine() ?: break
                    fileContent.append(line.replace(target!!, replacement!!))
                        .append(System.lineSeparator())
                }
                reader.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }
            try {
                val writer = BufferedWriter(FileWriter(file))
                writer.write(fileContent.toString())
                writer.close()
            } catch (e2: IOException) {
                e2.printStackTrace()
            }
        }

        //删除临时文件
        private fun deleteDirectory(dir: File) {
            if (dir.exists()) {
                if (dir.isDirectory) dir.listFiles()?.forEach { deleteDirectory(it) }
                dir.delete()
            }
        }

        //=============================================================================





    }
}
