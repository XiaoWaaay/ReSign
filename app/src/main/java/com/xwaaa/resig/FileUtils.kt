package com.xwaaa.resig

import android.content.Context
import android.util.Log
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.CompressionLevel
import net.lingala.zip4j.model.enums.CompressionMethod
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream


object FileUtils {


    //复制文件从原目录到新目录
    @Throws(IOException::class)
    open fun copyFile(sourceFilePath: String, destDirectory: String?) {
        val sourceFile = File(sourceFilePath)
        val destDir = File(destDirectory)
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        val destFile = File(destDir, sourceFile.name)
        try {
            val fis = FileInputStream(sourceFile)
            val fos = FileOutputStream(destFile)
            val buffer = ByteArray(1024)
            while (true) {
                val length = fis.read(buffer)
                if (length > 0) {
                    fos.write(buffer, 0, length)
                } else {
                    fos.close()
                    fis.close()
                    return
                }
            }
        } catch (e: FileNotFoundException) {
            throw FileNotFoundException("Source file not found: $sourceFilePath")
        } catch (e2: IOException) {
            throw IOException(
                "Error copying file from " + sourceFilePath + " to " + destFile.absolutePath,
                e2
            )
        }
    }
    //解压APK中的dex文件操作
    @Throws(IOException::class)
    open fun extractDexFile(apkFilePath: String, destDirectory: String) {
        val apkFile = File(apkFilePath)
        val destDir = File(destDirectory).apply { if (!exists()) mkdirs() }

        FileInputStream(apkFile).use { fis ->
            ZipInputStream(fis).use { zis ->
                val buffer = ByteArray(8192)
                var entry: ZipEntry? = zis.nextEntry
                while (entry != null) {
                    val name = entry.name
                    if (name.endsWith(".dex") && !name.contains("classesx.dex")) {
                        val outFile = File(destDir, name)
                        FileOutputStream(outFile).use { fos ->
                            var len: Int
                            while (zis.read(buffer).also { len = it } != -1) {
                                fos.write(buffer, 0, len)
                            }
                        }
                        Log.d("FileUtils", "✅ 解压Dex文件: ${outFile.absolutePath}")
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }
    }


    //解压APK中的xml文件
    @Throws(IOException::class)
    open fun extractXmlFile(apkFilePath: String, destDirectory: String) {
        val apkFile = File(apkFilePath)
        val destDir = File(destDirectory)
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        try {
            val fis = FileInputStream(apkFile)
            try {
                val zis = ZipInputStream(fis) // 用 zip 模式打开 apk
                while (true) {
                    val zipEntry: ZipEntry? = zis.getNextEntry()
                    if (zipEntry != null) {
                        // 只提取 AndroidManifest.xml 文件
                        if (zipEntry.name.equals("AndroidManifest.xml", ignoreCase = true)) {
                            val xmlFile = File(destDir, zipEntry.name)
                            val fos = FileOutputStream(xmlFile)
                            try {
                                val buffer = ByteArray(1024)
                                while (true) {
                                    val length = zis.read(buffer)
                                    if (length <= 0) break
                                    fos.write(buffer, 0, length)
                                }
                                fos.close()
                                Log.d("FileUtils", "解压 Manifest 文件: ${xmlFile.absolutePath}")
                            } catch (th: Throwable) {
                                try {
                                    fos.close()
                                } catch (th2: Throwable) {
                                    th.addSuppressed(th2)
                                }
                                throw th
                            }
                        }
                        zis.closeEntry()
                    } else {
                        zis.close()
                        fis.close()
                        return
                    }
                }
            } catch (th3: Throwable) {
                try {
                    fis.close()
                } catch (th4: Throwable) {
                    th3.addSuppressed(th4)
                }
                throw th3
            }
        } catch (e: FileNotFoundException) {
            throw FileNotFoundException("APK 未找到: $apkFilePath")
        } catch (e2: IOException) {
            throw IOException("从 APK 中解压 Manifest 文件错误: $apkFilePath → $destDirectory", e2)
        }
    }

    open fun copyAssetToFile(context: Context, assetFileName: String?, destFilePath: String?, name: String) {
        var `in`: InputStream? = null
        var out: FileOutputStream? = null
        try {
            try {
                try {
                    `in` = context.assets.open(assetFileName!!)
                    val outFile = File(destFilePath)
                    outFile.parentFile.mkdirs()
                    out = FileOutputStream(outFile.toString() + File.separator + name)
                    val buffer = ByteArray(1024)
                    while (true) {
                        val read = `in`.read(buffer)
                        if (read == -1) {
                            break
                        }
                        out.write(buffer, 0, read)
                    }
                    if (`in` != null) {
                        `in`.close()
                    }
                    out.close()
                } catch (e: IOException) {
                    e.printStackTrace()
                    `in`?.close()
                    out?.close()
                }
            } catch (th: Throwable) {
                if (`in` != null) {
                    try {
                        `in`.close()
                    } catch (e2: IOException) {
                        e2.printStackTrace()
                        throw th
                    }
                }
                out?.close()
                throw th
            }
        } catch (e3: IOException) {
            e3.printStackTrace()
        }
    }

    @Throws(IOException::class)
    fun copyFile(sourceFilePath: String, destDirectory: String?, destFileName: String?) {
        val sourceFile = File(sourceFilePath)
        val destDir = File(destDirectory)
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        val destFile = File(destDir, destFileName)
        try {
            val fis = FileInputStream(sourceFile)
            try {
                val fos = FileOutputStream(destFile)
                val buffer = ByteArray(1024)
                while (true) {
                    val length = fis.read(buffer)
                    if (length > 0) {
                        fos.write(buffer, 0, length)
                    } else {
                        fos.close()
                        fis.close()
                        return
                    }
                }
            } catch (th: Throwable) {
                try {
                    fis.close()
                } catch (th2: Throwable) {
                    th.addSuppressed(th2)
                }
                throw th
            }
        } catch (e: FileNotFoundException) {
            throw FileNotFoundException("Source file not found: $sourceFilePath")
        } catch (e2: IOException) {
            throw IOException(
                "Error copying file from " + sourceFilePath + " to " + destFile.absolutePath,
                e2
            )
        }
    }

    fun addToZip(sourceFile: File?, zipFilePath: String?, directoryInZip: String?) {
        try {
            val zipFile = ZipFile(zipFilePath)
            val zipParameters = ZipParameters()
            zipParameters.compressionMethod = CompressionMethod.STORE
            zipParameters.compressionLevel = CompressionLevel.NORMAL
            if (directoryInZip != null && !directoryInZip.isEmpty()) {
                zipParameters.rootFolderNameInZip = directoryInZip
            }
            if (!zipFile.isValidZipFile()) {
                println("目标 ZIP 文件无效或不存在！")
                return
            }
            zipFile.addFile(sourceFile, zipParameters)
            println("文件已成功添加到 ZIP 文件中的目录：$directoryInZip")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }



}
