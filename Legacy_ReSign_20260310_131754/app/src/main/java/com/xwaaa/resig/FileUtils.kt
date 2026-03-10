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
    fun copyFile(sourceFilePath: String, destDirectory: String) {
        val sourceFile = File(sourceFilePath)
        val destDir = File(destDirectory)
        if (!destDir.exists()) destDir.mkdirs()
        val destFile = File(destDir, sourceFile.name)
        try {
            FileInputStream(sourceFile).use { fis ->
                FileOutputStream(destFile).use { fos ->
                    val buffer = ByteArray(256 * 1024)
                    while (true) {
                        val length = fis.read(buffer)
                        if (length == -1) break
                        fos.write(buffer, 0, length)
                    }
                    try {
                        fos.fd.sync()
                    } catch (_: Throwable) {
                    }
                }
            }
        } catch (e: FileNotFoundException) {
            throw FileNotFoundException("Source file not found: $sourceFilePath")
        } catch (e2: IOException) {
            throw IOException(
                "Error copying file from $sourceFilePath to ${destFile.absolutePath}",
                e2
            )
        }
    }
    //解压APK中的dex文件操作
    @Throws(IOException::class)
    fun extractDexFile(apkFilePath: String, destDirectory: String) {
        val apkFile = File(apkFilePath)
        if (!apkFile.exists()) throw FileNotFoundException("APK 未找到: $apkFilePath")

        val destDir = File(destDirectory).apply { if (!exists()) mkdirs() }

        java.util.zip.ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val name = entry.name ?: continue
                if (!name.endsWith(".dex")) continue
                if (name.contains("classesx.dex")) continue
                if (entry.isDirectory) continue

                val outFile = File(destDir, name)
                outFile.parentFile?.mkdirs()

                zip.getInputStream(entry).use { input ->
                    FileOutputStream(outFile).use { output ->
                        val buffer = ByteArray(256 * 1024)
                        while (true) {
                            val n = input.read(buffer)
                            if (n <= 0) break
                            output.write(buffer, 0, n)
                        }
                        try {
                            output.fd.sync()
                        } catch (_: Throwable) {
                        }
                    }
                }

                Log.d("FileUtils", "✅ 解压Dex文件: ${outFile.absolutePath}")
            }
        }
    }


    //解压APK中的xml文件
    @Throws(IOException::class)
    fun extractXmlFile(apkFilePath: String, destDirectory: String) {
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

    fun copyAssetToFile(context: Context, assetFileName: String?, destFilePath: String?, name: String) {
        if (assetFileName.isNullOrEmpty()) throw IllegalArgumentException("assetFileName is empty")
        if (destFilePath.isNullOrEmpty()) throw IllegalArgumentException("destFilePath is empty")

        val destDir = File(destFilePath)
        if (!destDir.exists()) destDir.mkdirs()

        val destFile = File(destDir, name)
        context.assets.open(assetFileName).use { input ->
            FileOutputStream(destFile).use { output ->
                val buffer = ByteArray(256 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    output.write(buffer, 0, read)
                }
                try {
                    output.fd.sync()
                } catch (_: Throwable) {
                }
            }
        }
    }

    @Throws(IOException::class)
    fun copyFile(sourceFilePath: String, destDirectory: String?, destFileName: String?) {
        if (destDirectory.isNullOrEmpty()) throw IllegalArgumentException("destDirectory is empty")
        if (destFileName.isNullOrEmpty()) throw IllegalArgumentException("destFileName is empty")
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
        if (sourceFile == null || !sourceFile.exists()) throw FileNotFoundException("Source file not found")
        if (zipFilePath.isNullOrEmpty()) throw IllegalArgumentException("zipFilePath is empty")

        val zipFile = ZipFile(zipFilePath)
        if (!zipFile.isValidZipFile) throw IllegalStateException("Invalid zip file: $zipFilePath")

        val prefix = (directoryInZip ?: "").let {
            if (it.isEmpty()) "" else if (it.endsWith("/")) it else "$it/"
        }

        val entryName = prefix + sourceFile.name
        try {
            zipFile.removeFile(entryName)
        } catch (_: Throwable) {
        }

        val zipParameters = ZipParameters().apply {
            compressionMethod = CompressionMethod.STORE
            compressionLevel = CompressionLevel.NORMAL
            fileNameInZip = entryName
            isOverrideExistingFilesInZip = true
        }
        zipFile.addFile(sourceFile, zipParameters)
    }



}
