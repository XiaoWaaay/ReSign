/**
 * ReSignPro - FileUtils
 *
 * 文件操作工具集
 */
package com.resign.pro.util

import android.content.Context
import android.net.Uri
import android.os.Build
import java.io.*
import java.nio.channels.FileChannel
import java.security.MessageDigest

object FileUtils {

    private const val TAG = "FileUtils"
    private const val BUFFER_SIZE = 8192

    /**
     * 复制文件（使用 NIO FileChannel，效率高）
     */
    @JvmStatic
    fun copyFile(src: File, dst: File): Boolean {
        return try {
            dst.parentFile?.mkdirs()
            FileInputStream(src).channel.use { srcCh ->
                FileOutputStream(dst).channel.use { dstCh ->
                    dstCh.transferFrom(srcCh, 0, srcCh.size())
                }
            }
            true
        } catch (e: IOException) {
            Logger.e(TAG, "copyFile failed: ${src.path} -> ${dst.path}", e)
            false
        }
    }

    /**
     * 原子写文件（先写临时文件再 rename，防止中途崩溃导致文件损坏）
     */
    @JvmStatic
    fun atomicWriteFile(target: File, data: ByteArray): Boolean {
        val tmp = File(target.parent, "${target.name}.tmp.${System.currentTimeMillis()}")
        return try {
            tmp.parentFile?.mkdirs()
            FileOutputStream(tmp).use { fos ->
                fos.write(data)
                fos.fd.sync()
            }
            tmp.renameTo(target)
        } catch (e: IOException) {
            Logger.e(TAG, "atomicWriteFile failed: ${target.path}", e)
            tmp.delete()
            false
        }
    }

    /**
     * 原子写文件（从 InputStream）
     */
    @JvmStatic
    fun atomicWriteFile(target: File, inputStream: InputStream): Boolean {
        val tmp = File(target.parent, "${target.name}.tmp.${System.currentTimeMillis()}")
        return try {
            tmp.parentFile?.mkdirs()
            FileOutputStream(tmp).use { fos ->
                inputStream.copyTo(fos, BUFFER_SIZE)
                fos.fd.sync()
            }
            tmp.renameTo(target)
        } catch (e: IOException) {
            Logger.e(TAG, "atomicWriteFile from stream failed: ${target.path}", e)
            tmp.delete()
            false
        }
    }

    /**
     * 读取文件全部内容
     */
    @JvmStatic
    fun readAllBytes(file: File): ByteArray {
        return FileInputStream(file).use { it.readBytes() }
    }

    @JvmStatic
    fun copyStream(input: InputStream, output: OutputStream) {
        input.copyTo(output, BUFFER_SIZE)
    }

    /**
     * 计算文件 SHA-256
     */
    @JvmStatic
    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { fis ->
            val buf = ByteArray(BUFFER_SIZE)
            var n: Int
            while (fis.read(buf).also { n = it } > 0) {
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * 计算字节数组 SHA-256
     */
    @JvmStatic
    fun sha256(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data).joinToString("") { "%02x".format(it) }
    }

    /**
     * 从 Uri 复制到文件（处理 SAF content:// URI）
     */
    @JvmStatic
    fun copyUriToFile(context: Context, uri: Uri, outFile: File): Boolean {
        return try {
            outFile.parentFile?.mkdirs()
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(outFile).use { output ->
                    input.copyTo(output, BUFFER_SIZE)
                }
            }
            true
        } catch (e: Exception) {
            Logger.e(TAG, "copyUriToFile failed: $uri -> ${outFile.path}", e)
            false
        }
    }

    /**
     * 获取重打包工作目录
     */
    @JvmStatic
    fun getWorkDir(context: Context): File {
        val dir = File(context.cacheDir, "resign_work")
        dir.mkdirs()
        return dir
    }

    /**
     * 获取输出目录
     */
    @JvmStatic
    fun getOutputDir(context: Context): File {
        val dir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            File(context.getExternalFilesDir(null), "output")
        } else {
            @Suppress("DEPRECATION")
            File(android.os.Environment.getExternalStorageDirectory(), "ReSignPro/output")
        }
        dir.mkdirs()
        return dir
    }

    /**
     * 清理工作目录
     */
    @JvmStatic
    fun cleanWorkDir(context: Context) {
        deleteRecursive(getWorkDir(context))
    }

    /**
     * 递归删除目录
     */
    @JvmStatic
    fun deleteRecursive(file: File) {
        if (file.isDirectory) {
            file.listFiles()?.forEach { deleteRecursive(it) }
        }
        file.delete()
    }

    /**
     * 获取文件大小的可读字符串
     */
    @JvmStatic
    fun humanReadableSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
            else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /**
     * 获取文件扩展名
     */
    @JvmStatic
    fun getExtension(file: File): String {
        val name = file.name
        val idx = name.lastIndexOf('.')
        return if (idx >= 0) name.substring(idx + 1).lowercase() else ""
    }
}
