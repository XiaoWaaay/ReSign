package com.xwaaa.resig.utils

import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.nio.charset.Charset

object IOUtils {

    public const val BUFFER_SIZE = 4096
    public const val LINE_SEPARATOR_UNIX = "\n"


    /** 安全关闭 Closeable，不抛出异常 */
    fun closeQuietly(closeable: Closeable?) {
        try {
            closeable?.close()
        } catch (_: IOException) {
        }
    }

    /** 安全关闭多个流 */
    fun closeQuietly(vararg closeables: Closeable?) {
        closeables.forEach { closeQuietly(it) }
    }

    /** 安全关闭网络连接 */
    fun close(conn: URLConnection?) {
        if (conn is HttpURLConnection) conn.disconnect()
    }

    /** InputStream → ByteArray */
    @Throws(IOException::class)
    fun toByteArray(input: InputStream): ByteArray {
        ByteArrayOutputStream().use { output ->
            copy(input, output)
            return output.toByteArray()
        }
    }

    /** InputStream → String（默认 UTF-8） */
    @Throws(IOException::class)
    fun toString(input: InputStream, charset: Charset = Charsets.UTF_8): String {
        InputStreamReader(input, charset).use { reader ->
            val sb = StringBuilder()
            val buffer = CharArray(BUFFER_SIZE)
            var len: Int
            while (reader.read(buffer).also { len = it } != -1) {
                sb.append(buffer, 0, len)
            }
            return sb.toString()
        }
    }

    /** 拷贝流：InputStream → OutputStream */
    @Throws(IOException::class)
    fun copy(input: InputStream, output: OutputStream): Long {
        var total: Long = 0
        val buffer = ByteArray(BUFFER_SIZE)
        var n: Int
        while (input.read(buffer).also { n = it } != -1) {
            output.write(buffer, 0, n)
            total += n
        }
        return total
    }

    /** Reader → Writer */
    @Throws(IOException::class)
    fun copy(reader: Reader, writer: Writer): Long {
        var total: Long = 0
        val buffer = CharArray(BUFFER_SIZE)
        var n: Int
        while (reader.read(buffer).also { n = it } != -1) {
            writer.write(buffer, 0, n)
            total += n
        }
        return total
    }

    /** 快速读取文件内容为 String */
    fun readFileToString(file: File, charset: Charset = Charsets.UTF_8): String {
        FileInputStream(file).use { return toString(it, charset) }
    }

    /** 快速写入 String 到文件 */
    fun writeStringToFile(file: File, data: String, charset: Charset = Charsets.UTF_8) {
        FileOutputStream(file).use { it.write(data.toByteArray(charset)) }
    }

    /** 判断两个 InputStream 是否内容相同 */
    fun contentEquals(input1: InputStream, input2: InputStream): Boolean {
        val buf1 = BufferedInputStream(input1)
        val buf2 = BufferedInputStream(input2)
        var ch1: Int
        var ch2: Int
        while (true) {
            ch1 = buf1.read()
            ch2 = buf2.read()
            if (ch1 != ch2) return false
            if (ch1 == -1) return true
        }
    }
}
