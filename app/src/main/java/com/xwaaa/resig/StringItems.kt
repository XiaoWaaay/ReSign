package com.xwaaa.resig

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.Charset

object StringItems {
    /**
     * 从 AXML 中读取字符串表
     */
    @Throws(IOException::class)
    fun read(buf: ByteBuffer): Array<String?> {
        buf.order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.int
        val styleOffsetCount = buf.int
        val flags = buf.int
        val stringsOffset = buf.int
        val stylesOffset = buf.int

        val utf8 = (flags and 0x00000100) != 0
        val offsets = IntArray(stringCount) { buf.int }

        // 修正：字符串表实际开始位置
        val startPos = buf.position()
        val stringBase = startPos

        val strings = arrayOfNulls<String>(stringCount)
        for (i in 0 until stringCount) {
            buf.position(stringBase + offsets[i])
            strings[i] = if (utf8) readUtf8(buf) else readUtf16(buf)
        }

        // 修复读取偏移越界
        if (stylesOffset > 0 && stylesOffset > buf.position()) {
            buf.position(stylesOffset)
        }
        return strings
    }

    private fun readUtf8(buf: ByteBuffer): String {
        readLength8(buf) // utf16 length
        val bytesLen = readLength8(buf)
        val bytes = ByteArray(bytesLen)
        buf.get(bytes)
        buf.get() // 结尾 0x00
        return bytes.toString(Charset.forName("UTF-8"))
    }

    private fun readUtf16(buf: ByteBuffer): String {
        val strLen = readLength16(buf)
        val chars = CharArray(strLen)
        for (i in 0 until strLen) chars[i] = buf.char
        buf.short // 跳过结尾的0
        return String(chars)
    }

    private fun readLength8(buf: ByteBuffer): Int {
        var len = buf.get().toInt() and 0xFF
        if (len and 0x80 != 0) {
            len = (len and 0x7F shl 7) or (buf.get().toInt() and 0x7F)
        }
        return len
    }

    private fun readLength16(buf: ByteBuffer): Int {
        var len = buf.short.toInt() and 0xFFFF
        if (len and 0x8000 != 0) {
            len = (len and 0x7FFF shl 15) or (buf.short.toInt() and 0x7FFF)
        }
        return len
    }
}
