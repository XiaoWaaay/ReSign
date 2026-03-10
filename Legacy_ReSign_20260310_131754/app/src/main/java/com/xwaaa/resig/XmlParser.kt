package com.xwaaa.resig

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.IntBuffer
import kotlin.UShort

/**
 * Android 二进制 XML (AXML) 解析器
 * 用于解析 APK 中的 AndroidManifest.xml
 */
class XmlParser(private val input: ByteBuffer) {

    companion object {
        const val END_FILE = 7
        const val END_NS = 5
        const val END_TAG = 3
        const val START_FILE = 1
        const val START_NS = 4
        const val START_TAG = 2
        const val TEXT = 6
    }

    private var attributeCount = 0
    private var attrs: IntBuffer? = null
    private var classAttribute = 0
    private var fileSize = -1
    private var idAttribute = 0
    private var lineNumber = 0
    private var nameIdx = 0
    private var nsIdx = -1
    private var prefixIdx = -1
    private var resourceIds: IntArray? = null
    private var strings: Array<String?>? = null
    private var styleAttribute = 0
    private var textIdx = 0

    constructor(data: ByteArray) : this(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN))

    fun getAttrCount(): Int = attributeCount
    fun getAttrName(i: Int): String = strings!![attrs!!.get(i * 5 + 1)] ?: ""
    fun getAttrNs(i: Int): String? {
        val idx = attrs!!.get(i * 5)
        return if (idx >= 0) strings!![idx] else null
    }

    private fun getAttrRawString(i: Int): String? {
        val idx = attrs!!.get(i * 5 + 2)
        return if (idx >= 0) strings!![idx] else null
    }

    fun getAttrType(i: Int): Int = attrs!!.get(i * 5 + 3) shr 24
    fun getAttrValue(i: Int): Any? {
        val v = attrs!!.get(i * 5 + 4)
        return when (getAttrType(i)) {
            3 -> strings?.get(v)
            18 -> v != 0
            else -> v
        }
    }

    fun getName(): String = strings?.get(nameIdx) ?: ""
    fun getNamespacePrefix(): String = if (prefixIdx >= 0) strings?.get(prefixIdx) ?: "" else ""
    fun getNamespaceUri(): String? = if (nsIdx >= 0) strings?.get(nsIdx) else null
    fun getText(): String = strings?.get(textIdx) ?: ""

    /**
     * 解析下一个 XML 事件
     */
    @Throws(IOException::class)
    fun next(): Int {
        if (fileSize < 0) {
            val type = input.int and 0xFFFF
            if (type != 3) throw RuntimeException("AXML 文件头错误")
            fileSize = input.int
            return START_FILE
        }

        var pos = input.position()
        while (pos < fileSize) {
            val type = input.int and 0xFFFF
            val size = input.int

            when (type) {
                1 -> { // 字符串池
                    strings = StringItems.read(input)
                    input.position(pos + size)
                }

                256 -> { // namespace start
                    lineNumber = input.int
                    input.int
                    prefixIdx = input.int
                    nsIdx = input.int
                    input.position(pos + size)
                    return START_NS
                }

                257 -> { // namespace end
                    input.position(pos + size)
                    return END_NS
                }

                258 -> { // start tag
                    lineNumber = input.int
                    input.int
                    nsIdx = input.int
                    nameIdx = input.int
                    val flag = input.int
                    if (flag != 0x140014 && flag != 0x100014)
                        throw RuntimeException("意外标志位 flag=$flag")

                    attributeCount = input.short.toInt() and UShort.MAX_VALUE.toInt()
                    idAttribute = (input.short.toInt() and UShort.MAX_VALUE.toInt()) - 1
                    classAttribute = (input.short.toInt() and UShort.MAX_VALUE.toInt()) - 1
                    styleAttribute = (input.short.toInt() and 0xFFFF) - 1
                    attrs = input.asIntBuffer()
                    input.position(pos + size)
                    return START_TAG
                }

                259 -> { // end tag
                    input.position(pos + size)
                    return END_TAG
                }

                260 -> { // text
                    lineNumber = input.int
                    input.int
                    textIdx = input.int
                    input.int
                    input.int
                    input.position(pos + size)
                    return TEXT
                }

                384 -> { // 资源 ID 映射表
                    val count = (size / 4) - 2
                    resourceIds = IntArray(count)
                    for (i in 0 until count) {
                        resourceIds!![i] = input.int
                    }
                    input.position(pos + size)
                }

                else -> throw RuntimeException("未知 chunk 类型: $type")
            }

            pos = input.position()
        }
        return END_FILE
    }
}
