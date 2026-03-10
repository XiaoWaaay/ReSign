package com.xwaaa.resig

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

object DebugUtils {
    fun tracerPid(): Int {
        return try {
            val status = File("/proc/self/status").readText()
            val line = status.lineSequence().firstOrNull { it.startsWith("TracerPid:") }
            line?.substringAfter(":")?.trim()?.toIntOrNull() ?: -1
        } catch (t: Throwable) {
            -1
        }
    }
}

@RunWith(AndroidJUnit4::class)
class DebugSecurityInstrumentedTest {

    @Test
    fun process_not_actively_traced_in_default_env() {
        val tracer = DebugUtils.tracerPid()
        assertTrue(tracer == 0 || tracer == -1)
    }
}

