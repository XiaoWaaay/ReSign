package com.xwaaa.resig

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class DobbySecurityInstrumentedTest {

    @Test
    fun hook_accuracy_under_heavy_loop() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDir = context.filesDir
        val src = File(filesDir, "acc_base.apk").apply { writeText("SRC_A") }
        val rep = File(filesDir, "acc_origin.apk").apply { writeText("REP_A") }

        val ok = NativeRedirector.installRedirect(src.absolutePath, rep.absolutePath)
        assertTrue(ok)

        var mismatch = 0
        repeat(5000) {
            val head = NativeRedirector.readHeadForTest(src.absolutePath, 5)
            if (head == null || String(head) != "REP_A") {
                mismatch++
            }
        }
        assertEquals(0, mismatch)
    }

    @Test
    fun hook_stability_long_running_single_thread() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDir = context.filesDir
        val src = File(filesDir, "stab_base.apk").apply { writeText("SRC_B") }
        val rep = File(filesDir, "stab_origin.apk").apply { writeText("REP_B") }

        val ok = NativeRedirector.installRedirect(src.absolutePath, rep.absolutePath)
        assertTrue(ok)

        repeat(20_000) {
            val fd = NativeRedirector.openForTest(src.absolutePath)
            if (fd >= 0) {
                NativeRedirector.readlinkFdForTest(fd)
                NativeRedirector.closeForTest(fd)
            }
        }
        assertTrue(true)
    }
}
