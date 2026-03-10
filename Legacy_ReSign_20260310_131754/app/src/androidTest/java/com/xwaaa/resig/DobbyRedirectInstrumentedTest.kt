package com.xwaaa.resig

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.FixMethodOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class DobbyRedirectInstrumentedTest {

    @Test
    fun t01_installRedirect_and_open_shouldUseRedirectedFile() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDir = context.filesDir

        val src = File(filesDir, "src.apk").apply { writeText("SRC") }
        val rep = File(filesDir, "origin.apk").apply { writeText("REP") }

        val before = NativeRedirector.readHeadForTest(src.absolutePath, 3)
        assertNotNull(before)
        assertEquals("SRC", String(before!!))

        val ok = NativeRedirector.installRedirect(src.absolutePath, rep.absolutePath)
        assertTrue(ok)
        assertEquals(2, NativeRedirector.getRedirectBackend())

        val headSrc = NativeRedirector.readHeadForTest(src.absolutePath, 3)
        val headRep = NativeRedirector.readHeadForTest(rep.absolutePath, 3)

        assertNotNull(headSrc)
        assertNotNull(headRep)
        val s0 = String(headSrc!!)
        val s1 = String(headRep!!)
        assertEquals("REP", s0)
        assertEquals("REP", s1)
    }

    @Test
    fun t02_redirectedFd_readlink_shouldPointToSourcePath() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDir = context.filesDir

        val src = File(filesDir, "base.apk").apply { writeText("SRC2") }
        val rep = File(filesDir, "origin.apk").apply { writeText("REP2") }

        val ok = NativeRedirector.installRedirect(src.absolutePath, rep.absolutePath)
        assertTrue(ok)

        val fd = NativeRedirector.openForTest(src.absolutePath)
        assertNotEquals(-1, fd)
        val link = NativeRedirector.readlinkFdForTest(fd)
        NativeRedirector.closeForTest(fd)

        assertNotNull(link)
        assertTrue(link!!.contains("base.apk"))
        assertTrue(!link.contains("origin.apk"))
    }

    @Test
    fun t03_stress_multiThread_open_readlink_shouldBeStable() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDir = context.filesDir

        val src = File(filesDir, "base_stress.apk").apply { writeText("SRC3") }
        val rep = File(filesDir, "origin_stress.apk").apply { writeText("REP3") }

        val ok = NativeRedirector.installRedirect(src.absolutePath, rep.absolutePath)
        assertTrue(ok)

        val pool = Executors.newFixedThreadPool(4)
        val latch = CountDownLatch(4)

        repeat(4) {
            pool.execute {
                try {
                    repeat(500) {
                        val fd = NativeRedirector.openForTest(src.absolutePath)
                        if (fd >= 0) {
                            NativeRedirector.readlinkFdForTest(fd)
                            NativeRedirector.closeForTest(fd)
                        }
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue(latch.await(20, TimeUnit.SECONDS))
        pool.shutdownNow()
    }
}
