package com.xwaaa.resig

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.lang.reflect.Method

@RunWith(AndroidJUnit4::class)
class ReflectionVsDirectInstrumentedTest {

    private fun reflectCall(iter: Int): Long {
        val clazz = Class.forName("java.lang.String")
        val m: Method = clazz.getDeclaredMethod("valueOf", Any::class.java)
        val start = SystemClock.elapsedRealtimeNanos()
        var x = "x"
        repeat(iter) {
            x = m.invoke(null, x) as String
        }
        return SystemClock.elapsedRealtimeNanos() - start
    }

    private fun directCall(iter: Int): Long {
        val start = SystemClock.elapsedRealtimeNanos()
        var x = "x"
        repeat(iter) {
            x = java.lang.String.valueOf(x)
        }
        return SystemClock.elapsedRealtimeNanos() - start
    }

    @Test
    fun compare_reflection_and_direct_call_cost() {
        val iter = 50_000
        val tReflect = reflectCall(iter)
        val tDirect = directCall(iter)
        val ratio = tReflect.toDouble() / tDirect.toDouble().coerceAtLeast(1.0)
        assertTrue(ratio > 1.1)
    }
}

