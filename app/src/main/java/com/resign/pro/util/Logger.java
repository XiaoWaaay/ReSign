/**
 * ReSignPro - Logger
 *
 * 统一日志工具，支持文件输出和级别控制
 */
package com.resign.pro.util;

import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class Logger {

    private static final String DEFAULT_TAG = "ReSignPro";

    public static final int LEVEL_VERBOSE = 0;
    public static final int LEVEL_DEBUG = 1;
    public static final int LEVEL_INFO = 2;
    public static final int LEVEL_WARN = 3;
    public static final int LEVEL_ERROR = 4;
    public static final int LEVEL_NONE = 5;

    private static int sLevel = LEVEL_DEBUG;
    private static File sLogFile = null;
    private static BufferedWriter sFileWriter = null;
    private static final SimpleDateFormat sDateFormat =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    public static void setLevel(int level) {
        sLevel = level;
    }

    public static void enableFileLog(File logFile) {
        try {
            sLogFile = logFile;
            sFileWriter = new BufferedWriter(new FileWriter(logFile, true));
            i("Logger", "File logging enabled: " + logFile.getAbsolutePath());
        } catch (IOException e) {
            Log.e(DEFAULT_TAG, "Failed to enable file logging", e);
        }
    }

    public static void v(String tag, String msg) {
        if (sLevel <= LEVEL_VERBOSE) {
            Log.v(tag, msg);
            writeToFile("V", tag, msg);
        }
    }

    public static void d(String tag, String msg) {
        if (sLevel <= LEVEL_DEBUG) {
            Log.d(tag, msg);
            writeToFile("D", tag, msg);
        }
    }

    public static void i(String tag, String msg) {
        if (sLevel <= LEVEL_INFO) {
            Log.i(tag, msg);
            writeToFile("I", tag, msg);
        }
    }

    public static void w(String tag, String msg) {
        if (sLevel <= LEVEL_WARN) {
            Log.w(tag, msg);
            writeToFile("W", tag, msg);
        }
    }

    public static void w(String tag, String msg, Throwable t) {
        if (sLevel <= LEVEL_WARN) {
            Log.w(tag, msg, t);
            writeToFile("W", tag, msg + "\n" + Log.getStackTraceString(t));
        }
    }

    public static void e(String tag, String msg) {
        if (sLevel <= LEVEL_ERROR) {
            Log.e(tag, msg);
            writeToFile("E", tag, msg);
        }
    }

    public static void e(String tag, String msg, Throwable t) {
        if (sLevel <= LEVEL_ERROR) {
            Log.e(tag, msg, t);
            writeToFile("E", tag, msg + "\n" + Log.getStackTraceString(t));
        }
    }

    private static synchronized void writeToFile(String level, String tag, String msg) {
        if (sFileWriter == null) return;
        try {
            String timestamp = sDateFormat.format(new Date());
            sFileWriter.write(String.format("[%s] %s/%s: %s\n", timestamp, level, tag, msg));
            sFileWriter.flush();
        } catch (IOException ignored) {}
    }

    public static synchronized void close() {
        if (sFileWriter != null) {
            try {
                sFileWriter.close();
            } catch (IOException ignored) {}
            sFileWriter = null;
        }
    }
}
