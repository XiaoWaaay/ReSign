package com.xwaaa.resig

/**
 * Native redirection/hook test API.
 *
 * This is used by instrumentation tests to verify that the seccomp + SIGSYS
 * interception is correctly installed and does not break normal file IO.
 */
object NativeRedirector {
    init {
        System.loadLibrary("killsignture")
    }

    /**
     * Installs a redirector that rewrites open/openat from [sourcePath] to [redirectedPath]
     * and fakes readlink/readlinkat results for redirected fds.
     */
    external fun installRedirect(sourcePath: String, redirectedPath: String): Boolean

    /**
     * Returns the active redirect backend:
     * - 0: none
     * - 2: seccomp + SIGSYS
     */
    external fun getRedirectBackend(): Int

    external fun openForTest(path: String): Int

    external fun closeForTest(fd: Int)

    external fun readHeadForTest(path: String, maxLen: Int): ByteArray?

    external fun readlinkFdForTest(fd: Int): String?
}
