#include <jni.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/memfd.h>
#include <android/log.h>
#include <stdio.h>
#include <stdarg.h>

#include "common.h"

// Define dobby_dummy_func_t if not present
// typedef void (*dobby_dummy_func_t)(void);

// ==================== 全局配置 ====================
KillerConfig g_config = {};

// ==================== 原始函数指针 ====================
// Dobby hook 后，原始函数保存在这些指针中

// libc IO 函数
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...) = nullptr;
static int (*orig___openat_2)(int dirfd, const char *pathname, int flags) = nullptr;
static FILE *(*orig_fopen)(const char *pathname, const char *mode) = nullptr;
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;

// stat 系列
static int (*orig_fstatat)(int dirfd, const char *pathname,
                           struct stat *statbuf, int flags) = nullptr;
static int (*orig_stat)(const char *pathname, struct stat *statbuf) = nullptr;
static int (*orig_lstat)(const char *pathname, struct stat *statbuf) = nullptr;

// access 系列
static int (*orig_faccessat)(int dirfd, const char *pathname, int mode, int flags) = nullptr;
static int (*orig_access)(const char *pathname, int mode) = nullptr;

// readlink
static ssize_t (*orig_readlinkat)(int dirfd, const char *pathname,
                                   char *buf, size_t bufsiz) = nullptr;

// ==================== 路径检查 ====================

/**
 * 检查路径是否需要重定向
 */
static bool should_redirect(const char *path, char *redirect_to, size_t len) {
    if (!path || !g_config.active) return false;

    // 检查是否是当前 APK 路径
    if (g_config.current_apk_path[0] != '\0' &&
        strcmp(path, g_config.current_apk_path) == 0) {
        // 重定向到原始 APK
        if (g_config.original_apk_path[0] != '\0' &&
            strcmp(g_config.current_apk_path, g_config.original_apk_path) != 0) {
            strncpy(redirect_to, g_config.original_apk_path, len - 1);
            redirect_to[len - 1] = '\0';
            return true;
        }
    }

    // 检查自定义重定向规则
    for (int i = 0; i < g_config.redirect_count; i++) {
        if (strcmp(path, g_config.redirects[i].src_path) == 0) {
            strncpy(redirect_to, g_config.redirects[i].dst_path, len - 1);
            redirect_to[len - 1] = '\0';
            return true;
        }
    }

    return false;
}

/**
 * 检查路径是否是 /proc/self/maps
 */
static bool is_maps_path(const char *path) {
    if (!path) return false;
    return strcmp(path, "/proc/self/maps") == 0 ||
           strcmp(path, "/proc/thread-self/maps") == 0;
}

/**
 * 检查路径中是否包含与 APK 相关的模式
 */
static bool is_apk_related_path(const char *path) {
    if (!path) return false;

    // 检查 /data/app/ 下的 base.apk
    if (strstr(path, "/base.apk") && strstr(path, "/data/app/")) {
        // 进一步检查是否是当前包
        if (g_config.package_name[0] != '\0' &&
            strstr(path, g_config.package_name)) {
            return true;
        }
    }

    return false;
}

// ==================== Hook 函数实现 ====================

static int hook_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (pathname) {
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) {
                LOGD("[openat] /proc/self/maps -> filtered fd %d", fd);
                return fd;
            }
        }

        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[openat] redirect: %s -> %s", pathname, redirect);
            if (orig_openat) return orig_openat(dirfd, redirect, flags, mode);
        }

        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                LOGD("[openat] apk-related redirect: %s -> %s", pathname, redirect2);
                if (orig_openat) return orig_openat(dirfd, redirect2, flags, mode);
            }
        }
    }

    if (orig_openat) return orig_openat(dirfd, pathname, flags, mode);
    return -1;
}

static int hook___openat_2(int dirfd, const char *pathname, int flags) {
    if (pathname) {
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) return fd;
        }

        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[__openat_2] redirect: %s -> %s", pathname, redirect);
            if (orig___openat_2) return orig___openat_2(dirfd, redirect, flags);
        }

        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                if (orig___openat_2) return orig___openat_2(dirfd, redirect2, flags);
            }
        }
    }
    if (orig___openat_2) return orig___openat_2(dirfd, pathname, flags);
    return -1;
}

static FILE *hook_fopen(const char *pathname, const char *mode_str) {
    if (pathname) {
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) {
                return fdopen(fd, "r");
            }
        }

        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[fopen] redirect: %s -> %s", pathname, redirect);
            if (orig_fopen) return orig_fopen(redirect, mode_str);
        }

        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                if (orig_fopen) return orig_fopen(redirect2, mode_str);
            }
        }
    }
    if (orig_fopen) return orig_fopen(pathname, mode_str);
    return nullptr;
}

static int hook_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (pathname) {
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) return fd;
        }

        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[open] redirect: %s -> %s", pathname, redirect);
            if (orig_open) return orig_open(redirect, flags, mode);
        }
    }
    if (orig_open) return orig_open(pathname, flags, mode);
    return -1;
}

static int hook_fstatat(int dirfd, const char *pathname,
                        struct stat *statbuf, int flags) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[fstatat] redirect: %s -> %s", pathname, redirect);
            if (orig_fstatat) return orig_fstatat(dirfd, redirect, statbuf, flags);
        }
    }
    if (orig_fstatat) return orig_fstatat(dirfd, pathname, statbuf, flags);
    return -1;
}

static int hook_stat(const char *pathname, struct stat *statbuf) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[stat] redirect: %s -> %s", pathname, redirect);
            if (orig_stat) return orig_stat(redirect, statbuf);
        }
    }
    if (orig_stat) return orig_stat(pathname, statbuf);
    return -1;
}

static int hook_access(const char *pathname, int mode) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            if (orig_access) return orig_access(redirect, mode);
        }
    }
    if (orig_access) return orig_access(pathname, mode);
    return -1;
}

static int hook_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            if (orig_faccessat) return orig_faccessat(dirfd, redirect, mode, flags);
        }
    }
    if (orig_faccessat) return orig_faccessat(dirfd, pathname, mode, flags);
    return -1;
}

static ssize_t hook_readlinkat(int dirfd, const char *pathname,
                                char *buf, size_t bufsiz) {
    if (!orig_readlinkat) return -1;
    ssize_t ret = orig_readlinkat(dirfd, pathname, buf, bufsiz);

    if (ret > 0 && buf) {
        if (g_config.original_apk_path[0] != '\0' &&
            strncmp(buf, g_config.original_apk_path,
                    strlen(g_config.original_apk_path)) == 0) {
            size_t current_len = strlen(g_config.current_apk_path);
            if (current_len < bufsiz) {
                memcpy(buf, g_config.current_apk_path, current_len);
                buf[current_len] = '\0';
                return (ssize_t) current_len;
            }
        }
    }

    return ret;
}

// ==================== Dobby Hook 安装 ====================

static int install_inline_hooks() {
    LOGW("Dobby inline hooks are DISABLED due to build issues.");
    return 0;
}

// ==================== JNI 函数实现 ====================

extern "C" {

JNIEXPORT void JNICALL
Java_com_resign_pro_payload_HookEntry_nativeInit(
        JNIEnv *env, jclass clazz,
        jstring backend, jstring baseApkPath,
        jstring originApkPath, jstring packageName,
        jboolean ioRedirect, jboolean mapsHide, jboolean debug) {

    LOGI("=== NativeEngine initializing ===");
    
    // Set config
    const char *pkg = env->GetStringUTFChars(packageName, nullptr);
    const char *curApk = env->GetStringUTFChars(baseApkPath, nullptr);
    const char *origApk = env->GetStringUTFChars(originApkPath, nullptr);
    const char *bk = env->GetStringUTFChars(backend, nullptr);

    strncpy(g_config.package_name, pkg, sizeof(g_config.package_name) - 1);
    strncpy(g_config.current_apk_path, curApk, sizeof(g_config.current_apk_path) - 1);
    strncpy(g_config.original_apk_path, origApk, sizeof(g_config.original_apk_path) - 1);
    g_config.active = true;

    LOGI("Package: %s", g_config.package_name);
    LOGI("Base APK: %s", g_config.current_apk_path);
    LOGI("Origin APK: %s", g_config.original_apk_path);
    LOGI("Backend: %s", bk);

    // Add default redirect
    if (ioRedirect && strcmp(g_config.current_apk_path, g_config.original_apk_path) != 0) {
        strncpy(g_config.redirects[0].src_path, g_config.current_apk_path, MAX_PATH_LEN - 1);
        strncpy(g_config.redirects[0].dst_path, g_config.original_apk_path, MAX_PATH_LEN - 1);
        g_config.redirect_count = 1;
        LOGI("Added default redirect: Base -> Origin");
    }

    // Install hooks based on backend
    if (strcmp(bk, "DOBBY") == 0 || strcmp(bk, "HYBRID") == 0) {
        install_inline_hooks();
    } else if (strcmp(bk, "SECCOMP") == 0) {
        // Seccomp only
    } else {
        // PLT or default - assuming Dobby for now as requested
        install_inline_hooks(); 
    }

    // Install Seccomp if requested (HYBRID or SECCOMP)
    if (strcmp(bk, "HYBRID") == 0 || strcmp(bk, "SECCOMP") == 0) {
        int ret = seccomp_install();
        if (ret == 0) LOGI("Seccomp installed");
        else LOGW("Seccomp failed: %d", ret);
    }

    if (mapsHide) {
        maps_hide_install();
        LOGI("Maps hide installed");
    }

    env->ReleaseStringUTFChars(packageName, pkg);
    env->ReleaseStringUTFChars(baseApkPath, curApk);
    env->ReleaseStringUTFChars(originApkPath, origApk);
    env->ReleaseStringUTFChars(backend, bk);
}

} // extern "C"
