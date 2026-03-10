/**
 * ReSignPro V2 - native_killer.cpp
 *
 * JNI 入口 + Dobby Inline Hook 安装
 *
 * 核心思路（参考 KC 的三层过签方案）：
 *
 * 1. IO 重定向层：
 *    - 用 Dobby inline hook 替换 libc 的 openat/open/__openat_2
 *    - 当检测到读取 base.apk 时，重定向到原始 APK 备份
 *    - 这样 native 层直接读 APK 解析签名块时会读到正确签名
 *
 * 2. Maps 隐藏层：
 *    - Hook open/openat，当路径是 /proc/self/maps 时
 *    - 返回一个过滤后的 fd（通过 memfd_create）
 *    - 隐藏所有 hook 相关的 .so 库
 *
 * 3. SVC 拦截层：
 *    - seccomp + BPF 拦截直接系统调用
 *    - 防止 app 通过内联 SVC 指令绕过 libc hook
 *
 * 为什么 Dobby Inline Hook 比 PLT Hook 强：
 * - PLT Hook 只能 hook 通过 PLT 表调用的外部函数
 * - 如果 app 静态链接了 libc，或者直接调用函数地址，PLT hook 无效
 * - Inline Hook 直接修改函数入口处的指令，跳转到我们的代码
 * - 无论怎么调用这个函数（PLT/直接调用/函数指针），都会被拦截
 */

#include <jni.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/memfd.h>

#include "dobby.h"
#include "common.h"

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
 *
 * 需要重定向的路径：
 * 1. 当前 APK 路径（/data/app/xxx/base.apk）-> 原始 APK
 * 2. 自定义重定向规则中的路径
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
 * 某些 app 不直接用完整路径，而是用相对路径或 /proc/self/fd/ 来访问
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

/**
 * openat hook
 *
 * 这是最关键的 hook，几乎所有文件访问最终都走 openat
 * Android bionic libc 中 open/fopen 内部也会调用 openat
 */
static int hook_openat(int dirfd, const char *pathname, int flags, ...) {
    // 先处理变参
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (pathname) {
        // 检查 maps 路径
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) {
                LOGD("[openat] /proc/self/maps -> filtered fd %d", fd);
                return fd;
            }
        }

        // 检查 APK 路径重定向
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[openat] redirect: %s -> %s", pathname, redirect);
            return orig_openat(dirfd, redirect, flags, mode);
        }

        // 检查 APK 相关路径
        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                LOGD("[openat] apk-related redirect: %s -> %s", pathname, redirect2);
                return orig_openat(dirfd, redirect2, flags, mode);
            }
        }
    }

    return orig_openat(dirfd, pathname, flags, mode);
}

/**
 * __openat_2 hook (FORTIFY_SOURCE 版本)
 */
static int hook___openat_2(int dirfd, const char *pathname, int flags) {
    if (pathname) {
        if (is_maps_path(pathname)) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) return fd;
        }

        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[__openat_2] redirect: %s -> %s", pathname, redirect);
            return orig___openat_2(dirfd, redirect, flags);
        }

        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                return orig___openat_2(dirfd, redirect2, flags);
            }
        }
    }
    return orig___openat_2(dirfd, pathname, flags);
}

/**
 * fopen hook
 *
 * 很多 native 代码用 fopen 读取文件
 */
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
            return orig_fopen(redirect, mode_str);
        }

        if (is_apk_related_path(pathname)) {
            char redirect2[MAX_PATH_LEN];
            if (should_redirect(g_config.current_apk_path, redirect2, sizeof(redirect2))) {
                return orig_fopen(redirect2, mode_str);
            }
        }
    }
    return orig_fopen(pathname, mode_str);
}

/**
 * open hook
 */
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
            return orig_open(redirect, flags, mode);
        }
    }
    return orig_open(pathname, flags, mode);
}

/**
 * fstatat hook
 *
 * 防止 app 通过 stat 检查 APK 文件的修改时间/大小来检测重打包
 */
static int hook_fstatat(int dirfd, const char *pathname,
                        struct stat *statbuf, int flags) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[fstatat] redirect: %s -> %s", pathname, redirect);
            return orig_fstatat(dirfd, redirect, statbuf, flags);
        }
    }
    return orig_fstatat(dirfd, pathname, statbuf, flags);
}

/**
 * stat hook
 */
static int hook_stat(const char *pathname, struct stat *statbuf) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            LOGD("[stat] redirect: %s -> %s", pathname, redirect);
            return orig_stat(redirect, statbuf);
        }
    }
    return orig_stat(pathname, statbuf);
}

/**
 * access hook
 */
static int hook_access(const char *pathname, int mode) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            return orig_access(redirect, mode);
        }
    }
    return orig_access(pathname, mode);
}

/**
 * faccessat hook
 */
static int hook_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    if (pathname) {
        char redirect[MAX_PATH_LEN];
        if (should_redirect(pathname, redirect, sizeof(redirect))) {
            return orig_faccessat(dirfd, redirect, mode, flags);
        }
    }
    return orig_faccessat(dirfd, pathname, mode, flags);
}

/**
 * readlinkat hook
 *
 * 拦截 /proc/self/fd/xxx 的 readlink
 * 防止 app 通过 fd 反查实际文件路径
 */
static ssize_t hook_readlinkat(int dirfd, const char *pathname,
                                char *buf, size_t bufsiz) {
    ssize_t ret = orig_readlinkat(dirfd, pathname, buf, bufsiz);

    if (ret > 0 && buf) {
        // 如果 readlink 结果是原始 APK 备份路径，替换为当前 APK 路径
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

/**
 * 使用 Dobby 安装 Inline Hook
 *
 * Dobby 的优势：
 * 1. 支持 ARM/ARM64/x86/x86_64
 * 2. 直接修改函数入口处的指令（不依赖 PLT/GOT）
 * 3. 自动处理指令重定位
 * 4. 支持 Hook 任意地址（不仅限于导出函数）
 */
static int install_inline_hooks() {
    int success = 0;
    int total = 0;

    // Hook openat
    void *sym_openat = DobbySymbolResolver("libc.so", "openat");
    if (sym_openat) {
        total++;
        if (DobbyHook(sym_openat, (dobby_dummy_func_t)hook_openat,
                       (dobby_dummy_func_t *)&orig_openat) == 0) {
            success++;
            LOGI("Dobby: hooked openat");
        } else {
            LOGW("Dobby: failed to hook openat");
        }
    }

    // Hook __openat_2
    void *sym___openat_2 = DobbySymbolResolver("libc.so", "__openat_2");
    if (sym___openat_2) {
        total++;
        if (DobbyHook(sym___openat_2, (dobby_dummy_func_t)hook___openat_2,
                       (dobby_dummy_func_t *)&orig___openat_2) == 0) {
            success++;
            LOGI("Dobby: hooked __openat_2");
        } else {
            LOGW("Dobby: failed to hook __openat_2");
        }
    }

    // Hook fopen
    void *sym_fopen = DobbySymbolResolver("libc.so", "fopen");
    if (sym_fopen) {
        total++;
        if (DobbyHook(sym_fopen, (dobby_dummy_func_t)hook_fopen,
                       (dobby_dummy_func_t *)&orig_fopen) == 0) {
            success++;
            LOGI("Dobby: hooked fopen");
        } else {
            LOGW("Dobby: failed to hook fopen");
        }
    }

    // Hook open
    void *sym_open = DobbySymbolResolver("libc.so", "open");
    if (sym_open) {
        total++;
        if (DobbyHook(sym_open, (dobby_dummy_func_t)hook_open,
                       (dobby_dummy_func_t *)&orig_open) == 0) {
            success++;
            LOGI("Dobby: hooked open");
        } else {
            LOGW("Dobby: failed to hook open");
        }
    }

    // Hook fstatat (newfstatat on 64-bit)
    void *sym_fstatat = DobbySymbolResolver("libc.so", "fstatat");
    if (!sym_fstatat) sym_fstatat = DobbySymbolResolver("libc.so", "fstatat64");
    if (!sym_fstatat) sym_fstatat = DobbySymbolResolver("libc.so", "__fstatat64");
    if (sym_fstatat) {
        total++;
        if (DobbyHook(sym_fstatat, (dobby_dummy_func_t)hook_fstatat,
                       (dobby_dummy_func_t *)&orig_fstatat) == 0) {
            success++;
            LOGI("Dobby: hooked fstatat");
        }
    }

    // Hook stat
    void *sym_stat = DobbySymbolResolver("libc.so", "stat");
    if (!sym_stat) sym_stat = DobbySymbolResolver("libc.so", "stat64");
    if (sym_stat) {
        total++;
        if (DobbyHook(sym_stat, (dobby_dummy_func_t)hook_stat,
                       (dobby_dummy_func_t *)&orig_stat) == 0) {
            success++;
            LOGI("Dobby: hooked stat");
        }
    }

    // Hook access
    void *sym_access = DobbySymbolResolver("libc.so", "access");
    if (sym_access) {
        total++;
        if (DobbyHook(sym_access, (dobby_dummy_func_t)hook_access,
                       (dobby_dummy_func_t *)&orig_access) == 0) {
            success++;
            LOGI("Dobby: hooked access");
        }
    }

    // Hook faccessat
    void *sym_faccessat = DobbySymbolResolver("libc.so", "faccessat");
    if (sym_faccessat) {
        total++;
        if (DobbyHook(sym_faccessat, (dobby_dummy_func_t)hook_faccessat,
                       (dobby_dummy_func_t *)&orig_faccessat) == 0) {
            success++;
            LOGI("Dobby: hooked faccessat");
        }
    }

    // Hook readlinkat
    void *sym_readlinkat = DobbySymbolResolver("libc.so", "readlinkat");
    if (sym_readlinkat) {
        total++;
        if (DobbyHook(sym_readlinkat, (dobby_dummy_func_t)hook_readlinkat,
                       (dobby_dummy_func_t *)&orig_readlinkat) == 0) {
            success++;
            LOGI("Dobby: hooked readlinkat");
        }
    }

    LOGI("Dobby inline hooks: %d/%d installed successfully", success, total);
    return success;
}

// ==================== JNI 函数实现 ====================

extern "C" {

JNIEXPORT jint JNICALL
Java_com_xiao_resign_killsig_NativeSignatureKiller_nativeInstall(
        JNIEnv *env, jclass clazz,
        jstring packageName, jstring currentApkPath,
        jstring origApkPath, jstring dataDir,
        jobjectArray signatures) {

    LOGI("=== NativeKiller installing ===");
    LOGI("Arch: %s", CURRENT_ARCH);

    // 读取参数
    const char *pkg = env->GetStringUTFChars(packageName, nullptr);
    const char *curApk = env->GetStringUTFChars(currentApkPath, nullptr);
    const char *origApk = env->GetStringUTFChars(origApkPath, nullptr);
    const char *data = env->GetStringUTFChars(dataDir, nullptr);

    strncpy(g_config.package_name, pkg, sizeof(g_config.package_name) - 1);
    strncpy(g_config.current_apk_path, curApk, sizeof(g_config.current_apk_path) - 1);
    strncpy(g_config.original_apk_path, origApk, sizeof(g_config.original_apk_path) - 1);
    strncpy(g_config.data_dir, data, sizeof(g_config.data_dir) - 1);

    env->ReleaseStringUTFChars(packageName, pkg);
    env->ReleaseStringUTFChars(currentApkPath, curApk);
    env->ReleaseStringUTFChars(origApkPath, origApk);
    env->ReleaseStringUTFChars(dataDir, data);

    LOGI("Package: %s", g_config.package_name);
    LOGI("Current APK: %s", g_config.current_apk_path);
    LOGI("Original APK: %s", g_config.original_apk_path);

    // 添加默认重定向：当前 APK -> 原始 APK
    if (strcmp(g_config.current_apk_path, g_config.original_apk_path) != 0) {
        strncpy(g_config.redirects[0].src_path, g_config.current_apk_path,
                MAX_PATH_LEN - 1);
        strncpy(g_config.redirects[0].dst_path, g_config.original_apk_path,
                MAX_PATH_LEN - 1);
        g_config.redirect_count = 1;
    }

    g_config.active = true;

    // 安装 Dobby Inline Hook
    int hooked = install_inline_hooks();
    if (hooked <= 0) {
        LOGE("No hooks installed!");
        return -1;
    }

    // 安装 seccomp BPF 拦截（防止内联 SVC 绕过 libc hook）
    int seccomp_ret = seccomp_install();
    if (seccomp_ret == 0) {
        LOGI("Seccomp filter installed");
    } else {
        LOGW("Seccomp install failed (code %d), SVC bypass possible", seccomp_ret);
    }

    LOGI("=== NativeKiller installed: %d hooks ===", hooked);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_xiao_resign_killsig_NativeSignatureKiller_nativeHideMaps(
        JNIEnv *env, jclass clazz, jobjectArray filterKeywords) {

    int len = env->GetArrayLength(filterKeywords);
    for (int i = 0; i < len && g_config.filter_count < MAX_FILTERS; i++) {
        jstring keyword = (jstring) env->GetObjectArrayElement(filterKeywords, i);
        const char *kw = env->GetStringUTFChars(keyword, nullptr);
        maps_hide_add_filter(kw);
        env->ReleaseStringUTFChars(keyword, kw);
    }

    maps_hide_install();
}

JNIEXPORT void JNICALL
Java_com_xiao_resign_killsig_NativeSignatureKiller_nativeAddRedirect(
        JNIEnv *env, jclass clazz, jstring srcPath, jstring dstPath) {

    if (g_config.redirect_count >= MAX_REDIRECTS) {
        LOGW("Max redirects reached");
        return;
    }

    const char *src = env->GetStringUTFChars(srcPath, nullptr);
    const char *dst = env->GetStringUTFChars(dstPath, nullptr);

    int idx = g_config.redirect_count;
    strncpy(g_config.redirects[idx].src_path, src, MAX_PATH_LEN - 1);
    strncpy(g_config.redirects[idx].dst_path, dst, MAX_PATH_LEN - 1);
    g_config.redirect_count++;

    LOGI("Added redirect: %s -> %s", src, dst);

    env->ReleaseStringUTFChars(srcPath, src);
    env->ReleaseStringUTFChars(dstPath, dst);
}

JNIEXPORT jboolean JNICALL
Java_com_xiao_resign_killsig_NativeSignatureKiller_nativeIsActive(
        JNIEnv *env, jclass clazz) {
    return g_config.active ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
