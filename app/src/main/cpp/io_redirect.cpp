/**
 * ReSignPro - IO Redirect Implementation
 *
 * IO 重定向核心逻辑：
 * 1. 管理路径重定向规则表
 * 2. 提供 async-signal-safe 的路径匹配/替换
 * 3. 提供各 libc 函数的 hook 替换实现
 */

#include "io_redirect.h"
#include "maps_hide.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <linux/limits.h>

// ==================== 规则存储 ====================

static RedirectRule g_rules[MAX_REDIRECT_RULES];
static volatile int g_rule_count = 0;
static bool g_io_initialized = false;

// 原始函数指针（PLT hook 模式使用）
static int (*orig_openat)(int, const char *, int, ...) = nullptr;
static int (*orig___openat_2)(int, const char *, int) = nullptr;
static int (*orig_fstatat)(int, const char *, void *, int) = nullptr;
static int (*orig_faccessat)(int, const char *, int, int) = nullptr;
static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t) = nullptr;
static int (*orig_statx)(int, const char *, int, unsigned int, void *) = nullptr;
static int (*orig_execve)(const char *, char *const[], char *const[]) = nullptr;

// ==================== 规则管理 ====================

void io_redirect_init(const RedirectConfig *config) {
    if (g_io_initialized) return;

    memset(g_rules, 0, sizeof(g_rules));
    g_rule_count = 0;

    // 添加默认规则: 原始APK路径 -> 伪造APK路径
    if (config->orig_apk_path[0] && config->fake_apk_path[0]) {
        io_redirect_add_rule(config->orig_apk_path, config->fake_apk_path);
        LOGI("IO redirect: %s -> %s", config->orig_apk_path, config->fake_apk_path);
    }

    // 添加 base.apk 路径重定向
    // /data/app/~~hash~~/pkg/base.apk -> fake_apk_path
    if (config->package_name[0] && config->fake_apk_path[0]) {
        char pattern[MAX_PATH_LEN];
        // Android 12+ 路径格式
        snprintf(pattern, sizeof(pattern), "/data/app/");
        // 这个用前缀匹配不太合适，改用精确路径
        // 实际路径由 Java 层传入，这里只做基本映射
    }

    g_io_initialized = true;
    LOGI("IO redirect initialized with %d rules", g_rule_count);
}

bool io_redirect_add_rule(const char *from, const char *to) {
    if (g_rule_count >= MAX_REDIRECT_RULES) {
        LOGE("Redirect rule table full (%d)", MAX_REDIRECT_RULES);
        return false;
    }

    int idx = g_rule_count;
    safe_strncpy(g_rules[idx].from_path, from, MAX_PATH_LEN);
    safe_strncpy(g_rules[idx].to_path, to, MAX_PATH_LEN);
    g_rules[idx].from_len = safe_strlen(from);
    g_rules[idx].to_len = safe_strlen(to);
    g_rules[idx].prefix_match = false;

    // Memory barrier
    __sync_synchronize();
    g_rule_count = idx + 1;

    LOGI("Added redirect rule [%d]: %s -> %s", idx, from, to);
    return true;
}

bool io_redirect_add_prefix_rule(const char *from_prefix, const char *to_prefix) {
    if (g_rule_count >= MAX_REDIRECT_RULES) return false;

    int idx = g_rule_count;
    safe_strncpy(g_rules[idx].from_path, from_prefix, MAX_PATH_LEN);
    safe_strncpy(g_rules[idx].to_path, to_prefix, MAX_PATH_LEN);
    g_rules[idx].from_len = safe_strlen(from_prefix);
    g_rules[idx].to_len = safe_strlen(to_prefix);
    g_rules[idx].prefix_match = true;

    __sync_synchronize();
    g_rule_count = idx + 1;

    LOGI("Added prefix redirect rule [%d]: %s* -> %s*", idx, from_prefix, to_prefix);
    return true;
}

int io_redirect_rule_count(void) {
    return g_rule_count;
}

// ==================== 路径匹配 (async-signal-safe) ====================

/**
 * async-signal-safe 的路径重定向
 * 不使用 malloc, printf 等非 signal-safe 函数
 */
bool io_redirect_resolve(const char *path, char *new_path, size_t buf_size) {
    if (!path || !new_path || buf_size == 0) return false;

    int count = g_rule_count;
    for (int i = 0; i < count; i++) {
        const RedirectRule *rule = &g_rules[i];

        if (rule->prefix_match) {
            // 前缀匹配：检查 path 是否以 from_path 开头
            if (safe_strncmp(path, rule->from_path, rule->from_len) == 0) {
                // 构造新路径: to_path + path[from_len:]
                int suffix_len = safe_strlen(path) - rule->from_len;
                if ((size_t)(rule->to_len + suffix_len + 1) > buf_size) return false;

                safe_memcpy(new_path, rule->to_path, rule->to_len);
                safe_memcpy(new_path + rule->to_len, path + rule->from_len, suffix_len);
                new_path[rule->to_len + suffix_len] = '\0';
                return true;
            }
        } else {
            // 精确匹配
            if (safe_strcmp(path, rule->from_path) == 0) {
                if ((size_t)(rule->to_len + 1) > buf_size) return false;
                safe_memcpy(new_path, rule->to_path, rule->to_len + 1);
                return true;
            }
        }
    }

    return false;
}

// ==================== Hook 替换函数 ====================

/**
 * 路径重定向辅助：检查并重定向路径
 * 返回实际应使用的路径（可能是原始路径或重定向后的路径）
 */
static __thread char tls_redirect_buf[MAX_PATH_LEN];

static const char* redirect_path(const char *pathname) {
    if (!pathname) return pathname;

    // 检查是否是 maps 路径
    if (maps_hide_is_maps_path(pathname)) {
        // maps 文件处理由 maps_hide 模块负责
        // 这里不做重定向，而是在 openat hook 中特殊处理
        return pathname;
    }

    if (io_redirect_resolve(pathname, tls_redirect_buf, sizeof(tls_redirect_buf))) {
        return tls_redirect_buf;
    }
    return pathname;
}

// ---- openat hook ----

int hook_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }

    // 特殊处理: /proc/self/maps
    if (pathname && maps_hide_is_maps_path(pathname)) {
        int fd = maps_hide_get_filtered_fd();
        if (fd >= 0) {
            // 返回过滤后的 maps fd 的副本
            return dup(fd);
        }
    }

    const char *real_path = redirect_path(pathname);

    if (orig_openat) {
        return orig_openat(dirfd, real_path, flags, mode);
    }
    // Fallback: direct syscall
    return (int) syscall(SYS_OPENAT, dirfd, real_path, flags, mode);
}

int hook___openat_2(int dirfd, const char *pathname, int flags) {
    // __openat_2 是 fortified 版本，不接受 O_CREAT
    if (pathname && maps_hide_is_maps_path(pathname)) {
        int fd = maps_hide_get_filtered_fd();
        if (fd >= 0) return dup(fd);
    }

    const char *real_path = redirect_path(pathname);

    if (orig___openat_2) {
        return orig___openat_2(dirfd, real_path, flags);
    }
    return (int) syscall(SYS_OPENAT, dirfd, real_path, flags, 0);
}

// ---- fstatat hook ----

int hook_fstatat(int dirfd, const char *pathname, void *statbuf, int flags) {
    const char *real_path = redirect_path(pathname);

    if (orig_fstatat) {
        return orig_fstatat(dirfd, real_path, statbuf, flags);
    }
    return (int) syscall(SYS_FSTATAT, dirfd, real_path, statbuf, flags);
}

// ---- faccessat hook ----

int hook_faccessat(int dirfd, const char *pathname, int mode, int flags) {
    const char *real_path = redirect_path(pathname);

    if (orig_faccessat) {
        return orig_faccessat(dirfd, real_path, mode, flags);
    }
    return (int) syscall(SYS_FACCESSAT, dirfd, real_path, mode, flags);
}

// ---- readlinkat hook ----

ssize_t hook_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    ssize_t ret;

    if (orig_readlinkat) {
        ret = orig_readlinkat(dirfd, pathname, buf, bufsiz);
    } else {
        ret = (ssize_t) syscall(SYS_READLINKAT, dirfd, pathname, buf, bufsiz);
    }

    // 对 readlink 的结果进行重定向
    // 例如 /proc/self/exe 返回的路径可能包含原始 APK 路径
    if (ret > 0 && ret < (ssize_t) bufsiz) {
        char tmp[MAX_PATH_LEN];
        // 临时 null terminate
        char save = buf[ret];
        buf[ret] = '\0';

        if (io_redirect_resolve(buf, tmp, sizeof(tmp))) {
            int new_len = safe_strlen(tmp);
            if (new_len < (int) bufsiz) {
                safe_memcpy(buf, tmp, new_len);
                ret = new_len;
            }
        } else {
            buf[ret] = save;
        }
    }

    return ret;
}

// ---- statx hook (API 30+) ----

int hook_statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *statxbuf) {
    const char *real_path = redirect_path(pathname);

    if (orig_statx) {
        return orig_statx(dirfd, real_path, flags, mask, statxbuf);
    }
#ifdef SYS_STATX
    return (int) syscall(SYS_STATX, dirfd, real_path, flags, mask, statxbuf);
#else
    errno = ENOSYS;
    return -1;
#endif
}

// ---- execve hook ----

int hook_execve(const char *pathname, char *const argv[], char *const envp[]) {
    // 拦截 execve：有些检测工具通过执行命令检查 APK 信息
    // 这里可以选择拦截特定命令（如 pm, dumpsys 等）

    if (orig_execve) {
        return orig_execve(pathname, argv, envp);
    }
    return (int) syscall(SYS_EXECVE, pathname, argv, envp);
}

// ==================== 原始函数指针获取 ====================

void io_redirect_set_orig_openat(void *func) {
    orig_openat = (int (*)(int, const char *, int, ...)) func;
}

void io_redirect_set_orig___openat_2(void *func) {
    orig___openat_2 = (int (*)(int, const char *, int)) func;
}

void io_redirect_set_orig_fstatat(void *func) {
    orig_fstatat = (int (*)(int, const char *, void *, int)) func;
}

void io_redirect_set_orig_faccessat(void *func) {
    orig_faccessat = (int (*)(int, const char *, int, int)) func;
}

void io_redirect_set_orig_readlinkat(void *func) {
    orig_readlinkat = (ssize_t (*)(int, const char *, char *, size_t)) func;
}

void io_redirect_set_orig_statx(void *func) {
    orig_statx = (int (*)(int, const char *, int, unsigned int, void *)) func;
}

void io_redirect_set_orig_execve(void *func) {
    orig_execve = (int (*)(const char *, char *const[], char *const[])) func;
}
