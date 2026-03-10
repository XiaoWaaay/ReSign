#pragma once

#include <android/log.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

// ==================== 日志 ====================
#define LOG_TAG "ReSignPro-N"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 条件日志（仅debug模式输出）
extern bool g_debug;
#define LOGD_IF(fmt, ...) do { if (g_debug) LOGD(fmt, ##__VA_ARGS__); } while(0)

// ==================== 架构检测 ====================
#if defined(__aarch64__)
    #define IS_ARM64 1
    #define ARCH_NAME "arm64"
#elif defined(__arm__)
    #define IS_ARM 1
    #define ARCH_NAME "arm"
#elif defined(__x86_64__)
    #define IS_X86_64 1
    #define ARCH_NAME "x86_64"
#elif defined(__i386__)
    #define IS_X86 1
    #define ARCH_NAME "x86"
#else
    #error "Unsupported architecture"
#endif

// ==================== Syscall号定义 ====================
#if defined(__aarch64__)
    #define SYS_OPENAT      56
    #define SYS_FSTATAT     79
    #define SYS_FACCESSAT   48
    #define SYS_READLINKAT  78
    #define SYS_STATX       291
    #define SYS_OPENAT2     437
    #define SYS_EXECVE      221
#elif defined(__arm__)
    #define SYS_OPENAT      322
    #define SYS_FSTATAT     327
    #define SYS_FACCESSAT   334
    #define SYS_READLINKAT  332
    #define SYS_STATX       397
    #define SYS_OPENAT2     437
    #define SYS_EXECVE      11
#elif defined(__x86_64__)
    #define SYS_OPENAT      257
    #define SYS_FSTATAT     262
    #define SYS_FACCESSAT   269
    #define SYS_READLINKAT  267
    #define SYS_STATX       332
    #define SYS_OPENAT2     437
    #define SYS_EXECVE      59
#elif defined(__i386__)
    #define SYS_OPENAT      295
    #define SYS_FSTATAT     300
    #define SYS_FACCESSAT   307
    #define SYS_READLINKAT  305
    #define SYS_STATX       383
    #define SYS_OPENAT2     437
    #define SYS_EXECVE      11
#endif

// ==================== 路径管理 ====================
#define MAX_PATH_LEN 512

typedef enum {
    BACKEND_PLT_HOOK = 0,
    BACKEND_SECCOMP = 1,
    BACKEND_HYBRID = 2
} NativeBackend;

// 重定向配置
struct RedirectConfig {
    char orig_apk_path[MAX_PATH_LEN];
    char fake_apk_path[MAX_PATH_LEN];
    char package_name[128];
    char data_dir[MAX_PATH_LEN];
    int api_level;
    bool io_redirect_enabled;
    bool maps_hide_enabled;
    bool initialized;
};

extern RedirectConfig g_config;

// ==================== FD追踪 ====================
#define MAX_TRACKED_FDS 256

struct FdEntry {
    int fd;
    bool redirected;
};

extern FdEntry g_fd_table[MAX_TRACKED_FDS];
extern pthread_mutex_t g_fd_mutex;

void fd_track_add(int fd);
void fd_track_remove(int fd);
bool fd_is_tracked(int fd);

// ==================== 字符串工具（async-signal-safe） ====================
static inline int safe_strlen(const char *s) {
    if (!s) return 0;
    int n = 0;
    while (s[n] != '\0') n++;
    return n;
}

static inline int safe_strcmp(const char *a, const char *b) {
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    int i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        unsigned char ac = (unsigned char)a[i];
        unsigned char bc = (unsigned char)b[i];
        if (ac != bc) return (ac < bc) ? -1 : 1;
        i++;
    }
    if (a[i] == b[i]) return 0;
    return (a[i] == '\0') ? -1 : 1;
}

static inline int safe_strncmp(const char *a, const char *b, size_t n) {
    if (n == 0) return 0;
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    size_t i = 0;
    while (i < n && a[i] != '\0' && b[i] != '\0') {
        unsigned char ac = (unsigned char)a[i];
        unsigned char bc = (unsigned char)b[i];
        if (ac != bc) return (ac < bc) ? -1 : 1;
        i++;
    }
    if (i == n) return 0;
    if (a[i] == b[i]) return 0;
    return (a[i] == '\0') ? -1 : 1;
}

static inline char* safe_strncpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || dst_size == 0) return dst;
    if (!src) {
        dst[0] = '\0';
        return dst;
    }
    size_t i = 0;
    for (; i + 1 < dst_size && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
    return dst;
}

static inline char* safe_strcpy(char *dst, const char *src, size_t dst_size) {
    return safe_strncpy(dst, src, dst_size);
}

static inline void* safe_memcpy(void *dst, const void *src, size_t n) {
    if (!dst || !src || n == 0) return dst;
    unsigned char *d = (unsigned char*)dst;
    const unsigned char *s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dst;
}

static inline bool path_ends_with(const char *path, const char *suffix) {
    if (!path || !suffix) return false;
    int lp = safe_strlen(path);
    int ls = safe_strlen(suffix);
    if (ls <= 0 || lp < ls) return false;
    return safe_strncmp(path + (lp - ls), suffix, (size_t)ls) == 0;
}

static inline bool path_matches_base_apk(const char *path) {
    if (!path) return false;
    return path_ends_with(path, "/base.apk");
}

// ==================== raw_syscall ====================
#ifdef __cplusplus
extern "C" {
#endif
long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
#ifdef __cplusplus
}
#endif
