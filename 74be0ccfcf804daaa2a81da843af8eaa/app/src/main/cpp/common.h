/**
 * ReSignPro V2 - common.h
 *
 * 公共定义：日志、架构检测、系统调用号、共享数据结构
 */
#ifndef NATIVE_KILLER_COMMON_H
#define NATIVE_KILLER_COMMON_H

#include <android/log.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <stdint.h>

#define LOG_TAG "NativeKiller"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define MAX_PATH_LEN 512
#define MAX_REDIRECTS 32
#define MAX_FILTERS 64

// ==================== 架构检测 ====================
#if defined(__aarch64__)
    #define CURRENT_ARCH "arm64"
    #define SYS_OPENAT      __NR_openat
    #define SYS_FSTATAT     __NR_newfstatat
    #define SYS_FACCESSAT   __NR_faccessat
    #define SYS_READLINKAT  __NR_readlinkat
#elif defined(__arm__)
    #define CURRENT_ARCH "arm"
    #define SYS_OPENAT      __NR_openat
    #define SYS_FSTATAT     __NR_fstatat64
    #define SYS_FACCESSAT   __NR_faccessat
    #define SYS_READLINKAT  __NR_readlinkat
#elif defined(__x86_64__)
    #define CURRENT_ARCH "x86_64"
    #define SYS_OPENAT      __NR_openat
    #define SYS_FSTATAT     __NR_newfstatat
    #define SYS_FACCESSAT   __NR_faccessat
    #define SYS_READLINKAT  __NR_readlinkat
#elif defined(__i386__)
    #define CURRENT_ARCH "x86"
    #define SYS_OPENAT      __NR_openat
    #define SYS_FSTATAT     __NR_fstatat64
    #define SYS_FACCESSAT   __NR_faccessat
    #define SYS_READLINKAT  __NR_readlinkat
#endif

// ==================== 重定向配置 ====================
typedef struct {
    char src_path[MAX_PATH_LEN];   // 被拦截的路径
    char dst_path[MAX_PATH_LEN];   // 重定向到的路径
} RedirectEntry;

typedef struct {
    char package_name[256];
    char current_apk_path[MAX_PATH_LEN];
    char original_apk_path[MAX_PATH_LEN];
    char data_dir[MAX_PATH_LEN];

    RedirectEntry redirects[MAX_REDIRECTS];
    int redirect_count;

    char maps_filters[MAX_FILTERS][256];
    int filter_count;

    bool active;
} KillerConfig;

// ==================== 全局配置（所有模块共享） ====================
extern KillerConfig g_config;

// ==================== 函数声明 ====================

// io_redirect.cpp
int io_redirect_install(void);
bool io_redirect_resolve(const char *path, char *out, size_t out_len);

// maps_hide.cpp
int maps_hide_install(void);
void maps_hide_add_filter(const char *keyword);
bool maps_hide_is_maps_path(const char *path);
int maps_hide_get_filtered_fd(void);

// seccomp_handler.cpp
int seccomp_install(void);

// raw_syscall (in seccomp_handler.cpp)
long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6);

#endif // NATIVE_KILLER_COMMON_H
