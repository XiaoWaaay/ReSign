/**
 * ReSignPro V2 - maps_hide.cpp
 *
 * /proc/self/maps 过滤模块
 *
 * 核心思路：
 * 当 app 读取 /proc/self/maps 时，我们创建一个 memfd（内存文件描述符），
 * 将真实的 maps 内容过滤后写入 memfd，然后返回这个 fd。
 * 这样 app 就看不到我们注入的 .so 库和 Dobby 相关的内存映射。
 *
 * 使用 memfd_create 代替 tmpfile：
 * - memfd 不在文件系统中留下痕迹
 * - 无需写权限到任何目录
 * - API 26+ 可用（覆盖几乎所有目标设备）
 *
 * 过滤策略：
 * 1. 过滤包含 hook 框架路径的行（如 libdobby.so, libnative_killer.so）
 * 2. 过滤包含 memfd 自身映射的行
 * 3. 过滤自定义关键词（由 Java 层传入）
 * 4. 保留所有合法的系统库和 app 原始映射
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "common.h"

// ==================== 内置过滤关键词 ====================

static const char *BUILTIN_FILTERS[] = {
    "libdobby",           // Dobby hook 框架
    "native_killer",      // 我们的 native 库
    "libnative_killer",   // 完整库名
    "killsig",            // killsig 相关
    "memfd:",             // memfd 映射（我们创建的）
    "frida",              // 常见 hook 框架
    "xposed",             // Xposed 框架
    "substrate",          // Substrate 框架
    "lsposed",            // LSPosed
    "edxposed",           // EdXposed
    "riru",               // Riru
    "zygisk",             // Zygisk
    "magisk",             // Magisk
};
static const int BUILTIN_FILTER_COUNT = sizeof(BUILTIN_FILTERS) / sizeof(BUILTIN_FILTERS[0]);

// ==================== memfd_create 兼容 ====================

/**
 * memfd_create 系统调用包装
 *
 * Android API 26+ 的 bionic 不一定导出 memfd_create，
 * 但内核支持。直接用 syscall 调用。
 */
static int my_memfd_create(const char *name, unsigned int flags) {
#if defined(__NR_memfd_create)
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

// ==================== 核心过滤逻辑 ====================

/**
 * 检查一行 maps 内容是否应该被过滤
 *
 * @param line 一行 maps 内容
 * @return true 如果这行应该被隐藏
 */
static bool should_filter_line(const char *line) {
    if (!line) return false;

    // 检查内置过滤规则
    for (int i = 0; i < BUILTIN_FILTER_COUNT; i++) {
        if (strcasestr(line, BUILTIN_FILTERS[i]) != nullptr) {
            return true;
        }
    }

    // 检查用户自定义过滤规则
    for (int i = 0; i < g_config.filter_count; i++) {
        if (g_config.maps_filters[i][0] != '\0' &&
            strcasestr(line, g_config.maps_filters[i]) != nullptr) {
            return true;
        }
    }

    return false;
}

/**
 * 获取过滤后的 /proc/self/maps 文件描述符
 *
 * 工作流程：
 * 1. 打开真实的 /proc/self/maps
 * 2. 创建 memfd
 * 3. 逐行读取真实 maps，过滤后写入 memfd
 * 4. seek 到 memfd 开头
 * 5. 关闭真实 maps fd
 * 6. 返回 memfd fd
 *
 * 注意：返回的 fd 由调用者负责关闭（通常是 app 读完后关闭）
 */
int maps_hide_get_filtered_fd() {
    if (!g_config.active) {
        return -1;
    }

    // 直接用 syscall 打开真实的 /proc/self/maps
    // 不能用 orig_open/orig_openat，因为在 hook 上下文中调用可能导致递归
    // 使用 raw syscall 确保不经过任何 hook
    int real_fd = (int)syscall(SYS_OPENAT, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (real_fd < 0) {
        LOGE("maps_hide: cannot open real maps: %s", strerror(errno));
        return -1;
    }

    // 创建 memfd
    int mem_fd = my_memfd_create("maps", MFD_CLOEXEC);
    if (mem_fd < 0) {
        // 降级方案：使用 pipe
        int pipe_fds[2];
        if (pipe(pipe_fds) < 0) {
            close(real_fd);
            LOGE("maps_hide: memfd_create and pipe both failed");
            return -1;
        }

        // 用 pipe 做过滤（注意 pipe 有容量限制，先读全部再写）
        char *buffer = (char *)malloc(1024 * 1024); // 1MB 应该足够
        if (!buffer) {
            close(real_fd);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return -1;
        }

        // 读取全部 maps 内容
        ssize_t total_read = 0;
        ssize_t n;
        while ((n = read(real_fd, buffer + total_read, 1024 * 1024 - total_read)) > 0) {
            total_read += n;
        }
        close(real_fd);
        buffer[total_read] = '\0';

        // 逐行过滤并写入 pipe
        char *line = buffer;
        char *next;
        while (line && *line) {
            next = strchr(line, '\n');
            if (next) {
                *next = '\0';
            }

            if (!should_filter_line(line)) {
                // 写入 pipe_fds[1]
                write(pipe_fds[1], line, strlen(line));
                write(pipe_fds[1], "\n", 1);
            }

            if (next) {
                line = next + 1;
            } else {
                break;
            }
        }

        free(buffer);
        close(pipe_fds[1]); // 关闭写端
        return pipe_fds[0]; // 返回读端
    }

    // memfd 成功创建，用 fdopen 做逐行处理
    FILE *real_fp = fdopen(real_fd, "r");
    if (!real_fp) {
        close(real_fd);
        close(mem_fd);
        return -1;
    }

    char line_buf[4096];
    int filtered_count = 0;
    int total_lines = 0;

    while (fgets(line_buf, sizeof(line_buf), real_fp)) {
        total_lines++;

        // 去掉末尾换行做检查
        size_t len = strlen(line_buf);
        char check_buf[4096];
        memcpy(check_buf, line_buf, len + 1);
        if (len > 0 && check_buf[len - 1] == '\n') {
            check_buf[len - 1] = '\0';
        }

        if (should_filter_line(check_buf)) {
            filtered_count++;
            continue; // 跳过这行
        }

        // 写入原始行（保留换行符）
        write(mem_fd, line_buf, len);
    }

    fclose(real_fp); // 这也会关闭 real_fd

    // seek 到 memfd 开头
    lseek(mem_fd, 0, SEEK_SET);

    LOGD("maps_hide: filtered %d/%d lines", filtered_count, total_lines);
    return mem_fd;
}

// ==================== 接口函数 ====================

/**
 * 添加自定义过滤关键词
 */
void maps_hide_add_filter(const char *keyword) {
    if (!keyword || g_config.filter_count >= MAX_FILTERS) return;

    strncpy(g_config.maps_filters[g_config.filter_count],
            keyword, 255);
    g_config.maps_filters[g_config.filter_count][255] = '\0';
    g_config.filter_count++;

    LOGI("maps_hide: added filter keyword: %s (total: %d)",
         keyword, g_config.filter_count);
}

/**
 * 检查路径是否是 maps 相关路径
 */
bool maps_hide_is_maps_path(const char *path) {
    if (!path) return false;
    return strcmp(path, "/proc/self/maps") == 0 ||
           strcmp(path, "/proc/thread-self/maps") == 0 ||
           strncmp(path, "/proc/self/map_files/", 20) == 0;
}

/**
 * 安装 maps 隐藏
 *
 * 这个函数主要是初始化过滤规则
 * 实际的 hook 已经在 native_killer.cpp 中安装
 * （openat/fopen 的 hook 会检查 is_maps_path 并调用 maps_hide_get_filtered_fd）
 */
int maps_hide_install() {
    // 添加包名相关的过滤（隐藏 resign 相关的映射）
    if (g_config.package_name[0] != '\0') {
        char filter[256];
        snprintf(filter, sizeof(filter), "killsig");
        maps_hide_add_filter(filter);
    }

    // 添加 Dobby 相关过滤
    maps_hide_add_filter("dobby");
    maps_hide_add_filter("DobbyBridge");

    LOGI("maps_hide: installed with %d filter rules", g_config.filter_count);
    return 0;
}
