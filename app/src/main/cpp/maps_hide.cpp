/**
 * ReSignPro - Maps Hide Implementation
 *
 * /proc/self/maps 内容过滤实现
 *
 * 原理：
 * 1. 通过 memfd_create 创建内存匿名文件
 * 2. 读取真实的 /proc/self/maps
 * 3. 逐行解析，过滤包含指定关键词的行
 * 4. 对路径执行字符串替换（如替换包名）
 * 5. 将清洗后的内容写入 memfd
 * 6. 返回 memfd 的 fd 供 openat hook 使用
 */

#include "maps_hide.h"
#include "io_redirect.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

// ==================== 过滤规则存储 ====================

static char g_filter_keywords[MAX_MAPS_FILTERS][256];
static volatile int g_filter_count = 0;

typedef struct {
    char old_str[256];
    char new_str[256];
    int old_len;
    int new_len;
} MapsReplaceRule;

static MapsReplaceRule g_replace_rules[MAX_MAPS_REPLACES];
static volatile int g_replace_count = 0;

static int g_filtered_fd = -1;
static pthread_mutex_t g_maps_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_self_pid_maps[64] = {0};  // "/proc/<pid>/maps"
static bool g_maps_installed = false;

// ==================== memfd_create 兼容 ====================

/**
 * memfd_create 系统调用包装
 * Android API >= 26 (kernel >= 3.17) 支持
 */
static int my_memfd_create(const char *name, unsigned int flags) {
#ifdef __NR_memfd_create
    return (int) syscall(__NR_memfd_create, name, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

// ==================== 路径判断 ====================

bool maps_hide_is_maps_path(const char *path) {
    if (!path) return false;

    // /proc/self/maps
    if (strcmp(path, "/proc/self/maps") == 0) return true;

    // /proc/<pid>/maps
    if (g_self_pid_maps[0] && strcmp(path, g_self_pid_maps) == 0) return true;

    // /proc/self/map_files/ (遍历映射文件)
    if (strncmp(path, "/proc/self/map_files", 20) == 0) return true;

    // /proc/<tid>/maps
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *rest = path + 6;
        // 跳过数字（PID/TID）
        while (*rest >= '0' && *rest <= '9') rest++;
        if (strcmp(rest, "/maps") == 0) return true;
        if (strncmp(rest, "/map_files", 10) == 0) return true;
    }

    return false;
}

// ==================== 行过滤逻辑 ====================

/**
 * 检查一行是否应该被过滤
 * @return true 表示需要删除该行
 */
static bool should_filter_line(const char *line) {
    int count = g_filter_count;
    for (int i = 0; i < count; i++) {
        if (strstr(line, g_filter_keywords[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

/**
 * 对一行执行字符串替换
 * 注意：result 缓冲区必须足够大
 */
static void apply_replacements(const char *line, char *result, size_t result_size) {
    safe_strncpy(result, line, result_size);

    int replace_count = g_replace_count;
    for (int i = 0; i < replace_count; i++) {
        const MapsReplaceRule *rule = &g_replace_rules[i];
        char *pos = strstr(result, rule->old_str);
        if (pos) {
            // 简单替换（只替换第一个匹配）
            size_t prefix_len = pos - result;
            size_t suffix_start = prefix_len + rule->old_len;
            size_t suffix_len = strlen(result + suffix_start);

            // 检查缓冲区是否足够
            if (prefix_len + rule->new_len + suffix_len + 1 > result_size) continue;

            // 使用临时缓冲区避免覆盖问题
            char tmp[2048];
            safe_memcpy(tmp, result, prefix_len);
            safe_memcpy(tmp + prefix_len, rule->new_str, rule->new_len);
            safe_memcpy(tmp + prefix_len + rule->new_len, result + suffix_start, suffix_len);
            tmp[prefix_len + rule->new_len + suffix_len] = '\0';
            safe_strncpy(result, tmp, result_size);
        }
    }
}

// ==================== 核心过滤逻辑 ====================

/**
 * 生成过滤后的 maps 内容并写入 memfd
 */
static int generate_filtered_maps(void) {
    // 直接使用 syscall 读取真实 /proc/self/maps 避免被 hook
    int real_fd = (int) syscall(SYS_OPENAT, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (real_fd < 0) {
        LOGE("Failed to open real /proc/self/maps: %s", strerror(errno));
        return -1;
    }

    // 读取全部内容
    char *content = (char *) malloc(1024 * 1024); // 1MB should be enough
    if (!content) {
        close(real_fd);
        return -1;
    }

    ssize_t total = 0;
    ssize_t n;
    while ((n = read(real_fd, content + total, 1024 * 1024 - total - 1)) > 0) {
        total += n;
    }
    close(real_fd);
    content[total] = '\0';

    // 创建 memfd
    int memfd = my_memfd_create("maps", 0);
    if (memfd < 0) {
        // Fallback: 使用临时文件
        char tmppath[256];
        snprintf(tmppath, sizeof(tmppath), "/data/local/tmp/.maps_%d", getpid());
        memfd = open(tmppath, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (memfd < 0) {
            LOGE("Failed to create memfd or tmpfile: %s", strerror(errno));
            free(content);
            return -1;
        }
        unlink(tmppath); // 立即 unlink，fd 仍然有效
    }

    // 逐行处理
    char *line_start = content;
    char filtered_line[2048];

    while (*line_start) {
        // 找行尾
        char *line_end = strchr(line_start, '\n');
        if (line_end) {
            *line_end = '\0';
        }

        // 检查是否需要过滤
        if (!should_filter_line(line_start)) {
            // 执行替换
            apply_replacements(line_start, filtered_line, sizeof(filtered_line));

            // 写入 memfd
            write(memfd, filtered_line, strlen(filtered_line));
            write(memfd, "\n", 1);
        }

        if (line_end) {
            line_start = line_end + 1;
        } else {
            break;
        }
    }

    free(content);

    // 将 fd 位置重置到开头
    lseek(memfd, 0, SEEK_SET);

    return memfd;
}

// ==================== 公开 API ====================

int maps_hide_install(const RedirectConfig *config) {
    // 缓存自己的 PID maps 路径
    snprintf(g_self_pid_maps, sizeof(g_self_pid_maps), "/proc/%d/maps", getpid());

    // 添加默认过滤关键词
    if (config->package_name[0]) {
        // 不过滤包名（应用自己的映射需要保留），但过滤注入相关的
    }

    // 添加基本的注入痕迹过滤
    maps_hide_add_filter("resign_pro");
    maps_hide_add_filter("origin.apk");
    maps_hide_add_filter("payload.dex");

    g_maps_installed = true;
    LOGI("Maps hide installed, filters: %d, replaces: %d",
         g_filter_count, g_replace_count);

    return 0;
}

void maps_hide_add_filter(const char *keyword) {
    if (g_filter_count >= MAX_MAPS_FILTERS) {
        LOGW("Maps filter table full");
        return;
    }

    int idx = g_filter_count;
    safe_strncpy(g_filter_keywords[idx], keyword, sizeof(g_filter_keywords[idx]));
    __sync_synchronize();
    g_filter_count = idx + 1;

    // 有新规则时刷新缓存
    maps_hide_refresh();
}

void maps_hide_set_replace(const char *old_str, const char *new_str) {
    if (g_replace_count >= MAX_MAPS_REPLACES) return;

    int idx = g_replace_count;
    safe_strncpy(g_replace_rules[idx].old_str, old_str, sizeof(g_replace_rules[idx].old_str));
    safe_strncpy(g_replace_rules[idx].new_str, new_str, sizeof(g_replace_rules[idx].new_str));
    g_replace_rules[idx].old_len = strlen(old_str);
    g_replace_rules[idx].new_len = strlen(new_str);

    __sync_synchronize();
    g_replace_count = idx + 1;

    maps_hide_refresh();
}

int maps_hide_filter_count(void) {
    return g_filter_count;
}

int maps_hide_get_filtered_fd(void) {
    pthread_mutex_lock(&g_maps_mutex);

    // 每次请求都重新生成（maps 内容是动态的）
    if (g_filtered_fd >= 0) {
        close(g_filtered_fd);
        g_filtered_fd = -1;
    }

    g_filtered_fd = generate_filtered_maps();

    pthread_mutex_unlock(&g_maps_mutex);
    return g_filtered_fd;
}

void maps_hide_refresh(void) {
    pthread_mutex_lock(&g_maps_mutex);
    if (g_filtered_fd >= 0) {
        close(g_filtered_fd);
        g_filtered_fd = -1;
    }
    pthread_mutex_unlock(&g_maps_mutex);
}
