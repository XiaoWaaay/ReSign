/**
 * ReSignPro - IO Redirect Header
 *
 * IO 重定向模块接口声明
 * 负责管理路径重定向规则和实际的路径替换逻辑
 */

#ifndef RESIGN_PRO_IO_REDIRECT_H
#define RESIGN_PRO_IO_REDIRECT_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// 最大重定向规则数
#define MAX_REDIRECT_RULES 64

// 重定向规则
typedef struct {
    char from_path[MAX_PATH_LEN];  // 原始路径（需要被拦截的）
    char to_path[MAX_PATH_LEN];    // 重定向目标路径
    int from_len;                   // 缓存长度避免重复计算
    int to_len;
    bool prefix_match;              // 是否前缀匹配（目录级）
} RedirectRule;

/**
 * 初始化 IO 重定向引擎
 * 根据 config 设置默认规则（原始APK -> 伪造APK 等）
 */
void io_redirect_init(const RedirectConfig *config);

/**
 * 添加一条重定向规则
 * @return true 成功
 */
bool io_redirect_add_rule(const char *from, const char *to);

/**
 * 添加前缀匹配重定向规则（目录级）
 */
bool io_redirect_add_prefix_rule(const char *from_prefix, const char *to_prefix);

/**
 * 执行路径重定向
 * 如果 path 匹配某条规则，将重定向后的路径写入 new_path
 *
 * @param path      输入路径
 * @param new_path  输出缓冲区
 * @param buf_size  缓冲区大小
 * @return true 如果发生了重定向
 *
 * 注意：此函数在 signal handler 中调用，必须是 async-signal-safe
 */
bool io_redirect_resolve(const char *path, char *new_path, size_t buf_size);

/**
 * 获取当前规则数量
 */
int io_redirect_rule_count(void);

/**
 * 用于 PLT hook 的替换函数声明
 * 这些函数是 libc 函数的 hook 替换
 */

// openat hook (覆盖 open 和 openat)
int hook_openat(int dirfd, const char *pathname, int flags, ...);

// __openat_2 hook (fortified version)
int hook___openat_2(int dirfd, const char *pathname, int flags);

// fstatat hook (覆盖 stat, lstat, fstat 等)
int hook_fstatat(int dirfd, const char *pathname, void *statbuf, int flags);

// faccessat hook (覆盖 access)
int hook_faccessat(int dirfd, const char *pathname, int mode, int flags);

// readlinkat hook (覆盖 readlink)
ssize_t hook_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);

// statx hook (Linux 4.11+, Android API 30+)
int hook_statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *statxbuf);

// execve hook (拦截 exec 检测)
int hook_execve(const char *pathname, char *const argv[], char *const envp[]);

void io_redirect_set_orig_openat(void *func);
void io_redirect_set_orig___openat_2(void *func);
void io_redirect_set_orig_fstatat(void *func);
void io_redirect_set_orig_faccessat(void *func);
void io_redirect_set_orig_readlinkat(void *func);
void io_redirect_set_orig_statx(void *func);
void io_redirect_set_orig_execve(void *func);

#ifdef __cplusplus
}
#endif

#endif // RESIGN_PRO_IO_REDIRECT_H
