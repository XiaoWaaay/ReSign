/**
 * ReSignPro - PLT Hook Header
 *
 * ELF GOT/PLT Hook 引擎
 * 通过修改 GOT 表项实现 libc 函数的 hook
 */

#ifndef RESIGN_PRO_PLT_HOOK_H
#define RESIGN_PRO_PLT_HOOK_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Hook 条目
typedef struct {
    const char *symbol_name;    // 函数符号名
    void *new_func;             // 替换函数指针
    void **orig_func_ptr;       // 原函数指针存储位置
} PltHookEntry;

/**
 * 安装 PLT hook
 * 遍历已加载的 so，hook libc 中的 IO 相关函数
 *
 * @param config 重定向配置
 * @return 0 成功, -1 失败
 */
int plt_hook_install(const RedirectConfig *config);

/**
 * 对新加载的 so 库应用 hook
 * 应在 dlopen 回调或 linker namespace 监听中调用
 */
int plt_hook_apply_to_library(const char *lib_path);

/**
 * 检查 PLT hook 是否已激活
 */
bool plt_hook_is_active(void);

/**
 * 对单个 ELF 文件的指定符号执行 GOT hook
 *
 * @param elf_base   ELF 基地址
 * @param symbol     符号名
 * @param new_func   替换函数
 * @param old_func   原函数指针输出
 * @return 0 成功
 */
int plt_hook_single(void *elf_base, const char *symbol, void *new_func, void **old_func);

/**
 * 遍历 /proc/self/maps 获取所有已加载的 ELF
 */
int plt_hook_enum_modules(void (*callback)(const char *path, void *base, void *userdata),
                          void *userdata);

#ifdef __cplusplus
}
#endif

#endif // RESIGN_PRO_PLT_HOOK_H
