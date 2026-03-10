/**
 * ReSignPro - Seccomp Filter Header
 *
 * seccomp + BPF + SIGSYS 系统调用拦截
 * 作为 PLT hook 的补充/后备方案
 * 可拦截应用直接通过 syscall 指令发起的系统调用
 */

#ifndef RESIGN_PRO_SECCOMP_FILTER_H
#define RESIGN_PRO_SECCOMP_FILTER_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 安装 seccomp BPF 过滤器
 *
 * 工作原理：
 * 1. 构造 BPF 程序，匹配 openat/fstatat/faccessat/readlinkat/statx 等系统调用
 * 2. 匹配的调用返回 SECCOMP_RET_TRAP，触发 SIGSYS 信号
 * 3. SIGSYS handler 检查参数中的路径，决定是否需要重定向
 * 4. 如需重定向，修改 sigcontext 中的路径参数寄存器
 * 5. 如不需要，使用 raw_syscall 直接执行原始系统调用
 *
 * @param config 重定向配置
 * @return 0 成功, -1 失败
 */
int seccomp_install(const RedirectConfig *config);

/**
 * 检查 seccomp 是否已激活
 */
bool seccomp_is_active(void);

/**
 * 通过内联汇编直接发起系统调用
 * 绕过 seccomp 过滤（在 handler 内部使用）
 *
 * 支持 4 种架构: aarch64, arm, x86_64, i386
 */
long raw_syscall6(long number, long arg1, long arg2, long arg3,
                  long arg4, long arg5, long arg6);

#ifdef __cplusplus
}
#endif

#endif // RESIGN_PRO_SECCOMP_FILTER_H
