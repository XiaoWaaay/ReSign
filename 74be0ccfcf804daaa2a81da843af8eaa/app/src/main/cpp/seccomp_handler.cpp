/**
 * ReSignPro V2 - seccomp_handler.cpp
 *
 * Seccomp + BPF 系统调用拦截模块
 *
 * 为什么需要这个模块：
 * 即使用 Dobby 做了 inline hook，一些加固方案（如某些金融 app）会：
 * 1. 在代码中内联 SVC 指令，直接发起系统调用
 * 2. 自己实现 raw syscall 函数，不走 libc
 * 3. 通过 JIT 生成的代码发起系统调用
 *
 * 这些情况下，hook libc 函数是无效的，因为根本不经过 libc。
 *
 * 解决方案：Seccomp BPF
 * - Seccomp 是 Linux 内核级别的系统调用过滤机制
 * - 我们用 BPF（Berkeley Packet Filter）规则来指定：
 *   当 openat/newfstatat/readlinkat 等系统调用发生时，
 *   发送 SIGSYS 信号给进程
 * - 我们注册 SIGSYS 信号处理函数，在其中做路径重定向
 * - 通过修改 ucontext 中的寄存器来改变系统调用参数或返回值
 *
 * 架构差异处理：
 * - ARM64: x8=syscall_nr, x0-x5=args, 从 SIGSYS 的 si_syscall 获取 nr
 * - ARM:   r7=syscall_nr, r0-r5=args
 * - x86_64: rax=syscall_nr, rdi/rsi/rdx/r10/r8/r9=args
 * - x86:   eax=syscall_nr, ebx/ecx/edx/esi/edi/ebp=args
 *
 * 信号处理流程：
 * 1. 内核触发 SIGSYS，传递 siginfo_t 和 ucontext_t
 * 2. 从 ucontext_t 获取寄存器状态（包括系统调用号和参数）
 * 3. 检查第二个参数（pathname）是否需要重定向
 * 4. 如果需要，修改寄存器中的路径指针为新路径
 * 5. 用 raw_syscall 重新执行被拦截的系统调用
 * 6. 将结果写入 ucontext_t 的返回值寄存器
 * 7. 跳过被拦截的原始系统调用（通过设置 syscall_nr 为无效值）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>

// Seccomp 相关头文件
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

// 架构相关
#include <sys/ucontext.h>
#include <sys/syscall.h>

#include "common.h"

// ==================== 架构相关的 BPF 定义 ====================

// BPF 程序中需要匹配的 audit architecture
#if defined(__aarch64__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
    // seccomp_data.args offsets:
    // arg0 @ offsetof(seccomp_data, args[0]) = 16
    // arg1 @ offsetof(seccomp_data, args[1]) = 24
#elif defined(__arm__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_ARM
#elif defined(__x86_64__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__i386__)
    #define AUDIT_ARCH_CURRENT AUDIT_ARCH_I386
#else
    #error "Unsupported architecture"
#endif

// ==================== Raw Syscall 实现 ====================

/**
 * 通过内联汇编直接发起系统调用
 *
 * 在 SIGSYS 处理函数中，我们需要重新执行被拦截的系统调用。
 * 不能用 libc 的 syscall()，因为那会再次触发 seccomp 过滤。
 * 必须用 raw_syscall，并且要处理好寄存器。
 *
 * 注意：这个函数本身发起的 SVC 也会被 seccomp 拦截。
 * 但由于我们在 SIGSYS handler 中设置了标志位，
 * 再次进入 handler 时会检查标志位避免递归。
 */

// 递归保护标志（线程局部变量）
static __thread volatile int in_handler = 0;

#if defined(__aarch64__)
/**
 * ARM64 raw syscall
 *
 * ARM64 系统调用约定：
 *   x8  = syscall number
 *   x0-x5 = arguments
 *   x0  = return value
 *
 * 使用 SVC #0 触发系统调用
 */
__attribute__((naked))
long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    __asm__ volatile(
        "mov x8, x0\n"    // syscall number
        "mov x0, x1\n"    // arg1
        "mov x1, x2\n"    // arg2
        "mov x2, x3\n"    // arg3
        "mov x3, x4\n"    // arg4
        "mov x4, x5\n"    // arg5
        "mov x5, x6\n"    // arg6
        "svc #0\n"
        "ret\n"
    );
}

#elif defined(__arm__)
/**
 * ARM32 raw syscall
 *
 * ARM32 系统调用约定：
 *   r7  = syscall number
 *   r0-r5 = arguments (r4, r5 需要从栈上取)
 *   r0  = return value
 */
__attribute__((naked))
long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    __asm__ volatile(
        "push {r4, r5, r7}\n"
        "mov r7, r0\n"    // syscall number
        "mov r0, r1\n"    // arg1
        "mov r1, r2\n"    // arg2
        "mov r2, r3\n"    // arg3
        "ldr r3, [sp, #12]\n"  // arg4 (from original stack)
        "ldr r4, [sp, #16]\n"  // arg5
        "ldr r5, [sp, #20]\n"  // arg6
        "svc #0\n"
        "pop {r4, r5, r7}\n"
        "bx lr\n"
    );
}

#elif defined(__x86_64__)
/**
 * x86_64 raw syscall
 *
 * x86_64 系统调用约定：
 *   rax = syscall number
 *   rdi, rsi, rdx, r10, r8, r9 = arguments
 *   rax = return value
 *
 * 注意：libc 调用约定用 rcx 传第4个参数，但 syscall 用 r10
 */
__attribute__((naked))
long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    __asm__ volatile(
        "movq %rdi, %rax\n"   // syscall number
        "movq %rsi, %rdi\n"   // arg1
        "movq %rdx, %rsi\n"   // arg2
        "movq %rcx, %rdx\n"   // arg3
        "movq %r8,  %r10\n"   // arg4
        "movq %r9,  %r8\n"    // arg5
        "movq 8(%rsp), %r9\n" // arg6
        "syscall\n"
        "ret\n"
    );
}

#elif defined(__i386__)
/**
 * x86 raw syscall
 *
 * x86 系统调用约定（通过 int $0x80）：
 *   eax = syscall number
 *   ebx, ecx, edx, esi, edi, ebp = arguments
 *   eax = return value
 */
__attribute__((naked))
long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    __asm__ volatile(
        "push %ebp\n"
        "push %edi\n"
        "push %esi\n"
        "push %ebx\n"
        "mov 20(%esp), %eax\n"  // syscall number
        "mov 24(%esp), %ebx\n"  // arg1
        "mov 28(%esp), %ecx\n"  // arg2
        "mov 32(%esp), %edx\n"  // arg3
        "mov 36(%esp), %esi\n"  // arg4
        "mov 40(%esp), %edi\n"  // arg5
        "mov 44(%esp), %ebp\n"  // arg6
        "int $0x80\n"
        "pop %ebx\n"
        "pop %esi\n"
        "pop %edi\n"
        "pop %ebp\n"
        "ret\n"
    );
}

#endif

// ==================== SIGSYS 信号处理 ====================

/**
 * 从 ucontext_t 中提取系统调用参数
 */
static void get_syscall_args(ucontext_t *ctx, long *nr, long *args) {
#if defined(__aarch64__)
    mcontext_t *mctx = &ctx->uc_mcontext;
    *nr = mctx->regs[8];    // x8
    args[0] = mctx->regs[0]; // x0 (dirfd)
    args[1] = mctx->regs[1]; // x1 (pathname)
    args[2] = mctx->regs[2]; // x2 (flags/buf)
    args[3] = mctx->regs[3]; // x3 (mode/bufsiz)
    args[4] = mctx->regs[4]; // x4
    args[5] = mctx->regs[5]; // x5

#elif defined(__arm__)
    mcontext_t *mctx = &ctx->uc_mcontext;
    *nr = mctx->arm_r7;
    args[0] = mctx->arm_r0;
    args[1] = mctx->arm_r1;
    args[2] = mctx->arm_r2;
    args[3] = mctx->arm_r3;
    args[4] = mctx->arm_r4;
    args[5] = mctx->arm_r5;

#elif defined(__x86_64__)
    mcontext_t *mctx = &ctx->uc_mcontext;
    *nr = mctx->gregs[REG_RAX];
    args[0] = mctx->gregs[REG_RDI];
    args[1] = mctx->gregs[REG_RSI];
    args[2] = mctx->gregs[REG_RDX];
    args[3] = mctx->gregs[REG_R10];
    args[4] = mctx->gregs[REG_R8];
    args[5] = mctx->gregs[REG_R9];

#elif defined(__i386__)
    mcontext_t *mctx = &ctx->uc_mcontext;
    *nr = mctx->gregs[REG_EAX];
    args[0] = mctx->gregs[REG_EBX];
    args[1] = mctx->gregs[REG_ECX];
    args[2] = mctx->gregs[REG_EDX];
    args[3] = mctx->gregs[REG_ESI];
    args[4] = mctx->gregs[REG_EDI];
    args[5] = mctx->gregs[REG_EBP];
#endif
}

/**
 * 设置系统调用返回值到 ucontext_t
 */
static void set_syscall_return(ucontext_t *ctx, long retval) {
#if defined(__aarch64__)
    ctx->uc_mcontext.regs[0] = retval;
#elif defined(__arm__)
    ctx->uc_mcontext.arm_r0 = retval;
#elif defined(__x86_64__)
    ctx->uc_mcontext.gregs[REG_RAX] = retval;
#elif defined(__i386__)
    ctx->uc_mcontext.gregs[REG_EAX] = retval;
#endif
}

/**
 * 使原始系统调用不执行（设置 syscall nr 为无效值）
 *
 * 当我们在 SIGSYS handler 中重新执行了系统调用后，
 * 需要阻止内核继续执行原始的被拦截的系统调用。
 * 通过设置 syscall number 为 -1（无效），内核会返回 ENOSYS。
 * 但我们已经在返回值寄存器中写入了正确的结果。
 */
static void skip_original_syscall(ucontext_t *ctx) {
#if defined(__aarch64__)
    ctx->uc_mcontext.regs[8] = -1;
#elif defined(__arm__)
    ctx->uc_mcontext.arm_r7 = -1;
#elif defined(__x86_64__)
    ctx->uc_mcontext.gregs[REG_RAX] = -1;
#elif defined(__i386__)
    ctx->uc_mcontext.gregs[REG_EAX] = -1;
#endif
}

/**
 * SIGSYS 信号处理函数
 *
 * 当 seccomp BPF 拦截到匹配的系统调用时，内核发送 SIGSYS 信号。
 * 我们在这里：
 * 1. 提取被拦截的系统调用号和参数
 * 2. 检查路径参数是否需要重定向
 * 3. 如果需要，用重定向后的路径重新执行系统调用
 * 4. 将结果写回 ucontext，阻止原始调用
 */
static void sigsys_handler(int signo, siginfo_t *info, void *context) {
    // 递归保护：防止 raw_syscall 再次触发 SIGSYS 导致死循环
    if (in_handler) {
        return;
    }
    in_handler = 1;

    if (signo != SIGSYS || !info || !context) {
        in_handler = 0;
        return;
    }

    ucontext_t *ctx = (ucontext_t *)context;
    long syscall_nr;
    long args[6];
    get_syscall_args(ctx, &syscall_nr, args);

    // 根据系统调用类型处理
    // openat: args[0]=dirfd, args[1]=pathname, args[2]=flags, args[3]=mode
    // newfstatat/fstatat64: args[0]=dirfd, args[1]=pathname, args[2]=statbuf, args[3]=flags
    // faccessat: args[0]=dirfd, args[1]=pathname, args[2]=mode, args[3]=flags
    // readlinkat: args[0]=dirfd, args[1]=pathname, args[2]=buf, args[3]=bufsiz

    bool handled = false;

    if (syscall_nr == SYS_OPENAT) {
        const char *pathname = (const char *)args[1];
        if (pathname) {
            // 检查 maps 路径
            if (maps_hide_is_maps_path(pathname)) {
                int fd = maps_hide_get_filtered_fd();
                if (fd >= 0) {
                    set_syscall_return(ctx, fd);
                    skip_original_syscall(ctx);
                    handled = true;
                    LOGD("[seccomp/openat] maps -> filtered fd %d", fd);
                }
            }

            if (!handled) {
                // 检查路径重定向
                char redirect[MAX_PATH_LEN];
                if (io_redirect_resolve(pathname, redirect, sizeof(redirect))) {
                    long ret = raw_syscall6(SYS_OPENAT, args[0],
                                            (long)redirect, args[2], args[3], 0, 0);
                    set_syscall_return(ctx, ret);
                    skip_original_syscall(ctx);
                    handled = true;
                    LOGD("[seccomp/openat] redirect: %s -> %s (ret=%ld)",
                         pathname, redirect, ret);
                }
            }
        }
    }
    else if (syscall_nr == SYS_FSTATAT) {
        const char *pathname = (const char *)args[1];
        if (pathname) {
            char redirect[MAX_PATH_LEN];
            if (io_redirect_resolve(pathname, redirect, sizeof(redirect))) {
                long ret = raw_syscall6(SYS_FSTATAT, args[0],
                                        (long)redirect, args[2], args[3], 0, 0);
                set_syscall_return(ctx, ret);
                skip_original_syscall(ctx);
                handled = true;
                LOGD("[seccomp/fstatat] redirect: %s -> %s", pathname, redirect);
            }
        }
    }
    else if (syscall_nr == SYS_FACCESSAT) {
        const char *pathname = (const char *)args[1];
        if (pathname) {
            char redirect[MAX_PATH_LEN];
            if (io_redirect_resolve(pathname, redirect, sizeof(redirect))) {
                long ret = raw_syscall6(SYS_FACCESSAT, args[0],
                                        (long)redirect, args[2], args[3], 0, 0);
                set_syscall_return(ctx, ret);
                skip_original_syscall(ctx);
                handled = true;
                LOGD("[seccomp/faccessat] redirect: %s -> %s", pathname, redirect);
            }
        }
    }
    else if (syscall_nr == SYS_READLINKAT) {
        // readlinkat 特殊处理：先执行，再修改结果
        const char *pathname = (const char *)args[1];
        char *buf = (char *)args[2];
        size_t bufsiz = (size_t)args[3];

        long ret = raw_syscall6(SYS_READLINKAT, args[0], args[1],
                                args[2], args[3], 0, 0);

        if (ret > 0 && buf && g_config.original_apk_path[0] != '\0') {
            // 检查结果是否包含原始 APK 路径
            if (strncmp(buf, g_config.original_apk_path,
                        strlen(g_config.original_apk_path)) == 0) {
                size_t cur_len = strlen(g_config.current_apk_path);
                if (cur_len < bufsiz) {
                    memcpy(buf, g_config.current_apk_path, cur_len);
                    buf[cur_len] = '\0';
                    ret = (long)cur_len;
                }
            }
        }

        set_syscall_return(ctx, ret);
        skip_original_syscall(ctx);
        handled = true;
    }

    in_handler = 0;
}

// ==================== BPF 程序构建 ====================

/**
 * 构建 Seccomp BPF 过滤程序
 *
 * BPF 程序结构：
 * 1. 检查架构是否匹配（防止 32/64 位混淆）
 * 2. 加载系统调用号
 * 3. 逐个检查我们关心的系统调用
 * 4. 匹配则发送 SIGSYS（SECCOMP_RET_TRAP）
 * 5. 不匹配则允许通过（SECCOMP_RET_ALLOW）
 */

// BPF 辅助宏
#define BPF_STMT_M(code, k) { (unsigned short)(code), 0, 0, (unsigned int)(k) }
#define BPF_JUMP_M(code, k, jt, jf) { (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) }

int seccomp_install() {
    // 拦截的系统调用列表
    long target_syscalls[] = {
        SYS_OPENAT,
        SYS_FSTATAT,
        SYS_FACCESSAT,
        SYS_READLINKAT,
    };
    int num_targets = sizeof(target_syscalls) / sizeof(target_syscalls[0]);

    // 构建 BPF 程序
    // 结构:
    //   [0] 加载 arch
    //   [1] 检查 arch，不匹配跳到 ALLOW
    //   [2] 加载 syscall_nr
    //   [3..N] 每个目标 syscall: JEQ -> TRAP
    //   [N+1] ALLOW

    int prog_len = 3 + num_targets + 1; // header(3) + checks(N) + ALLOW(1)
    struct sock_filter *prog = (struct sock_filter *)calloc(prog_len, sizeof(struct sock_filter));
    if (!prog) {
        LOGE("seccomp: cannot allocate BPF program");
        return -1;
    }

    int idx = 0;

    // [0] 加载 seccomp_data.arch (offset 4)
    prog[idx++] = (struct sock_filter)
        BPF_STMT_M(BPF_LD | BPF_W | BPF_ABS, 4);

    // [1] 检查架构是否匹配
    // 如果不匹配，跳过所有检查到 ALLOW（跳 num_targets + 1 条指令）
    prog[idx++] = (struct sock_filter)
        BPF_JUMP_M(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 0, num_targets + 1);

    // [2] 加载 seccomp_data.nr (offset 0)
    prog[idx++] = (struct sock_filter)
        BPF_STMT_M(BPF_LD | BPF_W | BPF_ABS, 0);

    // [3..N] 检查每个目标系统调用
    for (int i = 0; i < num_targets; i++) {
        // 如果匹配，跳到 TRAP（跳过剩余的检查）
        int jump_to_trap = num_targets - i - 1; // 到 TRAP 的距离
        prog[idx++] = (struct sock_filter)
            BPF_JUMP_M(BPF_JMP | BPF_JEQ | BPF_K, target_syscalls[i], jump_to_trap, 0);
    }

    // [N+1] ALLOW (不匹配任何目标)
    prog[idx++] = (struct sock_filter)
        BPF_STMT_M(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // [N+2] TRAP (匹配目标, 发送 SIGSYS)
    // 等等，上面的跳转逻辑需要修正
    // 重新计算...

    // 实际上需要多一条 TRAP 指令
    free(prog);

    // 重新构建，更清晰的结构
    prog_len = 3 + num_targets + 2; // header(3) + checks(N) + ALLOW(1) + TRAP(1)
    prog = (struct sock_filter *)calloc(prog_len, sizeof(struct sock_filter));
    if (!prog) return -1;

    idx = 0;

    // 加载 arch
    prog[idx++] = (struct sock_filter)BPF_STMT_M(BPF_LD | BPF_W | BPF_ABS, 4);

    // 检查 arch
    prog[idx++] = (struct sock_filter)BPF_JUMP_M(BPF_JMP | BPF_JEQ | BPF_K,
                                                   AUDIT_ARCH_CURRENT,
                                                   0,
                                                   num_targets + 2); // 不匹配跳到 ALLOW

    // 加载 syscall_nr
    prog[idx++] = (struct sock_filter)BPF_STMT_M(BPF_LD | BPF_W | BPF_ABS, 0);

    // 检查每个 syscall
    for (int i = 0; i < num_targets; i++) {
        // 匹配：跳到最后的 TRAP（距离 = num_targets - i）
        // 不匹配：继续下一个检查（距离 = 0）
        prog[idx++] = (struct sock_filter)BPF_JUMP_M(BPF_JMP | BPF_JEQ | BPF_K,
                                                       target_syscalls[i],
                                                       num_targets - i,  // jt: to TRAP
                                                       0);               // jf: next
    }

    // ALLOW
    prog[idx++] = (struct sock_filter)BPF_STMT_M(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // TRAP
    prog[idx++] = (struct sock_filter)BPF_STMT_M(BPF_RET | BPF_K, SECCOMP_RET_TRAP);

    // 注册 SIGSYS 信号处理函数
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; // SA_NODEFER 允许嵌套（我们用 in_handler 控制）
    sigfillset(&sa.sa_mask);
    sigdelset(&sa.sa_mask, SIGSYS);  // 不阻塞 SIGSYS 自身

    if (sigaction(SIGSYS, &sa, nullptr) < 0) {
        LOGE("seccomp: sigaction failed: %s", strerror(errno));
        free(prog);
        return -2;
    }

    // 设置 NO_NEW_PRIVS（seccomp 要求）
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        LOGE("seccomp: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        free(prog);
        return -3;
    }

    // 安装 seccomp BPF 过滤器
    struct sock_fprog fprog;
    fprog.len = idx;
    fprog.filter = prog;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) < 0) {
        LOGE("seccomp: PR_SET_SECCOMP failed: %s (errno=%d)", strerror(errno), errno);
        free(prog);

        // Seccomp 可能被 SELinux/内核配置禁用
        // 在这种情况下不是致命错误，Dobby inline hook 仍然有效
        if (errno == EINVAL || errno == EACCES || errno == EFAULT) {
            LOGW("seccomp: not available on this device, relying on Dobby hooks only");
            return -4;
        }
        return -5;
    }

    free(prog);
    LOGI("seccomp: BPF filter installed for %d syscalls", num_targets);
    return 0;
}
