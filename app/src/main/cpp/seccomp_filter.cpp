/**
 * ReSignPro - Seccomp Filter Implementation
 *
 * seccomp + BPF + SIGSYS 系统调用拦截
 *
 * 工作原理：
 * 1. 构造 BPF 程序匹配目标系统调用号
 * 2. 匹配的调用返回 SECCOMP_RET_TRAP -> SIGSYS
 * 3. SIGSYS handler 从 siginfo 获取 syscall 参数
 * 4. 检查路径参数是否需要重定向
 * 5. 如需重定向，修改 ucontext 中的参数寄存器，然后 raw_syscall
 * 6. 将返回值写回 ucontext 并跳过原始 syscall
 *
 * 支持架构: aarch64, arm (EABI), x86_64, i386
 */

#include "seccomp_filter.h"
#include "io_redirect.h"
#include "maps_hide.h"

#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <ucontext.h>
#include <fcntl.h>
#include <sys/syscall.h>

// ==================== 架构适配 ====================

#if defined(__aarch64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
    #define REG_SYSCALL_NR(ctx) ((ctx)->uc_mcontext.regs[8])
    #define REG_ARG0(ctx)       ((ctx)->uc_mcontext.regs[0])
    #define REG_ARG1(ctx)       ((ctx)->uc_mcontext.regs[1])
    #define REG_ARG2(ctx)       ((ctx)->uc_mcontext.regs[2])
    #define REG_ARG3(ctx)       ((ctx)->uc_mcontext.regs[3])
    #define REG_ARG4(ctx)       ((ctx)->uc_mcontext.regs[4])
    #define REG_ARG5(ctx)       ((ctx)->uc_mcontext.regs[5])
    #define REG_RET(ctx)        ((ctx)->uc_mcontext.regs[0])
    #define REG_PC(ctx)         ((ctx)->uc_mcontext.pc)
#elif defined(__arm__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
    #define REG_SYSCALL_NR(ctx) ((ctx)->uc_mcontext.arm_r7)
    #define REG_ARG0(ctx)       ((ctx)->uc_mcontext.arm_r0)
    #define REG_ARG1(ctx)       ((ctx)->uc_mcontext.arm_r1)
    #define REG_ARG2(ctx)       ((ctx)->uc_mcontext.arm_r2)
    #define REG_ARG3(ctx)       ((ctx)->uc_mcontext.arm_r3)
    #define REG_ARG4(ctx)       ((ctx)->uc_mcontext.arm_r4)
    #define REG_ARG5(ctx)       ((ctx)->uc_mcontext.arm_r5)
    #define REG_RET(ctx)        ((ctx)->uc_mcontext.arm_r0)
    #define REG_PC(ctx)         ((ctx)->uc_mcontext.arm_pc)
#elif defined(__x86_64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
    #define REG_SYSCALL_NR(ctx) ((ctx)->uc_mcontext.gregs[REG_RAX])
    #define REG_ARG0(ctx)       ((ctx)->uc_mcontext.gregs[REG_RDI])
    #define REG_ARG1(ctx)       ((ctx)->uc_mcontext.gregs[REG_RSI])
    #define REG_ARG2(ctx)       ((ctx)->uc_mcontext.gregs[REG_RDX])
    #define REG_ARG3(ctx)       ((ctx)->uc_mcontext.gregs[REG_R10])
    #define REG_ARG4(ctx)       ((ctx)->uc_mcontext.gregs[REG_R8])
    #define REG_ARG5(ctx)       ((ctx)->uc_mcontext.gregs[REG_R9])
    #define REG_RET(ctx)        ((ctx)->uc_mcontext.gregs[REG_RAX])
    #define REG_PC(ctx)         ((ctx)->uc_mcontext.gregs[REG_RIP])
#elif defined(__i386__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
    #define REG_SYSCALL_NR(ctx) ((ctx)->uc_mcontext.gregs[REG_EAX])
    #define REG_ARG0(ctx)       ((ctx)->uc_mcontext.gregs[REG_EBX])
    #define REG_ARG1(ctx)       ((ctx)->uc_mcontext.gregs[REG_ECX])
    #define REG_ARG2(ctx)       ((ctx)->uc_mcontext.gregs[REG_EDX])
    #define REG_ARG3(ctx)       ((ctx)->uc_mcontext.gregs[REG_ESI])
    #define REG_ARG4(ctx)       ((ctx)->uc_mcontext.gregs[REG_EDI])
    #define REG_ARG5(ctx)       ((ctx)->uc_mcontext.gregs[REG_EBP])
    #define REG_RET(ctx)        ((ctx)->uc_mcontext.gregs[REG_EAX])
    #define REG_PC(ctx)         ((ctx)->uc_mcontext.gregs[REG_EIP])
#else
    #error "Unsupported architecture for seccomp filter"
#endif

// ==================== 全局状态 ====================

static bool g_seccomp_active = false;

// TLS 缓冲区用于路径重定向（每个线程独立，避免竞争）
static __thread char tls_seccomp_buf[MAX_PATH_LEN];

// ==================== raw_syscall 实现 ====================

/**
 * 直接通过汇编发起系统调用
 * 在 SIGSYS handler 中使用，绕过 seccomp 过滤
 *
 * 注意：seccomp 对 handler 中的 syscall 不会再次触发 SIGSYS
 * （因为 SIGSYS 不可嵌套）但为了安全起见使用 raw syscall
 */

#if defined(__aarch64__)
__attribute__((naked))
long raw_syscall6(long number, long arg1, long arg2, long arg3,
                  long arg4, long arg5, long arg6) {
    __asm__ volatile(
        "mov x8, x0\n"     // syscall number
        "mov x0, x1\n"     // arg1
        "mov x1, x2\n"     // arg2
        "mov x2, x3\n"     // arg3
        "mov x3, x4\n"     // arg4
        "mov x4, x5\n"     // arg5
        "mov x5, x6\n"     // arg6
        "svc #0\n"         // syscall
        "ret\n"
    );
}

#elif defined(__arm__)
__attribute__((naked))
long raw_syscall6(long number, long arg1, long arg2, long arg3,
                  long arg4, long arg5, long arg6) {
    __asm__ volatile(
        "push {r4, r5, r7}\n"
        "mov r7, r0\n"     // syscall number
        "mov r0, r1\n"     // arg1
        "mov r1, r2\n"     // arg2
        "mov r2, r3\n"     // arg3
        "ldr r3, [sp, #12]\n"  // arg4 (from stack)
        "ldr r4, [sp, #16]\n"  // arg5
        "ldr r5, [sp, #20]\n"  // arg6
        "svc #0\n"         // syscall
        "pop {r4, r5, r7}\n"
        "bx lr\n"
    );
}

#elif defined(__x86_64__)
__attribute__((naked))
long raw_syscall6(long number, long arg1, long arg2, long arg3,
                  long arg4, long arg5, long arg6) {
    __asm__ volatile(
        "movq %rdi, %rax\n"   // syscall number
        "movq %rsi, %rdi\n"   // arg1
        "movq %rdx, %rsi\n"   // arg2
        "movq %rcx, %rdx\n"   // arg3
        "movq %r8, %r10\n"    // arg4
        "movq %r9, %r8\n"     // arg5
        "movq 8(%rsp), %r9\n" // arg6 (from stack)
        "syscall\n"
        "ret\n"
    );
}

#elif defined(__i386__)
long raw_syscall6(long number, long arg1, long arg2, long arg3,
                  long arg4, long arg5, long arg6) {
    long ret;
    __asm__ volatile(
        "push %%ebp\n"
        "mov %7, %%ebp\n"
        "int $0x80\n"
        "pop %%ebp\n"
        : "=a"(ret)
        : "a"(number), "b"(arg1), "c"(arg2), "d"(arg3),
          "S"(arg4), "D"(arg5), "m"(arg6)
        : "memory"
    );
    return ret;
}

#endif

// ==================== SIGSYS Handler ====================

/**
 * SIGSYS 信号处理函数
 *
 * 此函数在 seccomp 触发 SECCOMP_RET_TRAP 时被调用
 * 必须是 async-signal-safe
 */
static void sigsys_handler(int signo, siginfo_t *info, void *context) {
    (void) signo;

    if (info->si_code != SYS_SECCOMP) {
        return;
    }

    ucontext_t *uc = (ucontext_t *) context;
    long syscall_nr = (long) REG_SYSCALL_NR(uc);

    // 获取路径参数（大多数 *at 系统调用的第二个参数是路径）
    const char *pathname = nullptr;
    int path_arg_index = 1; // 默认 arg1 是路径

    switch (syscall_nr) {
        case SYS_OPENAT:
        case SYS_FSTATAT:
        case SYS_FACCESSAT:
        case SYS_READLINKAT:
#ifdef SYS_STATX
        case SYS_STATX:
#endif
#ifdef SYS_OPENAT2
        case SYS_OPENAT2:
#endif
            pathname = (const char *) REG_ARG1(uc);
            path_arg_index = 1;
            break;

        case SYS_EXECVE:
            pathname = (const char *) REG_ARG0(uc);
            path_arg_index = 0;
            break;

        default:
            // 不认识的 syscall，直接执行
            goto passthrough;
    }

    if (!pathname) goto passthrough;

    // 特殊处理: /proc/self/maps
    if (maps_hide_is_maps_path(pathname)) {
        if (syscall_nr == SYS_OPENAT) {
            int fd = maps_hide_get_filtered_fd();
            if (fd >= 0) {
                int dup_fd = (int) raw_syscall6(__NR_dup, fd, 0, 0, 0, 0, 0);
                if (dup_fd >= 0) {
                    REG_RET(uc) = dup_fd;
                    // 跳过原始 syscall：将 syscall number 设为无效值
                    // 然后手动设置返回值
                    REG_SYSCALL_NR(uc) = -1;
                    return;
                }
            }
        }
    }

    // 检查路径是否需要重定向
    if (io_redirect_resolve(pathname, tls_seccomp_buf, sizeof(tls_seccomp_buf))) {
        // 路径需要重定向，执行修改后的 syscall
        long ret;

        switch (path_arg_index) {
            case 0:
                ret = raw_syscall6(syscall_nr,
                                   (long) tls_seccomp_buf,
                                   (long) REG_ARG1(uc),
                                   (long) REG_ARG2(uc),
                                   (long) REG_ARG3(uc),
                                   (long) REG_ARG4(uc),
                                   (long) REG_ARG5(uc));
                break;
            case 1:
            default:
                ret = raw_syscall6(syscall_nr,
                                   (long) REG_ARG0(uc),
                                   (long) tls_seccomp_buf,
                                   (long) REG_ARG2(uc),
                                   (long) REG_ARG3(uc),
                                   (long) REG_ARG4(uc),
                                   (long) REG_ARG5(uc));
                break;
        }

        REG_RET(uc) = ret;
        REG_SYSCALL_NR(uc) = -1;
        return;
    }

passthrough:
    {
        // 不需要重定向，执行原始 syscall
        long ret = raw_syscall6(syscall_nr,
                                (long) REG_ARG0(uc),
                                (long) REG_ARG1(uc),
                                (long) REG_ARG2(uc),
                                (long) REG_ARG3(uc),
                                (long) REG_ARG4(uc),
                                (long) REG_ARG5(uc));
        REG_RET(uc) = ret;
        REG_SYSCALL_NR(uc) = -1;
    }
}

// ==================== BPF 程序构造 ====================

/**
 * 构造 BPF 过滤程序
 * 匹配目标系统调用号，返回 SECCOMP_RET_TRAP
 * 其他系统调用返回 SECCOMP_RET_ALLOW
 */
static struct sock_fprog build_bpf_filter(void) {
    // 需要拦截的 syscall 列表
    int target_syscalls[] = {
        SYS_OPENAT,
        SYS_FSTATAT,
        SYS_FACCESSAT,
        SYS_READLINKAT,
#ifdef SYS_STATX
        SYS_STATX,
#endif
#ifdef SYS_OPENAT2
        SYS_OPENAT2,
#endif
        SYS_EXECVE,
    };
    int num_targets = sizeof(target_syscalls) / sizeof(target_syscalls[0]);

    /*
     * BPF 程序结构：
     *
     * [0] LD arch
     * [1] JNE target_arch -> ALLOW
     * [2] LD syscall_nr
     * [3] JEQ target1 -> TRAP
     * [4] JEQ target2 -> TRAP
     * ...
     * [N] ALLOW
     * [N+1] TRAP
     */
    int total_insns = 3 + num_targets + 2; // header(3) + jumps + allow + trap
    struct sock_filter *insns = (struct sock_filter *)
            calloc(total_insns, sizeof(struct sock_filter));

    int idx = 0;

    // [0] 加载架构字段
    insns[idx++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, arch));

    // [1] 检查架构，不匹配则 ALLOW
    insns[idx++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
            SECCOMP_AUDIT_ARCH, 0, (unsigned char)(num_targets + 2));

    // [2] 加载 syscall 号
    insns[idx++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, nr));

    // [3..3+N-1] 逐个比较 syscall 号
    for (int i = 0; i < num_targets; i++) {
        int jump_to_trap = num_targets - i; // 跳到 TRAP 的偏移
        insns[idx++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                (unsigned int)target_syscalls[i], (unsigned char)jump_to_trap, 0);
    }

    // [N] ALLOW
    insns[idx++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    // [N+1] TRAP
    insns[idx++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);

    struct sock_fprog prog;
    prog.len = (unsigned short) idx;
    prog.filter = insns;

    return prog;
}

// ==================== 公开 API ====================

int seccomp_install(const RedirectConfig *config) {
    if (g_seccomp_active) {
        LOGW("seccomp already installed");
        return 0;
    }

    LOGI("Installing seccomp filter...");

    // Step 1: 注册 SIGSYS handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigfillset(&sa.sa_mask);
    sigdelset(&sa.sa_mask, SIGSYS);

    if (sigaction(SIGSYS, &sa, nullptr) < 0) {
        LOGE("Failed to set SIGSYS handler: %s", strerror(errno));
        return -1;
    }

    // Step 2: 设置 PR_SET_NO_NEW_PRIVS（seccomp 要求）
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        LOGE("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
        return -2;
    }

    // Step 3: 构造并安装 BPF 过滤器
    struct sock_fprog prog = build_bpf_filter();

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) < 0) {
        LOGE("prctl(PR_SET_SECCOMP) failed: %s", strerror(errno));
        free(prog.filter);
        return -3;
    }

    free(prog.filter);

    g_seccomp_active = true;
    LOGI("seccomp filter installed successfully");
    return 0;
}

bool seccomp_is_active(void) {
    return g_seccomp_active;
}
