// resig_native.cpp  (编译成 libkillsignture.so)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stddef.h>   // offsetof
#include <string.h>   // 仅用于 memset
#include <stdlib.h>   // malloc/free/strdup
#include <errno.h>

// ===== 日志（避免在信号处理器里使用 LOG*）=====
#define TAG "resig-native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ===== seccomp/BPF 头 =====
#include <linux/filter.h>
#include <linux/seccomp.h>
#ifndef SECCOMP_RET_TRAP
# define SECCOMP_RET_TRAP 0x00030000U
#endif
#ifndef SECCOMP_RET_ALLOW
# define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER 2
#endif
#ifndef SECCOMP_SET_MODE_FILTER
# define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
# define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#if !defined(SYS_openat) && defined(__NR_openat)
# define SYS_openat __NR_openat
#endif
#if !defined(SYS_readlinkat) && defined(__NR_readlinkat)
# define SYS_readlinkat __NR_readlinkat
#endif
#if !defined(SYS_write) && defined(__NR_write)
# define SYS_write __NR_write
#endif

static constexpr unsigned int kSysOpenat = SYS_openat;
static constexpr unsigned int kSysReadlinkat = SYS_readlinkat;
static constexpr unsigned int kSysWrite = SYS_write;

// ===== 全局重定向目标 =====
static const char* g_apk_path = nullptr;  // 原始 APK
static const char* g_rep_path = nullptr;  // 替换 APK

static uintptr_t g_self_map_start = 0;
static uintptr_t g_self_map_end_inclusive = 0;

static __thread int g_in_sigsys_handler = 0;

static const int kMaxTrackedFd = 8192;
static unsigned char g_redirected_fds[kMaxTrackedFd];

static int g_dbg_pipe_w = -1;
static int g_dbg_pipe_r = -1;
static int g_dbg_started = 0;
static int g_dbg_enabled = 1;
static pthread_t g_dbg_thread;

// ===== 简单 async-signal-safe 字符串工具 =====
static inline int c_has_sub(const char* s, const char* sub) {
   if (!s || !sub) return 0;
   // 朴素搜索（避免调用 strstr/strlen）
   for (const char* p = s; *p; ++p) {
       const char* a = p;
       const char* b = sub;
       while (*a && *b && (*a == *b)) { ++a; ++b; }
       if (*b == '\0') return 1;
   }
   return 0;
}
static inline long c_strlen(const char* s) {
   if (!s) return 0;
   long n = 0; while (s[n] != '\0') ++n; return n;
}
static inline void c_strcpy(char* dst, const char* src) {
   if (!dst || !src) return;
   while (*src) { *dst++ = *src++; }
   *dst = '\0';
}
static inline int c_ends_with(const char* s, const char* suf) {
   if (!s || !suf) return 0;
   long ls = c_strlen(s), lu = c_strlen(suf);
   if (lu > ls) return 0;
   const char* sp = s + (ls - lu);
   while (*sp && *suf && (*sp == *suf)) { ++sp; ++suf; }
   return (*suf == '\0');
}

static inline int c_is_digit(char c) {
   return (c >= '0' && c <= '9');
}

static inline int c_parse_int(const char* s, int* out) {
   if (!s || !out) return -1;
   int v = 0;
   int any = 0;
   for (const char* p = s; *p; ++p) {
       if (!c_is_digit(*p)) break;
       any = 1;
       int d = (*p - '0');
       if (v > (2147483647 - d) / 10) return -1;
       v = v * 10 + d;
   }
   if (!any) return -1;
   *out = v;
   return 0;
}

static inline int c_has_prefix(const char* s, const char* pre) {
   if (!s || !pre) return 0;
   for (; *pre; ++pre, ++s) {
       if (*s != *pre) return 0;
   }
   return 1;
}

static inline int c_min_i(int a, int b) {
   return (a < b) ? a : b;
}

static inline int c_copy_cstr_limited(char* dst, int dst_cap, const char* src, int max_copy) {
   if (!dst || dst_cap <= 0) return 0;
   if (!src || max_copy <= 0) {
       dst[0] = '\0';
       return 0;
   }
   int n = 0;
   int limit = c_min_i(dst_cap - 1, max_copy);
   for (; n < limit; ++n) {
       char c = src[n];
       if (c == '\0') break;
       dst[n] = c;
   }
   dst[n] = '\0';
   return n;
}

static void* dbg_thread_main(void*) {
   char buf[512];
   for (;;) {
       ssize_t n = read(g_dbg_pipe_r, buf, sizeof(buf) - 1);
       if (n <= 0) {
           usleep(1000);
           continue;
       }
       buf[n] = '\0';
       LOGI("%s", buf);
   }
   return nullptr;
}

static void start_dbg_logger_once() {
   if (__atomic_exchange_n(&g_dbg_started, 1, __ATOMIC_ACQ_REL) != 0) return;
   int fds[2] = {-1, -1};
#if defined(__linux__)
   if (pipe2(fds, O_CLOEXEC) != 0) {
       if (pipe(fds) != 0) {
           g_dbg_started = 0;
           return;
       }
   }
#else
   if (pipe(fds) != 0) {
       g_dbg_started = 0;
       return;
   }
#endif
   g_dbg_pipe_r = fds[0];
   g_dbg_pipe_w = fds[1];
   pthread_create(&g_dbg_thread, nullptr, dbg_thread_main, nullptr);
}

static inline void mark_redirected_fd(int fd) {
   if (fd >= 0 && fd < kMaxTrackedFd) {
       __atomic_store_n(&g_redirected_fds[fd], (unsigned char)1, __ATOMIC_RELAXED);
   }
}

static inline void unmark_redirected_fd(int fd) {
   if (fd >= 0 && fd < kMaxTrackedFd) {
       __atomic_store_n(&g_redirected_fds[fd], (unsigned char)0, __ATOMIC_RELAXED);
   }
}

static inline int is_redirected_fd(int fd) {
   if (fd >= 0 && fd < kMaxTrackedFd) {
       return __atomic_load_n(&g_redirected_fds[fd], __ATOMIC_RELAXED) != 0;
   }
   return 0;
}
static inline const char* c_basename(const char* path) {
   if (!path) return path;
   const char* last = path;
   for (const char* p = path; *p; ++p) {
       if (*p == '/') last = p + 1;
   }
   return last;
}

static int find_self_map_range(uintptr_t* out_start, uintptr_t* out_end_inclusive) {
   if (!out_start || !out_end_inclusive) return -1;

   Dl_info info;
   memset(&info, 0, sizeof(info));
   const char* full = nullptr;
   const char* base = nullptr;
   void* fbase = nullptr;
   if (dladdr((void*)&find_self_map_range, &info) != 0 && info.dli_fname) {
       full = info.dli_fname;
       base = c_basename(full);
       fbase = info.dli_fbase;
   }

   struct Ctx {
       uintptr_t target_base;
       uintptr_t min_start;
       uintptr_t max_end;
       int found;
   };

   Ctx ctx;
   memset(&ctx, 0, sizeof(ctx));
   ctx.target_base = (uintptr_t)fbase;

   int (*cb)(struct dl_phdr_info*, size_t, void*) = [](struct dl_phdr_info* i, size_t, void* data) -> int {
       Ctx* c = (Ctx*)data;
       if (c->target_base == 0) return 0;
       if ((uintptr_t)i->dlpi_addr != c->target_base) return 0;

       uintptr_t min_start = 0;
       uintptr_t max_end = 0;
       int found = 0;
       for (int p = 0; p < i->dlpi_phnum; ++p) {
           const ElfW(Phdr)& ph = i->dlpi_phdr[p];
           if (ph.p_type != PT_LOAD) continue;
           uintptr_t start = (uintptr_t)i->dlpi_addr + (uintptr_t)ph.p_vaddr;
           uintptr_t end = start + (uintptr_t)ph.p_memsz;
           if (!found) {
               min_start = start;
               max_end = end;
               found = 1;
           } else {
               if (start < min_start) min_start = start;
               if (end > max_end) max_end = end;
           }
       }

       if (found && max_end > min_start) {
           c->min_start = min_start;
           c->max_end = max_end;
           c->found = 1;
           return 1;
       }
       return 0;
   };

   (void)dl_iterate_phdr(cb, &ctx);
   if (ctx.found && ctx.max_end > ctx.min_start) {
       *out_start = ctx.min_start;
       *out_end_inclusive = ctx.max_end - 1;
       return 0;
   }

   const char* candidates[3] = {nullptr, "libkillsignture.so", "killsignture.so"};
   candidates[0] = base;

   FILE* fp = fopen("/proc/self/maps", "r");
   if (!fp) {
       LOGE("open /proc/self/maps failed: %d", errno);
       return -1;
   }

   uintptr_t min_start = 0;
   uintptr_t max_end = 0;
   int found = 0;

   char line[4096];
   while (fgets(line, sizeof(line), fp)) {
       unsigned long long start_ll = 0;
       unsigned long long end_ll = 0;
       char perms[8] = {0};

       int n = sscanf(line, "%llx-%llx %7s", &start_ll, &end_ll, perms);
       if (n < 3) continue;

       uintptr_t start = (uintptr_t)start_ll;
       uintptr_t end = (uintptr_t)end_ll;

       int matched = 0;
       for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
           const char* key = candidates[i];
           if (!key || key[0] == '\0') continue;
           if (strstr(line, key) != nullptr) {
               matched = 1;
               break;
           }
       }
       if (!matched && full && strstr(line, full) != nullptr) matched = 1;
       if (!matched) continue;

       if (!found) {
           min_start = start;
           max_end = end;
           found = 1;
       } else {
           if (start < min_start) min_start = start;
           if (end > max_end) max_end = end;
       }
   }

   fclose(fp);

   if (!found || max_end == 0 || max_end <= min_start) return -1;
   *out_start = min_start;
   *out_end_inclusive = max_end - 1;
   return 0;
}

static inline long raw_syscall6(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
#if defined(__aarch64__)
   register long x8 __asm__("x8") = n;
   register long x0 __asm__("x0") = a0;
   register long x1 __asm__("x1") = a1;
   register long x2 __asm__("x2") = a2;
   register long x3 __asm__("x3") = a3;
   register long x4 __asm__("x4") = a4;
   register long x5 __asm__("x5") = a5;
   __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
   return x0;
#elif defined(__arm__)
   long ret = 0;
   __asm__ volatile(
           "push {r7}\n"
           "mov r7, %1\n"
           "mov r0, %2\n"
           "mov r1, %3\n"
           "mov r2, %4\n"
           "mov r3, %5\n"
           "mov r4, %6\n"
           "mov r5, %7\n"
           "svc 0\n"
           "mov %0, r0\n"
           "pop {r7}\n"
           : "=r"(ret)
           : "r"(n), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
           : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
   return ret;
#elif defined(__x86_64__)
   register long rax __asm__("rax") = n;
   register long rdi __asm__("rdi") = a0;
   register long rsi __asm__("rsi") = a1;
   register long rdx __asm__("rdx") = a2;
   register long r10 __asm__("r10") = a3;
   register long r8 __asm__("r8") = a4;
   register long r9 __asm__("r9") = a5;
   __asm__ volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
   return rax;
#elif defined(__i386__)
   register long eax __asm__("eax") = n;
   register long ebx __asm__("ebx") = a0;
   register long ecx __asm__("ecx") = a1;
   register long edx __asm__("edx") = a2;
   register long esi __asm__("esi") = a3;
   register long edi __asm__("edi") = a4;
   register long ebp __asm__("ebp") = a5;
   __asm__ volatile("int $0x80" : "+r"(eax) : "r"(ebx), "r"(ecx), "r"(edx), "r"(esi), "r"(edi), "r"(ebp) : "memory");
   return eax;
#else
   (void)n;
   (void)a0;
   (void)a1;
   (void)a2;
   (void)a3;
   (void)a4;
   (void)a5;
   return -ENOSYS;
#endif
}

static inline void dbg_write_line_78(const char* pathname) {
   if (!g_dbg_enabled || g_dbg_pipe_w < 0) return;
   if (!pathname) return;
   char msg[320];
   int p = 0;
   msg[p++] = '7';
   msg[p++] = '8';
   msg[p++] = ':';
   msg[p++] = ' ';
   p += c_copy_cstr_limited(msg + p, (int)sizeof(msg) - p, pathname, 260);
   if (p < (int)sizeof(msg) - 1) msg[p++] = '\n';
   msg[p] = '\0';
   (void)raw_syscall6((long)kSysWrite, (long)g_dbg_pipe_w, (long)msg, (long)p, 0, 0, 0);
}

static inline void dbg_write_line_78_target(const char* target) {
   if (!g_dbg_enabled || g_dbg_pipe_w < 0) return;
   if (!target) return;
   char msg[320];
   int p = 0;
   msg[p++] = '7';
   msg[p++] = '8';
   msg[p++] = '-';
   msg[p++] = '>';
   msg[p++] = ' ';
   p += c_copy_cstr_limited(msg + p, (int)sizeof(msg) - p, target, 260);
   if (p < (int)sizeof(msg) - 1) msg[p++] = '\n';
   msg[p] = '\0';
   (void)raw_syscall6((long)kSysWrite, (long)g_dbg_pipe_w, (long)msg, (long)p, 0, 0, 0);
}

static int install_seccomp_filter_all_threads() {
   if (g_self_map_start == 0 || g_self_map_end_inclusive == 0 || g_self_map_end_inclusive < g_self_map_start) {
       LOGE("self map range not ready");
       return -1;
   }

   const uint64_t start = (uint64_t)g_self_map_start;
   const uint64_t end = (uint64_t)g_self_map_end_inclusive;
   const uint32_t start_lo = (uint32_t)(start & 0xffffffffULL);
   const uint32_t start_hi = (uint32_t)((start >> 32) & 0xffffffffULL);
   const uint32_t end_lo = (uint32_t)(end & 0xffffffffULL);
   const uint32_t end_hi = (uint32_t)((end >> 32) & 0xffffffffULL);
   const uint32_t ip_off = (uint32_t)offsetof(struct seccomp_data, instruction_pointer);

   struct sock_filter filter_same_hi[] = {
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysOpenat, 2, 0),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysReadlinkat, 1, 0),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, ip_off + 4),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, start_hi, 0, 4),
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, ip_off + 0),
           BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start_lo, 0, 2),
           BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, end_lo, 1, 0),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
   };

   struct sock_filter filter_diff_hi[] = {
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysOpenat, 2, 0),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysReadlinkat, 1, 0),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, ip_off + 4),
           BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start_hi, 0, 9),
           BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, end_hi, 8, 0),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, start_hi, 0, 3),
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, ip_off + 0),
           BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, start_lo, 0, 5),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, end_hi, 0, 2),
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, ip_off + 0),
           BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, end_lo, 1, 0),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
   };

   struct sock_filter* filter = nullptr;
   size_t filter_len = 0;
   if (start_hi == end_hi) {
       filter = filter_same_hi;
       filter_len = sizeof(filter_same_hi) / sizeof(filter_same_hi[0]);
   } else {
       filter = filter_diff_hi;
       filter_len = sizeof(filter_diff_hi) / sizeof(filter_diff_hi[0]);
   }

   struct sock_fprog prog;
   prog.len    = (unsigned short)filter_len;
   prog.filter = filter;

   if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
       LOGE("PR_SET_NO_NEW_PRIVS failed");
       return -1;
   }

#if defined(SYS_seccomp)
   if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
       LOGE("seccomp(TSYNC) failed");
       return -1;
   }
#elif defined(__NR_seccomp)
   if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
       LOGE("seccomp(TSYNC) failed");
       return -1;
   }
#else
   LOGE("seccomp syscall not available");
   return -1;
#endif

   LOGI("seccomp installed (tsync)");
   return 0;
}

// ===== SIGSYS 处理器（改参 + 管道转发）=====
static void sigsys_handler(int signo, siginfo_t*, void* context) {
   if (signo != SIGSYS) return;
   ucontext_t* uc = (ucontext_t*)context;

   long nr = 0;
   long a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;

#if defined(__aarch64__)
   nr = uc->uc_mcontext.regs[8];
   a0 = uc->uc_mcontext.regs[0];
   a1 = uc->uc_mcontext.regs[1];
   a2 = uc->uc_mcontext.regs[2];
   a3 = uc->uc_mcontext.regs[3];
   a4 = uc->uc_mcontext.regs[4];
   a5 = uc->uc_mcontext.regs[5];
# define SET_RET(v) (uc->uc_mcontext.regs[0] = (v))
#elif defined(__arm__)
   nr = uc->uc_mcontext.arm_r7;
   a0 = uc->uc_mcontext.arm_r0;
   a1 = uc->uc_mcontext.arm_r1;
   a2 = uc->uc_mcontext.arm_r2;
   a3 = uc->uc_mcontext.arm_r3;
   a4 = uc->uc_mcontext.arm_r4;
   a5 = uc->uc_mcontext.arm_r5;
# define SET_RET(v) (uc->uc_mcontext.arm_r0 = (v))
#elif defined(__x86_64__)
   nr = uc->uc_mcontext.gregs[REG_RAX];
   a0 = uc->uc_mcontext.gregs[REG_RDI];
   a1 = uc->uc_mcontext.gregs[REG_RSI];
   a2 = uc->uc_mcontext.gregs[REG_RDX];
   a3 = uc->uc_mcontext.gregs[REG_R10];
   a4 = uc->uc_mcontext.gregs[REG_R8];
   a5 = uc->uc_mcontext.gregs[REG_R9];
# define SET_RET(v) (uc->uc_mcontext.gregs[REG_RAX] = (v))
#elif defined(__i386__)
   nr = uc->uc_mcontext.gregs[REG_EAX];
   a0 = uc->uc_mcontext.gregs[REG_EBX];
   a1 = uc->uc_mcontext.gregs[REG_ECX];
   a2 = uc->uc_mcontext.gregs[REG_EDX];
   a3 = uc->uc_mcontext.gregs[REG_ESI];
   a4 = uc->uc_mcontext.gregs[REG_EDI];
   a5 = uc->uc_mcontext.gregs[REG_EBP];
# define SET_RET(v) (uc->uc_mcontext.gregs[REG_EAX] = (v))
#else
# define SET_RET(v) ((void)(v))
   return;
#endif

   if (nr != kSysOpenat && nr != kSysReadlinkat) return;

   if (g_in_sigsys_handler != 0) {
       SET_RET(-ENOSYS);
       return;
   }
   g_in_sigsys_handler = 1;

   // --- openat(56)：如果 pathname 含 ".apk" 则改为 g_rep_path ---
   if (nr == kSysOpenat) {
       const char* pathname = (const char*)a1;
       int did_redirect = 0;
       if (pathname && g_apk_path && g_rep_path && g_apk_path[0] != '\0' && c_ends_with(pathname, g_apk_path)) {
           a1 = (long)g_rep_path; // 替换路径
           did_redirect = 1;
       }

       long ret = raw_syscall6((long)kSysOpenat, a0, a1, a2, a3, 0, 0);
       if (did_redirect && ret >= 0) {
           mark_redirected_fd((int)ret);
       }
       SET_RET(ret);
       g_in_sigsys_handler = 0;
       return;
   }

   // --- readlinkat(78)：如果要“伪造读到 apkPath”，直接在 handler 中写 buf 并返回长度；否则转发 ---
   if (nr == kSysReadlinkat) {
       const char* pathname = (const char*)a1;
       char* buf = (char*)a2;
       long buflen = a3;

       dbg_write_line_78(pathname);

       if (pathname && c_has_prefix(pathname, "/proc/self/fd/")) {
           int fd = -1;
           if (c_parse_int(pathname + 14, &fd) == 0 && is_redirected_fd(fd) && g_apk_path && g_apk_path[0] != '\0') {
               char tmp[512];
               long r = raw_syscall6((long)kSysReadlinkat, a0, a1, (long)tmp, (long)(sizeof(tmp) - 1), 0, 0);
               if (r > 0 && r < (long)sizeof(tmp)) {
                   tmp[r] = '\0';
                   dbg_write_line_78_target(tmp);
                   int match = 0;
                   if (g_rep_path && g_rep_path[0] != '\0') {
                       if (c_has_sub(tmp, g_rep_path)) {
                           match = 1;
                       } else {
                           const char* rep_base = c_basename(g_rep_path);
                           if (rep_base && rep_base[0] != '\0' && c_has_sub(tmp, rep_base)) {
                               match = 1;
                           }
                       }
                   }
                   if (match) {
                       if (buflen <= 0) {
                           SET_RET(-EINVAL);
                       } else {
                           long n = c_strlen(g_apk_path);
                           if (n >= buflen) n = buflen - 1;
                           for (long i = 0; i < n; ++i) buf[i] = g_apk_path[i];
                           buf[n] = '\0';
                           SET_RET(n);
                       }
                       g_in_sigsys_handler = 0;
                       return;
                   }
               }

               unmark_redirected_fd(fd);
           }
       }

       if (pathname && buf && g_apk_path && c_has_sub(pathname, "origin.apk")) {
           // 伪造 readlinkat 结果：把 g_apk_path 拷到 buf，返回长度
           if (buflen <= 0) {
               SET_RET(-EINVAL);
           } else {
               long n = c_strlen(g_apk_path);
               if (n >= buflen) n = buflen - 1;
               for (long i = 0; i < n; ++i) buf[i] = g_apk_path[i];
               buf[n] = '\0';
               SET_RET(n);
           }
           g_in_sigsys_handler = 0;
           return;
       }

       long ret = raw_syscall6((long)kSysReadlinkat, a0, a1, a2, a3, 0, 0);
       SET_RET(ret);
       g_in_sigsys_handler = 0;
       return;
   }

   g_in_sigsys_handler = 0;

#undef SET_RET
}

// ===== 安装 SIGSYS =====
static int install_sigsys() {
   struct sigaction sa;
   memset(&sa, 0, sizeof(sa));
   sigemptyset(&sa.sa_mask);
   sa.sa_sigaction = sigsys_handler;
   sa.sa_flags = SA_SIGINFO;
   if (sigaction(SIGSYS, &sa, nullptr) != 0) {
       LOGE("sigaction(SIGSYS) failed");
       return -1;
   }
   LOGI("SIGSYS handler installed");
   return 0;
}

// ===== JNI 入口：设置路径 + 启动工人线程 + 安装 SIGSYS + 安装 seccomp =====
extern "C"
JNIEXPORT void JNICALL
Java_com_xwaaa_hook_HookApplication_hookApkPath(
       JNIEnv* env, jclass /*clazz*/, jstring jSourcePath, jstring jRepPath) {
   const char* src = env->GetStringUTFChars(jSourcePath, nullptr);
   const char* rep = env->GetStringUTFChars(jRepPath, nullptr);

   // 保存重定向参数
   if (g_apk_path) { free((void*)g_apk_path); g_apk_path = nullptr; }
   if (g_rep_path) { free((void*)g_rep_path); g_rep_path = nullptr; }
   g_apk_path = strdup(src ? src : "");
   g_rep_path = strdup(rep ? rep : "");
   LOGI("hookApkPath: src=%s, rep=%s", g_apk_path, g_rep_path);

   start_dbg_logger_once();

   if (find_self_map_range(&g_self_map_start, &g_self_map_end_inclusive) != 0) {
       LOGE("find_self_map_range failed");
   }

   // 2) 安装 SIGSYS 处理器
   if (install_sigsys() != 0) {
       LOGE("install_sigsys failed");
   }

   if (install_seccomp_filter_all_threads() != 0) {
       LOGE("install_seccomp_filter_all_threads failed");
   }

   env->ReleaseStringUTFChars(jSourcePath, src);
   env->ReleaseStringUTFChars(jRepPath, rep);
}

// 可选清理
extern "C"
JNIEXPORT void JNICALL
Java_com_xwaaa_hook_HookApplication_cleanup(JNIEnv*, jclass) {
   if (g_apk_path) { free((void*)g_apk_path); g_apk_path = nullptr; }
   if (g_rep_path) { free((void*)g_rep_path); g_rep_path = nullptr; }
   // 管道/线程可按需收尾；通常进程退出由内核清理
}
