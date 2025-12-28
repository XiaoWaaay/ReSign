// resig_native.cpp  (编译成 libkillsignture.so)

#include <jni.h>
#include <android/log.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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

static constexpr unsigned int kSysOpenat = SYS_openat;
static constexpr unsigned int kSysReadlinkat = SYS_readlinkat;

// ===== 全局重定向目标 =====
static const char* g_apk_path = nullptr;  // 原始 APK
static const char* g_rep_path = nullptr;  // 替换 APK

// ===== 代理进程通信 =====
static int g_proxy_sock = -1;
static pid_t g_proxy_pid = -1;

static const int kMaxPathLen = 4096;
static const int kMaxReadlinkLen = 4096;

typedef struct {
   int type;
   int has_dirfd;
   int dirfd_value;
   int flags;
   int mode;
   int buflen;
   int path_len;
   char path[kMaxPathLen];
} ProxyReq;

typedef struct {
   long ret;
   int data_len;
   char data[kMaxReadlinkLen];
} ProxyResp;

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
static int send_msg_with_optional_fd(int sock, const void* buf, size_t len, int fd_to_send) {
   struct msghdr msg;
   memset(&msg, 0, sizeof(msg));

   struct iovec iov;
   iov.iov_base = (void*)buf;
   iov.iov_len = len;
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;

   char cmsg_buf[CMSG_SPACE(sizeof(int))];
   if (fd_to_send >= 0) {
       msg.msg_control = cmsg_buf;
       msg.msg_controllen = sizeof(cmsg_buf);
       struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
       cmsg->cmsg_level = SOL_SOCKET;
       cmsg->cmsg_type = SCM_RIGHTS;
       cmsg->cmsg_len = CMSG_LEN(sizeof(int));
       *((int*)CMSG_DATA(cmsg)) = fd_to_send;
   }

   ssize_t n = sendmsg(sock, &msg, MSG_NOSIGNAL);
   return (n == (ssize_t)len) ? 0 : -1;
}

static int recv_msg_with_optional_fd(int sock, void* buf, size_t len, int* out_fd) {
   if (out_fd) *out_fd = -1;

   struct msghdr msg;
   memset(&msg, 0, sizeof(msg));

   struct iovec iov;
   iov.iov_base = buf;
   iov.iov_len = len;
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;

   char cmsg_buf[CMSG_SPACE(sizeof(int))];
   msg.msg_control = cmsg_buf;
   msg.msg_controllen = sizeof(cmsg_buf);

   ssize_t n = recvmsg(sock, &msg, 0);
   if (n != (ssize_t)len) return -1;

   for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg != nullptr;
        cmsg = CMSG_NXTHDR(&msg, cmsg)) {
       if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
           if (out_fd) *out_fd = *((int*)CMSG_DATA(cmsg));
           break;
       }
   }

   return 0;
}

static void proxy_loop(int sock) {
   for (;;) {
       ProxyReq req;
       int recv_fd = -1;
       if (recv_msg_with_optional_fd(sock, &req, sizeof(req), &recv_fd) != 0) continue;

       ProxyResp resp;
       memset(&resp, 0, sizeof(resp));

       if (req.type == kSysOpenat) {
           int dirfd = req.has_dirfd ? recv_fd : req.dirfd_value;
           long ret = syscall(kSysOpenat, dirfd, req.path, req.flags, req.mode);
           if (ret == -1) {
               resp.ret = -errno;
               (void)send_msg_with_optional_fd(sock, &resp, sizeof(resp), -1);
           } else {
               int opened_fd = (int)ret;
               resp.ret = 0;
               (void)send_msg_with_optional_fd(sock, &resp, sizeof(resp), opened_fd);
               close(opened_fd);
           }
           if (recv_fd >= 0) close(recv_fd);
           continue;
       }

       if (req.type == kSysReadlinkat) {
           int dirfd = req.has_dirfd ? recv_fd : req.dirfd_value;
           int buflen = req.buflen;
           if (buflen < 0) buflen = 0;
           if (buflen > kMaxReadlinkLen) buflen = kMaxReadlinkLen;
           long ret = syscall(kSysReadlinkat, dirfd, req.path, resp.data, buflen);
           if (ret == -1) {
               resp.ret = -errno;
               resp.data_len = 0;
           } else {
               resp.ret = ret;
               resp.data_len = (int)ret;
               if (resp.data_len < 0) resp.data_len = 0;
               if (resp.data_len > kMaxReadlinkLen) resp.data_len = kMaxReadlinkLen;
           }
           (void)send_msg_with_optional_fd(sock, &resp, sizeof(resp), -1);
           if (recv_fd >= 0) close(recv_fd);
           continue;
       }

       resp.ret = -ENOSYS;
       (void)send_msg_with_optional_fd(sock, &resp, sizeof(resp), -1);
       if (recv_fd >= 0) close(recv_fd);
   }
}

static int start_proxy_process() {
   int sv[2] = {-1, -1};
   if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) return -1;

   pid_t pid = fork();
   if (pid < 0) {
       close(sv[0]);
       close(sv[1]);
       return -1;
   }

   if (pid == 0) {
       close(sv[0]);
       proxy_loop(sv[1]);
       _exit(0);
   }

   close(sv[1]);
   g_proxy_sock = sv[0];
   g_proxy_pid = pid;
   return 0;
}

static int install_seccomp_filter_all_threads() {
   // 只拦 openat(56) 与 readlinkat(78)
   struct sock_filter filter[] = {
           // A = seccomp_data.nr
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
           // if (A == 56) -> TRAP
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysOpenat, 0, 3),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
           // if (A == 78) -> TRAP
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kSysReadlinkat, 0, 1),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
           // 其他全部允许
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
   };
   struct sock_fprog prog;
   prog.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0]));
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

   LOGI("[*] SVC call %ld", nr);

   // --- openat(56)：如果 pathname 含 ".apk" 则改为 g_rep_path ---
   if (nr == kSysOpenat) {
       const char* pathname = (const char*)a1;
       LOGI("[*] open%s",pathname);
       if (pathname && g_apk_path && g_rep_path && c_ends_with(pathname, g_apk_path)) {
           LOGI("重定向到原apk：%s-->>%s",pathname,g_rep_path);
           a1 = (long)g_rep_path; // 替换路径
       }
       // 如果需要严格处理 O_CREAT 模式，可在此判断 a2 & O_CREAT 决定 a3 的有效性
   }

   // --- readlinkat(78)：如果要“伪造读到 apkPath”，直接在 handler 中写 buf 并返回长度；否则转发 ---
   if (nr == kSysReadlinkat) {
       const char* pathname = (const char*)a1;
       char* buf = (char*)a2;
       long buflen = a3;
       LOGI("[*] readlinkat origin %s",pathname);
       if (pathname && buf && g_apk_path && c_has_sub(pathname, "origin.apk")) {
           // 伪造 readlinkat 结果：把 g_apk_path 拷到 buf，返回长度
           long n = c_strlen(g_apk_path);
           if (n >= buflen) n = buflen - 1;
           for (long i = 0; i < n; ++i) buf[i] = g_apk_path[i];
           if (buflen > 0) buf[n] = '\0';
           SET_RET(n);
           return;
       }
   }

   if (g_proxy_sock < 0) {
       SET_RET(-ENOSYS);
       return;
   }

   if (nr == kSysOpenat) {
       ProxyReq req;
       memset(&req, 0, sizeof(req));
       req.type = kSysOpenat;
       req.flags = (int)a2;
       req.mode = (int)a3;
       int dirfd = (int)a0;
       req.has_dirfd = (dirfd >= 0) ? 1 : 0;
       req.dirfd_value = dirfd;

       const char* p = (const char*)a1;
       if (!p) {
           SET_RET(-EFAULT);
           return;
       }

       int i = 0;
       for (; i < kMaxPathLen - 1 && p[i]; ++i) req.path[i] = p[i];
       req.path[i] = '\0';
       req.path_len = i;

       int send_fd = req.has_dirfd ? dirfd : -1;
       if (send_msg_with_optional_fd(g_proxy_sock, &req, sizeof(req), send_fd) != 0) {
           SET_RET(-EIO);
           return;
       }

       ProxyResp resp;
       int recv_fd = -1;
       if (recv_msg_with_optional_fd(g_proxy_sock, &resp, sizeof(resp), &recv_fd) != 0) {
           SET_RET(-EIO);
           return;
       }

       SET_RET((recv_fd >= 0) ? recv_fd : resp.ret);
       return;
   }

   if (nr == kSysReadlinkat) {
       ProxyReq req;
       memset(&req, 0, sizeof(req));
       req.type = kSysReadlinkat;
       int dirfd = (int)a0;
       req.has_dirfd = (dirfd >= 0) ? 1 : 0;
       req.dirfd_value = dirfd;
       req.buflen = (int)a3;

       const char* p = (const char*)a1;
       char* out_buf = (char*)a2;
       if (!p || !out_buf) {
           SET_RET(-EFAULT);
           return;
       }

       int i = 0;
       for (; i < kMaxPathLen - 1 && p[i]; ++i) req.path[i] = p[i];
       req.path[i] = '\0';
       req.path_len = i;

       int send_fd = req.has_dirfd ? dirfd : -1;
       if (send_msg_with_optional_fd(g_proxy_sock, &req, sizeof(req), send_fd) != 0) {
           SET_RET(-EIO);
           return;
       }

       ProxyResp resp;
       int recv_fd = -1;
       if (recv_msg_with_optional_fd(g_proxy_sock, &resp, sizeof(resp), &recv_fd) != 0) {
           if (recv_fd >= 0) close(recv_fd);
           SET_RET(-EIO);
           return;
       }
       if (recv_fd >= 0) close(recv_fd);

       if (resp.ret > 0 && resp.data_len > 0) {
           int n = resp.data_len;
           long buflen = a3;
           if (buflen < 0) buflen = 0;
           if (n > (int)buflen) n = (int)buflen;
           for (int j = 0; j < n; ++j) out_buf[j] = resp.data[j];
       }
       SET_RET(resp.ret);
       return;
   }

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
   g_apk_path = strdup(src ? src : "");
   g_rep_path = strdup(rep ? rep : "");
   LOGI("hookApkPath: src=%s, rep=%s", g_apk_path, g_rep_path);

   if (start_proxy_process() != 0) {
       LOGE("start_proxy_process failed");
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
