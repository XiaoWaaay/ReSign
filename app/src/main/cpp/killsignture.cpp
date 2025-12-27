// resig_native.cpp  (编译成 libkillsignture.so)

#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stddef.h>   // offsetof
#include <string.h>   // 仅用于 memset
#include <stdlib.h>   // malloc/free/strdup

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

// ===== 全局重定向目标 =====
static const char* g_apk_path = nullptr;  // 原始 APK
static const char* g_rep_path = nullptr;  // 替换 APK

// ===== 工人线程与管道 =====
static int g_req_pipe[2]  = {-1, -1}; // handler -> worker
static int g_resp_pipe[2] = {-1, -1}; // worker  -> handler
static pthread_t g_worker;

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
// ===== 请求结构 =====
typedef struct {
   long nr;
   long args[6];
} SysReq;

// ===== 工人线程：执行真实 syscall =====
static void* worker_main(void*) {
   for (;;) {
       SysReq req;
       ssize_t n = read(g_req_pipe[0], &req, sizeof(req));
       if (n != (ssize_t)sizeof(req)) continue;

       long ret = syscall(req.nr,
                          req.args[0], req.args[1], req.args[2],
                          req.args[3], req.args[4], req.args[5]);
       (void)write(g_resp_pipe[1], &ret, sizeof(ret));
   }
   return nullptr;
}
static int start_worker_thread() {
   if (pipe(g_req_pipe)  != 0) return -1;
   if (pipe(g_resp_pipe) != 0) return -1;
   pthread_attr_t attr; pthread_attr_init(&attr);
   int rc = pthread_create(&g_worker, &attr, worker_main, nullptr);
   pthread_attr_destroy(&attr);
   return rc;
}

// ===== 安装 seccomp（仅当前线程）=====
static int install_seccomp_filter_for_current_thread() {
   // 只拦 openat(56) 与 readlinkat(78)
   struct sock_filter filter[] = {
           // A = seccomp_data.nr
           BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
           // if (A == 56) -> TRAP
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 56, 0, 3),
           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
           // if (A == 78) -> TRAP
           BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 78, 0, 1),
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
   if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
       LOGE("PR_SET_SECCOMP failed");
       return -1;
   }
   LOGI("seccomp installed (thread-local)");
   return 0;
}

// ===== SIGSYS 处理器（改参 + 管道转发）=====
static void sigsys_handler(int signo, siginfo_t*, void* context) {
   if (signo != SIGSYS) return;
   ucontext_t* uc = (ucontext_t*)context;

   // AArch64：x8=nr，x0..x5=args
   long nr = uc->uc_mcontext.regs[8];
   long a0 = uc->uc_mcontext.regs[0];
   long a1 = uc->uc_mcontext.regs[1];
   long a2 = uc->uc_mcontext.regs[2];
   long a3 = uc->uc_mcontext.regs[3];
   long a4 = uc->uc_mcontext.regs[4];
   long a5 = uc->uc_mcontext.regs[5];

   if (nr != 56 && nr != 78) return;

   LOGI("[*] SVC call %d",nr);

   // --- openat(56)：如果 pathname 含 ".apk" 则改为 g_rep_path ---
   if (nr == 56) {
       const char* pathname = (const char*)a1;
       LOGI("[*] open%s",pathname);
       if (pathname && g_rep_path && c_ends_with(pathname, g_apk_path)) {
           LOGI("重定向到原apk：%s-->>%s",pathname,g_rep_path);
           a1 = (long)g_rep_path; // 替换路径
       }
       // 如果需要严格处理 O_CREAT 模式，可在此判断 a2 & O_CREAT 决定 a3 的有效性
   }

   // --- readlinkat(78)：如果要“伪造读到 apkPath”，直接在 handler 中写 buf 并返回长度；否则转发 ---
   if (nr == 78) {
       const char* pathname = (const char*)a2;
       char* buf = (char*)a3;
       long buflen = a4;
       LOGI("[*] readlinkat origin %s",pathname);
       if (pathname && buf && g_apk_path && c_has_sub(pathname, "origin.apk")) {
           // 伪造 readlinkat 结果：把 g_apk_path 拷到 buf，返回长度
           long n = c_strlen(g_apk_path);
           if (n >= buflen) n = buflen - 1;
           for (long i = 0; i < n; ++i) buf[i] = g_apk_path[i];
           if (buflen > 0) buf[n] = '\0';
           uc->uc_mcontext.regs[0] = n; // 返回长度
           return;
       }
   }

   // --- 把（可能已改参的）syscall 请求交给工人线程 ---
   SysReq req;
   req.nr      = nr;
   req.args[0] = a0; req.args[1] = a1; req.args[2] = a2;
   req.args[3] = a3; req.args[4] = a4; req.args[5] = a5;

   (void)write(g_req_pipe[1], &req, sizeof(req));
   long ret = -1;
   (void)read(g_resp_pipe[0], &ret, sizeof(ret));

   // 把返回值填回 x0，继续执行
   uc->uc_mcontext.regs[0] = ret;
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

   // 1) 先起工人线程（保证该线程不受后续 seccomp 影响）
   if (start_worker_thread() != 0) {
       LOGE("start_worker_thread failed");
   }

   // 2) 安装 SIGSYS 处理器
   if (install_sigsys() != 0) {
       LOGE("install_sigsys failed");
   }

   // 3) 仅在**当前线程**安装 seccomp（避免把工人线程也拦住）
   if (install_seccomp_filter_for_current_thread() != 0) {
       LOGE("install_seccomp_filter_for_current_thread failed");
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
