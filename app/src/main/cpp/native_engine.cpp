/**
 * ReSignPro - Native Engine Entry Point
 *
 * JNI 入口 + 引擎初始化 + Hook 后端调度
 * 支持三种后端：PLT Hook, IO Redirect (seccomp+BPF), Maps Hide
 */

#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/prctl.h>

#include "common.h"
#include "io_redirect.h"
#include "plt_hook.h"
#include "maps_hide.h"
#include "seccomp_filter.h"

// ==================== Global State ====================

static JavaVM *g_jvm = nullptr;
RedirectConfig g_config;
static bool g_initialized = false;
static int g_api_level = 0;
static NativeBackend g_backend = BACKEND_PLT_HOOK;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

bool g_debug = false;

// ==================== Utility Functions ====================

static int get_api_level() {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", value);
    return atoi(value);
}

static NativeBackend parse_backend(const char *backend_str) {
    if (!backend_str) return BACKEND_PLT_HOOK;
    if (strcmp(backend_str, "seccomp") == 0) return BACKEND_SECCOMP;
    if (strcmp(backend_str, "plt_hook") == 0) return BACKEND_PLT_HOOK;
    if (strcmp(backend_str, "hybrid") == 0) return BACKEND_HYBRID;
    return BACKEND_PLT_HOOK;
}

/**
 * 从 Java 侧获取配置填充到 RedirectConfig
 */
static bool fill_config_from_java(JNIEnv *env, jstring origApkPath, jstring fakeApkPath,
                                   jstring origPkgName, jstring dataDir, jstring nativeBackend) {
    if (!origApkPath || !fakeApkPath) {
        LOGE("origApkPath or fakeApkPath is null");
        return false;
    }

    const char *orig = env->GetStringUTFChars(origApkPath, nullptr);
    const char *fake = env->GetStringUTFChars(fakeApkPath, nullptr);
    const char *pkg = origPkgName ? env->GetStringUTFChars(origPkgName, nullptr) : "";
    const char *data = dataDir ? env->GetStringUTFChars(dataDir, nullptr) : "";
    const char *backend = nativeBackend ? env->GetStringUTFChars(nativeBackend, nullptr) : "plt_hook";

    // 安全拷贝
    safe_strncpy(g_config.orig_apk_path, orig, sizeof(g_config.orig_apk_path));
    safe_strncpy(g_config.fake_apk_path, fake, sizeof(g_config.fake_apk_path));
    safe_strncpy(g_config.package_name, pkg, sizeof(g_config.package_name));
    safe_strncpy(g_config.data_dir, data, sizeof(g_config.data_dir));

    g_backend = parse_backend(backend);
    g_config.api_level = g_api_level;

    env->ReleaseStringUTFChars(origApkPath, orig);
    env->ReleaseStringUTFChars(fakeApkPath, fake);
    if (origPkgName) env->ReleaseStringUTFChars(origPkgName, pkg);
    if (dataDir) env->ReleaseStringUTFChars(dataDir, data);
    if (nativeBackend) env->ReleaseStringUTFChars(nativeBackend, backend);

    return true;
}

// ==================== JNI Methods ====================

extern "C" {

/**
 * 引擎初始化：安装所有 native hook
 *
 * @param origApkPath   原始 APK 路径（用于 IO 重定向目标）
 * @param fakeApkPath   伪装 APK 路径（重定向后读取到的路径）
 * @param origPkgName   包名
 * @param dataDir       应用数据目录
 * @param nativeBackend "plt_hook" / "seccomp" / "hybrid"
 * @return 0 成功, 负数失败
 */
JNIEXPORT jint JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeInit(
        JNIEnv *env, jclass clazz,
        jstring origApkPath, jstring fakeApkPath,
        jstring origPkgName, jstring dataDir,
        jstring nativeBackend) {

    pthread_mutex_lock(&g_init_mutex);
    if (g_initialized) {
        LOGW("Native engine already initialized, skipping");
        pthread_mutex_unlock(&g_init_mutex);
        return 0;
    }

    LOGI("========== ReSignPro Native Engine Init ==========");

    g_api_level = get_api_level();
    LOGI("API level: %d", g_api_level);

    // 填充配置
    if (!fill_config_from_java(env, origApkPath, fakeApkPath, origPkgName, dataDir, nativeBackend)) {
        LOGE("Failed to parse config from Java");
        pthread_mutex_unlock(&g_init_mutex);
        return -1;
    }

    LOGI("Backend: %s", g_backend == BACKEND_SECCOMP ? "seccomp" :
                         g_backend == BACKEND_HYBRID ? "hybrid" : "plt_hook");
    LOGI("Orig APK: %s", g_config.orig_apk_path);
    LOGI("Fake APK: %s", g_config.fake_apk_path);
    LOGI("Package:  %s", g_config.package_name);
    LOGI("DataDir:  %s", g_config.data_dir);

    int ret = 0;

    // Step 1: 初始化 IO 重定向规则
    io_redirect_init(&g_config);

    // Step 2: 根据后端类型安装 hook
    switch (g_backend) {
        case BACKEND_PLT_HOOK: {
            LOGI("[Step 2] Installing PLT hooks...");
            ret = plt_hook_install(&g_config);
            if (ret != 0) {
                LOGE("PLT hook install failed: %d, falling back to seccomp", ret);
                ret = seccomp_install(&g_config);
            }
            break;
        }
        case BACKEND_SECCOMP: {
            LOGI("[Step 2] Installing seccomp filter...");
            ret = seccomp_install(&g_config);
            if (ret != 0) {
                LOGE("seccomp install failed: %d, falling back to PLT hook", ret);
                ret = plt_hook_install(&g_config);
            }
            break;
        }
        case BACKEND_HYBRID: {
            LOGI("[Step 2] Installing hybrid hooks (PLT + seccomp)...");
            // PLT hook 拦截 libc wrapper 调用
            int plt_ret = plt_hook_install(&g_config);
            // seccomp 拦截直接 syscall
            int sec_ret = seccomp_install(&g_config);
            if (plt_ret != 0 && sec_ret != 0) {
                LOGE("Both PLT and seccomp failed");
                ret = -2;
            } else {
                LOGI("Hybrid: PLT=%s, seccomp=%s",
                     plt_ret == 0 ? "OK" : "FAIL",
                     sec_ret == 0 ? "OK" : "FAIL");
            }
            break;
        }
    }

    if (ret != 0) {
        LOGE("Hook installation failed with code: %d", ret);
        pthread_mutex_unlock(&g_init_mutex);
        return ret;
    }

    // Step 3: 初始化 maps 隐藏
    LOGI("[Step 3] Installing maps hide...");
    int maps_ret = maps_hide_install(&g_config);
    if (maps_ret != 0) {
        LOGW("Maps hide install failed: %d (non-fatal)", maps_ret);
    }

    g_initialized = true;
    pthread_mutex_unlock(&g_init_mutex);

    LOGI("========== Native Engine Init Complete ==========");
    return 0;
}

/**
 * 添加额外的路径重定向规则
 */
JNIEXPORT jboolean JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeAddRedirect(
        JNIEnv *env, jclass clazz,
        jstring fromPath, jstring toPath) {

    if (!fromPath || !toPath) return JNI_FALSE;

    const char *from = env->GetStringUTFChars(fromPath, nullptr);
    const char *to = env->GetStringUTFChars(toPath, nullptr);

    bool ok = io_redirect_add_rule(from, to);

    env->ReleaseStringUTFChars(fromPath, from);
    env->ReleaseStringUTFChars(toPath, to);

    return ok ? JNI_TRUE : JNI_FALSE;
}

/**
 * 添加需要隐藏的 maps 关键字
 */
JNIEXPORT void JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeAddMapsFilter(
        JNIEnv *env, jclass clazz,
        jstring keyword) {

    if (!keyword) return;
    const char *kw = env->GetStringUTFChars(keyword, nullptr);
    maps_hide_add_filter(kw);
    env->ReleaseStringUTFChars(keyword, kw);
}

/**
 * 设置 maps 内容中替换的包名
 */
JNIEXPORT void JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeSetMapsReplace(
        JNIEnv *env, jclass clazz,
        jstring oldStr, jstring newStr) {

    if (!oldStr || !newStr) return;
    const char *old_s = env->GetStringUTFChars(oldStr, nullptr);
    const char *new_s = env->GetStringUTFChars(newStr, nullptr);
    maps_hide_set_replace(old_s, new_s);
    env->ReleaseStringUTFChars(oldStr, old_s);
    env->ReleaseStringUTFChars(newStr, new_s);
}

/**
 * 获取引擎运行状态
 */
JNIEXPORT jstring JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeGetStatus(
        JNIEnv *env, jclass clazz) {

    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"initialized\":%s,\"api\":%d,\"backend\":\"%s\","
             "\"redirect_rules\":%d,\"maps_filters\":%d,"
             "\"plt_hooked\":%s,\"seccomp_active\":%s}",
             g_initialized ? "true" : "false",
             g_api_level,
             g_backend == BACKEND_SECCOMP ? "seccomp" :
             g_backend == BACKEND_HYBRID ? "hybrid" : "plt_hook",
             io_redirect_rule_count(),
             maps_hide_filter_count(),
             plt_hook_is_active() ? "true" : "false",
             seccomp_is_active() ? "true" : "false");

    return env->NewStringUTF(buf);
}

/**
 * 禁用 ptrace 附加（反调试）
 */
JNIEXPORT void JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeAntiDebug(
        JNIEnv *env, jclass clazz) {

    // PR_SET_DUMPABLE = 4, 设置为 0 阻止 ptrace attach
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // 自我 ptrace 占坑
    // 注意: 在某些 ROM 上可能导致崩溃，所以只在 API >= 26 启用
    if (g_api_level >= 26) {
        // 使用单独线程 ptrace 自身
        // 这里简化处理，仅设置 dumpable
        LOGI("Anti-debug: PR_SET_DUMPABLE=0 applied");
    }
}

/**
 * 隐藏 Zygisk/Riru 注入痕迹
 */
JNIEXPORT void JNICALL
Java_com_resign_pro_payload_NativeBridge_nativeHideInjection(
        JNIEnv *env, jclass clazz) {

    // 添加常见的注入框架路径到 maps 隐藏列表
    maps_hide_add_filter("libzygisk");
    maps_hide_add_filter("libriru");
    maps_hide_add_filter("liblspd");
    maps_hide_add_filter("resign_pro");
    maps_hide_add_filter("payload");
    maps_hide_add_filter("origin.apk");

    LOGI("Injection trace hide rules added");
}

} // extern "C"

// ==================== JNI_OnLoad ====================

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("ReSignPro native library loaded (JNI_OnLoad)");

    // 预初始化 API level
    g_api_level = get_api_level();

    return JNI_VERSION_1_6;
}
