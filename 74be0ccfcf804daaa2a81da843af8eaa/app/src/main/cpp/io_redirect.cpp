/**
 * ReSignPro V2 - io_redirect.cpp
 *
 * IO 重定向模块
 * 提供路径检查和重定向逻辑（供 hook 函数和 seccomp handler 使用）
 */

#include "common.h"
#include <string.h>

int io_redirect_install(void) {
    // IO 重定向的 hook 已经在 native_killer.cpp 中通过 Dobby 安装
    // 这里提供辅助函数
    LOGI("IO redirect module ready");
    return 0;
}

/**
 * 检查路径是否需要重定向，如需要则写入 out
 */
bool io_redirect_resolve(const char *path, char *out, size_t out_len) {
    if (!path || !g_config.active) return false;

    // 检查是否是当前 APK 路径
    if (g_config.current_apk_path[0] != '\0' &&
        strcmp(path, g_config.current_apk_path) == 0) {
        if (g_config.original_apk_path[0] != '\0' &&
            strcmp(g_config.current_apk_path, g_config.original_apk_path) != 0) {
            strncpy(out, g_config.original_apk_path, out_len - 1);
            out[out_len - 1] = '\0';
            return true;
        }
    }

    // 检查自定义重定向
    for (int i = 0; i < g_config.redirect_count; i++) {
        if (strcmp(path, g_config.redirects[i].src_path) == 0) {
            strncpy(out, g_config.redirects[i].dst_path, out_len - 1);
            out[out_len - 1] = '\0';
            return true;
        }
    }

    // 检查是否是 APK 相关路径（模式匹配）
    if (strstr(path, "/base.apk") && strstr(path, "/data/app/") &&
        g_config.package_name[0] != '\0' && strstr(path, g_config.package_name)) {
        if (g_config.original_apk_path[0] != '\0') {
            strncpy(out, g_config.original_apk_path, out_len - 1);
            out[out_len - 1] = '\0';
            return true;
        }
    }

    return false;
}
