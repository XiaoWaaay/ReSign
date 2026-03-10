/**
 * ReSignPro - Maps Hide Header
 *
 * /proc/self/maps 内容过滤
 * 阻止应用通过读取 maps 文件发现注入痕迹
 */

#ifndef RESIGN_PRO_MAPS_HIDE_H
#define RESIGN_PRO_MAPS_HIDE_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// 最大过滤关键词数
#define MAX_MAPS_FILTERS 32
// 最大替换规则数
#define MAX_MAPS_REPLACES 8

/**
 * 安装 maps 隐藏功能
 *
 * 实现方案：
 * 1. 使用 memfd_create 创建内存文件
 * 2. 读取真实 /proc/self/maps
 * 3. 过滤掉包含指定关键词的行
 * 4. 对路径执行字符串替换
 * 5. 将过滤后的内容写入 memfd
 * 6. 通过 IO redirect 将 /proc/self/maps 的 fd 重定向到 memfd
 *
 * @param config 配置
 * @return 0 成功
 */
int maps_hide_install(const RedirectConfig *config);

/**
 * 添加过滤关键词
 * maps 中包含该关键词的行会被删除
 */
void maps_hide_add_filter(const char *keyword);

/**
 * 设置字符串替换
 * maps 中 old_str 会被替换为 new_str
 */
void maps_hide_set_replace(const char *old_str, const char *new_str);

/**
 * 获取过滤关键词数量
 */
int maps_hide_filter_count(void);

/**
 * 获取过滤后的 maps fd
 * 如果尚未生成过滤内容，触发生成
 *
 * @return 内存文件 fd, 或 -1
 */
int maps_hide_get_filtered_fd(void);

/**
 * 刷新过滤缓存
 * 当有新的 so 加载后应调用此函数
 */
void maps_hide_refresh(void);

/**
 * 检查路径是否需要被过滤
 * 用于 openat 等 hook 中判断 /proc/self/maps 或 /proc/<pid>/maps
 */
bool maps_hide_is_maps_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif // RESIGN_PRO_MAPS_HIDE_H
