// Copyright (c) 2020-2024 ByteDance, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#ifndef BYTEDANCE_BYTEHOOK_H
#define BYTEDANCE_BYTEHOOK_H 1

#include <stdbool.h>
#include <stdint.h>

#define BYTEHOOK_VERSION "1.1.1"

#if defined(__GNUC__) || defined(__clang__)
#define BYTEHOOK_API __attribute__((visibility("default")))
#else
#define BYTEHOOK_API
#endif

#define bytehook_get_version         bhk_5c2f6e9a
#define bytehook_init                bhk_9b1d3f7a
#define bytehook_hook_single         bhk_a7c1e2d4
#define bytehook_hook_partial        bhk_3e8a0c1f
#define bytehook_hook_all            bhk_6d4b2a9c
#define bytehook_unhook              bhk_1f0c9e3a
#define bytehook_add_ignore          bhk_b8e2d1c4
#define bytehook_get_mode            bhk_0a7d2c8e
#define bytehook_get_debug           bhk_4e1c7a0b
#define bytehook_set_debug           bhk_2b9f0d6c
#define bytehook_get_recordable      bhk_8d3a1c7e
#define bytehook_set_recordable      bhk_c1e7b4a2
#define bytehook_get_records         bhk_7a2c0e9d
#define bytehook_dump_records        bhk_0c6e3a9f
#define bytehook_get_prev_func       bhk_e1a8d3c0
#define bytehook_pop_stack           bhk_3c0f8a1d
#define bytehook_get_return_address  bhk_9d2a7c0e
#define bytehook_add_dlopen_callback bhk_a0d1e2f3
#define bytehook_del_dlopen_callback bhk_1e2f3a4b

#define BYTEHOOK_STATUS_CODE_OK                  0
#define BYTEHOOK_STATUS_CODE_UNINIT              1
#define BYTEHOOK_STATUS_CODE_INITERR_INVALID_ARG 2
#define BYTEHOOK_STATUS_CODE_INITERR_SYM         3
#define BYTEHOOK_STATUS_CODE_INITERR_TASK        4
#define BYTEHOOK_STATUS_CODE_INITERR_HOOK        5
#define BYTEHOOK_STATUS_CODE_INITERR_ELF         6
#define BYTEHOOK_STATUS_CODE_INITERR_ELF_REFR    7
#define BYTEHOOK_STATUS_CODE_INITERR_TRAMPO      8
#define BYTEHOOK_STATUS_CODE_INITERR_SIG         9
#define BYTEHOOK_STATUS_CODE_INITERR_DLMTR       10
#define BYTEHOOK_STATUS_CODE_INVALID_ARG         11
#define BYTEHOOK_STATUS_CODE_UNMATCH_ORIG_FUNC   12
#define BYTEHOOK_STATUS_CODE_NOSYM               13
#define BYTEHOOK_STATUS_CODE_GET_PROT            14
#define BYTEHOOK_STATUS_CODE_SET_PROT            15
#define BYTEHOOK_STATUS_CODE_SET_GOT             16
#define BYTEHOOK_STATUS_CODE_NEW_TRAMPO          17
#define BYTEHOOK_STATUS_CODE_APPEND_TRAMPO       18
#define BYTEHOOK_STATUS_CODE_GOT_VERIFY          19
#define BYTEHOOK_STATUS_CODE_REPEATED_FUNC       20
#define BYTEHOOK_STATUS_CODE_READ_ELF            21
#define BYTEHOOK_STATUS_CODE_CFI_HOOK_FAILED     22
#define BYTEHOOK_STATUS_CODE_ORIG_ADDR           23
#define BYTEHOOK_STATUS_CODE_INITERR_CFI         24
#define BYTEHOOK_STATUS_CODE_IGNORE              25
#define BYTEHOOK_STATUS_CODE_INITERR_SAFE        26
#define BYTEHOOK_STATUS_CODE_INITERR_HUB         27
#define BYTEHOOK_STATUS_CODE_OOM                 28
#define BYTEHOOK_STATUS_CODE_DUP                 29
#define BYTEHOOK_ERRNO_NOT_FOUND                 30
#define BYTEHOOK_STATUS_CODE_MAX                 255

#define BYTEHOOK_MODE_AUTOMATIC 0
#define BYTEHOOK_MODE_MANUAL    1

#ifdef __cplusplus
extern "C" {
#endif

BYTEHOOK_API const char *bytehook_get_version(void);

typedef void *bytehook_stub_t;

typedef void (*bytehook_hooked_t)(bytehook_stub_t task_stub, int status_code, const char *caller_path_name,
                                  const char *sym_name, void *new_func, void *prev_func, void *arg);

typedef bool (*bytehook_caller_allow_filter_t)(const char *caller_path_name, void *arg);

BYTEHOOK_API int bytehook_init(int mode, bool debug);

BYTEHOOK_API bytehook_stub_t bytehook_hook_single(const char *caller_path_name, const char *callee_path_name,
                                                  const char *sym_name, void *new_func, bytehook_hooked_t hooked,
                                                  void *hooked_arg);

BYTEHOOK_API bytehook_stub_t bytehook_hook_partial(bytehook_caller_allow_filter_t caller_allow_filter,
                                                   void *caller_allow_filter_arg, const char *callee_path_name,
                                                   const char *sym_name, void *new_func, bytehook_hooked_t hooked,
                                                   void *hooked_arg);

BYTEHOOK_API bytehook_stub_t bytehook_hook_all(const char *callee_path_name, const char *sym_name, void *new_func,
                                               bytehook_hooked_t hooked, void *hooked_arg);

BYTEHOOK_API int bytehook_unhook(bytehook_stub_t stub);

BYTEHOOK_API int bytehook_add_ignore(const char *caller_path_name);

#define BYTEHOOK_IS_AUTOMATIC_MODE (BYTEHOOK_MODE_AUTOMATIC == bytehook_get_mode())
#define BYTEHOOK_IS_MANUAL_MODE    (BYTEHOOK_MODE_MANUAL == bytehook_get_mode())
BYTEHOOK_API int bytehook_get_mode(void);
BYTEHOOK_API bool bytehook_get_debug(void);
BYTEHOOK_API void bytehook_set_debug(bool debug);
BYTEHOOK_API bool bytehook_get_recordable(void);
BYTEHOOK_API void bytehook_set_recordable(bool recordable);

#define BYTEHOOK_RECORD_ITEM_ALL             0xFF
#define BYTEHOOK_RECORD_ITEM_TIMESTAMP       (1 << 0)
#define BYTEHOOK_RECORD_ITEM_CALLER_LIB_NAME (1 << 1)
#define BYTEHOOK_RECORD_ITEM_OP              (1 << 2)
#define BYTEHOOK_RECORD_ITEM_LIB_NAME        (1 << 3)
#define BYTEHOOK_RECORD_ITEM_SYM_NAME        (1 << 4)
#define BYTEHOOK_RECORD_ITEM_NEW_ADDR        (1 << 5)
#define BYTEHOOK_RECORD_ITEM_ERRNO           (1 << 6)
#define BYTEHOOK_RECORD_ITEM_STUB            (1 << 7)
BYTEHOOK_API char *bytehook_get_records(uint32_t item_flags);
BYTEHOOK_API void bytehook_dump_records(int fd, uint32_t item_flags);

BYTEHOOK_API void *bytehook_get_prev_func(void *func);

BYTEHOOK_API void bytehook_pop_stack(void *return_address);

BYTEHOOK_API void *bytehook_get_return_address(void);

typedef void (*bytehook_pre_dlopen_t)(const char *filename, void *data);

typedef void (*bytehook_post_dlopen_t)(const char *filename,
                                       int result,
                                       void *data);

BYTEHOOK_API void bytehook_add_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data);

BYTEHOOK_API void bytehook_del_dlopen_callback(bytehook_pre_dlopen_t pre, bytehook_post_dlopen_t post, void *data);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#define BYTEHOOK_CALL_PREV(func, ...) ((decltype(&(func)))bytehook_get_prev_func((void *)(func)))(__VA_ARGS__)
#else
#define BYTEHOOK_CALL_PREV(func, func_sig, ...) \
  ((func_sig)bytehook_get_prev_func((void *)(func)))(__VA_ARGS__)
#endif

#define BYTEHOOK_RETURN_ADDRESS()                                                          \
  ((void *)(BYTEHOOK_MODE_AUTOMATIC == bytehook_get_mode() ? bytehook_get_return_address() \
                                                           : __builtin_return_address(0)))

#define BYTEHOOK_POP_STACK()                                                                             \
  do {                                                                                                   \
    if (BYTEHOOK_MODE_AUTOMATIC == bytehook_get_mode()) bytehook_pop_stack(__builtin_return_address(0)); \
  } while (0)

#ifdef __cplusplus
class BytehookStackScope {
 public:
  BytehookStackScope(void *return_address) : return_address_(return_address) {}

  ~BytehookStackScope() {
    if (BYTEHOOK_MODE_AUTOMATIC == bytehook_get_mode()) bytehook_pop_stack(return_address_);
  }

 private:
  void *return_address_;
};

#define BYTEHOOK_STACK_SCOPE() BytehookStackScope bytehook_stack_scope(__builtin_return_address(0))
#endif

#endif
