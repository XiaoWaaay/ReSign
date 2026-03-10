/**
 * ReSignPro - PLT Hook Implementation
 *
 * ELF GOT/PLT Hook 引擎实现
 *
 * 原理：
 * 1. 遍历 /proc/self/maps 获取所有已加载的 ELF 文件
 * 2. 对每个 ELF 文件解析 ELF header -> Program header -> Dynamic segment
 * 3. 在 Dynamic segment 中找到 DT_JMPREL (PLT relocation table) 和 DT_REL/DT_RELA
 * 4. 在重定位表中查找目标符号（如 openat）
 * 5. 修改对应 GOT 表项为我们的 hook 函数地址
 * 6. 保存原始函数地址用于回调
 */

#include "plt_hook.h"
#include "io_redirect.h"

#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

// ==================== 平台适配 ====================

#if defined(__LP64__)
typedef Elf64_Ehdr ElfW_Ehdr;
typedef Elf64_Phdr ElfW_Phdr;
typedef Elf64_Dyn  ElfW_Dyn;
typedef Elf64_Sym  ElfW_Sym;
typedef Elf64_Rel  ElfW_Rel;
typedef Elf64_Rela ElfW_Rela;
#define ELF_R_SYM(x)  ELF64_R_SYM(x)
#define ELF_R_TYPE(x)  ELF64_R_TYPE(x)
#else
typedef Elf32_Ehdr ElfW_Ehdr;
typedef Elf32_Phdr ElfW_Phdr;
typedef Elf32_Dyn  ElfW_Dyn;
typedef Elf32_Sym  ElfW_Sym;
typedef Elf32_Rel  ElfW_Rel;
typedef Elf32_Rela ElfW_Rela;
#define ELF_R_SYM(x)  ELF32_R_SYM(x)
#define ELF_R_TYPE(x)  ELF32_R_TYPE(x)
#endif

// ==================== 全局状态 ====================

static bool g_plt_active = false;

// 原始函数指针
static void *g_orig_openat = nullptr;
static void *g_orig___openat_2 = nullptr;
static void *g_orig_fstatat = nullptr;
static void *g_orig_faccessat = nullptr;
static void *g_orig_readlinkat = nullptr;
static void *g_orig_statx = nullptr;
static void *g_orig_execve = nullptr;

// Hook 表
static PltHookEntry g_hook_entries[] = {
    {"openat",       (void *) hook_openat,       &g_orig_openat},
    {"__openat_2",   (void *) hook___openat_2,   &g_orig___openat_2},
    {"fstatat64",    (void *) hook_fstatat,       &g_orig_fstatat},
    {"__fstatat64",  (void *) hook_fstatat,       &g_orig_fstatat},
    {"fstatat",      (void *) hook_fstatat,       &g_orig_fstatat},
    {"faccessat",    (void *) hook_faccessat,     &g_orig_faccessat},
    {"readlinkat",   (void *) hook_readlinkat,    &g_orig_readlinkat},
#ifdef SYS_STATX
    {"statx",        (void *) hook_statx,         &g_orig_statx},
#endif
    {nullptr, nullptr, nullptr}  // sentinel
};

// ==================== ELF 解析 ====================

/**
 * 在 ELF 的 dynamic segment 中查找指定 tag
 */
static ElfW_Dyn* find_dynamic_entry(ElfW_Dyn *dyn_array, int tag) {
    for (ElfW_Dyn *d = dyn_array; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == tag) return d;
    }
    return nullptr;
}

/**
 * 对单个 ELF 模块执行 GOT hook
 *
 * @param base      模块基地址
 * @param bias      加载偏移
 * @param entries   要 hook 的符号列表
 */
static int hook_elf_module(uintptr_t base, uintptr_t bias, PltHookEntry *entries) {
    ElfW_Ehdr *ehdr = (ElfW_Ehdr *) base;

    // 验证 ELF magic
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return -1;
    }

    // 查找 PT_DYNAMIC
    ElfW_Phdr *phdr = (ElfW_Phdr *)(base + ehdr->e_phoff);
    ElfW_Dyn *dyn_array = nullptr;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn_array = (ElfW_Dyn *)(bias + phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn_array) return -1;

    // 获取关键 dynamic 表项
    ElfW_Dyn *dt_strtab = find_dynamic_entry(dyn_array, DT_STRTAB);
    ElfW_Dyn *dt_symtab = find_dynamic_entry(dyn_array, DT_SYMTAB);
    ElfW_Dyn *dt_jmprel = find_dynamic_entry(dyn_array, DT_JMPREL);
    ElfW_Dyn *dt_pltrelsz = find_dynamic_entry(dyn_array, DT_PLTRELSZ);
    ElfW_Dyn *dt_pltrel = find_dynamic_entry(dyn_array, DT_PLTREL);

    if (!dt_strtab || !dt_symtab) return -1;

    const char *strtab = (const char *)(bias + dt_strtab->d_un.d_ptr);
    ElfW_Sym *symtab = (ElfW_Sym *)(bias + dt_symtab->d_un.d_ptr);

    int hooked_count = 0;

    // 处理 PLT 重定位 (DT_JMPREL)
    if (dt_jmprel && dt_pltrelsz && dt_pltrel) {
        size_t rel_count;
        bool is_rela = (dt_pltrel->d_un.d_val == DT_RELA);

        if (is_rela) {
            rel_count = dt_pltrelsz->d_un.d_val / sizeof(ElfW_Rela);
            ElfW_Rela *rela = (ElfW_Rela *)(bias + dt_jmprel->d_un.d_ptr);

            for (size_t i = 0; i < rel_count; i++) {
                uint32_t sym_idx = ELF_R_SYM(rela[i].r_info);
                if (sym_idx == 0) continue;

                const char *sym_name = strtab + symtab[sym_idx].st_name;

                for (PltHookEntry *e = entries; e->symbol_name; e++) {
                    if (strcmp(sym_name, e->symbol_name) == 0) {
                        // 找到目标符号，修改 GOT 表项
                        void **got_addr = (void **)(bias + rela[i].r_offset);

                        // 保存原始函数地址（只保存第一次遇到的）
                        if (*(e->orig_func_ptr) == nullptr) {
                            *(e->orig_func_ptr) = *got_addr;
                        }

                        // 修改 GOT 表项的内存保护
                        uintptr_t page_start = (uintptr_t) got_addr & ~(getpagesize() - 1);
                        size_t page_size = getpagesize();

                        if (mprotect((void *) page_start, page_size,
                                     PROT_READ | PROT_WRITE) == 0) {
                            *got_addr = e->new_func;
                            mprotect((void *) page_start, page_size, PROT_READ);
                            hooked_count++;
                        }
                        break;
                    }
                }
            }
        } else {
            // DT_REL (32-bit)
            rel_count = dt_pltrelsz->d_un.d_val / sizeof(ElfW_Rel);
            ElfW_Rel *rel = (ElfW_Rel *)(bias + dt_jmprel->d_un.d_ptr);

            for (size_t i = 0; i < rel_count; i++) {
                uint32_t sym_idx = ELF_R_SYM(rel[i].r_info);
                if (sym_idx == 0) continue;

                const char *sym_name = strtab + symtab[sym_idx].st_name;

                for (PltHookEntry *e = entries; e->symbol_name; e++) {
                    if (strcmp(sym_name, e->symbol_name) == 0) {
                        void **got_addr = (void **)(bias + rel[i].r_offset);

                        if (*(e->orig_func_ptr) == nullptr) {
                            *(e->orig_func_ptr) = *got_addr;
                        }

                        uintptr_t page_start = (uintptr_t) got_addr & ~(getpagesize() - 1);
                        if (mprotect((void *) page_start, getpagesize(),
                                     PROT_READ | PROT_WRITE) == 0) {
                            *got_addr = e->new_func;
                            mprotect((void *) page_start, getpagesize(), PROT_READ);
                            hooked_count++;
                        }
                        break;
                    }
                }
            }
        }
    }

    // 也处理 DT_REL/DT_RELA (非 PLT 的 GOT 重定位)
    ElfW_Dyn *dt_rel = find_dynamic_entry(dyn_array, DT_REL);
    ElfW_Dyn *dt_relsz = find_dynamic_entry(dyn_array, DT_RELSZ);
    ElfW_Dyn *dt_rela = find_dynamic_entry(dyn_array, DT_RELA);
    ElfW_Dyn *dt_relasz = find_dynamic_entry(dyn_array, DT_RELASZ);

    if (dt_rela && dt_relasz) {
        size_t count = dt_relasz->d_un.d_val / sizeof(ElfW_Rela);
        ElfW_Rela *rela = (ElfW_Rela *)(bias + dt_rela->d_un.d_ptr);

        for (size_t i = 0; i < count; i++) {
            uint32_t sym_idx = ELF_R_SYM(rela[i].r_info);
            if (sym_idx == 0) continue;

            const char *sym_name = strtab + symtab[sym_idx].st_name;

            for (PltHookEntry *e = entries; e->symbol_name; e++) {
                if (strcmp(sym_name, e->symbol_name) == 0) {
                    void **got_addr = (void **)(bias + rela[i].r_offset);

                    if (*(e->orig_func_ptr) == nullptr) {
                        *(e->orig_func_ptr) = *got_addr;
                    }

                    uintptr_t page_start = (uintptr_t) got_addr & ~(getpagesize() - 1);
                    if (mprotect((void *) page_start, getpagesize(),
                                 PROT_READ | PROT_WRITE) == 0) {
                        *got_addr = e->new_func;
                        mprotect((void *) page_start, getpagesize(), PROT_READ);
                        hooked_count++;
                    }
                    break;
                }
            }
        }
    } else if (dt_rel && dt_relsz) {
        size_t count = dt_relsz->d_un.d_val / sizeof(ElfW_Rel);
        ElfW_Rel *rel = (ElfW_Rel *)(bias + dt_rel->d_un.d_ptr);

        for (size_t i = 0; i < count; i++) {
            uint32_t sym_idx = ELF_R_SYM(rel[i].r_info);
            if (sym_idx == 0) continue;

            const char *sym_name = strtab + symtab[sym_idx].st_name;

            for (PltHookEntry *e = entries; e->symbol_name; e++) {
                if (strcmp(sym_name, e->symbol_name) == 0) {
                    void **got_addr = (void **)(bias + rel[i].r_offset);

                    if (*(e->orig_func_ptr) == nullptr) {
                        *(e->orig_func_ptr) = *got_addr;
                    }

                    uintptr_t page_start = (uintptr_t) got_addr & ~(getpagesize() - 1);
                    if (mprotect((void *) page_start, getpagesize(),
                                 PROT_READ | PROT_WRITE) == 0) {
                        *got_addr = e->new_func;
                        mprotect((void *) page_start, getpagesize(), PROT_READ);
                        hooked_count++;
                    }
                    break;
                }
            }
        }
    }

    return hooked_count;
}

// ==================== 模块枚举 ====================

/**
 * 遍历 /proc/self/maps 枚举已加载模块
 */
int plt_hook_enum_modules(void (*callback)(const char *path, void *base, void *userdata),
                          void *userdata) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;

    char line[1024];
    char last_path[512] = {0};
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        // 格式: addr_start-addr_end perms offset dev inode pathname
        uintptr_t start, end;
        char perms[5], path[512];
        unsigned int offset;
        int dev_major, dev_minor;
        unsigned long inode;

        path[0] = '\0';
        int n = sscanf(line, "%lx-%lx %4s %x %x:%x %lu %511s",
                       &start, &end, perms, &offset, &dev_major, &dev_minor,
                       &inode, path);

        if (n < 7) continue;

        // 只处理可执行段 (r-xp)，且是文件映射
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        if (path[0] != '/' || path[0] == '[') continue;
        if (offset != 0) continue; // 只关心第一个映射段（ELF header所在）

        // 去重
        if (strcmp(path, last_path) == 0) continue;
        safe_strncpy(last_path, path, sizeof(last_path));

        // 跳过 linker 和 vdso
        if (strstr(path, "/linker") || strstr(path, "[vdso]")) continue;

        callback(path, (void *) start, userdata);
        count++;
    }

    fclose(fp);
    return count;
}

/**
 * dl_iterate_phdr 回调 —— 处理每个 ELF 模块
 */
static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

    // 跳过 linker
    if (strstr(info->dlpi_name, "linker")) return 0;

    // 跳过 ReSignPro 自己的库（避免自我 hook 导致死循环）
    if (strstr(info->dlpi_name, "librepack_native.so")) return 0;

    uintptr_t base = (uintptr_t) info->dlpi_addr;

    // 查找实际加载基址
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            base = (uintptr_t) info->dlpi_addr + info->dlpi_phdr[i].p_vaddr
                   - info->dlpi_phdr[i].p_offset;

            // 验证 ELF magic
            if (memcmp((void *) base, ELFMAG, SELFMAG) == 0) {
                int ret = hook_elf_module(base, (uintptr_t) info->dlpi_addr,
                                          g_hook_entries);
                if (ret > 0) {
                    LOGD("Hooked %d symbols in %s", ret, info->dlpi_name);
                }
            }
            break;
        }
    }

    return 0;
}

// ==================== 公开 API ====================

int plt_hook_install(const RedirectConfig *config) {
    LOGI("PLT Hook: installing hooks on all loaded modules...");

    // 使用 dl_iterate_phdr 遍历所有已加载的共享库
    dl_iterate_phdr(dl_iterate_callback, nullptr);

    // 将原始函数指针传递给 io_redirect 模块
    if (g_orig_openat) {
        io_redirect_set_orig_openat(g_orig_openat);
    }
    if (g_orig___openat_2) {
        io_redirect_set_orig___openat_2(g_orig___openat_2);
    }
    if (g_orig_fstatat) {
        io_redirect_set_orig_fstatat(g_orig_fstatat);
    }
    if (g_orig_faccessat) {
        io_redirect_set_orig_faccessat(g_orig_faccessat);
    }
    if (g_orig_readlinkat) {
        io_redirect_set_orig_readlinkat(g_orig_readlinkat);
    }
    if (g_orig_statx) {
        io_redirect_set_orig_statx(g_orig_statx);
    }
    if (g_orig_execve) {
        io_redirect_set_orig_execve(g_orig_execve);
    }

    g_plt_active = true;
    LOGI("PLT Hook: installation complete");
    return 0;
}

int plt_hook_apply_to_library(const char *lib_path) {
    if (!g_plt_active) return -1;

    // 获取库的加载基址
    void *handle = dlopen(lib_path, RTLD_NOLOAD);
    if (!handle) return -1;

    // 通过 dl_iterate_phdr 查找该库的信息
    dl_iterate_phdr(dl_iterate_callback, nullptr);
    dlclose(handle);

    return 0;
}

bool plt_hook_is_active(void) {
    return g_plt_active;
}

int plt_hook_single(void *elf_base, const char *symbol, void *new_func, void **old_func) {
    PltHookEntry entries[2];
    entries[0].symbol_name = symbol;
    entries[0].new_func = new_func;
    entries[0].orig_func_ptr = old_func;
    entries[1].symbol_name = nullptr;
    entries[1].new_func = nullptr;
    entries[1].orig_func_ptr = nullptr;

    return hook_elf_module((uintptr_t) elf_base, (uintptr_t) elf_base, entries);
}
