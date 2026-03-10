# ReSignPro Native Engine CMakeLists.txt
#
# 构建 librepack_native.so
# 包含：IO重定向、PLT Hook、Maps隐藏、Seccomp过滤

cmake_minimum_required(VERSION 3.22.1)
project("repack_native" C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# 优化和安全编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--exclude-libs,ALL")

# 针对不同架构的特定标志
if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=armv8-a")
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=armv7-a -mfpu=neon")
endif()

# 源文件
set(NATIVE_SOURCES
    native_engine.cpp
    io_redirect.cpp
    plt_hook.cpp
    maps_hide.cpp
    seccomp_filter.cpp
)

# 头文件
set(NATIVE_HEADERS
    common.h
    io_redirect.h
    plt_hook.h
    maps_hide.h
    seccomp_filter.h
)

# 构建共享库
add_library(repack_native SHARED ${NATIVE_SOURCES})

# 链接库
target_link_libraries(repack_native
    android        # Android NDK 基础库
    log            # __android_log_print
    dl             # dlopen, dlsym, dl_iterate_phdr
)

# 包含目录
target_include_directories(repack_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Release 模式下启用 LTO
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set_property(TARGET repack_native PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    target_compile_options(repack_native PRIVATE -O2 -DNDEBUG)
endif()

# Strip 调试信息（Release）
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET repack_native POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:repack_native>
        COMMENT "Stripping repack_native"
    )
endif()
