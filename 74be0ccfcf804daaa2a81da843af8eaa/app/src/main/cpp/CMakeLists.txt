cmake_minimum_required(VERSION 3.22.1)
project("resign_native" C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# 安全编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--exclude-libs,ALL")

# ===== Dobby Inline Hook Framework =====
include(FetchContent)
FetchContent_Declare(
    dobby
    GIT_REPOSITORY https://github.com/jmpews/Dobby.git
    GIT_TAG master
)
FetchContent_MakeAvailable(dobby)

# ===== 库1: native_killer (SignatureKiller Native 层) =====
set(KILLER_SOURCES
    native_killer.cpp
    io_redirect.cpp
    maps_hide.cpp
    seccomp_handler.cpp
)

add_library(native_killer SHARED ${KILLER_SOURCES})

target_link_libraries(native_killer
    android
    log
    dl
    dobby
)

target_include_directories(native_killer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${dobby_SOURCE_DIR}/include
)

# ===== 库2: native-lib (原始签名校验库) =====
add_library(native-lib SHARED native-lib.cpp)

target_link_libraries(native-lib
    android
    log
)

# ===== Release 优化 =====
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(native_killer PRIVATE -O2 -DNDEBUG)
    target_compile_options(native-lib PRIVATE -O2 -DNDEBUG)
endif()
