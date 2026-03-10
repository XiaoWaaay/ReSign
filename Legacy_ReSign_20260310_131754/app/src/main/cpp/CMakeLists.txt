cmake_minimum_required(VERSION 3.22.1)

project("killsignture")

# 1. 设置头文件目录 (确保能找到 include/bytehook.h)
# ${CMAKE_SOURCE_DIR} 指向当前 CMakeLists.txt 所在目录 (app/src/main/cpp)
include_directories(${CMAKE_SOURCE_DIR}/include)

# 2. 引入 ByteHook 静态库 (libbhk_61e9a2d7.a)
# 根据你的文件结构，它位于 app/src/main/include/，即 cpp 目录的上一级同级 include
add_library(bytehook_static STATIC IMPORTED)
set_target_properties(bytehook_static PROPERTIES IMPORTED_LOCATION
        "${CMAKE_SOURCE_DIR}/../include/libbhk_61e9a2d7.a")

# 3. 你的主库
add_library(${CMAKE_PROJECT_NAME} SHARED
        killsignture.cpp)

# 启用 ByteHook 代码路径（killsignture.cpp 内用宏控制）
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE RESIG_HAS_BYTEHOOK=1)

# 4. 链接 (静态链接 bytehook，避免运行时依赖)
target_link_libraries(${CMAKE_PROJECT_NAME}
        bytehook_static
        android
        log)
