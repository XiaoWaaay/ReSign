
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

project("killsignture")

add_library(${CMAKE_PROJECT_NAME} SHARED
        killsignture.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_link_libraries(${CMAKE_PROJECT_NAME}
            ${CMAKE_CURRENT_LIST_DIR}/../include/libdobby.a)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE RESIG_HAS_DOBBY=1)
endif()
