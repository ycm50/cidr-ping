cmake_minimum_required(VERSION 3.10)
project(cidr-ping CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

# Options to control what to build
option(BUILD_EXECUTABLE "Build the cidr-ping executable" ON)
option(BUILD_STATIC_LIB "Build a static library" OFF)
option(BUILD_SHARED_LIB "Build a shared library" OFF)
option(CIDR_PING_WARNINGS "Enable extra compiler warnings" ON)

# Common source files
set(CIDR_PING_SOURCES cidr-ping.cpp wireguard.cpp)
set(CIDR_PING_HEADERS cidr-ping.h wireguard.h text-util.h rtts-sort.h)

# 统一加告警（只对 GCC/Clang 生效，MSVC 走 /utf-8）
function(cidr_ping_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /utf-8 /W4)
    elseif(CIDR_PING_WARNINGS)
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# Executable target
if(BUILD_EXECUTABLE)
    add_executable(cidr-ping ${CIDR_PING_SOURCES} ${CIDR_PING_HEADERS})
    target_compile_definitions(cidr-ping PRIVATE MAIN)
    target_link_libraries(cidr-ping PRIVATE Threads::Threads)
    if(WIN32)
        target_link_libraries(cidr-ping PRIVATE ws2_32)
    endif()
    cidr_ping_apply_warnings(cidr-ping)
endif()

# Static library target
if(BUILD_STATIC_LIB)
    add_library(cidr-ping-static STATIC ${CIDR_PING_SOURCES} ${CIDR_PING_HEADERS})
    set_target_properties(cidr-ping-static PROPERTIES OUTPUT_NAME "cidr-ping")
    target_link_libraries(cidr-ping-static PUBLIC Threads::Threads)
    if(WIN32)
        target_link_libraries(cidr-ping-static INTERFACE ws2_32)
    endif()
    cidr_ping_apply_warnings(cidr-ping-static)
endif()

# Shared library target
if(BUILD_SHARED_LIB)
    add_library(cidr-ping-shared SHARED ${CIDR_PING_SOURCES} ${CIDR_PING_HEADERS})
    set_target_properties(cidr-ping-shared PROPERTIES OUTPUT_NAME "cidr-ping")
    target_compile_definitions(cidr-ping-shared PUBLIC CIDR_PING_SHARED)
    target_link_libraries(cidr-ping-shared PRIVATE Threads::Threads)
    if(WIN32)
        target_compile_definitions(cidr-ping-shared PRIVATE CIDR_PING_EXPORTS)
        target_link_libraries(cidr-ping-shared PRIVATE ws2_32)
    endif()
    cidr_ping_apply_warnings(cidr-ping-shared)
endif()

# Unit / integration tests
# 默认开启（include(CTest) 会定义 BUILD_TESTING，默认 ON）。
# 交叉编译（如 llvm-mingw 出的 Windows 可执行文件）无法在构建机上运行，
# 这类情况下请显式传 -DBUILD_TESTING=OFF。
include(CTest)
if(BUILD_TESTING)
    add_executable(cidr-ping-tests tests/test_cidr_ping.cpp ${CIDR_PING_SOURCES} ${CIDR_PING_HEADERS})
    target_include_directories(cidr-ping-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(cidr-ping-tests PRIVATE Threads::Threads)
    if(WIN32)
        target_link_libraries(cidr-ping-tests PRIVATE ws2_32)
    endif()
    cidr_ping_apply_warnings(cidr-ping-tests)
    add_test(NAME cidr-ping-tests COMMAND cidr-ping-tests)
    # 测试会在工作目录下反复写 rtts.csv，固定到构建目录，避免污染源码树
    set_tests_properties(cidr-ping-tests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        TIMEOUT 900)

    # 纯文本工具（严格数值解析 / CSV 转义与解析）单独一个轻量测试目标
    add_executable(cidr-ping-text-tests tests/test_text_util.cpp)
    target_include_directories(cidr-ping-text-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    cidr_ping_apply_warnings(cidr-ping-text-tests)
    add_test(NAME cidr-ping-text-tests COMMAND cidr-ping-text-tests)
    set_tests_properties(cidr-ping-text-tests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        TIMEOUT 120)

    # rtts-sort.h（读 CSV / 排序 / 写 CSV）的测试
    add_executable(cidr-ping-sort-tests tests/test_sort_rtts.cpp)
    target_include_directories(cidr-ping-sort-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    cidr_ping_apply_warnings(cidr-ping-sort-tests)
    add_test(NAME cidr-ping-sort-tests COMMAND cidr-ping-sort-tests)
    set_tests_properties(cidr-ping-sort-tests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        TIMEOUT 120)
endif()

# sort-rtts executable
add_executable(sort-rtts sort-rtts.cpp rtts-sort.h text-util.h)
target_include_directories(sort-rtts PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sort-rtts PRIVATE Threads::Threads)
cidr_ping_apply_warnings(sort-rtts)

# multy_apply executable
add_executable(multy_apply multy_apply.cpp ${CIDR_PING_SOURCES} ${CIDR_PING_HEADERS})
target_link_libraries(multy_apply PRIVATE Threads::Threads)
if(WIN32)
    target_link_libraries(multy_apply PRIVATE ws2_32)
endif()
cidr_ping_apply_warnings(multy_apply)