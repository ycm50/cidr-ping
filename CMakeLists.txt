cmake_minimum_required(VERSION 3.10)
project(cidr-ping CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

# Options to control what to build
option(BUILD_EXECUTABLE "Build the cidr-ping executable" ON)
option(BUILD_STATIC_LIB "Build a static library" OFF)
option(BUILD_SHARED_LIB "Build a shared library" OFF)

# Common source files
set(CIDR_PING_SOURCES cidr-ping.cpp wireguard.cpp)

# Executable target
if(BUILD_EXECUTABLE)
    add_executable(cidr-ping ${CIDR_PING_SOURCES})
    target_compile_definitions(cidr-ping PRIVATE MAIN)
    target_link_libraries(cidr-ping PRIVATE Threads::Threads)
    if(WIN32)
        target_link_libraries(cidr-ping PRIVATE ws2_32)
    endif()
    if(MSVC)
        target_compile_options(cidr-ping PRIVATE /utf-8)
    endif()
endif()

# Static library target
if(BUILD_STATIC_LIB)
    add_library(cidr-ping-static STATIC ${CIDR_PING_SOURCES})
    set_target_properties(cidr-ping-static PROPERTIES OUTPUT_NAME "cidr-ping")
    target_link_libraries(cidr-ping-static PUBLIC Threads::Threads)
    if(WIN32)
        # For a static lib, link options should be INTERFACE
        target_link_libraries(cidr-ping-static INTERFACE ws2_32)
    endif()
    if(MSVC)
        target_compile_options(cidr-ping-static PRIVATE /utf-8)
    endif()
endif()

# Shared library target
if(BUILD_SHARED_LIB)
    add_library(cidr-ping-shared SHARED ${CIDR_PING_SOURCES})
    set_target_properties(cidr-ping-shared PROPERTIES OUTPUT_NAME "cidr-ping")
    target_compile_definitions(cidr-ping-shared PUBLIC CIDR_PING_SHARED)
    target_link_libraries(cidr-ping-shared PRIVATE Threads::Threads)
    if(WIN32)
        target_compile_definitions(cidr-ping-shared PRIVATE CIDR_PING_EXPORTS)
    endif()
    if(WIN32)
        target_link_libraries(cidr-ping-shared PRIVATE ws2_32)
    endif()
    if(MSVC)
        target_compile_options(cidr-ping-shared PRIVATE /utf-8)
    endif()
endif()

# Unit / integration tests
# 默认开启（include(CTest) 会定义 BUILD_TESTING，默认 ON）。
# 交叉编译（如 llvm-mingw 出的 Windows 可执行文件）无法在构建机上运行，
# 这类情况下请显式传 -DBUILD_TESTING=OFF。
include(CTest)
if(BUILD_TESTING)
    add_executable(cidr-ping-tests tests/test_cidr_ping.cpp ${CIDR_PING_SOURCES})
    target_include_directories(cidr-ping-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(cidr-ping-tests PRIVATE Threads::Threads)
    if(WIN32)
        target_link_libraries(cidr-ping-tests PRIVATE ws2_32)
    endif()
    if(MSVC)
        target_compile_options(cidr-ping-tests PRIVATE /utf-8)
    endif()
    add_test(NAME cidr-ping-tests COMMAND cidr-ping-tests)
    # 测试会在工作目录下反复写 rtts.csv，固定到构建目录，避免污染源码树
    set_tests_properties(cidr-ping-tests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        TIMEOUT 900)
endif()

# sort-rtts executable
add_executable(sort-rtts sort-rtts.cpp)
target_link_libraries(sort-rtts PRIVATE Threads::Threads)
add_executable(multy_apply multy_apply.cpp ${CIDR_PING_SOURCES})
target_link_libraries(multy_apply PRIVATE Threads::Threads)
if(WIN32)
    target_link_libraries(multy_apply PRIVATE ws2_32)
endif()