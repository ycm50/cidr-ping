cmake_minimum_required(VERSION 3.22)
project(cidr-ping CXX)  # 明确指定是 C 项目

set(CMAKE_C_STANDARD 23)      # 改为 C23 标准
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_COMPILER "g++" )
add_executable(cidr-ping cidr-ping.cpp)
add_executable(sort-rtts sort-rtts.cpp)
target_compile_features(sort-rtts PRIVATE cxx_std_11)

# 为 Windows (MSVC) 添加 UTF-8 支持, 这有助于正确处理源代码和输出中的中文字符
if(MSVC)
    target_compile_options(cidr-ping PRIVATE /utf-8)
endif()

# 为 Windows 平台链接 Winsock 库
if(WIN32)
    target_link_libraries(cidr-ping PRIVATE ws2_32)
endif()