cmake_minimum_required(VERSION 3.22)
project(cidr-ping C)  # 明确指定是 C 项目

set(CMAKE_C_STANDARD 23)      # 改为 C23 标准
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(cidr-ping telnet_delay_test_general.c)