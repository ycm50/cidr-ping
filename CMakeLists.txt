cmake_minimum_required(VERSION 3.22)
project(cidr-ping CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options to control what to build
option(BUILD_EXECUTABLE "Build the cidr-ping executable" ON)
option(BUILD_STATIC_LIB "Build a static library" OFF)
option(BUILD_SHARED_LIB "Build a shared library" OFF)

# Common source files
set(CIDR_PING_SOURCES cidr-ping.cpp)

# Executable target
if(BUILD_EXECUTABLE)
    add_executable(cidr-ping ${CIDR_PING_SOURCES})
    target_compile_definitions(cidr-ping PRIVATE MAIN)
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

# sort-rtts executable
add_executable(sort-rtts sort-rtts.cpp)