cmake_minimum_required(VERSION 3.13)
project(dlalloc C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_BUILD_TYPE Debug)

option(LOCKS "LOCKS" OFF)
option(FOOTERS "FOOTERS" OFF)

if (NOT CMAKE_BUILD_TYPE)
    if ("${CMAKE_BINARY_DIR}" MATCHES ".*(D|d)ebug$")
        message(STATUS "No build type selected, default to *** Debug ***")
        set(CMAKE_BUILD_TYPE "Debug")
    else ()
        message(STATUS "No build type selected, default to *** Release ***")
        set(CMAKE_BUILD_TYPE "Release")
    endif ()
else ()
    message(STATUS "Build type specified as *** ${CMAKE_BUILD_TYPE} ***")
endif ()

if (CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang|GNU")
    list(APPEND dlalloc_flags -Wall -Wextra)
endif ()

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    list(APPEND dlalloc_defines DEBUG=1)
endif ()

if (LOCKS MATCHES "ON")
    list(APPEND dlalloc_defines USE_LOCKS=1)
endif ()

if (FOOTERS MATCHES "ON")
    list(APPEND dlalloc_defines USE_FOOTERS=1)
endif ()

set(dlalloc_sources
        src/chunk.c
        src/debug.c
        src/error.c
        src/heap-default.c
        src/heap-user.c
        src/heap.c
        src/init.c
        src/inspect.c
        src/lock.c
        src/log.c
        src/os.c
        src/sbrk.c
        src/segment.c
        src/state.c)

add_library(dlalloc-static STATIC ${dlalloc_sources})
target_compile_options(dlalloc-static PRIVATE ${dlalloc_flags})
target_compile_definitions(dlalloc-static PRIVATE ${dlalloc_defines})
target_link_libraries(dlalloc-static PRIVATE pthread)
target_include_directories(dlalloc-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

add_library(dlalloc SHARED ${dlalloc_sources})
target_compile_options(dlalloc PRIVATE ${dlalloc_flags})
target_compile_definitions(dlalloc PRIVATE ${dlalloc_defines})
target_link_libraries(dlalloc PRIVATE pthread)
target_include_directories(dlalloc PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

add_executable(test src/test.c src/log.c)
target_link_libraries(test PRIVATE dlalloc)
target_include_directories(test PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
