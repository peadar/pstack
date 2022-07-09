cmake_minimum_required(VERSION 3.7)
project(pstack-tests C CXX)

# Force debug build for tests. Many of the tests are looking at debug info that
# we need
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_STANDARD 14)

add_definitions("-O0 -D_FORTIFY_SOURCE=0 -I${CMAKE_SOURCE_DIR}")

add_library(testhelper STATIC abort.c)

add_executable(thread thread.cc)
add_executable(badfp badfp.c)
add_executable(basic basic.c)
add_executable(segv segv.c)
add_executable(segvrt segvrt.c)
add_executable(inline inline.c)
add_executable(args args.cc)
add_library(noreturn SHARED noreturn.c noreturn-ext.c)
add_executable(cpp cpp.cc)

target_link_libraries(thread pthread testhelper)
target_link_libraries(badfp testhelper)
target_link_libraries(basic testhelper)
target_link_libraries(segv testhelper)
target_link_libraries(segvrt testhelper)
target_link_libraries(noreturn testhelper)
target_link_libraries(cpp testhelper)
target_link_libraries(inline testhelper)
SET_TARGET_PROPERTIES(noreturn PROPERTIES COMPILE_FLAGS "-O2 -g")
