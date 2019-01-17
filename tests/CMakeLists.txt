cmake_minimum_required(VERSION 2.8.11)
project(pstack-tests C CXX)

set(CMAKE_CXX_STANDARD 14)

add_definitions("-Wall -Wextra -DELF_BITS=${ELF_BITS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")

add_library(testhelper STATIC abort.c)

add_executable(thread thread.cc)
add_executable(badfp badfp.c)
add_executable(basic basic.c)
add_executable(segv segv.c)
add_executable(segvrt segvrt.c)
add_executable(asserttext asserttext.cc)

target_link_libraries(thread pthread testhelper)
target_link_libraries(badfp testhelper)
target_link_libraries(basic testhelper)
target_link_libraries(segv testhelper)
target_link_libraries(segvrt testhelper)
target_link_libraries(asserttext testhelper)
