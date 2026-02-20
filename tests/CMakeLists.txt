cmake_minimum_required(VERSION 3.10)
project(pstack-tests C CXX)

# Force debug build for tests. Many of the tests are looking at debug info that
# we need
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_STANDARD 20)

add_definitions("-O0 -D_FORTIFY_SOURCE=0 -I${CMAKE_SOURCE_DIR}")

add_library(testhelper STATIC abort.c)

add_executable(thread thread.cc)
add_executable(badfp badfp.c)
add_executable(basic basic.c)
add_executable(basic-zlib basic.c)
add_executable(basic-zlib-gnu basic.c)
add_executable(segv segv.c)
add_executable(segvrt segvrt.c)
add_executable(inline inline.c)
add_executable(args args.cc)
add_executable(noreturn noreturn.c noreturn-ext.c)
add_executable(cpp cpp.cc)
add_executable(procself procself.cc)
add_executable(suspend suspend.cc)

target_link_libraries(thread pthread testhelper)
target_link_libraries(badfp testhelper)
target_link_libraries(basic testhelper)
target_link_libraries(segv testhelper)
target_link_libraries(segvrt testhelper)
target_link_libraries(noreturn testhelper)
target_link_libraries(cpp testhelper)
target_link_libraries(inline testhelper)
target_link_libraries(procself dwelf procman)
target_link_libraries(suspend dwelf procman)
SET_TARGET_PROPERTIES(noreturn PROPERTIES COMPILE_FLAGS "-O2 -g")

if (Python3_Development_FOUND OR Python2_Development_FOUND)
   add_executable(python_path_test python_path_test.cc)
   target_link_libraries(python_path_test procman dwelf)
endif()

add_custom_command(
   OUTPUT basic-no-unwind-gen
   COMMAND ${CMAKE_OBJCOPY} --strip-debug --remove-section .eh_frame basic basic-no-unwind
   VERBATIM )

add_custom_target(basic-no-unwind ALL DEPENDS basic basic-no-unwind-gen)

# Build the basic executable with some options to compress debug sections with
# zlib and zlib-gnu, and ensure we can decode them

target_link_options(basic-zlib PUBLIC -Wl,--compress-debug-sections=zlib)
target_link_options(basic-zlib-gnu PUBLIC -Wl,--compress-debug-sections=zlib-gnu)

enable_testing()

add_test(NAME args COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/args-test.py)
add_test(NAME badfp COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/badfp-test.py)
add_test(NAME basic COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/basic-test.py)
add_test(NAME cpp COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/cpp-test.py)
add_test(NAME noreturn COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/noreturn-test.py)
add_test(NAME segv COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/segv-test.py)
add_test(NAME thread COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/thread-test.py)
add_test(NAME jsondump COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/dump-test.py)
add_test(NAME procself COMMAND procself)

# Need to remove this test for environments with more restrictive ptrace
if (PTRACE_TESTS)
    add_test(NAME suspend COMMAND suspend)
endif()

if (Python3_Development_FOUND OR Python2_Development_FOUND)
    add_test(NAME python_path_test COMMAND python_path_test)
endif()

if (PYTHON3 AND Python3_Development_FOUND)
    add_test(NAME pydict COMMAND env PSTACK_BIN=${PSTACK_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/pydict_test.py)
endif()

