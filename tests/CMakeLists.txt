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

if (Python3_Development_FOUND)
   add_executable(python_path_test python_path_test.cc)
   target_link_libraries(python_path_test procman dwelf)
endif()

add_custom_command(
   OUTPUT basic-no-unwind-gen
   COMMAND ${CMAKE_OBJCOPY} --strip-debug --remove-section .eh_frame basic basic-no-unwind || true
   VERBATIM )

add_custom_target(basic-no-unwind ALL DEPENDS basic basic-no-unwind-gen)

# Build the basic executable with some options to compress debug sections with
# zlib and zlib-gnu, and ensure we can decode them

target_link_options(basic-zlib PUBLIC -Wl,--compress-debug-sections=zlib)
target_link_options(basic-zlib-gnu PUBLIC -Wl,--compress-debug-sections=zlib-gnu)

enable_testing()

set ( PSTACK_PATH $<TARGET_FILE:${PSTACK_BIN}>)

add_test(NAME args COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/args-test.py)
add_test(NAME badfp COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/badfp-test.py)
add_test(NAME basic COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/basic-test.py)
add_test(NAME cpp COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/cpp-test.py)
add_test(NAME noreturn COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/noreturn-test.py)
add_test(NAME segv COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/segv-test.py)
add_test(NAME thread COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/thread-test.py)
add_test(NAME jsondump COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/dump-test.py)

add_test(NAME procself COMMAND $<TARGET_FILE:procself>)

set(ALL_TESTS args badfp basic cpp noreturn segv thread jsondump)

# Need to remove these tests for environments with more restrictive ptrace
if (PTRACE_TESTS)
    add_test(NAME suspend COMMAND suspend)
    list(APPEND ALL_TESTS suspend)
if (Python3_Development_FOUND)
    add_test(NAME python-sanity COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/python-sanity.py")
    list(APPEND ALL_TESTS suspend)
    list(APPEND ALL_TESTS python-sanity)
endif()
endif()

if (Python3_Development_FOUND)
    add_test(NAME python_path_test COMMAND python_path_test)
    list(APPEND ALL_TESTS suspend python_path_test)
endif()

if (Python3_Development_FOUND)
    add_test(NAME pydict COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/pydict_test.py)
    list(APPEND ALL_TESTS pydict)
endif()


message( STATUS "all tests: ${ALL_TESTS}")

set(TEST_ENV
    "CMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}"
    "PSTACK_PATH=${PSTACK_PATH}" )

set_tests_properties(${ALL_TESTS} PROPERTIES ENVIRONMENT "${TEST_ENV}")
