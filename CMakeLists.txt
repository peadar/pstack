cmake_minimum_required(VERSION 2.8.11)
project(pstack C CXX)
enable_testing()

add_subdirectory(tests)

math(EXPR PLATFORM_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
set(PSTACK_BIN "pstack" CACHE STRING "Name of the 'pstack' binary")
set(ELF_BITS ${PLATFORM_BITS} CACHE STRING "32 or 64 - set to 32 to build 32-bit binary on 64-bit platform")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "Rpath to install for binaries or the empty string")
set(LIBTYPE "SHARED" CACHE STRING "Build libraries as STATIC or SHARED")
option(TIDY "Run clang-tidy on the source" False)

if(PLATFORM_BITS EQUAL 64 AND ELF_BITS EQUAL 32)
    # we want a 32-bit binary in a 64-bit build environment: use -m32 everywhere
    add_definitions("-m32")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
endif()

find_library(LTHREADDB NAMES thread_db PATHS (/usr/lib /usr/local/lib))
find_package(LibLZMA)
find_package(ZLIB)
find_package(PythonLibs 2)

find_package(Git)
if (GIT_FOUND)
   execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
      OUTPUT_VARIABLE GIT_TAG
      OUTPUT_STRIP_TRAILING_WHITESPACE
      )
   message(STATUS "Version from git tag: ${GIT_TAG}")
else()
   set(GIT_TAG "unknown")
   message(STATUS "No git/no version")
endif()
add_definitions("-DVERSION=${GIT_TAG}")

set(CMAKE_CXX_STANDARD 14)

add_definitions("-Wall -Wextra -DELF_BITS=${ELF_BITS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Make sure to use the local libpstack headers rather than what's installed.
include_directories(${CMAKE_SOURCE_DIR})

if (LIBLZMA_FOUND)
   set(lzmasrc lzma.cc)
   add_definitions("-DWITH_LZMA")
   include_directories(${LIBLZMA_INCLUDES})
endif()

if (ZLIB_FOUND)
   set(inflatesrc inflate.cc)
   add_definitions("-DWITH_ZLIB")
   include_directories(${ZLIB_INCLUDES})
endif()

if (PythonLibs_FOUND OR PYTHONLIBS_FOUND)
   set(pysrc python.cc)
   add_definitions("-DWITH_PYTHON")
   include_directories(${PYTHON_INCLUDE_DIRS})
endif()

add_library(dwelf ${LIBTYPE} dump.cc dwarf.cc elf.cc reader.cc util.cc
   ${inflatesrc} ${lzmasrc})
add_library(procman ${LIBTYPE} dead.cc live.cc process.cc proc_service.cc
   dwarfproc.cc procdump.cc ${stubsrc})

add_executable(canal canal.cc ${pysrc})
add_executable(${PSTACK_BIN} pstack.cc ${pysrc})

target_link_libraries(procman ${LTHREADDB} dwelf)
target_link_libraries(${PSTACK_BIN} dwelf procman)
target_link_libraries(canal dwelf procman)

if (TIDY)
set (CLANG_TIDY "clang-tidy;-checks=*,-*readability-braces-around-statements,-fuchsia*,-hicpp-braces-around-statements")
set_target_properties(canal PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY}")
set_target_properties(${PSTACK_BIN} PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY}")
set_target_properties(dwelf PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY}")
add_definitions("-DNDEBUG")
set_target_properties(procman PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY}")
endif()

set_target_properties(dwelf PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(procman PROPERTIES VERSION 1.0.0 SOVERSION 1)

if (ZLIB_FOUND)
   target_link_libraries(dwelf ${ZLIB_LIBRARIES})
else()
   message(WARNING "no ZLIB support found")
endif()

if (LIBLZMA_FOUND)
   target_link_libraries(dwelf ${LIBLZMA_LIBRARIES})
else()
   message(WARNING "no LZMA support found")
endif()

if (NOT (PythonLibs_FOUND OR PYTHONLIBS_FOUND))
   message(WARNING "no python support found")
endif()

install(TARGETS ${PSTACK_BIN} canal DESTINATION bin)
install(TARGETS dwelf procman DESTINATION lib${LIB_SUFFIX})
install(FILES ${CMAKE_SOURCE_DIR}/pstack.1 DESTINATION share/man/man1 RENAME ${PSTACK_BIN}.1 )
install(DIRECTORY libpstack DESTINATION include)
install(CODE "execute_process (COMMAND setcap cap_sys_ptrace+ep ${CMAKE_INSTALL_PREFIX}/bin/${PSTACK_BIN})")


add_test(NAME basic COMMAND ${CMAKE_SOURCE_DIR}/tests/basic-test.py)
add_test(NAME segv COMMAND ${CMAKE_SOURCE_DIR}/tests/segv-test.py)
add_test(NAME thread COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/thread-test.py)
add_test(NAME badfp COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/badfp-test.py)
add_test(NAME asserttext COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/asserttext-test.py)
