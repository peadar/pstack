cmake_minimum_required(VERSION 3.7)
project(pstack C CXX)
enable_testing()

add_subdirectory(tests)

option(PYTHON3 "Compile with experimental python 3 support" OFF)
option(PYTHON2 "Compile with python 2 support" ON)

math(EXPR PLATFORM_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
set(PSTACK_BIN "pstack" CACHE STRING "Name of the 'pstack' binary")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "Rpath to install for binaries or the empty string")
set(LIBTYPE "SHARED" CACHE STRING "Build libraries as STATIC or SHARED")
set (PYTHON3_SOURCE "" CACHE STRING "Path to the CPython source code")
option(TIDY "Run clang-tidy on the source" False)

find_library(LTHREADDB NAMES thread_db PATHS (/usr/lib /usr/local/lib))
find_package(LibLZMA)
find_package(ZLIB)

if (PYTHON2)
   find_package(Python2 COMPONENTS Development)
endif()
if (PYTHON3)
   find_package(Python3 COMPONENTS Development)
endif()

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

set(VERSION_TAG ${GIT_TAG} CACHE STRING "Version tag (defaults to git commit)")
message(STATUS "Version: ${VERSION_TAG}")

add_definitions("-DVERSION=${VERSION_TAG}")

set(CMAKE_CXX_STANDARD 14)

add_definitions("-Wall -Wextra -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")
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

if (Python3_Development_FOUND OR Python2_Development_FOUND)
   set(pysrc python.cc)
endif()

if (PYTHON3 AND Python3_Development_FOUND)
   if ("${PYTHON3_SOURCE}" STREQUAL "") # not set
      message(STATUS "Python 3 source not specified. Checking /usr/src/debug/Python-3.* as default")

      file(GLOB PYTHON3_SOURCE_GLOB "/usr/src/debug/Python-3.*")
      if ("${PYTHON3_SOURCE_GLOB}" STREQUAL "") # glob was empty
         file(GLOB PYTHON3_SOURCE_GLOB "/usr/src/debug/python3*")
      endif()

      if ("${PYTHON3_SOURCE_GLOB}" STREQUAL "") # glob was empty
         message(STATUS "Python 3 source not found")
      else()
         message(STATUS "Python3 source is \"${PYTHON3_SOURCE_GLOB}\"")
         set(PYTHON3_SOURCE "${PYTHON3_SOURCE_GLOB}")
      endif()
   endif()


   if (NOT "${PYTHON3_SOURCE}" STREQUAL "") # src found in some way
      set(pyinc "-I${PYTHON3_SOURCE} -I${PYTHON3_SOURCE}/Include -I${Python3_INCLUDE_DIRS}")
      message(STATUS  "Python3_INCLUDE_DIRS are ${pyinc}")
      add_definitions("-DWITH_PYTHON3")
      set(pysrc ${pysrc} python3.cc pythonc.c)
      set_source_files_properties(python3.cc PROPERTIES COMPILE_FLAGS ${pyinc})
      set_source_files_properties(pythonc.c PROPERTIES COMPILE_FLAGS ${pyinc})
   else()
      message(FATAL_ERROR "Path to CPython source code needed for Python 3 support\nSpecify with -DPYTHON3_SOURCE=<path>")
   endif()
endif()

if (Python2_Development_FOUND)
   set(pysrc ${pysrc} python2.cc)
   add_definitions("-DWITH_PYTHON2")
   set_source_files_properties(python2.cc PROPERTIES COMPILE_FLAGS -I${Python2_INCLUDE_DIRS})
endif()

add_definitions("-g3")

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

if ((NOT (Python3_Development_FOUND)) AND PYTHON3)
   message(WARNING "no python3 support found")
endif()

if (NOT (Python2_Development_FOUND))
   message(WARNING "no python2 support found")
endif()

install(TARGETS ${PSTACK_BIN} canal DESTINATION bin)
install(TARGETS dwelf procman DESTINATION lib${LIB_SUFFIX})
install(FILES ${CMAKE_SOURCE_DIR}/pstack.1 DESTINATION share/man/man1 RENAME ${PSTACK_BIN}.1 )
install(DIRECTORY libpstack DESTINATION include)
install(CODE "execute_process (COMMAND setcap cap_sys_ptrace+ep ${DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/${PSTACK_BIN} RESULT_VARIABLE ret)
if (NOT ret EQUAL \"0\")
   message(\"(setcap failed - you might need to use sudo to use pstack: \${ret})\")
endif()
")

add_test(NAME args COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/args-test.py)
add_test(NAME badfp COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/badfp-test.py)
add_test(NAME basic COMMAND ${CMAKE_SOURCE_DIR}/tests/basic-test.py)
add_test(NAME cpp COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp-test.py)
add_test(NAME noreturn COMMAND python2 ${CMAKE_CURRENT_SOURCE_DIR}/tests/noreturn-test.py)
add_test(NAME segv COMMAND ${CMAKE_SOURCE_DIR}/tests/segv-test.py)
add_test(NAME thread COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/thread-test.py)
