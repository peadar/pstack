cmake_minimum_required(VERSION 3.10)
set(PSTACK_SOVERSION 2.17)
set(PSTACK_VERSION 2.17.5)
project(pstack LANGUAGES C CXX VERSION "${PSTACK_VERSION}" )

include (GNUInstallDirs)
enable_testing()

option(PYTHON3 "Compile with python 3 support" OFF)
option(PYTHON2 "Compile with python 2 support" ON)
option(PTRACE_TESTS "Run extra tests that require unrestricted access to ptrace" OFF)

math(EXPR PLATFORM_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
set(PSTACK_BIN "pstack" CACHE STRING "Name of the 'pstack' binary")

# Generate position independent code, even for static libs - that way we can
# link them to shared libs.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/" CACHE STRING "Rpath to install for binaries or the empty string")
option(TIDY "Run clang-tidy on the source" False)

find_package(LibLZMA REQUIRED)
find_package(ZLIB REQUIRED)

if (PYTHON2)
   find_package(Python2 COMPONENTS Development)
endif()
if (PYTHON3)
   find_package(Python3 COMPONENTS Development)
endif()

find_package(Git)
if (GIT_FOUND AND EXISTS ${CMAKE_SOURCE_DIR}/.git)
   execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
      OUTPUT_VARIABLE GIT_TAG
      OUTPUT_STRIP_TRAILING_WHITESPACE
      )
   message(STATUS "Version from git tag: ${GIT_TAG}")
else()
   set(GIT_TAG "unknown")
   message(STATUS "git version information unavailable - defaulting to 'unknown'")
endif()

set(VERSION_TAG ${GIT_TAG} CACHE STRING "Version tag (defaults to git commit)")
message(STATUS "Version: ${VERSION_TAG}")

add_definitions(-DVERSION=${VERSION_TAG})

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON)

add_definitions("-Wall -Wextra -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")
# Adding frame pointers makes things easy to run performance measurements with,
# and doesn't cost much itself.
add_definitions("-fno-omit-frame-pointer")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Make sure to use the local libpstack headers rather than what's installed.
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${ZLIB_INCLUDE_DIRS})

include_directories(${LIBLZMA_INCLUDE_DIRS})


if (Python3_Development_FOUND OR Python2_Development_FOUND)
   set(pysrc python.cc)
endif()

if (PYTHON3 AND Python3_Development_FOUND)
   set(pyinc "-I${Python3_INCLUDE_DIRS}")
   message(STATUS  "Python3_INCLUDE_DIRS are ${pyinc}")
   add_definitions("-DWITH_PYTHON3")
   set(pysrc ${pysrc} python3.cc pythonc.c)
   set_source_files_properties(python3.cc PROPERTIES COMPILE_FLAGS ${pyinc})
   set_source_files_properties(pythonc.c PROPERTIES COMPILE_FLAGS ${pyinc})
   set_source_files_properties(canal.cc PROPERTIES COMPILE_FLAGS ${pyinc})
endif()

if (Python2_Development_FOUND)
   set(pysrc ${pysrc} python2.cc)
   add_definitions("-DWITH_PYTHON2")
   set_source_files_properties(python2.cc PROPERTIES COMPILE_FLAGS -I${Python2_INCLUDE_DIRS})
endif()

add_definitions("-g3")

add_library(dwelf_objects OBJECT
         dwarf_die.cc
         dwarf_frame.cc
         dwarf_info.cc
         dwarf_lines.cc
         dwarf_macros.cc
         dwarf_pubnames.cc
         dwarf_reader.cc
         dwarf_unit.cc
         dump.cc
         context.cc
         elf.cc
         flags.cc
         reader.cc
         inflate.cc
         lzma.cc
         )

add_library(procman_objects OBJECT dead.cc self.cc live.cc process.cc proc_service.cc
    dwarfproc.cc procdump.cc threaddb.cc ${pysrc})

add_library(dwelf SHARED $<TARGET_OBJECTS:dwelf_objects>)
add_library(dwelf_static STATIC $<TARGET_OBJECTS:dwelf_objects>)
set_target_properties(dwelf_static PROPERTIES OUTPUT_NAME dwelf_s)

add_library(procman SHARED $<TARGET_OBJECTS:procman_objects>)
add_library(procman_static STATIC $<TARGET_OBJECTS:procman_objects>)
set_target_properties(procman_static PROPERTIES OUTPUT_NAME procman_s)

option(LINK_STATIC "Link binaries against static libraries" OFF)
if (LINK_STATIC)
   set(PSTACK_LINK_LIBS procman_static dwelf_static)
else()
   set(PSTACK_LINK_LIBS dwelf procman)
endif()

add_executable(canal canal.cc)

add_executable(${PSTACK_BIN} pstack.cc)

target_link_libraries(procman dwelf dl)
target_link_libraries(procman_static dwelf_static dl)
target_link_libraries(${PSTACK_BIN} ${PSTACK_LINK_LIBS})
target_link_libraries(canal ${PSTACK_LINK_LIBS})
target_link_options(${PSTACK_BIN} PRIVATE -Wl,--export-dynamic)
target_link_options(canal PRIVATE -Wl,--export-dynamic)

set_target_properties(dwelf PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION "${PSTACK_SOVERSION}")
set_target_properties(procman PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION "${PSTACK_SOVERSION}")



if ((NOT (Python3_Development_FOUND)) AND PYTHON3)
   message(WARNING "no python3 support found")
endif()

if (NOT (Python2_Development_FOUND) AND PYTHON2)
   message(WARNING "no python2 support found")
endif()

# bonus: heap debugger
add_library(hdbg SHARED heap.c)
add_executable(hdmp hdmp.cc)
add_executable(stackusers stackusers.cc)
target_link_libraries(hdmp ${PSTACK_LINK_LIBS})
target_link_libraries(hdbg dl)
target_link_libraries(stackusers ${PSTACK_LINK_LIBS})

install(TARGETS ${PSTACK_BIN} canal)
install(TARGETS hdmp)
install(TARGETS dwelf procman dwelf_static procman_static hdbg)
install(FILES ${CMAKE_SOURCE_DIR}/pstack.1 DESTINATION share/man/man1 RENAME ${PSTACK_BIN}.1 )
install(DIRECTORY libpstack DESTINATION include)
install(CODE "execute_process (COMMAND setcap cap_sys_ptrace+ep ${DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/${PSTACK_BIN} RESULT_VARIABLE ret)
if (NOT ret EQUAL \"0\")
   message(\"(setcap failed - you might need to use sudo to use pstack: \${ret})\")
endif()
")

add_subdirectory(tests)

# for automake and rpmbuild
add_custom_target(check COMMAND make test)
