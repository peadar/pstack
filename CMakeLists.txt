cmake_minimum_required(VERSION 2.8.11)
project(pstack C CXX)

math(EXPR PLATFORM_BITS "${CMAKE_SIZEOF_VOID_P} * 8")
set(PSTACK_BIN "pstack" CACHE STRING "Name of the 'pstack' binary")
set(ELF_BITS ${PLATFORM_BITS} CACHE STRING "32 or 64 - set to 32 to build 32-bit binary on 64-bit platform")
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib" CACHE STRING "Rpath to install for binaries or the empty string")

set(LIBTYPE "STATIC" CACHE STRING "Build libraries as STATIC or SHARED")

if(PLATFORM_BITS EQUAL 64 AND ELF_BITS EQUAL 32)
    # we want a 32-bit binary in a 64-bit build environment: use -m32 everywhere
    add_definitions("-m32")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
endif()


find_library(LTHREADDB NAMES thread_db PATHS (/usr/lib /usr/local/lib))
find_package(LibLZMA)
find_package(ZLIB)

add_definitions("-std=c++11 -Wall -Wextra -DELF_BITS=${ELF_BITS} -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (ZLIB_FOUND)
   set(inflatesrc inflate.cc)
   add_definitions("-DWITH_ZLIB")
endif()

if (LIBLZMA_FOUND)
   set(lzmasrc lzma.cc)
   add_definitions("-DWITH_LZMA")
endif()

# Make sure to use the local libpstack headers rather than what's installed.
include_directories("." ${LIBLZMA_INCLUDES} ${ZLIB_INCLUDES})

add_library(dwelf ${LIBTYPE} dwarf.cc elf.cc reader.cc util.cc dump.cc
   ${inflatesrc} ${lzmasrc})
add_library(procman ${LIBTYPE} dead.cc live.cc process.cc proc_service.cc
   dwarfproc.cc procdump.cc ${stubsrc})

add_executable(canal canal.cc)
add_executable(${PSTACK_BIN} pstack.cc)

target_link_libraries(dwelf ${LIBLZMA_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_libraries(procman ${LTHREADDB} dwelf)
target_link_libraries(${PSTACK_BIN} dwelf procman)
target_link_libraries(canal dwelf procman)

set_target_properties(dwelf PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(procman PROPERTIES VERSION 1.0.0 SOVERSION 1)

install(TARGETS ${PSTACK_BIN} canal DESTINATION bin)
install(TARGETS dwelf procman DESTINATION lib)
install(DIRECTORY libpstack DESTINATION include)
install(CODE "execute_process (COMMAND setcap cap_sys_ptrace+ep ${CMAKE_INSTALL_PREFIX}/bin/${PSTACK_BIN})")
