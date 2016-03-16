cmake_minimum_required(VERSION 2.8.11)
project(pstack CXX)
add_definitions("-std=c++11")

include_directories("/usr/include/python2.7/")
include_directories(".")

add_executable(canal canal.cc)
add_library(dwelf STATIC dwarf.cc elf.cc reader.cc util.cc dump.cc)

add_library(procman STATIC dead.cc live.cc process.cc proc_service.cc dwarfproc.cc procdump.cc)
target_link_libraries(procman dwelf)

add_executable(pstack pstack.cc )
target_link_libraries(pstack dwelf procman "-lthread_db")
target_link_libraries(canal dwelf procman "-lthread_db")
target_link_libraries(procman "-lthread_db")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT ELF_BITS)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  SET(ELF_BITS 64)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 8)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  SET(ELF_BITS 32)  
endif(CMAKE_SIZEOF_VOID_P EQUAL 4)
endif(NOT ELF_BITS)

if (ELF_BITS EQUAL 32)
    add_definitions("-m32")
    set_target_properties(pstack PROPERTIES LINK_FLAGS -m32)
    set_target_properties(canal PROPERTIES LINK_FLAGS -m32)
endif()

add_definitions("-DELF_BITS=${ELF_BITS}")
target_link_libraries(procman "-lthread_db")
add_definitions("-D_FILE_OFFSET_BITS=64")
add_definitions("-D_LARGEFILE_SOURCE")


set_target_properties(dwelf PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(procman PROPERTIES VERSION 1.0.0 SOVERSION 1)

install(TARGETS pstack canal DESTINATION bin)
install(TARGETS dwelf procman DESTINATION lib)
install(DIRECTORY libpstack DESTINATION include)
