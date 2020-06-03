cmake_minimum_required(VERSION 3.2)
project(bcov)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_VERBOSE_MAKEFILE ON)

#############################################
############ compiler flags

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -pipe ")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer \
  -Wno-unused-function -Wno-unused-variable ")

set(CMAKE_CXX_FLAGS_ASAN "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address ")

set(CMAKE_CXX_FLAGS_UBSAN "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined ")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 ")

#############################################
############ find dependencies

include_directories(src ext ${CMAKE_INCLUDE_PATH})
link_directories(${CMAKE_LIBRARY_PATH})

get_property(BCOV_INCLUDE_DIRS DIRECTORY ${CMAKE_SRC_DIR} PROPERTY INCLUDE_DIRECTORIES)

get_property(BCOV_LINK_DIRS DIRECTORY ${CMAKE_SRC_DIR} PROPERTY LINK_DIRECTORIES)

find_path(CAPSTONE_INCLUDE_DIR NAMES capstone PATHS ${BCOV_INCLUDE_DIRS})
if (NOT CAPSTONE_INCLUDE_DIR)
  message(FATAL_ERROR "capstone include files were not found!")
endif ()

find_library(CAPSTONE_DYNAMIC_LIB NAMES capstone PATHS ${BCOV_LINK_DIRS})
if (NOT CAPSTONE_DYNAMIC_LIB)
  message(FATAL_ERROR "capstone library was not found!")
endif ()

find_path(UNICORN_INCLUDE_DIR NAMES unicorn PATHS ${BCOV_INCLUDE_DIRS})
if (NOT UNICORN_INCLUDE_DIR)
  message(FATAL_ERROR "unicorn include files were not found!")
endif ()

find_library(UNICORN_DYNAMIC_LIB NAMES unicorn PATHS ${BCOV_LINK_DIRS})
if (NOT UNICORN_DYNAMIC_LIB)
  message(FATAL_ERROR "unicorn library was not found!")
endif ()

#############################################
############## define sources

set(BCOV_GRAPH_SOURCES
    src/graph/Dot.cpp
    src/graph/CFG.cpp
    src/graph/DominatorTree.cpp
    src/graph/SuperBlock.cpp
    )

set(BCOV_X64_SOURCES
    src/x64/Inst.cpp
    src/x64/JumpTabAnalyzer.cpp
    src/x64/Arch.cpp
    src/x64/Asm.cpp
    )

set(BCOV_UTIL_SOURCES
    src/util/Logging.cpp
    src/util/BcovConfig.cpp
    src/util/BcovConfigParser.cpp
    src/util/ProgOptions.cpp
    src/util/Demangler.cpp
    )

set(BCOV_FLAX_SOURCES
    src/flax/Flax.cpp
    src/flax/Emulator.cpp
    )

set(BCOV_CORE_SOURCES
    src/core/Common.cpp
    src/core/CSInstWrapper.cpp
    src/core/MCInst.cpp
    src/core/Function.cpp
    src/core/BasicBlock.cpp
    src/core/FunctionBuilder.cpp
    src/core/FileLoader.cpp
    src/core/Region.cpp
    src/core/Disassembler.cpp
    )

set(BCOV_ELF_SOURCES
    src/elf/ElfParser.cpp
    src/elf/ElfModule.cpp
    src/elf/ElfExtender.cpp
    src/elf/ElfPatchManager.cpp
    src/dwarf/EhFrame.cpp
    src/dwarf/Data.cpp
    src/dwarf/PrettyPrint.cpp
    )

set(BCOV_DUMP_SOURCES
    src/dump/patch.c
    )

#############################################
############## setup static libs

add_library(easylogging STATIC ext/easylogging/easylogging++.cc)
set_target_properties(easylogging PROPERTIES COMPILE_FLAGS
    "-DELPP_DEFAULT_LOG_FILE='\"bcov.log\"' -DELPP_FRESH_LOG_FILE \
      -DELPP_DISABLE_DEFAULT_CRASH_HANDLING \
      -DELPP_DISABLE_FATAL_LOGS \
      -DELPP_FEATURE_PERFORMANCE_TRACKING \
      -Wno-unused-function -Wno-unused-variable"
    )

if (CMAKE_BUILD_TYPE STREQUAL "UBSAN")
  get_target_property(EASYLOGGING_COMPILE_FLAGS easylogging COMPILE_FLAGS)
  string(REPLACE "-fsanitize=undefined" "" UPDATED_EASYLOGGING_FLAGS ${EASYLOGGING_COMPILE_FLAGS})
  # workaround as easylogging has ub instances
  set_target_properties(easylogging PROPERTIES COMPILE_FLAGS
      "${UPDATED_EASYLOGGING_FLAGS} -fno-sanitize=undefined -fsanitize=unreachable")
endif()


set(LIBELFIN_DIR ${CMAKE_SOURCE_DIR}/ext/libelfin/elf)

add_library(elf++ STATIC
    ${LIBELFIN_DIR}/mmap_loader.cc
    ${LIBELFIN_DIR}/to_string.cc
    ${LIBELFIN_DIR}/elf.cc
    )

#############################################
############## builds

add_library(bcov_static STATIC
    ${BCOV_UTIL_SOURCES}
    ${BCOV_CORE_SOURCES}
    ${BCOV_FLAX_SOURCES}
    ${BCOV_ELF_SOURCES}
    ${BCOV_GRAPH_SOURCES}
    ${BCOV_X64_SOURCES}
    ${BCOV_DUMP_SOURCES}
    )

##############################################
###############
add_subdirectory(tools/bcov-rt)

add_executable(bcov src/main/main.cpp ${BCOV_SOURCES})
add_dependencies(bcov bcov_static easylogging elf++)
target_link_libraries(bcov
    bcov_static
    easylogging
    elf++
    capstone
    unicorn
    pthread
    )
