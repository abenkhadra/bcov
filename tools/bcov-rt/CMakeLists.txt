project(bcov-rt C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -pipe")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")

set(CMAKE_C_FLAGS_DEBUG_ASAN "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")

set(BCOV_DUMP_SOURCES
    bcov-rt.c
    ${CMAKE_SOURCE_DIR}/src/dump/patch.c
    )

set_source_files_properties(${BCOV_DUMP_SOURCES} PROPERTIES COMPILE_FLAGS "-Wno-unused-value")

add_library(bcov-rt SHARED ${BCOV_DUMP_SOURCES})
