enable_testing()

# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# zlib
find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# libwz.so or wz.dll - shared library
include_directories(../src)
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
set(SOURCES
  ../src/byteorder.c
  ../src/unicode.c
  ../src/file.c
)
add_library(testlib SHARED ${SOURCES} mem.c)
set_source_files_properties(${SOURCES} PROPERTIES
  COMPILE_DEFINITIONS "WZ_WRAP=1")
set_target_properties(testlib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(testlib ${LIBS})
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_C_COMPILER_ID}" MATCHES  "Clang")
  set(CMAKE_C_FLAGS "-Wall -Werror -std=c99 -pthread -pedantic")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_C_FLAGS "/WX")
endif()
set(LIBS testlib)

# Check
find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIR})
set(LIBS ${LIBS} ${CHECK_LIBRARIES})

# suite - testing program
include_directories(.)
add_executable(suite
  file.c
  suite.c
)
target_link_libraries(suite ${LIBS})
add_test(suite ${CMAKE_CURRENT_BINARY_DIR}/suite)

# encode - encode version & address program
add_executable(encode encode.c)
target_link_libraries(encode testlib)
