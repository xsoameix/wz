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
include_directories(.)
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()
set(SOURCES
  byteorder.c
  unicode.c
  file.c
)
add_library(lib SHARED ${SOURCES})
set_target_properties(lib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(lib ${LIBS})
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_C_COMPILER_ID}" MATCHES  "Clang")
  set(CMAKE_C_FLAGS
    "-std=c99 -pthread -pedantic -g"
    "-Wall -Wextra -Werror -Wconversion -Wshadow -Wwrite-strings")
  string(REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_C_FLAGS
    "/wd4204" # C99
    "/wd4710" # C89: inline function
    "/wd4820" # C89: struct padding
    "/wd4996" # C89: sprintf & fopen
    "/WX /Wall")
  string(REPLACE ";" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
endif()

# wz/*.h - headers
install(TARGETS lib
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(
  FILES file.h
  DESTINATION include/wz
)

# wz - main program
add_executable(wz main.c)
target_link_libraries(wz lib)
