# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# zlib
find_package(ZLIB REQUIRED)
set(DIRS ${DIRS} ${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# aes256
set(DIRS ${DIRS} lib)

# exports all symbols
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# flags
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_C_COMPILER_ID}" MATCHES  "Clang")
  set(FLAGS
    "-std=c99 -pthread -pedantic -g"
    "-Wall -Wextra -Werror -Wconversion -Wshadow -Wwrite-strings")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(FLAGS
    "/wd4127" # syntax: while (1)
    "/wd4204" # C99
    "/wd4710" # C89: inline function
    "/wd4820" # C89: struct padding
    "/wd4996" # C89: sprintf & fopen
    "/WX /Wall")
endif()
string(REPLACE ";" " " SOURCE_FLAGS "${FLAGS}")
string(REPLACE " " ";" TARGET_FLAGS "${FLAGS}")

# libwz.so or wz.dll - shared library
set(CRYPTO_SOURCES
  lib/aes256.c)
set(SOURCES
  byteorder.c
  unicode.c
  file.c)
set_source_files_properties(${SOURCES} PROPERTIES COMPILE_FLAGS ${SOURCE_FLAGS})
add_library(lib SHARED ${CRYPTO_SOURCES} ${SOURCES})
set_target_properties(lib PROPERTIES
  OUTPUT_NAME wz
  VERSION 0.0.0
  SOVERSION 0)
target_include_directories(lib PRIVATE ${DIRS})
target_link_libraries(lib ${LIBS})

# wz/*.h - headers
set(INSTALL_BINARY_DIR    ${CMAKE_INSTALL_PREFIX}/bin/wz)
set(INSTALL_LIBRARY_DIR   ${CMAKE_INSTALL_PREFIX}/lib)
set(INSTALL_INCLUDE_DIR   ${CMAKE_INSTALL_PREFIX}/include/wz)
set(INSTALL_PKGCONFIG_DIR ${CMAKE_INSTALL_PREFIX}/share/pkgconfig)
set(WZ_PC ${CMAKE_CURRENT_BINARY_DIR}/wz.pc)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wz.pc.cmake ${WZ_PC} @ONLY)
install(TARGETS lib
  RUNTIME DESTINATION ${INSTALL_BINARY_DIR}
  LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
  ARCHIVE DESTINATION ${INSTALL_LIBRARY_DIR})
install(FILES file.h DESTINATION ${INSTALL_INCLUDE_DIR})
install(FILES ${WZ_PC} DESTINATION ${INSTALL_PKGCONFIG_DIR})

# wz - main program
add_executable(wz main.c)
target_link_libraries(wz lib)
target_compile_options(wz PRIVATE ${TARGET_FLAGS})
