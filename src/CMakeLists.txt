# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# zlib
find_package(ZLIB REQUIRED)
set(DIRS ${DIRS} ${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# aes256
set(DIRS ${DIRS} "lib")

# exports all symbols
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# libwz.so or wz.dll - shared library
set(CRYPTO_SOURCES
  "lib/aes256.c")
set(SOURCES
  "byteorder.c"
  "file.c")
set_source_files_properties(
  ${SOURCES}
  PROPERTIES
    COMPILE_FLAGS
      "${SOURCES_CFLAGS}")
add_library(
  "lib"
  SHARED
    ${CRYPTO_SOURCES}
    ${SOURCES})
target_include_directories(
  "lib"
  SYSTEM
  PRIVATE
    ${DIRS})
target_link_libraries(
  "lib"
    ${LIBS})
set_target_properties(
  "lib"
  PROPERTIES
    OUTPUT_NAME
      "wz"
    VERSION
      "1.0.0"
    SOVERSION
      "1")

# wz/*.h - headers
set(INSTALL_BINARY_DIR    "${CMAKE_INSTALL_PREFIX}/bin")
set(INSTALL_LIBRARY_DIR   "${CMAKE_INSTALL_PREFIX}/lib")
set(INSTALL_INCLUDE_DIR   "${CMAKE_INSTALL_PREFIX}/include/wz")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig")
set(INSTALL_PKGCONFIG     "${CMAKE_CURRENT_BINARY_DIR}/wz.pc")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/wz.pc.in"
    "${INSTALL_PKGCONFIG}"
  @ONLY)
install(
  TARGETS
    "lib"
  RUNTIME
    DESTINATION
      "${INSTALL_BINARY_DIR}"
  LIBRARY
    DESTINATION
      "${INSTALL_LIBRARY_DIR}"
  ARCHIVE
    DESTINATION
      "${INSTALL_LIBRARY_DIR}")
install(
  FILES
    "file.h"
  DESTINATION
    "${INSTALL_INCLUDE_DIR}")
install(
  FILES
    "${INSTALL_PKGCONFIG}"
  DESTINATION
    "${INSTALL_PKGCONFIG_DIR}")

# wz - main program
add_executable(
  "wz"
    "main.c")
target_link_libraries(
  "wz"
    "lib")
target_compile_options(
  "wz"
  PRIVATE
    ${CFLAGS})
target_compile_definitions(
  "wz"
  PRIVATE
    "_POSIX_C_SOURCE=199309L")
