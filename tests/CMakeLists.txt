# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# zlib
find_package(ZLIB REQUIRED)
set(DIRS ${DIRS} ${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# aes256
set(DIRS ${DIRS} "../src/lib")

# Check
find_package(Check REQUIRED)
set(DIRS ${DIRS} ${CHECK_INCLUDE_DIR})
set(LIBS ${LIBS} ${CHECK_LIBRARIES})

# suite - testing program
set(DIRS ${DIRS} "../src")
set(CRYPTO_SOURCES
  "../src/lib/aes256.c")
set(SOURCES
  "../src/byteorder.c"
  "wrap_alloc.c"
  "test_file.c"
  "test_suite.c")
set_source_files_properties(
  ${SOURCES}
  PROPERTIES
    COMPILE_FLAGS
      "${SOURCES_CFLAGS}")
add_executable(
  "suite"
    ${CRYPTO_SOURCES}
    ${SOURCES})
target_include_directories(
  "suite"
  SYSTEM
  PRIVATE
    ${DIRS})
target_link_libraries(
  "suite"
    ${LIBS})
add_test(
  "suite"
    "${CMAKE_CURRENT_BINARY_DIR}/suite")
