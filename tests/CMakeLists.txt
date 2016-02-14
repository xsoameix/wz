find_package(OpenSSL)
find_package(ZLIB)
enable_testing()
find_package(Check REQUIRED)
find_package(Threads)

# OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# zlib
include_directories(${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# libwz.so - shared library
include_directories(../src)
add_library(testlib SHARED
  ../src/byteorder.c
  ../src/file.c
  mem.c
)
set_target_properties(testlib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(testlib ${LIBS})
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-wrap,malloc -Wl,-wrap,free")
set(CMAKE_C_FLAGS "-Wall -Werror -std=c99 -pedantic")
set(LIBS testlib)

# Check
include_directories(${CHECK_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# suite - testing program
include_directories(.)
add_executable(suite
  file.c
  suite.c
)
target_link_libraries(suite ${LIBS})
add_test(suite ${CMAKE_CURRENT_BINARY_DIR}/suite)
