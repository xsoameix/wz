find_package(OpenSSL)
enable_testing()
find_package(Check REQUIRED)
find_package(Threads)

# OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})
set(LIBS ${LIBS} ${OPENSSL_LIBRARIES})

# libwz.so - shared library
include_directories(../src)
file(GLOB_RECURSE SOURCES ../src/*.c)
add_library(testlib SHARED ${SOURCES})
add_definitions(-D_WZLIB_TEST)
set_target_properties(testlib PROPERTIES OUTPUT_NAME wz)
target_link_libraries(testlib ${LIBS})
set(LIBS testlib)

# Check
include_directories(${CHECK_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# suite - testing program
include_directories(.)
file(GLOB_RECURSE SUITE *.c)
add_executable(suite ${SUITE})
target_link_libraries(suite ${LIBS})
add_test(suite ${CMAKE_CURRENT_BINARY_DIR}/suite)
