enable_testing()

# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# zlib
find_package(ZLIB REQUIRED)
set(DIRS ${DIRS} ${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# exports all symbols
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# aes256
set(DIRS ${DIRS} ../src/lib)
set(LIBS ${LIBS} aes256)

# flags
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_C_COMPILER_ID}" MATCHES  "Clang")
  set(FLAGS "-Wall -Werror -std=c99 -pthread -pedantic")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(FLAGS
    "/wd4996" # C89: sprintf & fopen
    "/WX")
endif()
string(REPLACE ";" " " SOURCE_FLAGS "${FLAGS}")
string(REPLACE " " ";" TARGET_FLAGS "${FLAGS}")

# libwz.so or wz.dll - shared library
set(SOURCES
  ../src/byteorder.c
  ../src/unicode.c
  ../src/file.c)
set_source_files_properties(${SOURCES} PROPERTIES
  COMPILE_DEFINITIONS "WZ_WRAP=1")
set_source_files_properties(${SOURCES} PROPERTIES COMPILE_FLAGS ${SOURCE_FLAGS})
add_library(testlib SHARED ${SOURCES} mem.c)
set_target_properties(testlib PROPERTIES OUTPUT_NAME wz)
target_include_directories(testlib PRIVATE ${DIRS})
target_link_libraries(testlib ${LIBS})
target_compile_options(testlib PRIVATE ${TARGET_FLAGS})
set(DIRS ../src)
set(LIBS testlib)

# Check
find_package(Check REQUIRED)
set(DIRS ${DIRS} ${CHECK_INCLUDE_DIR})
set(LIBS ${LIBS} ${CHECK_LIBRARIES})

# suite - testing program
add_executable(suite
  file.c
  suite.c)
target_include_directories(suite PRIVATE ${DIRS})
target_link_libraries(suite ${LIBS})
target_compile_options(suite PRIVATE ${TARGET_FLAGS})
add_test(suite ${CMAKE_CURRENT_BINARY_DIR}/suite)
if (WIN32)
  add_custom_command(TARGET suite POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${ZLIB_ROOT}\\bin\\zlibd.dll $<TARGET_FILE_DIR:suite>)
  message(${ZLIB_LIBRARIES})
  add_custom_command(TARGET suite POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:aes256> $<TARGET_FILE_DIR:suite>)
endif()
