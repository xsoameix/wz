# thread
find_package(Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

# zlib
find_package(ZLIB REQUIRED)
set(DIRS ${DIRS} ${ZLIB_INCLUDE_DIRS})
set(LIBS ${LIBS} ${ZLIB_LIBRARIES})

# aes256
add_library(aes256 SHARED lib/aes256.c)
set(DIRS ${DIRS} lib)
set(LIBS ${LIBS} aes256)

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
    "/wd4204" # C99
    "/wd4710" # C89: inline function
    "/wd4820" # C89: struct padding
    "/wd4996" # C89: sprintf & fopen
    "/WX /Wall")
endif()
string(REPLACE " " ";" TARGET_FLAGS "${FLAGS}")

# libwz.so or wz.dll - shared library
add_library(lib SHARED
  byteorder.c
  unicode.c
  file.c)
set_target_properties(lib PROPERTIES OUTPUT_NAME wz)
target_include_directories(lib PRIVATE ${DIRS})
target_link_libraries(lib ${LIBS})
target_compile_options(lib PRIVATE ${TARGET_FLAGS})

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
target_compile_options(wz PRIVATE ${TARGET_FLAGS})
