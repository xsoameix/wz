cmake_minimum_required(VERSION 2.8)

# Use this policy if exists
if (POLICY CMP0054)
  cmake_policy(SET CMP0054 NEW)
endif()

# Support cmake 2.8.12 ~ 3.0 on Mac OS
set(CMAKE_MACOSX_RPATH 1)

project(wz C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules")
enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
