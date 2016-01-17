cmake_minimum_required(VERSION 2.8)
project(wzlib)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules")
enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
