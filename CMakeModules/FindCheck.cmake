# - Try to find the Check libraries
#  Once done this will define
#
#  CHECK_FOUND       - system has Check
#  CHECK_INCLUDE_DIR - the Check include directory
#  CHECK_LIBRARIES   - the libraries needed to use Check
#
#  Copyright (c) 2007 Daniel Gollub <gollub@b1-systems.de>
#  Copyright (c) 2007-2009 Bjoern Ricks  <bjoern.ricks@gmail.com>
#  Copyright (c) 2016 Lien Chiang  <xsoameix@gmail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(_CHECK_ROOT_HINTS ${CHECK_ROOT_DIR} ENV CHECK_ROOT_DIR)
  find_path(CHECK_INCLUDE_DIR
    NAMES check.h
    HINTS ${_CHECK_ROOT_HINTS}
    PATH_SUFFIXES "include")
  find_library(_CHECK_COMPAT_LIBRARY
    NAMES compat
    HINTS ${_CHECK_ROOT_HINTS}
    PATH_SUFFIXES "lib")
  find_library(_CHECK_LIBRARY
    NAMES check
    HINTS ${_CHECK_ROOT_HINTS}
    PATH_SUFFIXES "lib")
  set(CHECK_LIBRARIES ${_CHECK_LIBRARY} ${_CHECK_COMPAT_LIBRARY})
  find_package_handle_standard_args(Check "Could NOT find Check, try to set the path to Check root folder in the system variable CHECK_ROOT_DIR"
    CHECK_LIBRARIES CHECK_INCLUDE_DIR)
else()
  find_package(PkgConfig QUIET REQUIRED)
  pkg_search_module(CHECK REQUIRED QUIET check)
  find_path(CHECK_INCLUDE_DIR NAMES check.h HINTS ${CHECK_INCLUDE_DIRS})
  find_package(PackageHandleStandardArgs QUIET REQUIRED)
  find_package_handle_standard_args(Check
    REQUIRED_VARS CHECK_LIBRARIES CHECK_INCLUDE_DIR
    VERSION_VAR CHECK_VERSION)
endif()

mark_as_advanced(CHECK_INCLUDE_DIR CHECK_LIBRARIES)
