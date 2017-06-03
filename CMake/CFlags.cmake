include(CheckCCompilerFlag)

macro(filter_flags OUT_FLAGS IN_FLAGS)
  set(${OUT_FLAGS} "")
  foreach(_FLAG ${IN_FLAGS})
    set(_HAS_FLAG "has ${_FLAG}")
    check_c_compiler_flag("${_FLAG}" ${_HAS_FLAG})
    if (${_HAS_FLAG})
      set(${OUT_FLAGS} ${${OUT_FLAGS}} "${_FLAG}")
    endif()
  endforeach()
endmacro()

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  set(CFLAGS
    # C Language Options
    "-std=c89"

    "-pthread"

    # Warning Options
    "-Werror"
    "-Wall"
    "-Wextra"
    "-Wpedantic"
    "-Waggregate-return"
    "-Waggressive-loop-optimizations"
    #"-Wc++-compat"
    "-Wcast-align"
    "-Wcast-qual"
    "-Wconversion"
    "-Wcoverage-mismatch"
    "-Wdisabled-optimization"
    #"-Wdouble-promotion"
    #"-Wfatal-errors"
    "-Wfloat-equal"
    "-Wformat-nonliteral"
    "-Wformat-security"
    "-Wformat-y2k"
    #"-Wframe-larger-than=len"
    "-Wjump-misses-init"
    "-Wimplicit"
    "-Winit-self"
    "-Winline"
    "-Winvalid-pch"
    #"-Wlarger-than=len" # test coverage increase maximum size of usage
    "-Wunsafe-loop-optimizations"
    "-Wlogical-op"
    "-Wlong-long"
    "-Wmissing-include-dirs"
    "-Woverlength-strings"
    "-Wpacked"
    "-Wpacked-bitfield-compat"
    "-Wpadded"
    "-Wpointer-arith"
    "-Wredundant-decls"
    "-Wshadow"
    "-Wsign-conversion"
    "-Wsizeof-pointer-memaccess"
    "-Wstack-protector"
    "-Wstack-usage=1024"
    "-Wswitch-default"
    "-Wswitch-enum"
    "-Wsync-nand"
    #"-Wsystem-headers"
    "-Wtrampolines"
    "-Wundef"
    "-Wunsuffixed-float-constants"
    "-Wunused"
    "-Wunused-local-typedefs"
    "-Wunused-but-set-variable"
    "-Wvariadic-macros"
    "-Wvector-operation-performance"
    "-Wvla"
    "-Wwrite-strings"

    # C and Objective-C-only Warning Options
    "-Wbad-function-cast"
    "-Wmissing-declarations"
    "-Wmissing-prototypes"
    "-Wnested-externs"
    "-Wold-style-definition"
    "-Wstrict-prototypes"
    #"-Wtraditional"
    #"-Wtraditional-conversion"
    "-Wdeclaration-after-statement"

    "-Wno-long-long")
elseif ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
  set(CFLAGS
    "-std=c89"
    "-pthread"
    "-Werror"
    "-Weverything"
    "-Wno-double-promotion"
    "-Wno-format-nonliteral")
  if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    set(CFLAGS ${CFLAGS}
      "-Wno-disabled-macro-expansion")
  endif()
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  set(CFLAGS
    "/WX"
    "/Wall"
    "/wd4204"  # C99
    "/wd4710"  # C89: inline function
    "/wd4996") # C89: fopen
  if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    set(CFLAGS ${CFLAGS}
      "/wd4711") # C89: inline function when O2 is enabled
  endif()
endif()

if ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
  filter_flags(CFLAGS "${CFLAGS}")
endif()

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
  include(CheckCSourceCompiles)
  set(_FUNC "__func__")
  set(_HAS_FUNC "has ${_FUNC}")
  check_c_source_compiles("
    int
    main(int argc, char ** argv) {
      (void) argc;
      (void) argv;
      const char * str = ${_FUNC};
      (void) str;
      return 0;
    }"
    ${_HAS_FUNC})
  if (NOT ${_HAS_FUNC})
    set(CFLAGS ${CFLAGS} "/D${_FUNC}=__FUNCTION__")
  endif()
endif()

string(REPLACE ";" " " SOURCES_CFLAGS "${CFLAGS}")
