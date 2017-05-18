#ifndef WZ_PREDEF_H
#define WZ_PREDEF_H

// Standard Library
#if defined(__GLIBC__)
#  define WZ_LIB_C_GNU
#endif

// Operating System
#if defined(_WIN32)
#  define WZ_WINDOWS
#endif
#if defined(__APPLE__) && defined(__MACH__)
#  define WZ_MACOS
#endif

// Compiler
#if defined(__GNUC__) && \
    defined(__GNUC_MINOR__) && \
    defined(__GNUC_PATCHLEVEL__)
#  define WZ_GCC (__GNUC__ * 10000 + \
                  __GNUC_MINOR__ * 100 + \
                  __GNUC_PATCHLEVEL__)
#endif
#if defined(__clang__)
#  define WZ_CLANG
#endif
#if defined(_MSC_VER)
#  define WZ_MSVC _MSC_VER
#endif

#endif
