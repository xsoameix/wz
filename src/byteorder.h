#ifndef WZ_BYTEORDER_H
#define WZ_BYTEORDER_H

#include "predef.h"

#if defined(__BYTE_ORDER__)
#  if defined(__ORDER_BIG_ENDIAN__) && \
      (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define WZ_ENDIAN_BIG_BYTE
#    define WZ_ENDIAN_DEFINED
#  elif defined(__ORDER_LITTLE_ENDIAN__) && \
        (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define WZ_ENDIAN_LITTLE_BYTE
#    define WZ_ENDIAN_DEFINED
#  endif
#else
#  ifdef WZ_MSVC
#    pragma warning(push, 3)
#  endif
#  include <limits.h> // Let <features.h> be included, which defined __GLIBC__
#  if defined(WZ_LIB_C_GNU)
#    include <endian.h>
#  endif
#  ifdef WZ_MSVC
#    pragma warning(pop)
#  endif
#  if defined(__BYTE_ORDER)
#    if defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)
#      define WZ_ENDIAN_BIG_BYTE
#      define WZ_ENDIAN_DEFINED
#    elif defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#      define WZ_ENDIAN_LITTLE_BYTE
#      define WZ_ENDIAN_DEFINED
#    elif defined(__PDP_ENDIAN) && (__BYTE_ORDER == __PDP_ENDIAN)
#      define WZ_ENDIAN_LITTLE_WORD
#      define WZ_ENDIAN_DEFINED
#    endif
#  endif
#endif
#if !defined(WZ_ENDIAN_DEFINED)
#  if defined(WZ_WINDOWS)
#    define WZ_ENDIAN_LITTLE_BYTE
#    define WZ_ENDIAN_DEFINED
#  endif
#endif

#ifndef __has_builtin
#  define __has_builtin(x) 0 // compatibility with non-clang compilers
#endif

// clang use the Microsoft rather than GCC intrinsics, so
//  we check for defined(WZ_MSVC) before defined(WZ_CLANG)
#if defined(WZ_MSVC)
#  pragma warning(push, 3)
#  include <stdlib.h>
#  pragma warning(pop)
#  define WZ_SWAP16(x) _byteswap_ushort(x)
#  define WZ_SWAP32(x) _byteswap_ulong(x)
#  define WZ_SWAP64(x) _byteswap_uint64(x)
#  define WZ_SWAP_BUILTIN_DEFINED
#elif (defined(WZ_GCC) && WZ_GCC >= 40800) || \
      (defined(WZ_CLANG) && \
       __has_builtin(__builtin_bswap16) && \
       __has_builtin(__builtin_bswap32) && \
       __has_builtin(__builtin_bswap64))
#  define WZ_SWAP16(x) __builtin_bswap16(x)
#  define WZ_SWAP32(x) __builtin_bswap32(x)
#  define WZ_SWAP64(x) __builtin_bswap64(x)
#  define WZ_SWAP_BUILTIN_DEFINED
#else
#  define WZ_SWAP16(x) wz_swap16(x)
#  define WZ_SWAP32(x) wz_swap32(x)
#  define WZ_SWAP64(x) wz_swap64(x)
uint16_t wz_swap16(uint16_t x16);
uint32_t wz_swap32(uint32_t x32);
uint64_t wz_swap64(uint64_t x64);
#endif

#if defined(WZ_ENDIAN_BIG_BYTE)
#  define WZ_HTOLE16(x) WZ_SWAP16(x)
#  define WZ_HTOLE32(x) WZ_SWAP32(x)
#  define WZ_HTOLE64(x) WZ_SWAP64(x)
#  define WZ_HTOBE16(x) x
#  define WZ_HTOBE32(x) x
#  define WZ_HTOBE64(x) x
#  define WZ_LE16TOH(x) WZ_SWAP16(x)
#  define WZ_LE32TOH(x) WZ_SWAP32(x)
#  define WZ_LE64TOH(x) WZ_SWAP64(x)
#  define WZ_BE16TOH(x) x
#  define WZ_BE32TOH(x) x
#  define WZ_BE64TOH(x) x
#elif defined(WZ_ENDIAN_LITTLE_BYTE)
#  define WZ_HTOLE16(x) x
#  define WZ_HTOLE32(x) x
#  define WZ_HTOLE64(x) x
#  define WZ_HTOBE16(x) WZ_SWAP16(x)
#  define WZ_HTOBE32(x) WZ_SWAP32(x)
#  define WZ_HTOBE64(x) WZ_SWAP64(x)
#  define WZ_LE16TOH(x) x
#  define WZ_LE32TOH(x) x
#  define WZ_LE64TOH(x) x
#  define WZ_BE16TOH(x) WZ_SWAP16(x)
#  define WZ_BE32TOH(x) WZ_SWAP32(x)
#  define WZ_BE64TOH(x) WZ_SWAP64(x)
#endif

#endif
