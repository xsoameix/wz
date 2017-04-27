#ifndef WZ_BYTEORDER_H
#define WZ_BYTEORDER_H

#include <stdint.h>

#include <limits.h> // Let <features.h> be included, which defined __GLIBC__
#if defined(__GLIBC__)
#  include <endian.h>
#endif
#if defined(__BYTE_ORDER)
#  if defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN)
#    define WZ_ENDIAN_BIG_BYTE
#    define WZ_ENDIAN_DEFINED
#  elif defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#    define WZ_ENDIAN_LITTLE_BYTE
#    define WZ_ENDIAN_DEFINED
#  elif defined(__PDP_ENDIAN) && (__BYTE_ORDER == __PDP_ENDIAN)
#    define WZ_ENDIAN_LITTLE_WORD
#    define WZ_ENDIAN_DEFINED
#  endif
#endif
#if !defined(WZ_ENDIAN_DEFINED)
#  if defined(_WIN32)
#    define WZ_ENDIAN_LITTLE_BYTE
#    define WZ_ENDIAN_DEFINED
#  endif
#endif

#if defined(_MSC_VER)
#  include <stdlib.h>
#  define WZ_SWAP16(x) _byteswap_ushort(x)
#  define WZ_SWAP32(x) _byteswap_ulong(x)
#  define WZ_SWAP64(x) _byteswap_uint64(x)
#elif defined(__GNUC__) && (__GNUC__ > 4 || \
                            (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))
#  define WZ_SWAP16(x) __builtin_bswap16(x)
#  define WZ_SWAP32(x) __builtin_bswap32(x)
#  define WZ_SWAP64(x) __builtin_bswap64(x)
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
