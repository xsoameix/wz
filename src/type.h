#ifndef WZ_TYPE_H
#define WZ_TYPE_H

#include "predef.h"
#include "wz.h"

#define WZ_INT8_MIN   (-128)
#define WZ_INT8_MAX   127
#define WZ_UINT8_MAX  255
#define WZ_UINT16_MAX 65535
#define WZ_INT32_MAX  2147483647

#if defined(WZ_MSVC)
# define WZ_PRId32 "I32d"
# define WZ_PRIu32 "I32u"
# define WZ_PRIx32 "I32x"
# define WZ_PRId64 "I64d"
# define WZ_PRIu64 "I64u"
#elif defined(WZ_ARCH_32)
# define WZ_PRId32 "d"
# define WZ_PRIu32 "u"
# define WZ_PRIx32 "x"
# define WZ_PRId64 "lld"
# define WZ_PRIu64 "llu"
#else
# define WZ_PRId32 "d"
# define WZ_PRIu32 "u"
# define WZ_PRIx32 "x"
# define WZ_PRId64 "ld"
# define WZ_PRIu64 "lu"
#endif

#if defined(WZ_ARCH_32)
typedef   signed int wz_intptr_t;
typedef unsigned int wz_uintptr_t;
#elif defined(WZ_MSVC)
typedef   signed __int64 wz_intptr_t;
typedef unsigned __int64 wz_uintptr_t;
#else
typedef   signed long wz_intptr_t;
typedef unsigned long wz_uintptr_t;
#endif

#endif
