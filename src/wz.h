#ifndef WZ_H
#define WZ_H

#if defined(_WIN64) || defined(__x86_64__) || \
    defined(__aarch64__) || defined(__ppc64__)
#  define WZ_ARCH_64
#else
#  define WZ_ARCH_32
#endif

typedef   signed char  wz_int8_t;
typedef   signed short wz_int16_t;
typedef   signed int   wz_int32_t;
typedef unsigned char  wz_uint8_t;
typedef unsigned short wz_uint16_t;
typedef unsigned int   wz_uint32_t;

#if defined(_MSC_VER)
typedef   signed __int64 wz_int64_t;
typedef unsigned __int64 wz_uint64_t;
#elif defined(WZ_ARCH_32)
typedef   signed long long wz_int64_t;
typedef unsigned long long wz_uint64_t;
#else
typedef   signed long wz_int64_t;
typedef unsigned long wz_uint64_t;
#endif

#if defined(WZ_ARCH_32)
typedef   signed int wz_intptr_t;
typedef unsigned int wz_uintptr_t;
#elif defined(_MSC_VER)
typedef   signed __int64 wz_intptr_t;
typedef unsigned __int64 wz_uintptr_t;
#else
typedef   signed long wz_intptr_t;
typedef unsigned long wz_uintptr_t;
#endif

#define WZ_INT8_MIN   (-128)
#define WZ_INT8_MAX   127
#define WZ_UINT8_MAX  255
#define WZ_UINT16_MAX 65535
#define WZ_INT32_MAX  2147483647

#if defined(_MSC_VER)
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

typedef union wznode wznode;
typedef struct wzfile wzfile;
typedef struct wzctx wzctx;

enum {
  WZ_NIL,
  WZ_I16,
  WZ_I32,
  WZ_I64,
  WZ_F32,
  WZ_F64,
  WZ_VEC,  /* "Shape2D#Vector2D" */
  WZ_UNK,  /* not read yet */
  WZ_ARY,  /* "Property" */
  WZ_IMG,  /* "Canvas" */
  WZ_VEX,  /* "Shape2D#Convex2D" */
  WZ_AO,   /* "Sound_DX8" */
  WZ_UOL,  /* "UOL" */
  WZ_STR,
  WZ_LEN
};

enum {
  WZ_COLOR_4444 =    1,
  WZ_COLOR_8888 =    2,
  WZ_COLOR_565  =  513,
  WZ_COLOR_DXT3 = 1026,
  WZ_COLOR_DXT5 = 2050
};

enum { /* microsoft define these values in Mmreg.h */
  WZ_AUDIO_PCM = 0x0001,
  WZ_AUDIO_MP3 = 0x0055
};

wz_uint8_t   wz_get_type(wznode * node);
int          wz_get_int(wz_int32_t * val, wznode * node);
int          wz_get_i64(wz_int64_t * val, wznode * node);
int          wz_get_f32(float * val, wznode * node);
int          wz_get_f64(double * val, wznode * node);
char *       wz_get_str(wznode * node);
wz_uint8_t * wz_get_img(wz_uint32_t * w, wz_uint32_t * h,
                        wz_uint16_t * depth, wz_uint8_t * scale, wznode * node);
int          wz_get_vex_len(wz_uint32_t * len, wznode * node);
int          wz_get_vex_at(wz_int32_t * x, wz_int32_t * y, wz_uint32_t i,
                           wznode * node);
int          wz_get_vec(wz_int32_t * x, wz_int32_t * y, wznode * node);
wz_uint8_t * wz_get_ao(wz_uint32_t * size, wz_uint32_t * ms,
                       wz_uint16_t * format, wznode * node);

wznode *     wz_open_node(wznode * node, const char * path);
int          wz_close_node(wznode * node);
wznode *     wz_open_root(wzfile * file);

char *       wz_get_name(wznode * node);
int          wz_get_len(wz_uint32_t * len, wznode * node);
wznode *     wz_open_node_at(wznode * node, wz_uint32_t i);

wzfile *     wz_open_file(const char * filename, wzctx * ctx);
int          wz_parse_file(wzfile * file);
int          wz_close_file(wzfile * file);

wzctx *      wz_init_ctx(void);
int          wz_free_ctx(wzctx * ctx);

#endif
