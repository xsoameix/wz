#include "predef.h"

#ifdef WZ_MSVC
#  pragma warning(push, 3)
#endif

/* Standard Library */

#ifndef WZ_NO_THRD
#  ifdef WZ_WINDOWS
#    include <Windows.h>
#    include <process.h>
#  else
#    include <pthread.h>
#  endif
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

/* Third Party Library */

#include <aes256.h>
#include <zlib.h>

#ifdef WZ_MSVC
#  pragma warning(pop)
#endif

/* This Library */

#include "wz.h"
#include "type.h"
#include "byteorder.h"

#define WZ_IS_LV0_NIL(type)  ((type) == 0x01)
#define WZ_IS_LV0_LINK(type) ((type) == 0x02)
#define WZ_IS_LV0_ARY(type)  ((type) == 0x03)
#define WZ_IS_LV0_OBJ(type)  ((type) == 0x04)

#define WZ_IS_LV1_NIL(type) ((type) == 0x00)
#define WZ_IS_LV1_I16(type) ((type) == 0x02 || (type) == 0x0b)
#define WZ_IS_LV1_I32(type) ((type) == 0x03 || (type) == 0x13)
#define WZ_IS_LV1_I64(type) ((type) == 0x14)
#define WZ_IS_LV1_F32(type) ((type) == 0x04)
#define WZ_IS_LV1_F64(type) ((type) == 0x05)
#define WZ_IS_LV1_STR(type) ((type) == 0x08)
#define WZ_IS_LV1_OBJ(type) ((type) == 0x09)

#define WZ_IS_LV1_ARY(type) (!strcmp((char *) (type), "Property"))
#define WZ_IS_LV1_IMG(type) (!strcmp((char *) (type), "Canvas"))
#define WZ_IS_LV1_VEX(type) (!strcmp((char *) (type), "Shape2D#Convex2D"))
#define WZ_IS_LV1_VEC(type) (!strcmp((char *) (type), "Shape2D#Vector2D"))
#define WZ_IS_LV1_AO(type)  (!strcmp((char *) (type), "Sound_DX8"))
#define WZ_IS_LV1_UOL(type) (!strcmp((char *) (type), "UOL"))

typedef struct {
  wz_uint8_t   b;
  wz_uint8_t   g;
  wz_uint8_t   r;
  wz_uint8_t   a;
} wzcolor;

typedef struct {
  wz_uint16_t  format;
  wz_uint16_t  channels;
  wz_uint32_t  sample_rate;
  wz_uint32_t  byte_rate;
  wz_uint16_t  block_align;
  wz_uint16_t  bits_per_sample;
  wz_uint16_t  extra_size;
  wz_uint8_t   _[2]; /* padding */
} wzwav;  /* microsoft WAVEFORMATEX structure */

typedef struct {
  wzwav        wav;
  wz_uint16_t  id;
  wz_uint8_t   _1[2]; /* padding */
  wz_uint32_t  flags;
  wz_uint16_t  block_size;
  wz_uint16_t  frames_per_block;
  wz_uint16_t  codec_delay;
  wz_uint8_t   _2[2]; /* padding */
} wzmp3;  /* microsoft MPEGLAYER3WAVEFORMAT structure */

typedef struct {
  wz_uint32_t  chunk_id;
  wz_uint32_t  chunk_size;
  wz_uint32_t  format;
  wz_uint32_t  subchunk1_id;
  wz_uint32_t  subchunk1_size;
  wz_uint16_t  audio_format;
  wz_uint16_t  channels;
  wz_uint32_t  sample_rate;
  wz_uint32_t  byte_rate;
  wz_uint16_t  block_align;
  wz_uint16_t  bits_per_sample;
  wz_uint32_t  subchunk2_id;
  wz_uint32_t  subchunk2_size;
} wzpcm;

typedef struct { wz_int32_t x; wz_int32_t y; } wzvec;

/* wznode format:
   0    4    8    12   16   20   24   28   32   36   40
   p--- ---- n--- ---- tlb- ---- b--- ---- ---- --2-
   p--- ---- n--- ---- tlb- ---- b--- ---- ---- 4---
   p--- ---- n--- ---- tlb- ---- b--- ---- 8--- ----
   p--- ---- n--- ---- tlb- ---- b--- ---- o--- ----
   p--- ---- f--- ---- tlb- ---- b--- ---- d--- ----
   p--- ---- f--- ---- tlb- ---- ---k a--- d--- ----
   p--- ---- f--- ---- tlk. a--- b--- ---- d--- ----

   p--- n--- tlb- b--- ---- --2-
   p--- n--- tlb- b--- ---- 4---
   p--- n--- tlb- b--- 8--- ----
   p--- n--- tlb- b--- ---- o---
   p--- f--- tlb- b--- ---- d---
   p--- f--- tlb- ---k a--- d---
   p--- f--- tlk. b--- a--- d--- */

typedef struct {
  wz_uint8_t   _[4 * sizeof(void *) + 8 - 2]; /* padding */
  wz_int16_t   val;
} wznode_16;

typedef struct {
  wz_uint8_t   _[4 * sizeof(void *) + 8 - 4]; /* padding */
  union        { wz_int32_t i; float f; } val;
} wznode_32;

typedef struct {
  wz_uint8_t   _[4 * sizeof(void *)]; /* padding */
  union        { wz_int64_t i; double f; wzvec vec; } val;
} wznode_64;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8];
} wznode_nil_embed;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 2];
} wznode_16_embed;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 4];
} wznode_32_embed;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *)];
} wznode_64_embed;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 -
                        sizeof(void *)];
} wznode_ptr_embed;

typedef struct {
  wz_uint8_t   _[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   name_buf[sizeof(void *) - 2 + 4 - 1];
  wz_uint8_t   key;
  wz_uint32_t  addr;
} wznode_addr_embed;

typedef struct {
  wz_uint8_t   _1[2 * sizeof(void *) + 2]; /* padding */
  wz_uint8_t   key;
  wz_uint8_t   _2[1]; /* padding */
#ifdef WZ_ARCH_32
  wz_uint8_t   _3[sizeof(void *)]; /* name in prototype */
#endif
  wz_uint32_t  addr;
} wznode_addr;

typedef struct {
  union {
    union  wznode * node;
    struct wzfile * file;
  }              root;
  union wznode * parent;
  wz_uint8_t     info;
  wz_uint8_t     name_len;
  wz_uint8_t     name_e[sizeof(void *) - 2];
  wz_uint8_t *   name;
#ifdef WZ_ARCH_32
  wz_uint8_t     _[4]; /* addr in wznode_addr */
#endif
  union {
    struct wzstr * str;
    struct wzary * ary;
    struct wzimg * img;
    struct wzvex * vex;
    struct wzao  * ao;
  }              val;
} wznode_proto; /* prototype */

union wznode {
  wznode_nil_embed   nil_e;
  wznode_16_embed    n16_e;
  wznode_32_embed    n32_e;
  wznode_64_embed    n64_e;
  wznode_16          n16;
  wznode_32          n32;
  wznode_64          n64;
  wznode_ptr_embed   np_e;
  wznode_addr_embed  na_e;
  wznode_addr        na;
  wznode_proto       n;
};

typedef struct wzstr {
  wz_uint32_t  len;
  wz_uint8_t   bytes[4]; /* variable array */
} wzstr;

typedef struct wzary {
  wz_uint32_t  len;
  wz_uint8_t   _[4]; /* padding */
  wznode       nodes[1]; /* variable array */
} wzary;

typedef struct wzimg {
  wz_uint32_t  w;
  wz_uint32_t  h;
  wz_uint8_t * data;
  wz_uint16_t  depth;
  wz_uint8_t   scale;
  wz_uint8_t   _1[1]; /* padding */
  wz_uint32_t  size;
  wz_uint32_t  len;
#ifdef WZ_ARCH_64
  wz_uint8_t   _2[4]; /* padding */
#endif
  wznode       nodes[1]; /* variable array */
} wzimg;

typedef struct wzvex {
  wz_uint32_t  len;
  wzvec        ary[1]; /* variable array */
} wzvex;

typedef struct wzao {
  wz_uint32_t  size;
  wz_uint32_t  ms;
  wz_uint16_t  format;
  wz_uint8_t   _[sizeof(void *) - 2]; /* padding */
  wz_uint8_t * data;
} wzao;

struct wzfile {
  struct wzctx * ctx;
  FILE *       raw;
  wz_uint32_t  pos;
  wz_uint32_t  size;
  wz_uint32_t  start;
  wz_uint32_t  hash;
  wz_uint8_t   key;
  wz_uint8_t   _[8 - 1]; /* padding */
  wznode       root;
};

struct wzctx {
  wz_uint8_t * keys;
};

typedef union {
  wz_uint8_t        * u8;
  wz_uint16_t       * u16;
  wz_uint32_t       * u32;
  wz_uint64_t       * u64;
  const wz_uint8_t  * c8;
  const wz_uint16_t * c16;
  const wz_uint32_t * c32;
  const wz_uint64_t * c64;
  wznode            * n;
  wzstr             * s;
} wzptr;

static const wz_uint8_t wz_aes_key[32 / 4] = {
  /* These value would be expanded to aes key */
  0x13, 0x08, 0x06, 0xb4, 0x1b, 0x0f, 0x33, 0x52
};

static const wz_uint32_t wz_aes_ivs[] = {
  /* These values would be expanded to aes ivs */
  0x2bc7234d,
  0xe9637db9 /* used to decode UTF8 (lua script) */
};

enum {
  WZ_KEYS_LEN = sizeof(wz_aes_ivs) / sizeof(* wz_aes_ivs),

  /* Get the index of the last key, which is empty and filled with zeros */
  WZ_KEY_EMPTY = WZ_KEYS_LEN,

  /* There may be a giant json string which is large than 0x10000 bytes and
      use only first 0x10000 bytes of the key to decode the characters,
      which is encoded in ascii
     The image chunk and wav header, which are small than 0x10000 bytes,
      also use the key to decode itself */
  WZ_KEY_ASCII_MAX_LEN = 0x10000,

  /* The largest lua script (jms v357: Etc.wz: /Script/BattleScene.lua)
      we found is 0x1106c bytes and fully encoded in utf8,
      so we set a number bigger than this */
  WZ_KEY_UTF8_MAX_LEN  = 0x12000
};

enum { /* bit fields of wznode->info */
  WZ_TYPE  = 0x0f,
  WZ_LEVEL = 0x10,
  WZ_LEAF  = 0x20, /* is it a leaf in level 0 or not */
  WZ_EMBED = 0x40
};

enum {
  WZ_ENC_AUTO,
  WZ_ENC_CP1252,
  WZ_ENC_UTF16LE,
  WZ_ENC_UTF8
};

enum {
  WZ_LV0_NAME,
  WZ_LV1_NAME,
  WZ_LV1_STR,
  WZ_LV1_TYPENAME,
  WZ_LV1_TYPENAME_OR_STR
};

enum {
  WZ_AUDIO_WAV_SIZE = 18, /* sizeof(packed wzwav) */
  WZ_AUDIO_PCM_SIZE = 44  /* sizeof(packed wzpcm) */
};

#ifdef WZ_MSVC
#  define WZ_ONCE \
    __pragma(warning(push)) \
    __pragma(warning(disable: 4127)) \
    while (0) \
    __pragma(warning(pop))
#else
#  define WZ_ONCE while (0)
#endif
#define WZ_ERR \
    fprintf(stderr, "Error: %s at %s:%d\n", __func__, __FILE__, __LINE__)
#define WZ_ERR_GOTO(x) do { WZ_ERR; goto x; } WZ_ONCE
#define WZ_ERR_RET(x) do { WZ_ERR; return x; } WZ_ONCE
/*
#define malloc(x) \
    (printf("malloc(%zu) at %s:%s:%d\n", \
            (size_t) x, __func__, __FILE__, __LINE__), \
     malloc(x))
#define realloc(ptr, x) \
    (printf("realloc(%p, %zu) at %s:%s:%d\n", \
            (void *) ptr, (size_t) x, __func__, __FILE__, __LINE__), \
     realloc(ptr, x))
#define free(ptr) \
    (printf("free(%p) at %s:%s:%d\n", \
            (void *) ptr, __func__, __FILE__, __LINE__), \
     free(ptr))
*/

static void
wz_error(const char * format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, format, args);
  va_end(args);
}

static int
wz_read_bytes(void * bytes, wz_uint32_t len, wzfile * file) {
  if (len > file->size - file->pos) WZ_ERR_RET(1);
  if (!len) return 0;
  if (fread(bytes, len, 1, file->raw) != 1) WZ_ERR_RET(1);
  return file->pos += len, 0;
}

static int
wz_read_byte(wz_uint8_t * byte, wzfile * file) {
  if (1 > file->size - file->pos) WZ_ERR_RET(1);
  if (fread(byte, 1, 1, file->raw) != 1) WZ_ERR_RET(1);
  return file->pos += 1, 0;
}

static int
wz_read_le16(wz_uint16_t * le16, wzfile * file) {
  if (2 > file->size - file->pos) WZ_ERR_RET(1);
  if (fread(le16, 2, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le16 = WZ_LE16TOH(* le16);
  return file->pos += 2, 0;
}

static int
wz_read_le32(wz_uint32_t * le32, wzfile * file) {
  if (4 > file->size - file->pos) WZ_ERR_RET(1);
  if (fread(le32, 4, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le32 = WZ_LE32TOH(* le32);
  return file->pos += 4, 0;
}

static int
wz_read_le64(wz_uint64_t * le64, wzfile * file) {
  if (8 > file->size - file->pos) WZ_ERR_RET(1);
  if (fread(le64, 8, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le64 = WZ_LE64TOH(* le64);
  return file->pos += 8, 0;
}

static int /* read packed integer (int8 or int32) */
wz_read_int32(wz_uint32_t * int32, wzfile * file) {
  wz_int8_t byte;
  if (wz_read_byte((wz_uint8_t *) &byte, file)) WZ_ERR_RET(1);
  if (byte == WZ_INT8_MIN) return wz_read_le32(int32, file);
  return * (wz_int32_t *) int32 = byte, 0;
}

static int /* read packed long (int8 or int64) */
wz_read_int64(wz_uint64_t * int64, wzfile * file) {
  wz_int8_t byte;
  if (wz_read_byte((wz_uint8_t *) &byte, file)) WZ_ERR_RET(1);
  if (byte == WZ_INT8_MIN) return wz_read_le64(int64, file);
  return * (wz_int64_t *) int64 = byte, 0;
}

static int
wz_seek(wz_uint32_t pos, int origin, wzfile * file) {
  switch (origin) {
  case SEEK_CUR:
    if (pos > file->size - file->pos)
      WZ_ERR_RET(1);
    if (fseek(file->raw, pos, origin))
      WZ_ERR_RET(1);
    file->pos += pos;
    break;
  case SEEK_SET:
    if (pos > file->size)
      WZ_ERR_RET(1);
    if (fseek(file->raw, pos, origin))
      WZ_ERR_RET(1);
    file->pos = pos;
    break;
  default:
    WZ_ERR_RET(1);
  }
  return 0;
}

static const wz_uint16_t wz_cp1252_to_unicode[128] = {
  /* 0x80 to 0xff, cp1252 only, code 0xffff means the char is undefined */
  0x20ac, 0xffff, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
  0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0xffff, 0x017d, 0xffff,
  0xffff, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
  0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xffff, 0x017e, 0x0178,
  0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7,
  0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
  0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7,
  0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bf,
  0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
  0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
  0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7,
  0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
  0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
  0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
  0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
  0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff
};

static int
wz_cp1252_to_utf8(wz_uint8_t * ret_u8, wz_uint32_t * ret_u8_len,
                  const wz_uint8_t * cp1252, wz_uint32_t cp1252_len) {
  wz_uint8_t * u8 = ret_u8 == NULL ? 0 : ret_u8;
  for (; cp1252_len; cp1252_len--) {
    wz_uint16_t code = * cp1252++;
    if (code >= 0x80)
      code = wz_cp1252_to_unicode[code - 0x80];
    if (code < 0x80) {
      if (ret_u8 != NULL)
        u8[0] = (wz_uint8_t) code;
      u8++;
    } else if (code < 0x800) {
      if (ret_u8 != NULL) {
        u8[0] = (wz_uint8_t) (((code >> 6)       ) | 0xc0);
        u8[1] = (wz_uint8_t) (((code     ) & 0x3f) | 0x80);
      }
      u8 += 2;
    } else if (code < 0xffff) {
      if (ret_u8 != NULL) {
        u8[0] = (wz_uint8_t) (((code >> 12)       ) | 0xe0);
        u8[1] = (wz_uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[2] = (wz_uint8_t) (((code      ) & 0x3f) | 0x80);
      }
      u8 += 3;
    } else {
      WZ_ERR_RET(1);
    }
  }
  if (ret_u8 == NULL)
    * ret_u8_len = (wz_uint32_t) (wz_uintptr_t) u8;
  else
    * u8 = '\0';
  return 0;
}

static int
wz_utf16le_to_utf8(wz_uint8_t * ret_u8, wz_uint32_t * ret_u8_len,
                   const wz_uint8_t * u16, wz_uint32_t u16_len) {
  wz_uint8_t * u8 = ret_u8 == NULL ? 0 : ret_u8;
  while (u16_len) {
    wz_uint32_t code; /* unicode */
    if (u16_len < 2)
      WZ_ERR_RET(1);
    if ((u16[1] & 0xfc) == 0xd8) {
      if (u16_len < 4)
        WZ_ERR_RET(1);
      if ((u16[3] & 0xfc) == 0xdc) {
        code = (wz_uint32_t) ((u16[1] & 0x03) << 18 |
                              (u16[0]       ) << 10 |
                              (u16[3] & 0x03) <<  8 |
                              (u16[2]       )      );
        u16     += 4;
        u16_len -= 4;
      } else {
        WZ_ERR_RET(1);
      }
    } else {
      code = (wz_uint32_t) ((u16[1] << 8) |
                            (u16[0]     ));
      u16     += 2;
      u16_len -= 2;
    }
    if (code < 0x80) {
      if (ret_u8 != NULL)
        u8[0] = (wz_uint8_t) code;
      u8++;
    } else if (code < 0x800) {
      if (ret_u8 != NULL) {
        u8[0] = (wz_uint8_t) (((code >> 6)       ) | 0xc0);
        u8[1] = (wz_uint8_t) (((code     ) & 0x3f) | 0x80);
      }
      u8 += 2;
    } else if (code < 0x10000) {
      if (ret_u8 != NULL) {
        u8[0] = (wz_uint8_t) (((code >> 12)       ) | 0xe0);
        u8[1] = (wz_uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[2] = (wz_uint8_t) (((code      ) & 0x3f) | 0x80);
      }
      u8 += 3;
    } else if (code < 0x110000) {
      if (ret_u8 != NULL) {
        u8[0] = (wz_uint8_t) (((code >> 18)       ) | 0xf0);
        u8[1] = (wz_uint8_t) (((code >> 12) & 0x3f) | 0x80);
        u8[2] = (wz_uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[3] = (wz_uint8_t) (((code      ) & 0x3f) | 0x80);
      }
      u8 += 4;
    } else {
      WZ_ERR_RET(1);
    }
  }
  if (ret_u8 == NULL)
    * ret_u8_len = (wz_uint32_t) (wz_uintptr_t) u8;
  else
    * u8 = '\0';
  return 0;
}

static int
wz_decode_chars(wz_uint8_t * bytes, wz_uint32_t len,
                wz_uint8_t key_i, const wz_uint8_t * keys, wz_uint8_t enc) {
  wz_uint32_t min_len;
  wzptr key;
  wzptr dst;
  wz_uint8_t mask_8;
  wz_uint16_t mask_16;
  wz_uint32_t i;
  if (enc == WZ_ENC_CP1252) {
    if (key_i == WZ_KEY_EMPTY) {
      min_len = 0;
      key.c8 = NULL;
    } else {
      if (len <= WZ_KEY_ASCII_MAX_LEN)
        min_len = len;
      else
        min_len = WZ_KEY_ASCII_MAX_LEN;
      key.c8 = keys + key_i * WZ_KEY_UTF8_MAX_LEN;
    }
    mask_8 = 0xaa;
    for (i = 0; i < min_len; i++)
      bytes[i] ^= (wz_uint8_t) (mask_8++ ^ key.c8[i]);
    for (i = min_len; i < len; i++)
      bytes[i] ^= (wz_uint8_t) mask_8++;
  } else if (enc == WZ_ENC_UTF16LE) {
    dst.u8 = bytes;
    if (key_i == WZ_KEY_EMPTY) {
      len >>= 1;
      min_len = 0;
      key.c8 = NULL;
    } else {
      if (len > WZ_KEY_ASCII_MAX_LEN)
        WZ_ERR_RET(1);
      len >>= 1;
      min_len = len;
      key.c8 = keys + key_i * WZ_KEY_UTF8_MAX_LEN;
    }
    mask_16 = 0xaaaa;
    for (i = 0; i < min_len; i++)
      dst.u16[i] = WZ_HTOLE16(WZ_LE16TOH(dst.u16[i]) ^ mask_16++ ^
                              WZ_LE16TOH(key.c16[i]));
    for (i = min_len; i < len; i++)
      dst.u16[i] = WZ_HTOLE16(WZ_LE16TOH(dst.u16[i]) ^ mask_16++);
  } else {
    assert(enc == WZ_ENC_UTF8);
    if (len > WZ_KEY_UTF8_MAX_LEN)
      WZ_ERR_RET(1);
    key.c8 = keys + key_i * WZ_KEY_UTF8_MAX_LEN;
    for (i = 0; i < len; i++)
      bytes[i] ^= key.c8[i];
  }
  return 0;
}

static int (* const wz_to_utf8[])(wz_uint8_t *, wz_uint32_t *,
                                  const wz_uint8_t *, wz_uint32_t) = {
  /* WZ_ENC_AUTO    */ NULL,
  /* WZ_ENC_CP1252  */ wz_cp1252_to_utf8,
  /* WZ_ENC_UTF16LE */ wz_utf16le_to_utf8,
  /* WZ_ENC_UTF8    */ NULL
};

static int /* read characters (cp1252, utf16le, or utf8) */
wz_read_chars(wz_uint8_t ** ret_bytes, wz_uint32_t * ret_len,
              wz_uint8_t * ret_enc,
              wz_uint32_t capa, wz_uint32_t addr, wz_uint8_t type,
              wz_uint8_t key, wz_uint8_t * keys, wzfile * file) {
  int ret = 1;
  wz_uint8_t enc = WZ_ENC_AUTO;
  wz_uint32_t pos = 0;
  wz_uint8_t padding = 0;
  wz_int8_t byte;
  wz_uint32_t len;
  wz_uint8_t * bytes_ptr;
  wz_uint8_t * bytes;
  wz_uint8_t * utf8_ptr;
  wz_uint32_t  utf8_len;
  if (type != WZ_LV0_NAME) {
    wz_uint8_t fmt;
    enum {UNK = 2};
    wz_uint8_t inplace;
    if (wz_read_byte(&fmt, file))
      WZ_ERR_RET(ret);
    inplace = UNK;
    switch (type) {
    case WZ_LV1_NAME:
    case WZ_LV1_STR:
      switch (fmt) {
      case 0x00: inplace = 1; break;
      case 0x01: inplace = 0; break;
      default:                break;
      }
      break;
    case WZ_LV1_TYPENAME:
      switch (fmt) {
      case 0x1b: inplace = 0; break;
      case 0x73: inplace = 1; break;
      default:                break;
      }
      break;
    case WZ_LV1_TYPENAME_OR_STR:
      switch (fmt) {
      case 0x01: inplace = 1; break;
      case 0x1b: inplace = 0; break;
      case 0x73: inplace = 1; break;
      default:                break;
      }
      break;
    default:
      break;
    }
    if (inplace == UNK)
      return wz_error("Unsupported string type: 0x%02"WZ_PRIx32"\n",
                      (wz_uint32_t) fmt), ret;
    if (!inplace) {
      wz_uint32_t offset;
      if (wz_read_le32(&offset, file))
        WZ_ERR_RET(ret);
      pos = file->pos;
      if (wz_seek(addr + offset, SEEK_SET, file))
        WZ_ERR_RET(ret);
    }
    if (type == WZ_LV1_STR) {
      padding = sizeof(wz_uint32_t);
    } else if (type == WZ_LV1_TYPENAME_OR_STR && fmt == 0x01) {
      enc = WZ_ENC_UTF8;
      capa = 0;
      key = 1;
      padding = sizeof(wz_uint32_t);
    }
  }
  if (wz_read_byte((wz_uint8_t *) &byte, file))
    WZ_ERR_RET(ret);
  if (byte <= 0) { /* cp1252/ascii/utf8 */
    if (byte == WZ_INT8_MIN) {
      if (wz_read_le32(&len, file))
        WZ_ERR_RET(ret);
    } else {
      len = (wz_uint32_t) -byte;
    }
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_CP1252;
  } else { /* utf16-le */
    if (byte == WZ_INT8_MAX) {
      if (wz_read_le32(&len, file))
        WZ_ERR_RET(ret);
    } else {
      len = (wz_uint32_t) byte;
    }
    len <<= 1;
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_UTF16LE;
  }
  if (capa) {
    if (len >= capa)
      WZ_ERR_RET(ret);
    bytes_ptr = * ret_bytes;
  } else {
    if (len > WZ_INT32_MAX)
      WZ_ERR_RET(ret);
    if ((bytes_ptr = malloc(padding + len + 1)) == NULL)
      WZ_ERR_RET(ret);
  }
  utf8_ptr = NULL;
  bytes = bytes_ptr + padding;
  if (wz_read_bytes(bytes, len, file))
    WZ_ERR_GOTO(free_bytes_ptr);
  bytes[len] = '\0';
  utf8_len = 0;
  if (key != 0xff) {
    int (* to)(wz_uint8_t *, wz_uint32_t *, const wz_uint8_t *, wz_uint32_t);
    if (wz_decode_chars(bytes, len, key, keys, enc))
      WZ_ERR_GOTO(free_bytes_ptr);
    if ((to = wz_to_utf8[enc]) != NULL) {
      wz_uint8_t   utf8_buf[256];
      wz_uint8_t * utf8;
      if (to(NULL, &utf8_len, bytes, len))
        WZ_ERR_GOTO(free_bytes_ptr);
      if (capa && (utf8_len >= capa))
        WZ_ERR_GOTO(free_bytes_ptr);
      if (utf8_len < sizeof(utf8_buf) && (utf8_len <= len || capa)) {
        utf8 = utf8_buf;
      } else { /* malloc new string only if capa == 0 && utf8_len > len */
        if ((utf8_ptr = malloc(padding + utf8_len + 1)) == NULL)
          WZ_ERR_GOTO(free_bytes_ptr);
        utf8 = utf8_ptr + padding;
      }
      if (to(utf8, NULL, bytes, len))
        WZ_ERR_GOTO(free_utf8_ptr);
      if (utf8_len <= len || capa) {
        wz_uint32_t i;
        for (i = 0; i < utf8_len; i++)
          bytes[i] = utf8[i];
        bytes[utf8_len] = '\0';
        if (utf8_ptr != NULL) {
          free(utf8_ptr);
          utf8_ptr = NULL;
        }
      }
    }
  }
  if (pos && wz_seek(pos, SEEK_SET, file))
    WZ_ERR_GOTO(free_utf8_ptr);
  if (utf8_ptr != NULL) {
    * ret_bytes = utf8_ptr;
  } else if (!capa) {
    * ret_bytes = bytes_ptr;
  }
  * ret_len = utf8_len ? utf8_len : len;
  if (ret_enc != NULL)
    * ret_enc = enc;
  ret = 0;
free_utf8_ptr:
  if (ret && utf8_ptr != NULL)
    free(utf8_ptr);
free_bytes_ptr:
  if ((ret || utf8_ptr != NULL) && !capa)
    free(bytes_ptr);
  return ret;
}

static void
wz_free_chars(wz_uint8_t * bytes) {
  free(bytes);
}

static void
wz_decode_addr(wz_uint32_t * ret_val, wz_uint32_t val, wz_uint32_t pos,
               wz_uint32_t start, wz_uint32_t hash) {
  wz_uint32_t key = 0x581c3f6d;
  wz_uint32_t x = ~(pos - start) * hash - key;
  wz_uint32_t n = x & 0x1f;
  x = (x << n) | (x >> (32 - n)); /* rotate left n bit */
  * ret_val = (x ^ val) + start * 2;
}

static int
wz_read_lv0(wznode * node, wzfile * file, wz_uint8_t * keys) {
  int ret = 1;
  wz_uint32_t len;
  wzary * ary;
  wznode * nodes;
  wz_uint8_t  key;
  wz_uint32_t start;
  wz_uint32_t hash;
  wz_uint8_t   name[WZ_UINT8_MAX];
  wz_uint8_t * name_ptr = name;
  wz_uint32_t  name_len;
  wz_uint32_t i;
  wz_uint32_t j;
  if (wz_seek(node->n.info & WZ_EMBED ?
              node->na_e.addr : node->na.addr, SEEK_SET, file))
    WZ_ERR_RET(ret);
  if (wz_read_int32(&len, file))
    WZ_ERR_RET(ret);
  if ((ary = malloc(offsetof(wzary, nodes) +
                    len * sizeof(* ary->nodes))) == NULL)
    WZ_ERR_RET(ret);
  nodes = ary->nodes;
  key   = file->key;
  start = file->start;
  hash  = file->hash;
  for (i = 0; i < len; i++) {
    int err = 1;
    wznode * child = nodes + i;
    wz_uint8_t type;
    wz_uint32_t pos;
    if (wz_read_byte(&type, file))
      WZ_ERR_GOTO(free_child);
    pos = 0;
    if (WZ_IS_LV0_LINK(type)) {
      wz_uint32_t offset;
      if (wz_read_le32(&offset, file))
        WZ_ERR_GOTO(free_child);
      pos = file->pos;
      if (wz_seek(file->start + offset, SEEK_SET, file) ||
          wz_read_byte(&type, file)) /* type and name are in the other place */
        WZ_ERR_GOTO(free_child);
    }
    if (WZ_IS_LV0_ARY(type) ||
        WZ_IS_LV0_OBJ(type)) {
      wz_uint32_t size;
      wz_uint32_t check;
      wz_uint32_t addr;
      wz_uint32_t addr_pos;
      wz_uint8_t * bytes;
      if (wz_read_chars(&name_ptr, &name_len, NULL, sizeof(name),
                        0, WZ_LV0_NAME, key, keys, file) ||
          (pos && wz_seek(pos, SEEK_SET, file)) ||
          wz_read_int32(&size, file) ||
          wz_read_int32(&check, file))
        WZ_ERR_GOTO(free_child);
      addr_pos = file->pos;
      if (wz_read_le32(&addr, file))
        WZ_ERR_GOTO(free_child);
      wz_decode_addr(&addr, addr, addr_pos, start, hash);
      if (name_len < sizeof(child->na_e.name_buf)) {
        bytes = child->n.name_e;
        child->na_e.addr = addr;
        child->na_e.key = 0xff;
        child->n.info = WZ_EMBED;
      } else {
        if ((bytes = malloc(name_len + 1)) == NULL)
          WZ_ERR_GOTO(free_child);
        child->n.name = bytes;
        child->na.addr = addr;
        child->na.key = 0xff;
        child->n.info = 0;
      }
      for (j = 0; j < name_len; j++)
        bytes[j] = name[j];
      bytes[name_len] = '\0';
      child->n.name_len = (wz_uint8_t) name_len;
      if (WZ_IS_LV0_ARY(type))
        child->n.info |= WZ_ARY;
      else
        child->n.info |= WZ_UNK | WZ_LEAF;
    } else if (WZ_IS_LV0_NIL(type)) {
      if (wz_seek(10, SEEK_CUR, file)) /* unknown 10 bytes */
        WZ_ERR_GOTO(free_child);
      child->n.name_e[0] = '\0';
      child->n.name_len = 0;
      child->n.info = WZ_EMBED | WZ_NIL | WZ_LEAF;
    } else {
      wz_error("Unsupported node type: 0x%02"WZ_PRIx32"\n", (wz_uint32_t) type);
      goto free_child;
    }
    child->n.parent = node;
    child->n.root.file = file;
    child->n.val.ary = NULL;
    err = 0;
free_child:
    if (err) {
      for (j = 0; j < i; j++) {
        wznode * child_ = nodes + j;
        if (!(child_->n.info & WZ_EMBED))
          wz_free_chars(child_->n.name);
      }
      goto free_ary;
    }
  }
  ary->len = len;
  node->n.val.ary = ary;
  ret = 0;
free_ary:
  if (ret)
    free(ary);
  return ret;
}

static void
wz_free_lv0(wznode * node) {
  wzary * ary = node->n.val.ary;
  wz_uint32_t len = ary->len;
  wz_uint32_t i;
  wznode * nodes = ary->nodes;
  for (i = 0; i < len; i++) {
    wznode * child = nodes + i;
    if (!(child->n.info & WZ_EMBED))
      wz_free_chars(child->n.name);
  }
  free(ary);
  node->n.val.ary = NULL;
}

static void
wz_encode_ver(wz_uint16_t * ret_enc, wz_uint32_t * ret_hash, wz_uint16_t dec) {
  wz_uint8_t b[5 + 1];
  wz_uint8_t i = 5;
  wz_uint8_t c;
  wz_uint32_t hash;
  wz_uint16_t enc;
  b[5] = '\0';
  if (dec == 0)
    b[--i] = '0';
  else
    do {
      b[--i] = (wz_uint8_t) (dec % 10 + '0');
    } while (dec /= 10);
  hash = 0;
  while ((c = b[i++]) != 0)
    hash = (hash << 5) + c + 1;
  enc = (wz_uint8_t) ~(((hash      ) & 0xff) ^
                       ((hash >>  8) & 0xff) ^
                       ((hash >> 16) & 0xff) ^
                       ((hash >> 24)       ));
  * ret_enc = enc;
  * ret_hash = hash;
}

static int /* if string key is found, the string is also decoded. */
wz_deduce_key(wz_uint8_t * ret_key, wz_uint8_t * bytes, wz_uint32_t len,
              const wz_uint8_t * keys) {
  wz_uint8_t i;
  wz_uint32_t j;
  for (i = 0; i <= WZ_KEY_EMPTY; i++) {
    if (wz_decode_chars(bytes, len, i, keys, WZ_ENC_CP1252)) continue;
    for (j = 0; j < len && isprint(bytes[j]); j++)
      if (j == len - 1) return * ret_key = (wz_uint8_t) i, 0;
    if (wz_decode_chars(bytes, len, i, keys, WZ_ENC_CP1252)) continue;
  }
  return wz_error("Cannot deduce the string key\n"), 1;
}

static int
wz_deduce_ver(wz_uint16_t * ret_dec, wz_uint32_t * ret_hash,
              wz_uint8_t * ret_key, wz_uint16_t enc,
              wz_uint32_t addr, wz_uint32_t start, wz_uint32_t size, FILE * raw,
              const wz_uint8_t * keys) {
  int ret = 1;
  wz_uint32_t len;
  wz_uint32_t i;
  wzfile file;
  file.raw = raw;
  file.size = size; /* used in read_lv0/int32/byte */
  if (wz_seek(addr, SEEK_SET, &file))
    WZ_ERR_RET(ret);
  if (wz_read_int32(&len, &file))
    WZ_ERR_RET(ret);
  if (len) {
    int err = 1;
    struct entity {
      wz_uint8_t  name_enc;
      wz_uint8_t  name[42 + 1];
      wz_uint32_t name_len;
      wz_uint32_t addr_enc;
      wz_uint32_t addr_pos;
    } * entities;
    int guessed;
    wz_uint16_t g_dec;
    wz_uint32_t g_hash;
    wz_uint16_t g_enc;
    wz_uint8_t key;
    if ((entities = malloc(len * sizeof(* entities))) == NULL)
      WZ_ERR_RET(ret);
    for (i = 0; i < len; i++) {
      struct entity * entity = entities + i;
      wz_uint8_t type;
      wz_uint32_t pos;
      if (wz_read_byte(&type, &file))
        WZ_ERR_GOTO(free_entities);
      pos = 0;
      if (WZ_IS_LV0_LINK(type)) {
        wz_uint32_t offset;
        if (wz_read_le32(&offset, &file))
          WZ_ERR_GOTO(free_entities);
        pos = file.pos;
        if (wz_seek(start + offset, SEEK_SET, &file) ||
            wz_read_byte(&type, &file)) /* type & name are in the other place */
          WZ_ERR_GOTO(free_entities);
      }
      if (WZ_IS_LV0_ARY(type) ||
          WZ_IS_LV0_OBJ(type)) {
        wz_uint8_t * name = entity->name;
        wz_uint32_t  size_;
        wz_uint32_t  check_;
        wz_uint32_t  addr_enc;
        wz_uint32_t  addr_pos;
        if (wz_read_chars(&name, &entity->name_len, &entity->name_enc,
                          sizeof(entity->name),
                          0, WZ_LV0_NAME, 0xff, NULL, &file) ||
            (pos && wz_seek(pos, SEEK_SET, &file)) ||
            wz_read_int32(&size_, &file) ||
            wz_read_int32(&check_, &file))
          WZ_ERR_GOTO(free_entities);
        addr_pos = file.pos;
        if (wz_read_le32(&addr_enc, &file))
          WZ_ERR_GOTO(free_entities);
        entity->addr_enc = addr_enc;
        entity->addr_pos = addr_pos;
      } else if (WZ_IS_LV0_NIL(type)) {
        if (wz_seek(10, SEEK_CUR, &file)) /* unknown 10 bytes */
          WZ_ERR_GOTO(free_entities);
        entity->addr_enc = 0; /* no need to decode */
      } else {
        wz_error("Unsupported node type: 0x%02"WZ_PRIx32"\n",
                 (wz_uint32_t) type);
        goto free_entities;
      }
    }
    guessed = 0;
    g_hash = 0;
    for (g_dec = 0; g_dec < 512; g_dec++) { /* guess dec */
      wz_encode_ver(&g_enc, &g_hash, g_dec);
      if (g_enc == enc) {
        int addr_err = 0;
        for (i = 0; i < len; i++) {
          struct entity * entity = entities + i;
          wz_uint32_t addr_enc = entity->addr_enc;
          if (addr_enc) {
            wz_uint32_t addr_pos = entity->addr_pos;
            wz_uint32_t addr_dec;
            wz_decode_addr(&addr_dec, addr_enc, addr_pos, start, g_hash);
            if (addr_dec > size) {
              addr_err = 1;
              break;
            }
          }
        }
        if (!addr_err) {
          guessed = 1;
          break;
        }
      }
    }
    if (!guessed)
      WZ_ERR_GOTO(free_entities);
    key = 0xff;
    for (i = 0; i < len; i++) {
      struct entity * entity = entities + i;
      wz_uint32_t addr_enc = entity->addr_enc;
      if (addr_enc) {
        wz_uint8_t name_enc = entity->name_enc;
        if (name_enc == WZ_ENC_CP1252) {
          if (wz_deduce_key(&key, entity->name, entity->name_len, keys)) {
            WZ_ERR;
            guessed = 0;
            break;
          }
        }
      }
    }
    if (!guessed)
      goto free_entities;
    if (key == 0xff)
      WZ_ERR_GOTO(free_entities);
    * ret_dec = g_dec;
    * ret_hash = g_hash;
    * ret_key = key;
    err = 0;
free_entities:
    free(entities);
    if (err)
      goto exit;
  } else {
    * ret_dec = 0;
    * ret_hash = 0;
    * ret_key = 0xff;
  }
  ret = 0;
exit:
  return ret;
}

#ifdef DEBUG
static wznode *
wz_invert_node(wznode * node) { /* node must not be NULL */
  wznode * root;
  wznode * c = node;
  wznode * n = c->n.parent;
  wznode * p;
  for (;;) {
    if (n == NULL) {
      root = c;
      break;
    }
    p = n->n.parent;
    n->n.parent = c;
    if (p == NULL) {
      root = n;
      break;
    }
    c = n;
    n = p;
  }
  node->n.parent = NULL;
  return root;
}
#endif

static int
wz_read_list(void ** ret_ary, wz_uint8_t nodes_off, wz_uint8_t len_off,
             wz_uint32_t root_addr, wz_uint8_t root_key,
             wz_uint8_t * keys, wznode * node, wznode * root, wzfile * file) {
  int ret = 1;
  wz_uint32_t len;
  wz_uint32_t i;
  wz_uint32_t j;
  void * ary;
  wzptr len_ptr;
  wzptr nodes;
  wz_uint8_t   name[WZ_UINT8_MAX];
  wz_uint8_t * name_ptr = name;
  wz_uint32_t  name_len;
  if (wz_seek(2, SEEK_CUR, file))
    WZ_ERR_RET(ret);
  if (wz_read_int32(&len, file))
    WZ_ERR_RET(ret);
  if ((ary = malloc(nodes_off + len * sizeof(* nodes.n))) == NULL)
    WZ_ERR_RET(ret);
  nodes.u8 = (wz_uint8_t *) ary + nodes_off;
  for (i = 0; i < len; i++) {
    int err = 1;
    wznode * child = nodes.n + i;
    wz_uint8_t type;
    wz_uint8_t name_capa;
    wz_uint8_t info;
    wz_uint8_t * bytes;
    if (wz_read_chars(&name_ptr, &name_len, NULL, sizeof(name),
                      root_addr, WZ_LV1_NAME, root_key, keys, file))
      WZ_ERR_GOTO(free_child);
    if (wz_read_byte(&type, file))
      WZ_ERR_GOTO(free_child);
    if (WZ_IS_LV1_NIL(type)) {
      name_capa = sizeof(child->nil_e.name_buf);
      info = WZ_NIL;
    } else if (WZ_IS_LV1_I16(type)) {
      wz_int16_t i16;
      if (wz_read_le16((wz_uint16_t *) &i16, file))
        WZ_ERR_GOTO(free_child);
      child->n16.val = i16;
      name_capa = sizeof(child->n16_e.name_buf);
      info = WZ_I16;
    } else if (WZ_IS_LV1_I32(type)) {
      wz_int32_t i32;
      if (wz_read_int32((wz_uint32_t *) &i32, file))
        WZ_ERR_GOTO(free_child);
      child->n32.val.i = i32;
      name_capa = sizeof(child->n32_e.name_buf);
      info = WZ_I32;
    } else if (WZ_IS_LV1_I64(type)) {
      wz_int64_t i64;
      if (wz_read_int64((wz_uint64_t *) &i64, file))
        WZ_ERR_GOTO(free_child);
      child->n64.val.i = i64;
      name_capa = sizeof(child->n64_e.name_buf);
      info = WZ_I64;
    } else if (WZ_IS_LV1_F32(type)) {
      wz_int8_t flt8;
      if (wz_read_byte((wz_uint8_t *) &flt8, file))
        WZ_ERR_GOTO(free_child);
      if (flt8 == WZ_INT8_MIN) {
        union { wz_uint32_t i; float f; } flt32;
        if (wz_read_le32(&flt32.i, file))
          WZ_ERR_GOTO(free_child);
        child->n32.val.f = flt32.f;
      } else {
        child->n32.val.f = flt8;
      }
      name_capa = sizeof(child->n32_e.name_buf);
      info = WZ_F32;
    } else if (WZ_IS_LV1_F64(type)) {
      union { wz_uint64_t i; double f; } flt64;
      if (wz_read_le64(&flt64.i, file))
        WZ_ERR_GOTO(free_child);
      child->n64.val.f = flt64.f;
      name_capa = sizeof(child->n64_e.name_buf);
      info = WZ_F64;
    } else if (WZ_IS_LV1_STR(type)) {
      wzstr * str;
      wz_uint32_t str_len;
      if (wz_read_chars((wz_uint8_t **) &str, &str_len, NULL, 0, root_addr,
                        WZ_LV1_STR, root_key, keys, file))
        WZ_ERR_GOTO(free_child);
      str->len = str_len;
      child->n.val.str = str;
      name_capa = sizeof(child->np_e.name_buf);
      info = WZ_STR;
    } else if (WZ_IS_LV1_OBJ(type)) {
      wz_uint32_t size;
      wz_uint32_t pos;
      if (wz_read_le32(&size, file))
        WZ_ERR_GOTO(free_child);
      pos = file->pos;
      if (wz_seek(size, SEEK_CUR, file))
        WZ_ERR_GOTO(free_child);
      if (name_len < sizeof(child->na_e.name_buf))
        child->na_e.addr = pos;
      else
        child->na.addr = pos;
      child->n.val.ary = NULL;
      name_capa = sizeof(child->na_e.name_buf);
      info = WZ_UNK;
    } else {
      wz_error("Unsupported primitive type: 0x%02"WZ_PRIx32"\n",
               (wz_uint32_t) type);
      goto free_child;
    }
    if (name_len < name_capa) {
      bytes = child->n.name_e;
      info |= WZ_EMBED;
    } else {
      if ((bytes = malloc(name_len + 1)) == NULL)
        WZ_ERR_GOTO(free_str);
      child->n.name = bytes;
    }
    for (j = 0; j < name_len; j++)
      bytes[j] = name[j];
    bytes[name_len] = '\0';
    child->n.name_len = (wz_uint8_t) name_len;
    child->n.info = info | WZ_LEVEL;
    child->n.parent = node;
    child->n.root.node = root;
    err = 0;
free_str:
    if (err && WZ_IS_LV1_STR(type))
      wz_free_chars((wz_uint8_t *) child->n.val.str);
free_child:
    if (err) {
      for (j = 0; j < i; j++) {
        wznode * child_ = nodes.n + j;
        if ((child_->n.info & WZ_TYPE) == WZ_STR)
          wz_free_chars((wz_uint8_t *) child_->n.val.str);
        if (!(child_->n.info & WZ_EMBED))
          wz_free_chars(child_->n.name);
      }
      goto free_ary;
    }
  }
  len_ptr.u8 = (wz_uint8_t *) ary + len_off;
  * len_ptr.u32 = len;
  * ret_ary = ary;
  ret = 0;
free_ary:
  if (ret)
    free(ary);
  return ret;
}

static void
wz_free_list(void * ary, wz_uint8_t nodes_off, wz_uint8_t len_off) {
  wzptr len_ptr;
  wz_uint32_t len;
  wz_uint32_t i;
  wzptr nodes;
  len_ptr.u8 = (wz_uint8_t *) ary + len_off;
  len = * len_ptr.u32;
  nodes.u8 = (wz_uint8_t *) ary + nodes_off;
  for (i = 0; i < len; i++) {
    wznode * child = nodes.n + i;
    if ((child->n.info & WZ_TYPE) == WZ_STR)
      wz_free_chars((wz_uint8_t *) child->n.val.str);
    if (!(child->n.info & WZ_EMBED))
      wz_free_chars(child->n.name);
  }
  free(ary);
}

static int
wz_decode_bitmap(wz_uint32_t * written, wz_uint8_t * out, wz_uint8_t * in,
                 wz_uint32_t size, wz_uint8_t * key) {
  wzptr src;
  wz_uint8_t * src_end = in + size;
  wz_uint32_t wrote = 0;
  src.u8 = in;
  while (src.u8 < src_end) {
    wz_uint32_t len = WZ_LE32TOH(* src.u32++);
    wz_uint32_t i;
    if (len > WZ_KEY_ASCII_MAX_LEN)
      return wz_error("Image chunk size is too large: %"WZ_PRIu32"\n", len), 1;
    for (i = 0; i < len; i++)
      out[wrote++] = * src.u8++ ^ key[i];
  }
  return * written = wrote, 0;
}

static int
wz_inflate_bitmap(wz_uint32_t * written,
                  wz_uint8_t * out, wz_uint32_t out_len,
                  wz_uint8_t * in, wz_uint32_t in_len) {
  int ret = 1;
  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.next_in = in;
  strm.avail_in = in_len;
  if (inflateInit(&strm) != Z_OK)
    WZ_ERR_RET(ret);
  strm.next_out = out;
  strm.avail_out = out_len;
  if (inflate(&strm, Z_NO_FLUSH) != Z_OK)
    goto inflate_end;
  * written = (wz_uint32_t) strm.total_out;
  ret = 0;
inflate_end:
  inflateEnd(&strm);
  return ret;
}

static const wz_uint8_t wz_u4[16] = {
  /* unpack 4 bit to 8 bit color: (i << 4) | i */
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const wz_uint8_t wz_u5[32] = {
  /* unpack 5 bit to 8 bit color: (i << 3) | (i >> 2) */
  0x00, 0x08, 0x10, 0x18, 0x21, 0x29, 0x31, 0x39,
  0x42, 0x4a, 0x52, 0x5a, 0x63, 0x6b, 0x73, 0x7b,
  0x84, 0x8c, 0x94, 0x9c, 0xa5, 0xad, 0xb5, 0xbd,
  0xc6, 0xce, 0xd6, 0xde, 0xe7, 0xef, 0xf7, 0xff
};
static const wz_uint8_t wz_u6[64] = {
  /* unpack 6 bit to 8 bit color: (i << 2) | (i >> 4) */
  0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c,
  0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
  0x41, 0x45, 0x49, 0x4d, 0x51, 0x55, 0x59, 0x5d,
  0x61, 0x65, 0x69, 0x6d, 0x71, 0x75, 0x79, 0x7d,
  0x82, 0x86, 0x8a, 0x8e, 0x92, 0x96, 0x9a, 0x9e,
  0xa2, 0xa6, 0xaa, 0xae, 0xb2, 0xb6, 0xba, 0xbe,
  0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf,
  0xe3, 0xe7, 0xeb, 0xef, 0xf3, 0xf7, 0xfb, 0xff
};

static int
wz_read_bitmap(wzcolor ** data, wz_uint32_t w, wz_uint32_t h,
               wz_uint16_t depth, wz_uint16_t scale, wz_uint32_t size,
               wz_uint8_t key, wz_uint8_t * keys) {
  int ret = 1;
  wz_uint32_t pixels = w * h;
  wz_uint32_t full_size = pixels * (wz_uint32_t) sizeof(wzcolor);
  wz_uint32_t max_size = size > full_size ? size : full_size;
  wz_uint8_t * in = (wz_uint8_t *) * data;
  wz_uint8_t * tmp;
  wz_uint8_t * out;
  wz_uint32_t scale_size;
  wz_uint32_t depth_size;
  wz_uint32_t sw;
  wz_uint32_t sh;
  int dxt3;
  if ((out = malloc(max_size)) == NULL)
    WZ_ERR_RET(ret);
  if (wz_inflate_bitmap(&size, out, full_size, in, size)) {
    if (key == WZ_KEY_EMPTY)
      WZ_ERR_GOTO(free_out);
    if (wz_decode_bitmap(&size, out, in, size,
                         keys + key * WZ_KEY_UTF8_MAX_LEN) ||
        wz_inflate_bitmap(&size, in, full_size, out, size))
      WZ_ERR_GOTO(free_out);
  } else {
    tmp = in, in = out, out = tmp;
  }
  switch (scale) {
  case 0: scale_size =  1; break; /* pow(2, 0) == 1 */
  case 4: scale_size = 16; break; /* pow(2, 4) == 16 */
  default: {
    wz_error("Unsupported color scale %"WZ_PRIu32"\n", (wz_uint32_t) scale);
    goto free_out;
  }}
  switch (depth) {
  case WZ_COLOR_8888: depth_size = 4; break;
  case WZ_COLOR_4444:
  case WZ_COLOR_565:  depth_size = 2; break;
  case WZ_COLOR_DXT3:
  case WZ_COLOR_DXT5: depth_size = 1; break;
  default: {
    wz_error("Unsupported color depth %"WZ_PRIu32"\n", (wz_uint32_t) depth);
    goto free_out;
  }}
  if (size * (scale_size * scale_size) != pixels * depth_size)
    WZ_ERR_GOTO(free_out);
  sw = w / scale_size; /* shrunk by scale_size */
  sh = h / scale_size; /* shrunk by scale_size */
  dxt3 = 0;
  switch (depth) {
  case WZ_COLOR_8888: tmp = in, in = out, out = tmp; break;
  case WZ_COLOR_4444: {
    wzptr src;
    wzcolor * dst = (wzcolor *) out; /* cast to pixel based type */
    wz_uint32_t len = sw * sh;
    wz_uint32_t i;
    src.u8 = in;
    for (i = 0; i < len; i++, dst++) {
      wz_uint16_t pixel = WZ_LE16TOH(* src.u16++);
      dst->b = wz_u4[(pixel      ) & 0x0f];
      dst->g = wz_u4[(pixel >>  4) & 0x0f];
      dst->r = wz_u4[(pixel >>  8) & 0x0f];
      dst->a = wz_u4[(pixel >> 12) & 0x0f];
    }
    break;
  }
  case WZ_COLOR_565: {
    wzptr src;
    wzcolor * dst = (wzcolor *) out; /* cast to pixel based type */
    wz_uint32_t len = sw * sh;
    wz_uint32_t i;
    src.u8 = in;
    for (i = 0; i < len; i++, dst++) {
      wz_uint16_t pixel = WZ_LE16TOH(* src.u16++);
      dst->b = wz_u5[(pixel      ) & 0x1f];
      dst->g = wz_u6[(pixel >>  5) & 0x3f];
      dst->r = wz_u5[(pixel >> 11) & 0x1f];
      dst->a = 0xff;
    }
    break;
  }
  case WZ_COLOR_DXT3: dxt3 = 1;
  case WZ_COLOR_DXT5: {
    wzptr src;
    wzcolor * dst = (wzcolor *) out; /* cast to pixel based type */
    wz_uint8_t lw = sw & 0x03; /* last block width */
    wz_uint8_t lh = sh & 0x03; /* last block height */
    wz_uint32_t bw = (sw >> 2) + (lw > 0); /* number of blocks in width */
    wz_uint32_t bh = (sh >> 2) + (lh > 0); /* number of blocks in height */
    wz_uint32_t bn = sw * (4 - 1); /* goto next row of blocks */
    wz_uint32_t x;
    wz_uint32_t y;
    wzcolor c[4]; /* 4 codes */
    c[0].a = 0;
    c[1].a = 0;
    c[2].a = 0;
    c[3].a = 0;
    src.u8 = in;
    for (y = 0; y < bh; y++) { /* goto the next row */
      for (x = 0; x < bw; x++) { /* goto the next block */
        wzcolor block[16]; /* inflate 4x4 block */
        wz_uint64_t alpha  = WZ_LE64TOH(* src.u64++); /* indices */
        wz_uint16_t color0 = WZ_LE16TOH(* src.u16++); /* color code 0 */
        wz_uint16_t color1 = WZ_LE16TOH(* src.u16++); /* color code 1 */
        wz_uint32_t color  = WZ_LE32TOH(* src.u32++); /* indices */
        wzcolor * from;
        wzcolor * to;
        wz_uint32_t pw;
        wz_uint32_t ph;
        wz_uint32_t py;
        wz_uint32_t px;
        c[0].b = wz_u5[(color0      ) & 0x1f];
        c[0].g = wz_u6[(color0 >>  5) & 0x3f];
        c[0].r = wz_u5[(color0 >> 11) & 0x1f];
        c[1].b = wz_u5[(color1      ) & 0x1f];
        c[1].g = wz_u6[(color1 >>  5) & 0x3f];
        c[1].r = wz_u5[(color1 >> 11) & 0x1f];
        c[2].b = (wz_uint8_t) (((c[0].b << 1) + c[1].b) / 3); /* color code 2 */
        c[2].g = (wz_uint8_t) (((c[0].g << 1) + c[1].g) / 3);
        c[2].r = (wz_uint8_t) (((c[0].r << 1) + c[1].r) / 3);
        c[3].b = (wz_uint8_t) ((c[0].b + (c[1].b << 1)) / 3); /* color code 3 */
        c[3].g = (wz_uint8_t) ((c[0].g + (c[1].g << 1)) / 3);
        c[3].r = (wz_uint8_t) ((c[0].r + (c[1].r << 1)) / 3);
        block[0]  = c[(color      ) & 0x3]; /* unpack color value */
        block[1]  = c[(color >>  2) & 0x3];
        block[2]  = c[(color >>  4) & 0x3];
        block[3]  = c[(color >>  6) & 0x3];
        block[4]  = c[(color >>  8) & 0x3];
        block[5]  = c[(color >> 10) & 0x3];
        block[6]  = c[(color >> 12) & 0x3];
        block[7]  = c[(color >> 14) & 0x3];
        block[8]  = c[(color >> 16) & 0x3];
        block[9]  = c[(color >> 18) & 0x3];
        block[10] = c[(color >> 20) & 0x3];
        block[11] = c[(color >> 22) & 0x3];
        block[12] = c[(color >> 24) & 0x3];
        block[13] = c[(color >> 26) & 0x3];
        block[14] = c[(color >> 28) & 0x3];
        block[15] = c[(color >> 30) & 0x3];
        if (dxt3) {
          block[0].a  = wz_u4[(alpha >>  0) & 0xf]; /* unpack alpha value */
          block[1].a  = wz_u4[(alpha >>  4) & 0xf];
          block[2].a  = wz_u4[(alpha >>  8) & 0xf];
          block[3].a  = wz_u4[(alpha >> 12) & 0xf];
          block[4].a  = wz_u4[(alpha >> 16) & 0xf];
          block[5].a  = wz_u4[(alpha >> 20) & 0xf];
          block[6].a  = wz_u4[(alpha >> 24) & 0xf];
          block[7].a  = wz_u4[(alpha >> 28) & 0xf];
          block[8].a  = wz_u4[(alpha >> 32) & 0xf];
          block[9].a  = wz_u4[(alpha >> 36) & 0xf];
          block[10].a = wz_u4[(alpha >> 40) & 0xf];
          block[11].a = wz_u4[(alpha >> 44) & 0xf];
          block[12].a = wz_u4[(alpha >> 48) & 0xf];
          block[13].a = wz_u4[(alpha >> 52) & 0xf];
          block[14].a = wz_u4[(alpha >> 56) & 0xf];
          block[15].a = wz_u4[(alpha >> 60) & 0xf];
        } else { /* dxt5 */
          wz_uint8_t a[8];
          a[0] = src.u8[-16]; /* alpha 0 */
          a[1] = src.u8[-15]; /* alpha 1 */
          if (a[0] > a[1]) {
            a[2] = (wz_uint8_t) ((a[0] * 6 + a[1]    ) / 7); /* alpha 2 */
            a[3] = (wz_uint8_t) ((a[0] * 5 + a[1] * 2) / 7); /* alpha 3 */
            a[4] = (wz_uint8_t) ((a[0] * 4 + a[1] * 3) / 7); /* alpha 4 */
            a[5] = (wz_uint8_t) ((a[0] * 3 + a[1] * 4) / 7); /* alpha 5 */
            a[6] = (wz_uint8_t) ((a[0] * 2 + a[1] * 5) / 7); /* alpha 6 */
            a[7] = (wz_uint8_t) ((a[0]     + a[1] * 6) / 7); /* alpha 7 */
          } else {
            a[2] = (wz_uint8_t) ((a[0] * 4 + a[1]    ) / 5); /* alpha 2 */
            a[3] = (wz_uint8_t) ((a[0] * 3 + a[1] * 2) / 5); /* alpha 3 */
            a[4] = (wz_uint8_t) ((a[0] * 2 + a[1] * 3) / 5); /* alpha 4 */
            a[5] = (wz_uint8_t) ((a[0]     + a[1] * 4) / 5); /* alpha 5 */
            a[6] = 0;                                        /* alpha 6 */
            a[7] = 0xff;                                     /* alpha 7 */
          }
          block[0].a  = a[(alpha >> 16) & 0x7]; /* unpack alpha value */
          block[1].a  = a[(alpha >> 19) & 0x7];
          block[2].a  = a[(alpha >> 22) & 0x7];
          block[3].a  = a[(alpha >> 25) & 0x7];
          block[4].a  = a[(alpha >> 28) & 0x7];
          block[5].a  = a[(alpha >> 31) & 0x7];
          block[6].a  = a[(alpha >> 34) & 0x7];
          block[7].a  = a[(alpha >> 37) & 0x7];
          block[8].a  = a[(alpha >> 40) & 0x7];
          block[9].a  = a[(alpha >> 43) & 0x7];
          block[10].a = a[(alpha >> 46) & 0x7];
          block[11].a = a[(alpha >> 49) & 0x7];
          block[12].a = a[(alpha >> 52) & 0x7];
          block[13].a = a[(alpha >> 55) & 0x7];
          block[14].a = a[(alpha >> 58) & 0x7];
          block[15].a = a[(alpha >> 61) & 0x7];
        }
        from = block;
        to = dst;
        pw = (x + 1 < bw || !lw) ? 4 : lw; /* the pixel may be */
        ph = (y + 1 < bh || !lh) ? 4 : lh; /*  out of image */
        for (py = 0; py < ph; py++, to += sw, from += 4)
          for (px = 0; px < pw; px++)
            to[px] = from[px]; /* write to correct location */
        dst += pw;
      }
      dst += bn;
    }
    break;
  }
  default: {
    wz_error("Unsupported color depth %"WZ_PRIu32"\n", (wz_uint32_t) depth);
    goto free_out;
  }}
  if (scale_size > 1 && sw) {
    wzcolor * src;
    wzcolor * dst;
    wz_uint32_t col;
    wz_uint32_t row;
    wz_uint32_t x;
    wz_uint32_t y;
    wz_uint32_t px;
    wz_uint32_t py;
    tmp = in, in = out, out = tmp;
    src = (wzcolor *) in; /* cast to pixel based type */
    dst = (wzcolor *) out;
    col = scale_size * (w - 1); /* goto next col (block based) */
    row = scale_size * (sw - 1); /* goto next row (block based) */
    for (y = 0; y < sh; y++)
      for (x = 0;;) {
        wzcolor pixel = * src++;
        for (py = 0; py < scale_size; py++, dst += w)
          for (px = 0; px < scale_size; px++)
            dst[px] = pixel;
        if (++x < sw) {
          dst -= col;
        } else {
          dst -= row;
          break;
        }
      }
  }
  * data = (wzcolor *) out;
  free(in);
  ret = 0;
free_out:
  if (ret)
    free(out == (wz_uint8_t *) * data ? in : out);
  return ret;
}

static const wz_uint8_t wz_guid_wav[16] = {
  /* DWORD data1    */ 0x81, 0x9f, 0x58, 0x05,
  /* WORD  data2    */ 0x56, 0xc3,
  /* WORD  data3    */ 0xce, 0x11,
  /* BYTE  data4[8] */ 0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a
};

static void
wz_read_wav(wzwav * wav, wz_uint8_t * data) {
  wzptr src;
  src.u8 = data;
  wav->format          = WZ_LE16TOH(* src.u16++);
  wav->channels        = WZ_LE16TOH(* src.u16++);
  wav->sample_rate     = WZ_LE32TOH(* src.u32++);
  wav->byte_rate       = WZ_LE32TOH(* src.u32++);
  wav->block_align     = WZ_LE16TOH(* src.u16++);
  wav->bits_per_sample = WZ_LE16TOH(* src.u16++);
  wav->extra_size      = WZ_LE16TOH(* src.u16++);
}

static void
wz_decode_wav(wz_uint8_t * wav, wz_uint8_t size, wz_uint8_t * key) {
  wz_uint8_t i;
  for (i = 0; i < size; i++)
    wav[i] ^= key[i];
}

static void
wz_write_pcm(wz_uint8_t * pcm, wzwav * wav, wz_uint32_t size) {
  wzptr dst;
  dst.u8 = pcm;
  * dst.u32++ = WZ_HTOBE32(0x52494646); /* "RIFF" */
  * dst.u32++ = WZ_HTOLE32(36 + size);  /* following */
  * dst.u32++ = WZ_HTOBE32(0x57415645); /* "WAVE" */
  * dst.u32++ = WZ_HTOBE32(0x666d7420); /* "fmt " */
  * dst.u32++ = WZ_HTOLE32(16);         /* PCM = 16 */
  * dst.u16++ = WZ_HTOLE16(wav->format);
  * dst.u16++ = WZ_HTOLE16(wav->channels);
  * dst.u32++ = WZ_HTOLE32(wav->sample_rate);
  * dst.u32++ = WZ_HTOLE32(wav->byte_rate);
  * dst.u16++ = WZ_HTOLE16(wav->block_align);
  * dst.u16++ = WZ_HTOLE16(wav->bits_per_sample);
  * dst.u32++ = WZ_HTOBE32(0x64617461); /* "data" */
  * dst.u32++ = WZ_HTOLE32(size);
}

static int
wz_read_lv1(wznode * node, wznode * root, wzfile * file, wz_uint8_t * keys,
            wz_uint8_t eager) {
  int ret = 1;
  wz_uint32_t  root_addr;
  wz_uint8_t   root_key;
  wz_uint32_t  addr;
  wz_uint8_t   type_enc;
  wz_uint8_t   type[sizeof("Shape2D#Convex2D")];
  wz_uint8_t * type_ptr = type;
  wz_uint32_t  type_len;
  if (root->n.info & WZ_EMBED) {
    root_addr    = root->na_e.addr;
    root_key     = root->na_e.key;
  } else {
    root_addr    = root->na.addr;
    root_key     = root->na.key;
  }
  addr = node->n.info & WZ_EMBED ? node->na_e.addr : node->na.addr;
  if (wz_seek(addr, SEEK_SET, file) ||
      wz_read_chars(&type_ptr, &type_len, &type_enc, sizeof(type),
                    root_addr, WZ_LV1_TYPENAME_OR_STR, root_key, keys, file))
    WZ_ERR_RET(ret);
  if (type_enc == WZ_ENC_UTF8) {
    wzptr str;
    str.u8 = type_ptr;
    str.s->len = type_len;
    node->n.val.str = str.s;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_STR;
    return ret = 0, ret;
  }
  if (root_key == 0xff) {
    if (wz_deduce_key(&root_key, type, type_len, keys))
      WZ_ERR_RET(ret);
    * (root->n.info & WZ_EMBED ? &root->na_e.key : &root->na.key) = root_key;
  }
  if (WZ_IS_LV1_ARY(type)) {
    void * ary;
    if (wz_read_list(&ary, offsetof(wzary, nodes), offsetof(wzary, len),
                     root_addr, root_key, keys, node, root, file))
      WZ_ERR_GOTO(exit);
    node->n.val.ary = ary;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_ARY;
  } else if (WZ_IS_LV1_IMG(type)) {
    int err = 1;
    wz_uint8_t list;
    wzimg * img;
    wz_uint32_t w;
    wz_uint32_t h;
    wz_uint32_t depth;
    wz_uint8_t  scale;
    wz_uint32_t size;
    wz_uint32_t pixels;
    wz_uint32_t full_size;
    wz_uint32_t max_size;
    wz_uint8_t * data;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_byte(&list, file))
      WZ_ERR_GOTO(exit);
    if (list == 1) {
      if (wz_read_list((void **) &img,
                       offsetof(wzimg, nodes), offsetof(wzimg, len),
                       root_addr, root_key, keys, node, root, file))
        WZ_ERR_GOTO(exit);
    } else {
      if ((img = malloc(offsetof(wzimg, nodes))) == NULL)
        WZ_ERR_GOTO(exit);
      img->len = 0;
    }
    if (wz_read_int32(&w, file)      ||
        wz_read_int32(&h, file)      ||
        wz_read_int32(&depth, file)  || depth > WZ_UINT16_MAX ||
        wz_read_byte(&scale, file)   ||
        wz_seek(4, SEEK_CUR, file)   || /* blank */
        wz_read_le32(&size, file)    ||
        wz_seek(1, SEEK_CUR, file))     /* blank */
      WZ_ERR_GOTO(free_img);
    if (size <= 1)
      WZ_ERR_GOTO(free_img);
    size--; /* remove null terminator */
    pixels = w * h;
    full_size = pixels * (wz_uint32_t) sizeof(wzcolor);
    max_size = size > full_size ? size : full_size;
    if ((data = malloc(max_size)) == NULL)
      WZ_ERR_GOTO(free_img);
    if (wz_read_bytes(data, size, file) ||
        (eager && wz_read_bitmap((wzcolor **) &data, w, h, (wz_uint16_t) depth,
                                 scale, size, root_key, keys)))
      WZ_ERR_GOTO(free_img_data);
    img->w = w;
    img->h = h;
    img->depth = (wz_uint16_t) depth;
    img->scale = scale;
    img->size = size;
    img->data = data;
    node->n.val.img = img;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_IMG;
    err = 0;
free_img_data:
    if (err)
      free(data);
free_img:
    if (err) {
      wz_free_list(img, offsetof(wzimg, nodes), offsetof(wzimg, len));
      goto exit;
    }
  } else if (WZ_IS_LV1_VEX(type)) {
    int err = 1;
    wz_uint32_t len;
    wz_uint32_t i;
    wzvex * vex;
    wzvec * vecs;
    if (wz_read_int32(&len, file))
      WZ_ERR_GOTO(exit);
    if ((vex = malloc(offsetof(wzvex, ary) +
                      len * sizeof(* vex->ary))) == NULL)
      WZ_ERR_GOTO(exit);
    vecs = vex->ary;
    for (i = 0; i < len; i++) {
      wzvec * vec = vecs + i;
      if (wz_read_chars(&type_ptr, &type_len, NULL, sizeof(type),
                        root_addr, WZ_LV1_TYPENAME, root_key, keys, file))
        WZ_ERR_GOTO(free_vex);
      if (!WZ_IS_LV1_VEC(type)) {
        wz_error("Convex should contain only vectors\n");
        goto free_vex;
      }
      if (wz_read_int32((wz_uint32_t *) &vec->x, file) ||
          wz_read_int32((wz_uint32_t *) &vec->y, file))
        WZ_ERR_GOTO(free_vex);
    }
    vex->len = len;
    node->n.val.vex = vex;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_VEX;
    err = 0;
free_vex:
    if (err) {
      free(vex);
      goto exit;
    }
  } else if (WZ_IS_LV1_VEC(type)) {
    wzvec vec;
    if (wz_read_int32((wz_uint32_t *) &vec.x, file) ||
        wz_read_int32((wz_uint32_t *) &vec.y, file))
      WZ_ERR_GOTO(exit);
    node->n64.val.vec = vec;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_VEC;
  } else if (WZ_IS_LV1_AO(type)) {
    int err = 1;
    wz_uint32_t size;
    wz_uint32_t ms;
    wz_uint8_t guid[16];
    wzao * ao;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_int32(&size, file) ||
        wz_read_int32(&ms, file) ||
        wz_seek(1 + 16 * 2 + 2, SEEK_CUR, file) || /* major and subtype GUID */
        wz_read_bytes(guid, sizeof(guid), file))
      WZ_ERR_GOTO(exit);
    if ((ao = malloc(sizeof(* ao))) == NULL)
      WZ_ERR_GOTO(exit);
    if (memcmp(guid, wz_guid_wav, sizeof(guid)) == 0) {
      int hdr_err = 1;
      wz_uint8_t hsize; /* header size */
      wz_uint8_t * hdr; /* header */
      wzwav wav;
      wav.format = 0;
      if (wz_read_byte(&hsize, file))
        WZ_ERR_GOTO(free_ao);
      if ((hdr = malloc(hsize)) == NULL)
        WZ_ERR_GOTO(free_ao);
      if (wz_read_bytes(hdr, hsize, file))
        WZ_ERR_GOTO(free_hdr);
      wz_read_wav(&wav, hdr);
      if (WZ_AUDIO_WAV_SIZE + wav.extra_size != hsize) {
        wz_uint8_t decoded = 0;
        wz_uint8_t i;
        for (i = 0; i < WZ_KEY_EMPTY; i++) {
          wz_decode_wav(hdr, hsize, keys + i * WZ_KEY_UTF8_MAX_LEN);
          wz_read_wav(&wav, hdr);
          if (WZ_AUDIO_WAV_SIZE + wav.extra_size == hsize) {
            decoded = 1;
            break;
          }
          wz_decode_wav(hdr, hsize, keys + i * WZ_KEY_UTF8_MAX_LEN);
        }
        if (!decoded)
          WZ_ERR_GOTO(free_hdr);
      }
      hdr_err = 0;
free_hdr:
      free(hdr);
      if (hdr_err)
        goto free_ao;
      if (wav.format == WZ_AUDIO_PCM) {
        int pcm_err = 1;
        wz_uint8_t * pcm;
        if ((pcm = malloc(WZ_AUDIO_PCM_SIZE + size)) == NULL)
          WZ_ERR_GOTO(free_ao);
        wz_write_pcm(pcm, &wav, size);
        if (wz_read_bytes(pcm + WZ_AUDIO_PCM_SIZE, size, file))
          WZ_ERR_GOTO(free_pcm);
        ao->data = pcm;
        ao->size = WZ_AUDIO_PCM_SIZE + size;
        pcm_err = 0;
free_pcm:
        if (pcm_err) {
          free(pcm);
          goto free_ao;
        }
      } else if (wav.format == WZ_AUDIO_MP3) {
        int data_err = 1;
        wz_uint8_t * data;
        if ((data = malloc(size)) == NULL)
          WZ_ERR_GOTO(free_ao);
        if (wz_read_bytes(data, size, file))
          WZ_ERR_GOTO(free_ao_data);
        ao->data = data;
        ao->size = size;
        data_err = 0;
free_ao_data:
        if (data_err) {
          free(data);
          goto free_ao;
        }
      } else {
        wz_error("Unsupported audio format: 0x%"WZ_PRIx32"\n",
                 (wz_uint32_t) wav.format);
        goto free_ao;
      }
      ao->format = wav.format;
    } else {
      wz_uint8_t empty = 1;
      wz_uint8_t i;
      for (i = 0; i < sizeof(guid); i++)
        if (guid[i]) {
          empty = 0;
          break;
        }
      if (empty) {
        int data_err = 1;
        wz_uint8_t * data;
        if ((data = malloc(size)) == NULL)
          WZ_ERR_GOTO(free_ao);
        if (wz_read_bytes(data, size, file))
          WZ_ERR_GOTO(free_ao_data_);
        ao->data = data;
        ao->size = size;
        ao->format = WZ_AUDIO_MP3;
        data_err = 0;
free_ao_data_:
        if (data_err) {
          free(data);
          goto free_ao;
        }
      } else {
        wz_error("Unsupport audio GUID type: %.16s\n", guid);
        goto free_ao;
      }
    }
    ao->ms = ms;
    node->n.val.ao = ao;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_AO;
    err = 0;
free_ao:
    if (err) {
      free(ao);
      goto exit;
    }
  } else if (WZ_IS_LV1_UOL(type)) {
    wzstr * str;
    wz_uint32_t str_len;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_chars((wz_uint8_t **) &str, &str_len, NULL, 0, root_addr,
                      WZ_LV1_STR, root_key, keys, file))
      WZ_ERR_GOTO(exit);
    str->len = str_len;
    node->n.val.str = str;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_UOL;
  } else {
    wz_error("Unsupported object type: %s\n", type);
    goto exit;
  }
  ret = 0;
exit:
  return ret;
}

static void
wz_free_lv1(wznode * node) {
  switch (node->n.info & WZ_TYPE) {
  case WZ_STR:
    wz_free_chars((wz_uint8_t *) node->n.val.str);
    node->n.val.str = NULL;
    break;
  case WZ_ARY: {
    wzary * ary = node->n.val.ary;
    wz_free_list(ary, offsetof(wzary, nodes), offsetof(wzary, len));
    node->n.val.ary = NULL;
    break;
  }
  case WZ_IMG: {
    wzimg * img = node->n.val.img;
    free(img->data);
    wz_free_list(img, offsetof(wzimg, nodes), offsetof(wzimg, len));
    node->n.val.img = NULL;
    break;
  }
  case WZ_VEX:
    free(node->n.val.vex);
    node->n.val.vex = NULL;
    break;
  case WZ_AO: {
    wzao * ao = node->n.val.ao;
    free(ao->data);
    free(ao);
    node->n.val.ao = NULL;
    break;
  }
  case WZ_UOL:
    wz_free_chars((wz_uint8_t *) node->n.val.str);
    node->n.val.str = NULL;
    break;
  default:
    break;
  }
}

#ifndef WZ_NO_THRD
typedef struct {
  wz_uint32_t  w;
  wz_uint32_t  h;
  wz_uint16_t  depth;
  wz_uint16_t  scale;
  wz_uint32_t  size;
  wz_uint8_t * data;
  wz_uint8_t   key;
  wz_uint8_t   _[sizeof(void *) - 1]; /* padding */
} wz_iter_node_thrd_node;

typedef struct {
#ifdef WZ_WINDOWS
  HANDLE mutex;
  HANDLE event;
#else
  pthread_mutex_t mutex;
  pthread_cond_t cond;
#endif
  wz_uint32_t capa;
  wz_uint32_t len;
  wz_iter_node_thrd_node * nodes;
  wz_uint8_t * keys;
  wz_uint8_t exit;
  wz_uint8_t _[sizeof(void *) - 1];
} wz_iter_node_thrd_queue;

typedef struct {
#ifdef WZ_WINDOWS
  HANDLE thrd;
#else
  pthread_t tid;
#endif
  wz_uint16_t id;
  wz_uint8_t _[sizeof(void *) - 2]; /* padding */
  wz_iter_node_thrd_queue * queue;
} wz_iter_node_thrd_data;

enum {WZ_ITER_NODE_CAPA = 4};

#ifdef WZ_WINDOWS
static unsigned __stdcall
wz_iter_node_thrd(wz_iter_node_thrd_data * data) {
  wz_uint8_t ret = 0;
  wz_uint8_t err = 0;
  wz_iter_node_thrd_queue * queue = data->queue;
  wz_uint8_t * keys = queue->keys;
  for (;;) {
    wz_uint8_t exit;
    wz_iter_node_thrd_node nodes[WZ_ITER_NODE_CAPA];
    wz_uint8_t nodes_len;
    wz_uint8_t i;
    if (WaitForSingleObject(queue->mutex, INFINITE) != WAIT_OBJECT_0)
      WZ_ERR_GOTO(exit);
    for (;;) {
      nodes_len = 0;
      exit = queue->exit;
      if (queue->len) {
        do {
          nodes[nodes_len++] = queue->nodes[--queue->len];
        } while (queue->len && nodes_len < WZ_ITER_NODE_CAPA);
        break;
      } else if (exit) {
        if (SetEvent(queue->event) == FALSE)
          WZ_ERR_GOTO(exit);
        break;
      }
      if (ReleaseMutex(queue->mutex) == FALSE)
        WZ_ERR_GOTO(exit);
      if (WaitForSingleObject(queue->event, INFINITE) != WAIT_OBJECT_0)
        WZ_ERR_GOTO(exit);
      if (WaitForSingleObject(queue->mutex, INFINITE) != WAIT_OBJECT_0)
        WZ_ERR_GOTO(exit);
    }
    if (ReleaseMutex(queue->mutex) == FALSE)
      WZ_ERR_GOTO(exit);
    if (!nodes_len && exit)
      break;
    for (i = 0; i < nodes_len; i++) {
      wz_iter_node_thrd_node * node = nodes + i;
      if (wz_read_bitmap((wzcolor **) &node->data, node->w, node->h,
                         node->depth, node->scale, node->size, node->key, keys))
        err = 1;
      free(node->data);
    }
  }
  if (!err)
    ret = 0;
exit:
  return ret;
}
#else
static void *
wz_iter_node_thrd(wz_iter_node_thrd_data * data) {
  wz_uint8_t ret = 1;
  wz_uint8_t err = 0;
  wz_iter_node_thrd_queue * queue = data->queue;
  wz_uint8_t * keys = queue->keys;
  for (;;) {
    wz_uint8_t exit;
    wz_iter_node_thrd_node nodes[WZ_ITER_NODE_CAPA];
    wz_uint8_t nodes_len;
    wz_uint8_t i;
    if (pthread_mutex_lock(&queue->mutex))
      WZ_ERR_GOTO(exit);
    for (;;) {
      nodes_len = 0;
      exit = queue->exit;
      if (queue->len) {
        do {
          nodes[nodes_len++] = queue->nodes[--queue->len];
        } while (queue->len && nodes_len < WZ_ITER_NODE_CAPA);
        break;
      } else if (exit) {
        break;
      }
      if (pthread_cond_wait(&queue->cond, &queue->mutex))
        WZ_ERR_GOTO(exit);
    }
    if (pthread_mutex_unlock(&queue->mutex))
      WZ_ERR_GOTO(exit);
    if (!nodes_len && exit)
      break;
    for (i = 0; i < nodes_len; i++) {
      wz_iter_node_thrd_node * node = nodes + i;
      if (wz_read_bitmap((wzcolor **) &node->data, node->w, node->h,
                         node->depth, node->scale, node->size, node->key, keys))
        err = 1;
      free(node->data);
    }
  }
  if (!err)
    ret = 0;
exit:
  return ret ? (void *) (wz_uintptr_t) !NULL : NULL;
}
#endif
#endif

int
wz_parse_file(wzfile * file) {
  int ret = 1;
  int err = 0;
  wznode * node = &file->root;
  wznode * root = node;
  wz_uint8_t * keys = file->ctx->keys;
  wz_uint32_t stack_capa;
  wz_uint32_t stack_len;
  wznode ** stack;
#ifndef WZ_NO_THRD
  wz_iter_node_thrd_queue queue;
  wz_uint16_t thrds_len;
  wz_uint16_t thrds_init;
  wz_uint16_t thrd_i;
  wz_iter_node_thrd_data * thrds;
# ifdef WZ_WINDOWS
  SYSTEM_INFO info;
# else
  long thrds_avail_l;
  pthread_attr_t attr;
  wz_uint8_t attr_err;
# endif
#endif
#ifndef WZ_NO_THRD
  queue.capa = 0;
  queue.len = 0;
  queue.nodes = NULL;
  queue.keys = keys;
  queue.exit = 0;
# ifdef WZ_WINDOWS
  if ((queue.mutex = CreateMutex(NULL, FALSE, NULL)) == NULL)
    WZ_ERR_RET(ret);
  if ((queue.event = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
    WZ_ERR_GOTO(close_mutex);
  GetSystemInfo(&info);
  thrds_len = (wz_uint16_t) info.dwNumberOfProcessors;
  thrds_init = 0;
  if ((thrds = malloc(thrds_len * sizeof(*thrds))) == NULL)
    WZ_ERR_GOTO(close_event);
  for (thrd_i = 0; thrd_i < thrds_len; thrd_i++) {
    wz_iter_node_thrd_data * thrd = thrds + thrd_i;
    thrd->id = thrd_i;
    thrd->queue = &queue;
    if ((thrd->thrd = (HANDLE) _beginthreadex(
                NULL, 0, (unsigned (__stdcall *)(void *)) wz_iter_node_thrd,
                thrd, 0, NULL)) == NULL)
      WZ_ERR_GOTO(join_thrds);
    thrds_init++;
  }
# else
  if (pthread_mutex_init(&queue.mutex, NULL))
    WZ_ERR_RET(ret);
  if (pthread_cond_init(&queue.cond, NULL))
    WZ_ERR_GOTO(destroy_mutex);
  if ((thrds_avail_l = sysconf(_SC_NPROCESSORS_ONLN)) < 1)
    WZ_ERR_GOTO(destroy_cond);
  thrds_len = (wz_uint16_t) thrds_avail_l;
  thrds_init = 0;
  attr_err = 1;
  thrds = NULL;
  if (pthread_attr_init(&attr))
    WZ_ERR_GOTO(destroy_cond);
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
    WZ_ERR_GOTO(destroy_attr);
  if ((thrds = malloc(thrds_len * sizeof(* thrds))) == NULL)
    WZ_ERR_GOTO(destroy_attr);
  for (thrd_i = 0; thrd_i < thrds_len; thrd_i++) {
    wz_iter_node_thrd_data * thrd = thrds + thrd_i;
    thrd->id = thrd_i;
    thrd->queue = &queue;
    if (pthread_create(&thrd->tid, &attr,
                       (void * (*)(void *)) wz_iter_node_thrd, thrd))
      WZ_ERR_GOTO(destroy_attr);
    thrds_init++;
  }
  attr_err = 0;
destroy_attr:
  if (pthread_attr_destroy(&attr))
    WZ_ERR_GOTO(join_thrds);
  if (attr_err)
    goto join_thrds;
# endif
#endif
  stack_capa = 1;
  stack_len = 0;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    WZ_ERR_GOTO(join_thrds);
  stack[stack_len++] = node;
  while (stack_len) {
    wz_uint8_t type;
    wz_uint32_t req;
    wz_uint32_t len;
    wz_uint32_t i;
    wznode * nodes;
    node = stack[--stack_len];
    if (node == NULL) {
      node = stack[--stack_len];
      if (node->n.info & (WZ_LEVEL | WZ_LEAF))
        wz_free_lv1(node);
      else
        wz_free_lv0(node);
      continue;
    }
    if (node->n.info & WZ_LEAF)
      root = node;
    if ((node->n.info & WZ_TYPE) >= WZ_UNK &&
        node->n.val.ary == NULL) {
      if (node->n.info & (WZ_LEVEL | WZ_LEAF)) {
#ifdef WZ_NO_THRD
        if (wz_read_lv1(node, root, file, keys, 1)) {
#else
        if (wz_read_lv1(node, root, file, keys, 0)) {
#endif
          err = 1;
          continue;
        }
      } else {
        if (wz_read_lv0(node, file, keys)) {
          err = 1;
          continue;
        }
      }
    }
    type = node->n.info & WZ_TYPE;
    if (type < WZ_UNK)
      continue;
    if (type > WZ_IMG) {
      wz_free_lv1(node);
      continue;
    }
    if (type == WZ_ARY) {
      wzary * ary = node->n.val.ary;
      len   = ary->len;
      nodes = ary->nodes;
    } else {
#ifndef WZ_NO_THRD
      wz_iter_node_thrd_node * tnode;
#endif
      wzimg * img = node->n.val.img;
      len   = img->len;
      nodes = img->nodes;
#ifndef WZ_NO_THRD
# ifdef WZ_WINDOWS
      if (WaitForSingleObject(queue.mutex, INFINITE) != WAIT_OBJECT_0)
        WZ_ERR_GOTO(free_stack);
# else
      if (pthread_mutex_lock(&queue.mutex))
        WZ_ERR_GOTO(free_stack);
# endif
      req = queue.len + 1;
      if (req > queue.capa) {
        wz_iter_node_thrd_node * mem;
        wz_uint32_t l = queue.capa;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        if ((mem = realloc(queue.nodes, l * sizeof(* queue.nodes))) == NULL)
          WZ_ERR_GOTO(free_stack);
        queue.nodes = mem, queue.capa = l;
      }
      tnode = queue.nodes + queue.len;
      tnode->w     = img->w;
      tnode->h     = img->h;
      tnode->depth = img->depth;
      tnode->scale = img->scale;
      tnode->size  = img->size;
      tnode->data  = img->data;
      tnode->key   = root->n.info & WZ_EMBED ? root->na_e.key : root->na.key;
      img->data = NULL;
      queue.len++;
# ifdef WZ_WINDOWS
      if (queue.len >= WZ_ITER_NODE_CAPA)
        if (SetEvent(queue.event) == FALSE)
          WZ_ERR_GOTO(free_stack);
      if (ReleaseMutex(queue.mutex) == FALSE)
        WZ_ERR_GOTO(free_stack);
# else
      if (queue.len >= WZ_ITER_NODE_CAPA)
        if (pthread_cond_signal(&queue.cond))
          WZ_ERR_GOTO(free_stack);
      if (pthread_mutex_unlock(&queue.mutex))
        WZ_ERR_GOTO(free_stack);
# endif
#endif
    }
    req = stack_len + 2 + len;
    if (req > stack_capa) {
      wznode ** mem;
      wz_uint32_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
        WZ_ERR_GOTO(free_stack);
      stack = mem, stack_capa = l;
    }
    stack_len++;
    stack[stack_len++] = NULL;
    for (i = len; i--;)
      stack[stack_len++] = nodes + i;
  }
  if (!err)
    ret = 0;
free_stack:
  free(stack);
join_thrds:
#ifndef WZ_NO_THRD
# ifdef WZ_WINDOWS
  if (WaitForSingleObject(queue.mutex, INFINITE) != WAIT_OBJECT_0)
    ret = 1;
  queue.exit = 1;
  if (SetEvent(queue.event) == FALSE)
    ret = 1;
  if (ReleaseMutex(queue.mutex) == FALSE)
    ret = 1;
  for (thrd_i = 0; thrd_i < thrds_init; thrd_i++) {
    wz_iter_node_thrd_data * thrd = thrds + thrd_i;
    DWORD status;
    if (WaitForSingleObject(thrd->thrd, INFINITE) != WAIT_OBJECT_0 ||
        GetExitCodeThread(thrd->thrd, &status) == FALSE ||
        status ||
        CloseHandle(thrd->thrd) == FALSE)
      ret = 1;
  }
  free(thrds);
close_event:
  if (CloseHandle(queue.event) == FALSE)
    ret = 1;
close_mutex:
  if (CloseHandle(queue.mutex) == FALSE)
    ret = 1;
# else
  if (pthread_mutex_lock(&queue.mutex))
    ret = 1;
  queue.exit = 1;
  if (pthread_cond_broadcast(&queue.cond))
    ret = 1;
  if (pthread_mutex_unlock(&queue.mutex))
    ret = 1;
  for (thrd_i = 0; thrd_i < thrds_init; thrd_i++) {
    wz_iter_node_thrd_data * thrd = thrds + thrd_i;
    void * status;
    if (pthread_join(thrd->tid, &status) ||
        status != NULL)
      ret = 1;
  }
  free(thrds);
destroy_cond:
  if (pthread_cond_destroy(&queue.cond))
    ret = 1;
destroy_mutex:
  if (pthread_mutex_destroy(&queue.mutex))
    ret = 1;
# endif
  free(queue.nodes);
#endif
  return ret;
}

static size_t /* [^\0{delim}]+ */
wz_next_tok(const char ** begin, const char ** end, const char * str,
            const char delim) {
  for (;;) {
    const char c = * str;
    if (c == '\0') return * begin = NULL, * end = NULL, (size_t) 0;
    if (c != delim) break;
    str++;
  }
  * begin = str++;
  for (;;) {
    const char c = * str;
    if (c == '\0') return * end = str, (size_t) (str - * begin);
    if (c == delim) return * end = str + 1, (size_t) (str - * begin);
    str++;
  }
}

wz_uint8_t
wz_get_type(wznode * node) {
  return node->n.info & WZ_TYPE;
}

int
wz_get_int(wz_int32_t * val, wznode * node) {
  switch (node->n.info & WZ_TYPE) {
  case WZ_I16: * val = node->n16.val;   break;
  case WZ_I32: * val = node->n32.val.i; break;
  default:     WZ_ERR_RET(1);
  }
  return 0;
}

int
wz_get_i64(wz_int64_t * val, wznode * node) {
  if ((node->n.info & WZ_TYPE) != WZ_I64)
    WZ_ERR_RET(1);
  * val = node->n64.val.i;
  return 0;
}

int
wz_get_f32(float * val, wznode * node) {
  if ((node->n.info & WZ_TYPE) != WZ_F32)
    WZ_ERR_RET(1);
  * val = node->n32.val.f;
  return 0;
}

int
wz_get_f64(double * val, wznode * node) {
  if ((node->n.info & WZ_TYPE) != WZ_F64)
    WZ_ERR_RET(1);
  * val = node->n64.val.f;
  return 0;
}

char *
wz_get_str(wznode * node) {
  wzstr * str;
  if ((node->n.info & WZ_TYPE) != WZ_STR ||
      ((str = node->n.val.str) == NULL))
    WZ_ERR_RET(NULL);
  return (char *) str->bytes;
}

wz_uint8_t *
wz_get_img(wz_uint32_t * w, wz_uint32_t * h,
           wz_uint16_t * depth, wz_uint8_t * scale, wznode * node) {
  wzimg * img;
  if ((node->n.info & WZ_TYPE) != WZ_IMG ||
      (img = node->n.val.img) == NULL)
    WZ_ERR_RET(NULL);
  * w = img->w;
  * h = img->h;
  if (depth != NULL)
    * depth = img->depth;
  if (scale != NULL)
    * scale = img->scale;
  return img->data;
}

int
wz_get_vex_len(wz_uint32_t * len, wznode * node) {
  wzvex * vex;
  if ((node->n.info & WZ_TYPE) != WZ_VEX ||
      (vex = node->n.val.vex) == NULL)
    WZ_ERR_RET(1);
  * len = vex->len;
  return 0;
}

int
wz_get_vex_at(wz_int32_t * x, wz_int32_t * y, wz_uint32_t i, wznode * node) {
  wzvex * vex;
  if ((node->n.info & WZ_TYPE) != WZ_VEX ||
      (vex = node->n.val.vex) == NULL ||
      i >= vex->len)
    WZ_ERR_RET(1);
  * x = vex->ary[i].x;
  * y = vex->ary[i].y;
  return 0;
}

int
wz_get_vec(wz_int32_t * x, wz_int32_t * y, wznode * node) {
  if ((node->n.info & WZ_TYPE) != WZ_VEC)
    WZ_ERR_RET(1);
  * x = node->n64.val.vec.x;
  * y = node->n64.val.vec.y;
  return 0;
}

wz_uint8_t *
wz_get_ao(wz_uint32_t * size, wz_uint32_t * ms, wz_uint16_t * format,
          wznode * node) {
  wzao * ao;
  if ((node->n.info & WZ_TYPE) != WZ_AO ||
      (ao = node->n.val.ao) == NULL)
    WZ_ERR_RET(NULL);
  * size = ao->size;
  * ms = ao->ms;
  * format = ao->format;
  return ao->data;
}

wznode *
wz_open_node(wznode * node, const char * path) {
  wznode * root;
  wzfile * file;
  wz_uint8_t * keys;
  char * search;
  size_t search_capa;
  wz_uint8_t found;
  if (node->n.info & WZ_LEVEL) {
    root = node->n.root.node;
    file = root->n.root.file;
  } else {
    root = NULL;
    file = node->n.root.file;
  }
  keys = file->ctx->keys;
  search = NULL;
  search_capa = 0;
  found = 0;
  for (;;) {
    const char * name;
    size_t name_len;
    wz_uint32_t len;
    wz_uint32_t i;
    wznode * nodes;
    wznode * next;
    if (node->n.info & WZ_LEAF)
      root = node;
    if ((node->n.info & WZ_TYPE) >= WZ_UNK &&
        node->n.val.ary == NULL) {
      if (node->n.info & (WZ_LEVEL | WZ_LEAF)) {
        if (wz_read_lv1(node, root, file, keys, 1))
          WZ_ERR_GOTO(free_search);
        if ((node->n.info & WZ_TYPE) == WZ_UOL) {
          wzstr * uol = node->n.val.str;
          if (path == NULL) {
            path = (char *) uol->bytes;
          } else {
            char * str = search;
            size_t req = uol->len + 1 + strlen(path) + 1;
            if (req > search_capa) {
              size_t l = search_capa;
              do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
              if ((str = realloc(str, l)) == NULL)
                WZ_ERR_GOTO(free_search);
              search = str;
              search_capa = l;
            }
            strcpy(str, (char *) uol->bytes), str += uol->len;
            strcat(str, "/"),                 str += 1;
            strcat(str, path);
            path = search;
          }
          if ((node = node->n.parent) == NULL)
            WZ_ERR_GOTO(free_search);
          continue;
        }
      } else {
        if (wz_read_lv0(node, file, keys))
          WZ_ERR_GOTO(free_search);
      }
    }
    name_len = wz_next_tok(&name, &path, path, '/');
    if (name_len == 2 && name[0] == '.' && name[1] == '.') {
      if ((node = node->n.parent) == NULL)
        WZ_ERR_GOTO(free_search);
      continue;
    }
    if (name == NULL) {
      found = 1;
      goto free_search;
    }
    switch (node->n.info & WZ_TYPE) {
    case WZ_ARY: {
      wzary * ary = node->n.val.ary;
      len   = ary->len;
      nodes = ary->nodes;
      break;
    }
    case WZ_IMG: {
      wzimg * img = node->n.val.img;
      len   = img->len;
      nodes = img->nodes;
      break;
    }
    default:
      WZ_ERR_GOTO(free_search);
    }
    next = NULL;
    for (i = 0; i < len; i++) {
      wznode * child = nodes + i;
      wz_uint32_t name_len_ = child->n.name_len;
      wz_uint8_t * name_ = (child->n.info & WZ_EMBED ?
                            child->n.name_e : child->n.name);
      if (name_len_ == name_len &&
          !strncmp((char *) name_, name, name_len)) {
        next = child;
        break;
      }
    }
    if (next == NULL)
      goto free_search;
    node = next;
  }
free_search:
  free(search);
  return found ? node : NULL;
}

int
wz_close_node(wznode * node) {
  int ret = 1;
  wz_uint32_t stack_capa = 1;
  wz_uint32_t stack_len = 0;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    WZ_ERR_RET(ret);
  stack[stack_len++] = node;
  while (stack_len) {
    wz_uint32_t req;
    wz_uint32_t len;
    wz_uint32_t i;
    wznode * nodes;
    node = stack[--stack_len];
    if (node == NULL) {
      node = stack[--stack_len];
      if (node->n.info & (WZ_LEVEL | WZ_LEAF))
        wz_free_lv1(node);
      else
        wz_free_lv0(node);
      continue;
    }
    if ((node->n.info & WZ_TYPE) <= WZ_UNK ||
        node->n.val.ary == NULL)
      continue;
    switch (node->n.info & WZ_TYPE) {
    case WZ_ARY: {
      wzary * ary = node->n.val.ary;
      len   = ary->len;
      nodes = ary->nodes;
      break;
    }
    case WZ_IMG: {
      wzimg * img = node->n.val.img;
      len   = img->len;
      nodes = img->nodes;
      break;
    }
    default:
      wz_free_lv1(node);
      continue;
    }
    req = stack_len + 2 + len;
    if (req > stack_capa) {
      wznode ** fit;
      wz_uint32_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      if ((fit = realloc(stack, l * sizeof(* stack))) == NULL)
        WZ_ERR_GOTO(free_stack);
      stack = fit, stack_capa = l;
    }
    stack_len++, stack[stack_len++] = NULL;
    for (i = 0; i < len; i++)
      stack[stack_len++] = nodes + i;
  }
  ret = 0;
free_stack:
  free(stack);
  return ret;
}

wznode *
wz_open_root(wzfile * file) {
  return wz_open_node(&file->root, "");
}

char *
wz_get_name(wznode * node) {
  return (char *) (node->n.info & WZ_EMBED ? node->n.name_e : node->n.name);
}

int
wz_get_len(wz_uint32_t * len, wznode * node) {
  switch (node->n.info & WZ_TYPE) {
  case WZ_ARY: {
    wzary * ary;
    if ((ary = node->n.val.ary) == NULL)
      WZ_ERR_RET(1);
    * len = ary->len;
    break;
  }
  case WZ_IMG: {
    wzimg * img;
    if ((img = node->n.val.img) == NULL)
      WZ_ERR_RET(1);
    * len = img->len;
    break;
  }
  default:
    WZ_ERR_RET(1);
  }
  return 0;
}

wznode *
wz_open_node_at(wznode * node, wz_uint32_t i) {
  switch (node->n.info & WZ_TYPE) {
  case WZ_ARY: {
    wzary * ary;
    if ((ary = node->n.val.ary) == NULL)
      WZ_ERR_RET(NULL);
    return wz_open_node(ary->nodes + i, "");
  }
  case WZ_IMG: {
    wzimg * img;
    if ((img = node->n.val.img) == NULL)
      WZ_ERR_RET(NULL);
    return wz_open_node(img->nodes + i, "");
  }
  default:
    WZ_ERR_RET(NULL);
  }
}

wzfile *
wz_open_file(const char * filename, wzctx * ctx) {
  wzfile * file = NULL;
  FILE * raw;
  long size_l;
  wz_uint32_t size;
  wzfile tmp;
  wz_uint32_t start;
  wz_uint16_t enc;
  wz_uint16_t dec;
  wz_uint32_t hash;
  wz_uint32_t addr;
  wz_uint8_t  key;
  if ((raw = fopen(filename, "rb")) == NULL) {
    perror(filename);
    return file;
  }
  if (fseek(raw, 0, SEEK_END)) {
    perror(filename);
    goto close_raw;
  }
  if ((size_l = ftell(raw)) < 0) {
    perror(filename);
    goto close_raw;
  }
  if (size_l > WZ_INT32_MAX) {
    wz_error("The file is too large: %s\n", filename);
    goto close_raw;
  }
  if (fseek(raw, 0, SEEK_SET)) {
    perror(filename);
    goto close_raw;
  }
  size = (wz_uint32_t) size_l;
  tmp.raw = raw;
  tmp.pos = 0;
  tmp.size = size;
  if (wz_seek(4 + 4 + 4, SEEK_CUR, &tmp) || /* ident + size + unk */
      wz_read_le32(&start, &tmp) ||
      wz_seek(start - tmp.pos, SEEK_CUR, &tmp) || /* copyright */
      wz_read_le16(&enc, &tmp)) {
    perror(filename);
    goto close_raw;
  }
  addr = tmp.pos;
  if (wz_deduce_ver(&dec, &hash, &key,
                    enc, addr, start, size, raw, ctx->keys))
    WZ_ERR_GOTO(close_raw);
  if ((file = malloc(sizeof(* file))) == NULL)
    WZ_ERR_GOTO(close_raw);
  file->ctx = ctx;
  file->raw = raw;
  file->pos = 0;
  file->size = size;
  file->start = start;
  file->hash = hash;
  file->key = key;
  file->root.n.parent = NULL;
  file->root.n.root.file = file;
  file->root.n.info = WZ_ARY | WZ_EMBED;
  file->root.n.name_len = 0;
  file->root.n.name_e[0] = '\0';
  file->root.na_e.addr = addr;
  file->root.n.val.ary = NULL;
close_raw:
  if (file == NULL)
    fclose(raw);
  return file;
}

int
wz_close_file(wzfile * file) {
  wz_uint8_t ret = 0;
  if (wz_close_node(&file->root))
    ret = 1;
  if (fclose(file->raw))
    ret = 1;
  free(file);
  return ret;
}

static void /* aes ofb */
wz_encode_aes(wz_uint8_t * cipher, wz_uint32_t len,
              wz_uint8_t * key, const wz_uint8_t * iv) {
  aes256_context ctx;
  wzptr cipher_c;
  wzptr iv_c;
  wz_uint32_t i;
  wz_uint8_t j;
  aes256_init(&ctx, key);
  cipher_c.u8 = cipher;
  iv_c.c8 = iv;
  len >>= 4;
  for (i = 0; i < len; i++) {
    for (j = 0; j < 16 / 4; j++)
      cipher_c.u32[j] = iv_c.c32[j];
    aes256_encrypt_ecb(&ctx, cipher_c.u8);
    iv_c = cipher_c, cipher_c.u8 += 16;
  }
  aes256_done(&ctx);
}

wzctx *
wz_init_ctx(void) {
  wzctx * ctx = NULL;
  wz_uint8_t aes_key[32];
  wz_uint8_t aes_iv[16];
  wzptr aes_key_c;
  wzptr aes_iv_c;
  wz_uint8_t * keys;
  wz_uint8_t i;
  wz_uint8_t j;
  aes_key_c.u8 = aes_key;
  for (i = 0; i < 32 / 4; i++)
    aes_key_c.u32[i] = WZ_HTOLE32(wz_aes_key[i]);
  aes_iv_c.u8 = aes_iv;
  if ((keys = malloc(WZ_KEYS_LEN * WZ_KEY_UTF8_MAX_LEN)) == NULL)
    WZ_ERR_RET(ctx);
  for (i = 0; i < WZ_KEYS_LEN; i++) {
    wz_uint32_t aes_iv4 = WZ_HTOLE32(wz_aes_ivs[i]);
    for (j = 0; j < 16 / 4; j++)
      aes_iv_c.u32[j] = aes_iv4;
    wz_encode_aes(keys + i * WZ_KEY_UTF8_MAX_LEN, WZ_KEY_UTF8_MAX_LEN,
                  aes_key, aes_iv);
  }
  if ((ctx = malloc(sizeof(* ctx))) == NULL)
    WZ_ERR_GOTO(free_keys);
  ctx->keys = keys;
free_keys:
  if (ctx == NULL)
    free(keys);
  return ctx;
}

int
wz_free_ctx(wzctx * ctx) {
  free(ctx->keys);
  free(ctx);
  return 0;
}
