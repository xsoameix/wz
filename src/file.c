// Standard Library

#include <pthread.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>

#include <string.h>
#include <assert.h>
#include <inttypes.h>

// Third Party Library

#include <aes256.h>
#include <zlib.h>

// This Library

#include "wrap.h"
#include "byteorder.h"
#include "file.h"

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

const uint8_t wz_aes_key[32 / 4] = { // These value would be expanded to aes key
  0x13, 0x08, 0x06, 0xb4, 0x1b, 0x0f, 0x33, 0x52
};

const uint32_t wz_aes_ivs[] = { // These values would be expanded to aes ivs
  0x2bc7234d,
  0xe9637db9 // used to decode UTF8 (lua script)
};

enum {
  WZ_KEYS_LEN = sizeof(wz_aes_ivs) / sizeof(* wz_aes_ivs),
  // Get the index of the last key, which is empty and filled with zeros
  WZ_KEY_EMPTY = WZ_KEYS_LEN,
  // There may be a giant json string which is large than 0x10000 bytes and
  //  use only first 0x10000 bytes of the key to decode the characters,
  //  which is encoded in ascii
  // The image chunk and wav header, which are small than 0x10000 bytes,
  //  also use the key to decode itself
  WZ_KEY_ASCII_MAX_LEN = 0x10000,
  // The largest lua script (jms v357: Etc.wz: /Script/BattleScene.lua)
  //  we found is 0x1106c bytes and fully encoded in utf8,
  //  so we set a number bigger than this
  WZ_KEY_UTF8_MAX_LEN  = 0x12000
};

#define WZ_ERR \
    fprintf(stderr, "Error: %s at %s:%d\n", __func__, __FILE__, __LINE__)
#define WZ_ERR_GOTO(x) do { WZ_ERR; goto x; } while (0)
#define WZ_ERR_RET(x) do { WZ_ERR; return x; } while (0)
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

void
wz_error(const char * format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, format, args);
  va_end(args);
}

int
wz_read_bytes(void * bytes, uint32_t len, wzfile * file) {
  if (file->pos + len > file->size) WZ_ERR_RET(1);
  if (!len) return 0;
  if (fread(bytes, len, 1, file->raw) != 1) WZ_ERR_RET(1);
  return file->pos += len, 0;
}

int
wz_read_byte(uint8_t * byte, wzfile * file) {
  if (file->pos + 1 > file->size) WZ_ERR_RET(1);
  if (fread(byte, 1, 1, file->raw) != 1) WZ_ERR_RET(1);
  return file->pos += 1, 0;
}

int
wz_read_le16(uint16_t * le16, wzfile * file) {
  if (file->pos + 2 > file->size) WZ_ERR_RET(1);
  if (fread(le16, 2, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le16 = WZ_LE16TOH(* le16);
  return file->pos += 2, 0;
}

int
wz_read_le32(uint32_t * le32, wzfile * file) {
  if (file->pos + 4 > file->size) WZ_ERR_RET(1);
  if (fread(le32, 4, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le32 = WZ_LE32TOH(* le32);
  return file->pos += 4, 0;
}

int
wz_read_le64(uint64_t * le64, wzfile * file) {
  if (file->pos + 8 > file->size) WZ_ERR_RET(1);
  if (fread(le64, 8, 1, file->raw) != 1) WZ_ERR_RET(1);
  * le64 = WZ_LE64TOH(* le64);
  return file->pos += 8, 0;
}

int // read packed integer (int8 or int32)
wz_read_int32(uint32_t * int32, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) WZ_ERR_RET(1);
  if (byte == INT8_MIN) return wz_read_le32(int32, file);
  return * (int32_t *) int32 = byte, 0;
}

int // read packed long (int8 or int64)
wz_read_int64(uint64_t * int64, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) WZ_ERR_RET(1);
  if (byte == INT8_MIN) return wz_read_le64(int64, file);
  return * (int64_t *) int64 = byte, 0;
}

const uint16_t wz_cp1252_to_unicode[128] = {
  // 0x80 to 0xff, cp1252 only, code 0xffff means the char is undefined
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

int
wz_cp1252_to_utf8(uint8_t * u8_bytes, uint32_t * u8_len,
                  const uint8_t * cp1252_bytes, uint32_t cp1252_len) {
  uint32_t        cp1252_last = cp1252_len;
  const uint8_t * cp1252      = cp1252_bytes;
  uint8_t *       u8          = u8_bytes == NULL ? 0 : u8_bytes;
  while (cp1252_last) {
    uint16_t code = * cp1252;
    if (code >= 0x80)
      code = wz_cp1252_to_unicode[code - 0x80];
    uint8_t u8_size;
    if (code < 0x80) {
      u8_size = 1;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) code;
      }
    } else if (code < 0x800) {
      u8_size = 2;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) (((code >> 6) & 0x1f) | 0xc0);
        u8[1] = (uint8_t) (((code     ) & 0x3f) | 0x80);
      }
    } else if (code < 0xffff) {
      u8_size = 3;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) (((code >> 12) & 0x0f) | 0xe0);
        u8[1] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[2] = (uint8_t) (((code      ) & 0x3f) | 0x80);
      }
    } else {
      WZ_ERR_RET(1);
    }
    cp1252      += 1;
    cp1252_last -= 1;
    u8          += u8_size;
  }
  if (u8_bytes == NULL)
    * u8_len = (uint32_t) (uintptr_t) u8;
  else
    * u8 = '\0';
  return 0;
}

int
wz_utf16le_to_utf8(uint8_t * u8_bytes, uint32_t * u8_len,
                   const uint8_t * u16_bytes, uint32_t u16_len) {
  uint32_t        u16_last = u16_len;
  const uint8_t * u16      = u16_bytes;
  uint8_t *       u8       = u8_bytes == NULL ? 0 : u8_bytes;
  while (u16_last) {
    uint8_t  u16_size;
    uint32_t code; // unicode
    if (u16_last < 2)
      WZ_ERR_RET(1);
    if ((u16[1] & 0xfc) == 0xd8) {
      if (u16_last < 4)
        WZ_ERR_RET(1);
      if ((u16[3] & 0xfc) == 0xdc) {
        u16_size = 4;
        code = (uint32_t) ((u16[1] & 0x03) << 18 |
                           (u16[0]       ) << 10 |
                           (u16[3] & 0x03) <<  8 |
                           (u16[2]       ) <<  0);
      } else {
        WZ_ERR_RET(1);
      }
    } else {
      u16_size = 2;
      code = (uint32_t) ((u16[1] << 8) |
                         (u16[0]     ));
    }
    uint8_t u8_size;
    if (code < 0x80) {
      u8_size = 1;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) code;
      }
    } else if (code < 0x800) {
      u8_size = 2;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) (((code >> 6) & 0x1f) | 0xc0);
        u8[1] = (uint8_t) (((code     ) & 0x3f) | 0x80);
      }
    } else if (code < 0x10000) {
      u8_size = 3;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) (((code >> 12) & 0x0f) | 0xe0);
        u8[1] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[2] = (uint8_t) (((code      ) & 0x3f) | 0x80);
      }
    } else if (code < 0x110000) {
      u8_size = 4;
      if (u8_bytes != NULL) {
        u8[0] = (uint8_t) (((code >> 18) & 0x07) | 0xf0);
        u8[1] = (uint8_t) (((code >> 12) & 0x3f) | 0x80);
        u8[2] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
        u8[3] = (uint8_t) (((code      ) & 0x3f) | 0x80);
      }
    } else {
      WZ_ERR_RET(1);
    }
    u16      += u16_size;
    u16_last -= u16_size;
    u8       += u8_size;
  }
  if (u8_bytes == NULL)
    * u8_len = (uint32_t) (uintptr_t) u8;
  else
    * u8 = '\0';
  return 0;
}

int
wz_decode_chars(uint8_t * bytes, uint32_t len,
                uint8_t key_i, const uint8_t * keys, uint8_t enc) {
  if (enc == WZ_ENC_CP1252) {
    uint32_t        min_len;
    const uint8_t * key;
    if (key_i == WZ_KEY_EMPTY) {
      min_len = 0;
      key = NULL;
    } else {
      if (len <= WZ_KEY_ASCII_MAX_LEN)
        min_len = len;
      else
        min_len = WZ_KEY_ASCII_MAX_LEN;
      key = keys + key_i * WZ_KEY_UTF8_MAX_LEN;
    }
    uint8_t mask = 0xaa;
    for (uint32_t i = 0; i < min_len; i++)
      bytes[i] ^= (uint8_t) (mask++ ^ key[i]);
    for (uint32_t i = min_len; i < len; i++)
      bytes[i] ^= (uint8_t) mask++;
  } else if (enc == WZ_ENC_UTF16LE) {
    uint32_t         u16_len = len >> 1;
    uint16_t *       u16 = (uint16_t *) bytes;
    uint32_t         u16_min_len;
    const uint16_t * u16_key;
    if (key_i == WZ_KEY_EMPTY) {
      u16_min_len = 0;
      u16_key = NULL;
    } else {
      if (len > WZ_KEY_ASCII_MAX_LEN)
        WZ_ERR_RET(1);
      u16_min_len = u16_len;
      u16_key = (const uint16_t *) (keys + key_i * WZ_KEY_UTF8_MAX_LEN);
    }
    uint16_t mask = 0xaaaa;
    for (uint32_t i = 0; i < u16_min_len; i++)
      u16[i] = WZ_HTOLE16(WZ_LE16TOH(u16[i]) ^ mask++ ^ WZ_LE16TOH(u16_key[i]));
    for (uint32_t i = u16_min_len; i < u16_len; i++)
      u16[i] = WZ_HTOLE16(WZ_LE16TOH(u16[i]) ^ mask++);
  } else {
    assert(enc == WZ_ENC_UTF8);
    if (len > WZ_KEY_UTF8_MAX_LEN)
      WZ_ERR_RET(1);
    const uint8_t * key = keys + key_i * WZ_KEY_UTF8_MAX_LEN;
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= key[i];
  }
  return 0;
}

int // read characters (cp1252, utf16le, or utf8)
wz_read_chars(uint8_t ** ret_bytes, uint32_t * ret_len, uint8_t * ret_enc,
              uint32_t capa, uint32_t addr, uint8_t type,
              uint8_t key, uint8_t * keys, wzfile * file) {
  int ret = 1;
  uint8_t enc = WZ_ENC_AUTO;
  uint32_t pos = 0;
  uint8_t padding = 0;
  if (type != WZ_LV0_NAME) {
    uint8_t fmt;
    if (wz_read_byte(&fmt, file))
      WZ_ERR_RET(ret);
    enum {UNK = 2};
    uint8_t inplace = UNK;
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
      return wz_error("Unsupported string type: 0x%02hhx\n", fmt), ret;
    if (!inplace) {
      uint32_t offset;
      if (wz_read_le32(&offset, file))
        WZ_ERR_RET(ret);
      pos = file->pos;
      if (wz_seek(addr + offset, SEEK_SET, file))
        WZ_ERR_RET(ret);
    }
    if (type == WZ_LV1_STR) {
      padding = sizeof(uint32_t);
    } else if (type == WZ_LV1_TYPENAME_OR_STR && fmt == 0x01) {
      enc = WZ_ENC_UTF8;
      capa = 0;
      key = 1;
      padding = sizeof(uint32_t);
    }
  }
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file))
    WZ_ERR_RET(ret);
  uint32_t len;
  if (byte <= 0) { // CP1252
    if (byte == INT8_MIN) {
      if (wz_read_le32(&len, file))
        WZ_ERR_RET(ret);
    } else {
      len = (uint32_t) -byte;
    }
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_CP1252;
  } else { // UTF16-LE
    if (byte == INT8_MAX) {
      if (wz_read_le32(&len, file))
        WZ_ERR_RET(ret);
    } else {
      len = (uint32_t) byte;
    }
    len <<= 1;
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_UTF16LE;
  }
  uint8_t * bytes_ptr;
  uint8_t * bytes;
  if (capa) {
    if (len >= capa)
      WZ_ERR_RET(ret);
    bytes_ptr = * ret_bytes;
  } else {
    if (len > INT32_MAX)
      WZ_ERR_RET(ret);
    if ((bytes_ptr = malloc(padding + len + 1)) == NULL)
      WZ_ERR_RET(ret);
  }
  uint8_t * utf8_ptr = NULL;
  uint32_t  utf8_len = 0;
  bytes = bytes_ptr + padding;
  if (wz_read_bytes(bytes, len, file))
    WZ_ERR_GOTO(free_bytes_ptr);
  bytes[len] = '\0';
  if (key != 0xff) {
    if (wz_decode_chars(bytes, len, key, keys, enc))
      WZ_ERR_GOTO(free_bytes_ptr);
    int (* to)(uint8_t *, uint32_t *, const uint8_t *, uint32_t);
    if (enc == WZ_ENC_CP1252) {
      to = wz_cp1252_to_utf8;
    } else if (enc == WZ_ENC_UTF16LE) {
      to = wz_utf16le_to_utf8;
    } else {
      to = NULL;
    }
    if (to != NULL) { // malloc new string only if capa == 0 && utf8_len > len
      if (to(NULL, &utf8_len, bytes, len))
        WZ_ERR_GOTO(free_bytes_ptr);
      if (capa && (utf8_len >= capa))
        WZ_ERR_GOTO(free_bytes_ptr);
      uint8_t   utf8_buf[256];
      uint8_t * utf8;
      if (utf8_len < sizeof(utf8_buf) && (utf8_len <= len || capa)) {
        utf8 = utf8_buf;
      } else {
        if ((utf8_ptr = malloc(padding + utf8_len + 1)) == NULL)
          WZ_ERR_GOTO(free_bytes_ptr);
        utf8 = utf8_ptr + padding;
      }
      if (to(utf8, NULL, bytes, len))
        WZ_ERR_GOTO(free_utf8_ptr);
      if (utf8_len <= len || capa) {
        for (uint32_t i = 0; i < utf8_len; i++)
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
  if (utf8_ptr != NULL || (ret && !capa))
    free(bytes_ptr);
  return ret;
}

void
wz_free_chars(uint8_t * bytes) {
  free(bytes);
}

void
wz_decode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
               uint32_t start, uint32_t hash) {
  uint32_t key = 0x581c3f6d;
  uint32_t x = ~(pos - start) * hash - key;
  uint32_t n = x & 0x1f;
  x = (x << n) | (x >> (32 - n)); // rotate left n bit
  * ret_val = (x ^ val) + start * 2;
}

int
wz_seek(uint32_t pos, int origin, wzfile * file) {
  if (pos > INT32_MAX) WZ_ERR_RET(1);
  if (fseek(file->raw, pos, origin)) WZ_ERR_RET(1);
  if (origin == SEEK_CUR) return file->pos += pos, 0;
  return file->pos = pos, 0;
}

int
wz_read_lv0(wznode * node, wzfile * file, uint8_t * keys) {
  int ret = 1;
  if (wz_seek(node->n.info & WZ_EMBED ?
              node->na_e.addr : node->na.addr, SEEK_SET, file))
    WZ_ERR_RET(ret);
  uint32_t len;
  if (wz_read_int32(&len, file))
    WZ_ERR_RET(ret);
  wzary * ary;
  if ((ary = malloc(offsetof(wzary, nodes) +
                    len * sizeof(* ary->nodes))) == NULL)
    WZ_ERR_RET(ret);
  wznode * nodes = ary->nodes;
  uint8_t   name[UINT8_MAX];
  uint8_t * name_ptr = name;
  uint32_t  name_len;
  uint8_t   key   = file->key;
  uint32_t  start = file->start;
  uint32_t  hash  = file->hash;
  for (uint32_t i = 0; i < len; i++) {
    int err = 1;
    wznode * child = nodes + i;
    uint8_t type;
    if (wz_read_byte(&type, file))
      WZ_ERR_GOTO(free_child);
    uint32_t pos = 0;
    if (WZ_IS_LV0_LINK(type)) {
      uint32_t offset;
      if (wz_read_le32(&offset, file))
        WZ_ERR_GOTO(free_child);
      pos = file->pos;
      if (wz_seek(file->start + offset, SEEK_SET, file) ||
          wz_read_byte(&type, file)) // type and name are in the other place
        WZ_ERR_GOTO(free_child);
    }
    if (WZ_IS_LV0_ARY(type) ||
        WZ_IS_LV0_OBJ(type)) {
      uint32_t size;
      uint32_t check;
      uint32_t addr;
      uint32_t addr_pos;
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
      uint8_t * bytes;
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
      for (uint32_t j = 0; j < name_len; j++)
        bytes[j] = name[j];
      bytes[name_len] = '\0';
      child->n.name_len = (uint8_t) name_len;
      if (WZ_IS_LV0_ARY(type)) {
        child->n.info |= WZ_ARY;
      } else {
        child->n.info |= WZ_UNK | WZ_LEAF;
      }
    } else if (WZ_IS_LV0_NIL(type)) {
      if (wz_seek(10, SEEK_CUR, file)) // unknown 10 bytes
        WZ_ERR_GOTO(free_child);
      child->n.name_e[0] = '\0';
      child->n.name_len = 0;
      child->n.info = WZ_EMBED | WZ_NIL | WZ_LEAF;
    } else {
      wz_error("Unsupported node type: 0x%02hhx\n", type);
      goto free_child;
    }
    child->n.parent = node;
    child->n.root.file = file;
    child->n.val.ary = NULL;
    err = 0;
free_child:
    if (err) {
      for (uint32_t j = 0; j < i; j++) {
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

void
wz_free_lv0(wznode * node) {
  wzary * ary = node->n.val.ary;
  uint32_t len = ary->len;
  wznode * nodes = ary->nodes;
  for (uint32_t i = 0; i < len; i++) {
    wznode * child = nodes + i;
    if (!(child->n.info & WZ_EMBED))
      wz_free_chars(child->n.name);
  }
  free(ary);
  node->n.val.ary = NULL;
}

void
wz_encode_ver(uint16_t * ret_enc, uint32_t * ret_hash, uint16_t dec) {
  uint8_t b[5 + 1];
  uint8_t i = 5;
  b[5] = '\0';
  if (dec == 0)
    b[--i] = '0';
  else
    do {
      b[--i] = (uint8_t) (dec % 10 + '0');
    } while (dec /= 10);
  uint32_t hash = 0;
  for (uint8_t c; (c = b[i++]) != 0;)
    hash = (hash << 5) + c + 1;
  uint16_t enc = (uint8_t) ~(((hash      ) & 0xff) ^
                             ((hash >>  8) & 0xff) ^
                             ((hash >> 16) & 0xff) ^
                             ((hash >> 24)       ));
  * ret_enc = enc;
  * ret_hash = hash;
}

int // if string key is found, the string is also decoded.
wz_deduce_key(uint8_t * ret_key, uint8_t * bytes, uint32_t len,
              const uint8_t * keys) {
  for (uint8_t i = 0; i <= WZ_KEY_EMPTY; i++) {
    if (wz_decode_chars(bytes, len, i, keys, WZ_ENC_CP1252)) continue;
    for (uint32_t j = 0; j < len && isprint(bytes[j]); j++)
      if (j == len - 1) return * ret_key = (uint8_t) i, 0;
    if (wz_decode_chars(bytes, len, i, keys, WZ_ENC_CP1252)) continue;
  }
  return wz_error("Cannot deduce the string key\n"), 1;
}

int
wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash, uint8_t * ret_key,
              uint16_t enc,
              uint32_t addr, uint32_t start, uint32_t size, FILE * raw,
              const uint8_t * keys) {
  int ret = 1;
  wzfile file;
  file.raw = raw;
  file.size = size; // used in read_lv0/int32/byte/bytes
  if (wz_seek(addr, SEEK_SET, &file))
    WZ_ERR_RET(ret);
  uint32_t len;
  if (wz_read_int32(&len, &file))
    WZ_ERR_RET(ret);
  if (len) {
    int err = 1;
    struct entity {
      uint8_t  name_enc;
      uint8_t  name[42 + 1];
      uint32_t name_len;
      uint32_t addr_enc;
      uint32_t addr_pos;
    } * entities;
    if ((entities = malloc(len * sizeof(* entities))) == NULL)
      WZ_ERR_RET(ret);
    for (uint32_t i = 0; i < len; i++) {
      struct entity * entity = entities + i;
      uint8_t type;
      if (wz_read_byte(&type, &file))
        WZ_ERR_GOTO(free_entities);
      uint32_t pos = 0;
      if (WZ_IS_LV0_LINK(type)) {
        uint32_t offset;
        if (wz_read_le32(&offset, &file))
          WZ_ERR_GOTO(free_entities);
        pos = file.pos;
        if (wz_seek(start + offset, SEEK_SET, &file) ||
            wz_read_byte(&type, &file)) // type and name are in the other place
          WZ_ERR_GOTO(free_entities);
      }
      if (WZ_IS_LV0_ARY(type) ||
          WZ_IS_LV0_OBJ(type)) {
        uint8_t * name = entity->name;
        uint32_t  size_;
        uint32_t  check_;
        uint32_t  addr_enc;
        uint32_t  addr_pos;
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
        if (wz_seek(10, SEEK_CUR, &file)) // unknown 10 bytes
          WZ_ERR_GOTO(free_entities);
        entity->addr_enc = 0; // no need to decode
      } else {
        wz_error("Unsupported node type: 0x%02hhx\n", type);
        goto free_entities;
      }
    }
    int guessed = 0;
    uint16_t g_dec;
    uint32_t g_hash;
    uint16_t g_enc;
    for (g_dec = 0; g_dec < 512; g_dec++) { // guess dec
      wz_encode_ver(&g_enc, &g_hash, g_dec);
      if (g_enc == enc) {
        int addr_err = 0;
        for (uint32_t i = 0; i < len; i++) {
          struct entity * entity = entities + i;
          uint32_t addr_enc = entity->addr_enc;
          if (addr_enc) {
            uint32_t addr_pos = entity->addr_pos;
            uint32_t addr_dec;
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
    uint8_t   key = 0xff;
    for (uint32_t i = 0; i < len; i++) {
      struct entity * entity = entities + i;
      uint32_t addr_enc = entity->addr_enc;
      if (addr_enc) {
        uint8_t name_enc = entity->name_enc;
        if (name_enc == WZ_ENC_CP1252) {
          if (wz_deduce_key(&key, entity->name, entity->name_len, keys)) {
            WZ_ERR;
            guessed = 0;
            break;
          }
        }
      }
    }
    if (key == 0xff)
      WZ_ERR_GOTO(free_entities);
    if (!guessed)
      goto free_entities;
    * ret_dec = g_dec;
    * ret_hash = g_hash;
    * ret_key = key;
    err = 0;
free_entities:
    free(entities);
    if (err)
      goto exit;
  }
  ret = 0;
exit:
  return ret;
}

wznode *
wz_invert_node(wznode * node) { // node must not be NULL
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

int
wz_read_list(void ** ret_ary, uint8_t nodes_off, uint8_t len_off,
             uint32_t root_addr, uint8_t root_key,
             uint8_t * keys, wznode * node, wznode * root, wzfile * file) {
  int ret = 1;
  if (wz_seek(2, SEEK_CUR, file))
    WZ_ERR_RET(ret);
  uint32_t len;
  if (wz_read_int32(&len, file))
    WZ_ERR_RET(ret);
  wznode * nodes;
  void * ary;
  if ((ary = malloc(nodes_off + len * sizeof(* nodes))) == NULL)
    WZ_ERR_RET(ret);
  nodes = (wznode *) ((uint8_t *) ary + nodes_off);
  uint8_t   name[UINT8_MAX];
  uint8_t * name_ptr = name;
  uint32_t  name_len;
  for (uint32_t i = 0; i < len; i++) {
    int err = 1;
    wznode * child = nodes + i;
    if (wz_read_chars(&name_ptr, &name_len, NULL, sizeof(name),
                      root_addr, WZ_LV1_NAME, root_key, keys, file))
      WZ_ERR_GOTO(free_child);
    uint8_t name_capa;
    uint8_t info;
    uint8_t type;
    if (wz_read_byte(&type, file))
      WZ_ERR_GOTO(free_child);
    if (WZ_IS_LV1_NIL(type)) {
      name_capa = sizeof(child->nil_e.name_buf);
      info = WZ_NIL;
    } else if (WZ_IS_LV1_I16(type)) {
      int16_t i16;
      if (wz_read_le16((uint16_t *) &i16, file))
        WZ_ERR_GOTO(free_child);
      child->n16.val = i16;
      name_capa = sizeof(child->n16_e.name_buf);
      info = WZ_I16;
    } else if (WZ_IS_LV1_I32(type)) {
      int32_t i32;
      if (wz_read_int32((uint32_t *) &i32, file))
        WZ_ERR_GOTO(free_child);
      child->n32.val.i = i32;
      name_capa = sizeof(child->n32_e.name_buf);
      info = WZ_I32;
    } else if (WZ_IS_LV1_I64(type)) {
      int64_t i64;
      if (wz_read_int64((uint64_t *) &i64, file))
        WZ_ERR_GOTO(free_child);
      child->n64.val.i = i64;
      name_capa = sizeof(child->n64_e.name_buf);
      info = WZ_I64;
    } else if (WZ_IS_LV1_F32(type)) {
      int8_t flt8;
      if (wz_read_byte((uint8_t *) &flt8, file))
        WZ_ERR_GOTO(free_child);
      if (flt8 == INT8_MIN) {
        union { uint32_t i; float f; } flt32;
        if (wz_read_le32(&flt32.i, file))
          WZ_ERR_GOTO(free_child);
        child->n32.val.f = flt32.f;
      } else {
        child->n32.val.f = flt8;
      }
      name_capa = sizeof(child->n32_e.name_buf);
      info = WZ_F32;
    } else if (WZ_IS_LV1_F64(type)) {
      union { uint64_t i; double f; } flt64;
      if (wz_read_le64(&flt64.i, file))
        WZ_ERR_GOTO(free_child);
      child->n64.val.f = flt64.f;
      name_capa = sizeof(child->n64_e.name_buf);
      info = WZ_F64;
    } else if (WZ_IS_LV1_STR(type)) {
      wzstr * str;
      uint32_t  str_len;
      if (wz_read_chars((uint8_t **) &str, &str_len, NULL, 0, root_addr,
                        WZ_LV1_STR, root_key, keys, file))
        WZ_ERR_GOTO(free_child);
      str->len = str_len;
      child->n.val.str = str;
      name_capa = sizeof(child->np_e.name_buf);
      info = WZ_STR;
    } else if (WZ_IS_LV1_OBJ(type)) {
      uint32_t size;
      if (wz_read_le32(&size, file))
        WZ_ERR_GOTO(free_child);
      uint32_t pos = file->pos;
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
      wz_error("Unsupported primitive type: 0x%02hhx\n", type);
      goto free_child;
    }
    uint8_t * bytes;
    if (name_len < name_capa) {
      bytes = child->n.name_e;
      info |= WZ_EMBED;
    } else {
      if ((bytes = malloc(name_len + 1)) == NULL)
        WZ_ERR_GOTO(free_str);
      child->n.name = bytes;
    }
    for (uint32_t j = 0; j < name_len; j++)
      bytes[j] = name[j];
    bytes[name_len] = '\0';
    child->n.name_len = (uint8_t) name_len;
    child->n.info = info | WZ_LEVEL;
    child->n.parent = node;
    child->n.root.node = root;
    err = 0;
free_str:
    if (err && WZ_IS_LV1_STR(type))
      wz_free_chars((uint8_t *) child->n.val.str);
free_child:
    if (err) {
      for (uint32_t j = 0; j < i; j++) {
        wznode * child_ = nodes + j;
        if ((child_->n.info & WZ_TYPE) == WZ_STR)
          wz_free_chars((uint8_t *) child_->n.val.str);
        if (!(child_->n.info & WZ_EMBED))
          wz_free_chars(child_->n.name);
      }
      goto free_ary;
    }
  }
  * (uint32_t *) ((uint8_t *) ary + len_off) = len;
  * ret_ary = ary;
  ret = 0;
free_ary:
  if (ret)
    free(ary);
  return ret;
}

void
wz_free_list(void * ary, uint8_t nodes_off, uint8_t len_off) {
  uint32_t len = * (uint32_t *) ((uint8_t *) ary + len_off);
  wznode * nodes = (wznode *) ((uint8_t *) ary + nodes_off);
  for (uint32_t i = 0; i < len; i++) {
    wznode * child = nodes + i;
    if ((child->n.info & WZ_TYPE) == WZ_STR)
      wz_free_chars((uint8_t *) child->n.val.str);
    if (!(child->n.info & WZ_EMBED))
      wz_free_chars(child->n.name);
  }
  free(ary);
}

int
wz_decode_bitmap(uint32_t * written,
                 uint8_t * out, uint8_t * in, uint32_t size, uint8_t * key) {
  uint32_t read = 0;
  uint32_t wrote = 0;
  while (read < size) {
    uint32_t len = WZ_LE32TOH(* (uint32_t *) (in + read));
    read += (uint32_t) sizeof(len);
    if (len > WZ_KEY_ASCII_MAX_LEN)
      return wz_error("Image chunk size is too large: %"PRIu32"\n", len), 1;
    for (uint32_t i = 0; i < len; i++)
      out[wrote++] = in[read++] ^ key[i];
  }
  return * written = wrote, 0;
}

int
wz_inflate_bitmap(uint32_t * written,
                  uint8_t * out, uint32_t out_len,
                  uint8_t * in, uint32_t in_len) {
  int ret = 1;
  z_stream strm = {.zalloc = Z_NULL, .zfree = Z_NULL, .opaque = Z_NULL};
  strm.next_in = in;
  strm.avail_in = in_len;
  if (inflateInit(&strm) != Z_OK)
    WZ_ERR_RET(ret);
  strm.next_out = out;
  strm.avail_out = out_len;
  if (inflate(&strm, Z_NO_FLUSH) != Z_OK)
    goto inflate_end;
  * written = (uint32_t) strm.total_out;
  ret = 0;
inflate_end:
  inflateEnd(&strm);
  return ret;
}

const uint8_t wz_u4[16] = { // unpack 4 bit to 8 bit color: (i << 4) | i
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
const uint8_t wz_u5[32] = { // unpack 5 bit to 8 bit color: (i << 3) | (i >> 2)
  0x00, 0x08, 0x10, 0x18, 0x21, 0x29, 0x31, 0x39,
  0x42, 0x4a, 0x52, 0x5a, 0x63, 0x6b, 0x73, 0x7b,
  0x84, 0x8c, 0x94, 0x9c, 0xa5, 0xad, 0xb5, 0xbd,
  0xc6, 0xce, 0xd6, 0xde, 0xe7, 0xef, 0xf7, 0xff
};
const uint8_t wz_u6[64] = { // unpack 6 bit to 8 bit color: (i << 2) | (i >> 4)
  0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c,
  0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
  0x41, 0x45, 0x49, 0x4d, 0x51, 0x55, 0x59, 0x5d,
  0x61, 0x65, 0x69, 0x6d, 0x71, 0x75, 0x79, 0x7d,
  0x82, 0x86, 0x8a, 0x8e, 0x92, 0x96, 0x9a, 0x9e,
  0xa2, 0xa6, 0xaa, 0xae, 0xb2, 0xb6, 0xba, 0xbe,
  0xc3, 0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf,
  0xe3, 0xe7, 0xeb, 0xef, 0xf3, 0xf7, 0xfb, 0xff
};

int
wz_read_bitmap(wzcolor ** data, uint32_t w, uint32_t h,
               uint16_t depth, uint16_t scale, uint32_t size, uint8_t * key) {
  int ret = 1;
  uint32_t pixels = w * h;
  uint32_t full_size = pixels * (uint32_t) sizeof(wzcolor);
  uint32_t max_size = size > full_size ? size : full_size; // inflated > origin
  uint8_t * in = (uint8_t *) * data;
  uint8_t * tmp;
  uint8_t * out;
  if ((out = malloc(max_size)) == NULL)
    WZ_ERR_RET(ret);
  if (wz_inflate_bitmap(&size, out, full_size, in, size)) {
    if (wz_decode_bitmap(&size, out, in, size, key) ||
        wz_inflate_bitmap(&size, in, full_size, out, size))
      WZ_ERR_GOTO(free_out);
  } else {
    tmp = in, in = out, out = tmp;
  }
  uint32_t scale_size;
  switch (scale) {
  case 0: scale_size =  1; break; // pow(2, 0) == 1
  case 4: scale_size = 16; break; // pow(2, 4) == 16
  default: {
    wz_error("Unsupported color scale %hhd\n", scale);
    goto free_out;
  }}
  uint32_t depth_size;
  switch (depth) {
  case WZ_COLOR_8888: depth_size = 4; break;
  case WZ_COLOR_4444:
  case WZ_COLOR_565:  depth_size = 2; break;
  case WZ_COLOR_DXT3:
  case WZ_COLOR_DXT5: depth_size = 1; break;
  default: {
    wz_error("Unsupported color depth %hhd\n", depth);
    goto free_out;
  }}
  if (size * (scale_size * scale_size) != pixels * depth_size)
    WZ_ERR_GOTO(free_out);
  uint32_t sw = w / scale_size; // shrunk by scale_size
  uint32_t sh = h / scale_size; // shrunk by scale_size
  int dxt3 = 0;
  switch (depth) {
  case WZ_COLOR_8888: tmp = in, in = out, out = tmp; break;
  case WZ_COLOR_4444: {
    uint8_t * src = in;
    wzcolor * dst = (wzcolor *) out; // cast to pixel based type
    uint32_t len = sw * sh;
    for (uint32_t i = 0; i < len; i++, src += 2, dst++) {
      uint16_t pixel = WZ_LE16TOH(* (uint16_t *) src);
      dst->b = wz_u4[(pixel      ) & 0x0f];
      dst->g = wz_u4[(pixel >>  4) & 0x0f];
      dst->r = wz_u4[(pixel >>  8) & 0x0f];
      dst->a = wz_u4[(pixel >> 12) & 0x0f];
    }
    break;
  }
  case WZ_COLOR_565: {
    uint8_t * src = in;
    wzcolor * dst = (wzcolor *) out; // cast to pixel based type
    uint32_t len = sw * sh;
    for (uint32_t i = 0; i < len; i++, src += 2, dst++) {
      uint16_t pixel = WZ_LE16TOH(* (uint16_t *) src);
      dst->b = wz_u5[(pixel      ) & 0x1f];
      dst->g = wz_u6[(pixel >>  5) & 0x3f];
      dst->r = wz_u5[(pixel >> 11) & 0x1f];
      dst->a = 0xff;
    }
    break;
  }
  case WZ_COLOR_DXT3: dxt3 = 1;
  case WZ_COLOR_DXT5: {
    uint8_t * src = in;
    wzcolor * dst = (wzcolor *) out; // cast to pixel based type
    uint8_t lw = sw & 0x03; // last block width
    uint8_t lh = sh & 0x03; // last block height
    uint32_t bw = (sw >> 2) + (lw > 0); // number of blocks in width
    uint32_t bh = (sh >> 2) + (lh > 0); // number of blocks in height
    uint32_t bn = sw * (4 - 1); // goto next row of blocks
    wzcolor c[4]; // 4 codes
    c[0].a = 0;
    c[1].a = 0;
    c[2].a = 0;
    c[3].a = 0;
    for (uint32_t y = 0; y < bh; y++) { // goto the next row
      for (uint32_t x = 0; x < bw; x++) { // goto the next block
        wzcolor block[16]; // inflate 4x4 block
        uint64_t alpha  = WZ_LE64TOH(* (uint64_t *) (src     )); // indices
        uint16_t color0 = WZ_LE16TOH(* (uint16_t *) (src +  8)); // color code 0
        uint16_t color1 = WZ_LE16TOH(* (uint16_t *) (src + 10)); // color code 1
        uint32_t color  = WZ_LE32TOH(* (uint32_t *) (src + 12)); // indices
        c[0].b = wz_u5[(color0      ) & 0x1f];
        c[0].g = wz_u6[(color0 >>  5) & 0x3f];
        c[0].r = wz_u5[(color0 >> 11) & 0x1f];
        c[1].b = wz_u5[(color1      ) & 0x1f];
        c[1].g = wz_u6[(color1 >>  5) & 0x3f];
        c[1].r = wz_u5[(color1 >> 11) & 0x1f];
        c[2].b = (uint8_t) (((c[0].b << 1) + c[1].b) / 3); // color code 2
        c[2].g = (uint8_t) (((c[0].g << 1) + c[1].g) / 3);
        c[2].r = (uint8_t) (((c[0].r << 1) + c[1].r) / 3);
        c[3].b = (uint8_t) ((c[0].b + (c[1].b << 1)) / 3); // color code 3
        c[3].g = (uint8_t) ((c[0].g + (c[1].g << 1)) / 3);
        c[3].r = (uint8_t) ((c[0].r + (c[1].r << 1)) / 3);
        block[0]  = c[(color      ) & 0x3]; // unpack color value
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
          block[0].a  = wz_u4[(alpha >>  0) & 0xf]; // unpack alpha value
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
        } else { // dxt5
          uint8_t a[8];
          a[0] = src[0]; // alpha 0
          a[1] = src[1]; // alpha 1
          if (a[0] > a[1]) {
            a[2] = (uint8_t) ((a[0] * 6 + a[1]    ) / 7); // alpha 2 if a0 > a1
            a[3] = (uint8_t) ((a[0] * 5 + a[1] * 2) / 7); // alpha 3 if a0 > a1
            a[4] = (uint8_t) ((a[0] * 4 + a[1] * 3) / 7); // alpha 4 if a0 > a1
            a[5] = (uint8_t) ((a[0] * 3 + a[1] * 4) / 7); // alpha 5 if a0 > a1
            a[6] = (uint8_t) ((a[0] * 2 + a[1] * 5) / 7); // alpha 6 if a0 > a1
            a[7] = (uint8_t) ((a[0]     + a[1] * 6) / 7); // alpha 7 if a0 > a1
          } else {
            a[2] = (uint8_t) ((a[0] * 4 + a[1]    ) / 5); // alpha 2 if a0 <= a1
            a[3] = (uint8_t) ((a[0] * 3 + a[1] * 2) / 5); // alpha 3 if a0 <= a1
            a[4] = (uint8_t) ((a[0] * 2 + a[1] * 3) / 5); // alpha 4 if a0 <= a1
            a[5] = (uint8_t) ((a[0]     + a[1] * 4) / 5); // alpha 5 if a0 <= a1
            a[6] = 0;                                     // alpha 6 if a0 <= a1
            a[7] = 0xff;                                  // alpha 7 if a0 <= a1
          }
          block[0].a  = a[(alpha >> 16) & 0x7]; // unpack alpha value
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
        wzcolor * from = block;
        wzcolor * to = dst;
        uint32_t pw = (x + 1 < bw || !lw) ? 4 : lw; // the pixel may be
        uint32_t ph = (y + 1 < bh || !lh) ? 4 : lh; //  out of image
        for (uint32_t py = 0; py < ph; py++, to += sw, from += 4)
          for (uint32_t px = 0; px < pw; px++)
            to[px] = from[px]; // write to correct location
        src += 16;
        dst += pw;
      }
      dst += bn;
    }
    break;
  }
  default: {
    wz_error("Unsupported color depth %hhd\n", depth);
    goto free_out;
  }}
  if (scale_size > 1 && sw) {
    tmp = in, in = out, out = tmp;
    wzcolor * src = (wzcolor *) in; // cast to pixel based type
    wzcolor * dst = (wzcolor *) out;
    uint32_t col = scale_size * (w - 1); // goto next col (block based)
    uint32_t row = scale_size * (sw - 1); // goto next row (block based)
    for (uint32_t y = 0; y < sh; y++)
      for (uint32_t x = 0;;) {
        wzcolor pixel = * src++;
        for (uint32_t py = 0; py < scale_size; py++, dst += w)
          for (uint32_t px = 0; px < scale_size; px++)
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
    free(out == (uint8_t *) * data ? in : out);
  return ret;
}

const uint8_t wz_guid_wav[16] = {
  /* DWORD data1    */ 0x81, 0x9f, 0x58, 0x05,
  /* WORD  data2    */ 0x56, 0xc3,
  /* WORD  data3    */ 0xce, 0x11,
  /* BYTE  data4[8] */ 0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a
};

void
wz_read_wav(wzwav * wav, uint8_t * data) {
  wav->format          = WZ_LE16TOH(* (uint16_t *) data), data += 2;
  wav->channels        = WZ_LE16TOH(* (uint16_t *) data), data += 2;
  wav->sample_rate     = WZ_LE32TOH(* (uint32_t *) data), data += 4;
  wav->byte_rate       = WZ_LE32TOH(* (uint32_t *) data), data += 4;
  wav->block_align     = WZ_LE16TOH(* (uint16_t *) data), data += 2;
  wav->bits_per_sample = WZ_LE16TOH(* (uint16_t *) data), data += 2;
  wav->extra_size      = WZ_LE16TOH(* (uint16_t *) data), data += 2;
}

void
wz_decode_wav(uint8_t * wav, uint8_t size, uint8_t * key) {
  for (uint8_t i = 0; i < size; i++)
    wav[i] ^= key[i];
}

void
wz_write_pcm(uint8_t * pcm, wzwav * wav, uint32_t size) {
  * (uint32_t *) pcm = WZ_HTOBE32(0x52494646),           pcm += 4; // "RIFF"
  * (uint32_t *) pcm = WZ_HTOLE32(36 + size),            pcm += 4; // following
  * (uint32_t *) pcm = WZ_HTOBE32(0x57415645),           pcm += 4; // "WAVE"
  * (uint32_t *) pcm = WZ_HTOBE32(0x666d7420),           pcm += 4; // "fmt "
  * (uint32_t *) pcm = WZ_HTOLE32(16),                   pcm += 4; // PCM = 16
  * (uint16_t *) pcm = WZ_HTOLE16(wav->format),          pcm += 2;
  * (uint16_t *) pcm = WZ_HTOLE16(wav->channels),        pcm += 2;
  * (uint32_t *) pcm = WZ_HTOLE32(wav->sample_rate),     pcm += 4;
  * (uint32_t *) pcm = WZ_HTOLE32(wav->byte_rate),       pcm += 4;
  * (uint16_t *) pcm = WZ_HTOLE16(wav->block_align),     pcm += 2;
  * (uint16_t *) pcm = WZ_HTOLE16(wav->bits_per_sample), pcm += 2;
  * (uint32_t *) pcm = WZ_HTOBE32(0x64617461),           pcm += 4; // "data"
  * (uint32_t *) pcm = WZ_HTOLE32(size),                 pcm += 4;
}

void
wz_read_pcm(wzpcm * out, uint8_t * pcm) {
  out->chunk_id        = WZ_HTOBE32(* (uint32_t *) pcm), pcm += 4; // "RIFF"
  out->chunk_size      = WZ_HTOLE32(* (uint32_t *) pcm), pcm += 4; // following
  out->format          = WZ_HTOBE32(* (uint32_t *) pcm), pcm += 4; // "WAVE"
  out->subchunk1_id    = WZ_HTOBE32(* (uint32_t *) pcm), pcm += 4; // "fmt "
  out->subchunk1_size  = WZ_HTOLE32(* (uint32_t *) pcm), pcm += 4; // PCM = 16
  out->audio_format    = WZ_HTOLE16(* (uint16_t *) pcm), pcm += 2;
  out->channels        = WZ_HTOLE16(* (uint16_t *) pcm), pcm += 2;
  out->sample_rate     = WZ_HTOLE32(* (uint32_t *) pcm), pcm += 4;
  out->byte_rate       = WZ_HTOLE32(* (uint32_t *) pcm), pcm += 4;
  out->block_align     = WZ_HTOLE16(* (uint16_t *) pcm), pcm += 2;
  out->bits_per_sample = WZ_HTOLE16(* (uint16_t *) pcm), pcm += 2;
  out->subchunk2_id    = WZ_HTOBE32(* (uint32_t *) pcm), pcm += 4; // "data"
  out->subchunk2_size  = WZ_HTOLE32(* (uint32_t *) pcm), pcm += 4;
}

int
wz_read_lv1(wznode * node, wznode * root, wzfile * file, uint8_t * keys,
            uint8_t eager) {
  int ret = 1;
  uint32_t  root_addr;
  uint8_t   root_key;
  if (root->n.info & WZ_EMBED) {
    root_addr    = root->na_e.addr;
    root_key     = root->na_e.key;
  } else {
    root_addr    = root->na.addr;
    root_key     = root->na.key;
  }
  uint32_t  addr = node->n.info & WZ_EMBED ? node->na_e.addr : node->na.addr;
  uint8_t   type_enc;
  uint8_t   type[sizeof("Shape2D#Convex2D")];
  uint8_t * type_ptr = type;
  uint32_t  type_len;
  if (wz_seek(addr, SEEK_SET, file) ||
      wz_read_chars(&type_ptr, &type_len, &type_enc, sizeof(type),
                    root_addr, WZ_LV1_TYPENAME_OR_STR, root_key, keys, file))
    WZ_ERR_RET(ret);
  if (type_enc == WZ_ENC_UTF8) {
    ((wzstr *) type_ptr)->len = type_len;
    node->n.val.str = (wzstr *) type_ptr;
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
    uint8_t list;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_byte(&list, file))
      WZ_ERR_GOTO(exit);
    wzimg * img;
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
    uint32_t w;
    uint32_t h;
    uint32_t depth;
    uint8_t  scale;
    uint32_t size;
    if (wz_read_int32(&w, file)      ||
        wz_read_int32(&h, file)      ||
        wz_read_int32(&depth, file)  || depth > UINT16_MAX ||
        wz_read_byte(&scale, file)   ||
        wz_seek(4, SEEK_CUR, file)   || // blank
        wz_read_le32(&size, file)    ||
        wz_seek(1, SEEK_CUR, file))     // blank
      WZ_ERR_GOTO(free_img);
    if (size <= 1)
      WZ_ERR_GOTO(free_img);
    size--; // remove null terminator
    uint32_t pixels = w * h;
    uint32_t full_size = pixels * (uint32_t) sizeof(wzcolor);
    uint32_t max_size = size > full_size ? size : full_size; // inflate > origin
    uint8_t * data;
    if ((data = malloc(max_size)) == NULL)
      WZ_ERR_GOTO(free_img);
    if (wz_read_bytes(data, size, file) ||
        (eager && wz_read_bitmap((wzcolor **) &data, w, h, (uint16_t) depth,
                                 scale, size,
                                 keys + root_key * WZ_KEY_UTF8_MAX_LEN)))
      WZ_ERR_GOTO(free_img_data);
    img->w = w;
    img->h = h;
    img->depth = (uint16_t) depth;
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
    uint32_t len;
    if (wz_read_int32(&len, file))
      WZ_ERR_GOTO(exit);
    wzvex * vex;
    if ((vex = malloc(offsetof(wzvex, ary) +
                      len * sizeof(* vex->ary))) == NULL)
      WZ_ERR_GOTO(exit);
    wzvec * vecs = vex->ary;
    for (uint32_t i = 0; i < len; i++) {
      wzvec * vec = vecs + i;
      if (wz_read_chars(&type_ptr, &type_len, NULL, sizeof(type),
                        root_addr, WZ_LV1_TYPENAME, root_key, keys, file))
        WZ_ERR_GOTO(free_vex);
      if (!WZ_IS_LV1_VEC(type)) {
        wz_error("Convex should contain only vectors\n");
        goto free_vex;
      }
      if (wz_read_int32((uint32_t *) &vec->x, file) ||
          wz_read_int32((uint32_t *) &vec->y, file))
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
    if (wz_read_int32((uint32_t *) &vec.x, file) ||
        wz_read_int32((uint32_t *) &vec.y, file))
      WZ_ERR_GOTO(exit);
    node->n64.val.vec = vec;
    node->n.info = (node->n.info ^ WZ_UNK) | WZ_VEC;
  } else if (WZ_IS_LV1_AO(type)) {
    int err = 1;
    uint32_t size;
    uint32_t ms;
    uint8_t  guid[16];
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_int32(&size, file) ||
        wz_read_int32(&ms, file) ||
        wz_seek(1 + 16 * 2 + 2, SEEK_CUR, file) || // major and subtype GUID
        wz_read_bytes(guid, sizeof(guid), file))
      WZ_ERR_GOTO(exit);
    wzao * ao;
    if ((ao = malloc(sizeof(* ao))) == NULL)
      WZ_ERR_GOTO(exit);
    if (memcmp(guid, wz_guid_wav, sizeof(guid)) == 0) {
      int hdr_err = 1;
      uint8_t hsize; // header size
      if (wz_read_byte(&hsize, file))
        WZ_ERR_GOTO(free_ao);
      uint8_t * hdr; // header
      if ((hdr = malloc(hsize)) == NULL)
        WZ_ERR_GOTO(free_ao);
      if (wz_read_bytes(hdr, hsize, file))
        WZ_ERR_GOTO(free_hdr);
      wzwav wav;
      wz_read_wav(&wav, hdr);
      if (WZ_AUDIO_WAV_SIZE + wav.extra_size != hsize) {
        wz_decode_wav(hdr, hsize, keys + root_key * WZ_KEY_UTF8_MAX_LEN);
        wz_read_wav(&wav, hdr);
        if (WZ_AUDIO_WAV_SIZE + wav.extra_size != hsize)
          WZ_ERR_GOTO(free_hdr);
      }
      hdr_err = 0;
free_hdr:
      free(hdr);
      if (hdr_err)
        WZ_ERR_GOTO(free_ao);
      if (wav.format == WZ_AUDIO_PCM) {
        int pcm_err = 1;
        uint8_t * pcm;
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
        uint8_t * data;
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
        wz_error("Unsupported audio format: 0x%hx\n", wav.format);
        goto free_ao;
      }
      ao->format = wav.format;
    } else {
      uint8_t empty = 1;
      for (uint8_t i = 0; i < sizeof(guid); i++)
        if (guid[i]) {
          empty = 0;
          break;
        }
      if (empty) {
        int data_err = 1;
        uint8_t * data;
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
    uint32_t  str_len;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_chars((uint8_t **) &str, &str_len, NULL, 0, root_addr,
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

void
wz_free_lv1(wznode * node) {
  switch (node->n.info & WZ_TYPE) {
  case WZ_STR:
    wz_free_chars((uint8_t *) node->n.val.str);
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
    wz_free_chars((uint8_t *) node->n.val.str);
    node->n.val.str = NULL;
    break;
  default:
    break;
  }
}

struct wz_read_lv1_thrd_node {
  wznode *  root;
  uint32_t  w;
  uint32_t  h;
  uint16_t  depth;
  uint16_t  scale;
  uint32_t  size;
  uint8_t * data;
};

struct wz_read_lv1_thrd_arg {
  uint8_t id;
  uint8_t _[sizeof(void *) - 1]; // padding
  pthread_mutex_t * mutex;
  pthread_cond_t * work_cond;
  pthread_cond_t * done_cond;
  uint8_t * exit;
  struct wz_read_lv1_thrd_node * nodes;
  size_t len;
  size_t * remain;
};

void *
wz_read_lv1_thrd(void * arg) {
  struct wz_read_lv1_thrd_arg * targ = arg;
  pthread_mutex_t * mutex = targ->mutex;
  pthread_cond_t * work_cond = targ->work_cond;
  pthread_cond_t * done_cond = targ->done_cond;
  uint8_t * exit = targ->exit;
  size_t * remain = targ->remain;
  size_t len = 0;
  int node_err = 0;
  for (;;) {
    int err = 0;
    if ((err = pthread_mutex_lock(mutex)) != 0)
      return (void *) !NULL;
    if (len) {
      (* remain) -= len;
      if (!* remain && (err = pthread_cond_signal(done_cond)) != 0)
        goto unlock_mutex;
      targ->len = 0;
    }
    uint8_t leave;
    struct wz_read_lv1_thrd_node * nodes;
    while (!(leave = * exit) && !(len = targ->len))
      if ((err = pthread_cond_wait(work_cond, mutex)) != 0)
        goto unlock_mutex;
    if (!leave && len)
      nodes = targ->nodes;
    int unlock_err;
unlock_mutex:
    if ((unlock_err = pthread_mutex_unlock(mutex)) != 0)
      return (void *) !NULL;
    if (err)
      return (void *) !NULL;
    if (leave)
      break;
    for (uint32_t i = 0; i < len; i++) {
      struct wz_read_lv1_thrd_node * node = nodes + i;
      wznode * root = node->root;
      wzfile * file = root->n.root.file;
      wzctx * ctx = file->ctx;
      uint8_t key = root->n.info & WZ_EMBED ? root->na_e.key : root->na.key;
      if (wz_read_bitmap((wzcolor **) &node->data, node->w, node->h,
                         node->depth, node->scale, node->size,
                         ctx->keys + key * WZ_KEY_UTF8_MAX_LEN))
        node_err = 1;
    }
  }
  if (node_err)
    return (void *) !NULL;
  return NULL;
}

int // Non recursive DFS
wz_read_lv1_thrd_r(wznode * root, wzfile * file, wzctx * ctx,
                   uint8_t tlen, struct wz_read_lv1_thrd_arg * targs,
                   pthread_mutex_t * mutex,
                   pthread_cond_t * work_cond,
                   pthread_cond_t * done_cond, size_t * remain) {
  int ret = 1;
  int node_err = 0;
  size_t stack_capa = 1;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    return ret;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  char * blank = NULL;
  size_t blank_capa = 0;
  size_t blank_len = 0;
  struct wz_read_lv1_thrd_node * queue = NULL;
  size_t queue_capa = 0;
  size_t queue_len = 0;
  while (stack_len) {
    wznode * node = stack[--stack_len];
    if (node == NULL) {
      wz_free_lv1(stack[--stack_len]);
      continue;
    }
    size_t blank_req = 0;
    for (wznode * n = node; (n = n->n.parent) != NULL;)
      blank_req++;
    if (blank_req + 1 > blank_capa) { // null byte
      size_t l = blank_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < blank_req + 1); // null byte
      void * mem;
      if ((mem = realloc(blank, l)) == NULL)
        goto free_queue;
      blank = mem, blank_capa = l;
    }
    while (blank_len < blank_req)
      blank[blank_len++] = ' ';
    blank[blank_len = blank_req] = '\0';
    //printf("%s name   %s\n",
    //       blank, var->n.info & WZ_EMBED ? var->n.name_e : var->n.name);
    if ((node->n.info & WZ_TYPE) == WZ_UNK)
      if (wz_read_lv1(node, root, file, ctx->keys, 0)) {
        node_err = 1;
        continue;
      }
    //wznode * root_ = wz_invert_node(node);
    //for (wznode * n = root_; (n = n->n.parent) != NULL; )
    //  printf("/%s", n->n.info & WZ_EMBED ? n->n.name_e : n->n.name);
    //printf(": ");
    //wz_invert_node(root_);
    //if ((node->n.info & WZ_TYPE) == WZ_STR) {
    //  wzstr * str = node->n.val.str;
    //  printf("str {%s}", str->bytes);
    //} else if ((node->n.info & WZ_TYPE) == WZ_IMG) {
    //  wzimg * img = node->n.val.img;
    //  const char * depth = "unk";
    //  switch (img->depth) {
    //  case WZ_COLOR_8888: depth = "8888"; break;
    //  case WZ_COLOR_4444: depth = "4444"; break;
    //  case WZ_COLOR_565:  depth = "565";  break;
    //  case WZ_COLOR_DXT3: depth = "dxt3"; break;
    //  case WZ_COLOR_DXT5: depth = "dxt5"; break;
    //  }
    //  uint8_t scale = 0;
    //  switch (img->scale) {
    //  case 0: scale =  1; break; // pow(2, 0) == 1
    //  case 4: scale = 16; break; // pow(2, 4) == 16
    //  }
    //  printf("img %s/%hhu", depth, scale);
    //} else if ((node->n.info & WZ_TYPE) == WZ_AO) {
    //  wzao * ao = node->n.val.ao;
    //  const char * format = "unk";
    //  switch (ao->format) {
    //  case WZ_AUDIO_PCM: format = "pcm"; break;
    //  case WZ_AUDIO_MP3: format = "mp3"; break;
    //  }
    //  printf("ao %s", format);
    //} else if ((node->n.info & WZ_TYPE) == WZ_NIL) {
    //  printf("nil");
    //} else if ((node->n.info & WZ_TYPE) == WZ_I16) {
    //  printf("i16");
    //} else if ((node->n.info & WZ_TYPE) == WZ_I32) {
    //  printf("i32");
    //} else if ((node->n.info & WZ_TYPE) == WZ_I64) {
    //  printf("i64");
    //} else if ((node->n.info & WZ_TYPE) == WZ_F32) {
    //  printf("f32");
    //} else if ((node->n.info & WZ_TYPE) == WZ_F64) {
    //  printf("f64");
    //} else if ((node->n.info & WZ_TYPE) == WZ_VEC) {
    //  printf("vec");
    //} else if ((node->n.info & WZ_TYPE) == WZ_ARY) {
    //  printf("ary");
    //} else if ((node->n.info & WZ_TYPE) == WZ_VEX) {
    //  printf("vex");
    //} else if ((node->n.info & WZ_TYPE) == WZ_UOL) {
    //  printf("uol");
    //}
    //printf("\n");
    uint32_t len;
    wznode * nodes;
    if ((node->n.info & WZ_TYPE) == WZ_ARY) {
      wzary * ary = node->n.val.ary;
      len = ary->len;
      nodes = ary->nodes;
    } else if ((node->n.info & WZ_TYPE) == WZ_IMG) {
      size_t req = queue_len + 1;
      if (req > queue_capa) {
        size_t l = queue_capa;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        struct wz_read_lv1_thrd_node * mem;
        if ((mem = realloc(queue, l * sizeof(* queue))) == NULL)
          goto free_queue;
        queue = mem, queue_capa = l;
      }
      wzimg * img = node->n.val.img;
      struct wz_read_lv1_thrd_node * tnode = queue + queue_len;
      tnode->root = root;
      tnode->w = img->w;
      tnode->h = img->h;
      tnode->depth = img->depth;
      tnode->scale = img->scale;
      tnode->size = img->size;
      tnode->data = img->data;
      img->data = NULL;
      queue_len++;
      len = img->len;
      nodes = img->nodes;
    } else if ((node->n.info & WZ_TYPE) > WZ_UNK) {
      wz_free_lv1(node);
      continue;
    } else {
      continue;
    }
    size_t req = stack_len + 2 + len;
    if (req > stack_capa) {
      size_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      wznode ** mem;
      if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
        goto free_queue;
      stack = mem, stack_capa = l;
    }
    stack[stack_len++] = node;
    stack[stack_len++] = NULL;
    for (uint32_t i = 0; i < len; i++)
      stack[stack_len++] = nodes + len - i - 1;
  }
  if (queue_len) {
    int err;
    if ((err = pthread_mutex_lock(mutex)) != 0)
      goto free_queue;
    size_t start = 0;
    size_t slice = (queue_len + tlen - 1) / tlen;
    for (uint8_t i = 0; i < tlen; i++) {
      struct wz_read_lv1_thrd_arg * targ = targs + i;
      if (start < queue_len) {
        targ->nodes = queue + start;
        targ->len = start + slice < queue_len ? slice : queue_len - start;
      } else {
        targ->nodes = NULL;
        targ->len = 0;
      }
      start += slice;
    }
    * remain = queue_len;
    if ((err = pthread_cond_broadcast(work_cond)) != 0)
      goto unlock_mutex;
    while (* remain)
      if ((err = pthread_cond_wait(done_cond, mutex)) != 0)
        goto unlock_mutex;
    for (size_t i = 0; i < queue_len; i++)
      free(queue[i].data);
    int unlock_err;
unlock_mutex:
    if ((unlock_err = pthread_mutex_unlock(mutex)) != 0)
      goto free_queue;
    if (err)
      goto free_queue;
  }
  if (!node_err)
    ret = 0;
free_queue:
  free(queue);
  free(blank);
  free(stack);
  return ret;
}

int // Non recursive DFS
wz_read_lv1_r(wznode * root, wzfile * file, wzctx * ctx) {
  int ret = 1;
  int err = 0;
  size_t stack_capa = 1;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    return ret;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  while (stack_len) {
    wznode * node = stack[--stack_len];
    if (node == NULL) {
      wz_free_lv1(stack[--stack_len]);
      continue;
    }
    if ((node->n.info & WZ_TYPE) == WZ_UNK) {
      if (wz_read_lv1(node, root, file, ctx->keys, 1)) {
        err = 1;
      } else if ((node->n.info & WZ_TYPE) == WZ_STR) {
      } else if ((node->n.info & WZ_TYPE) == WZ_ARY ||
                 (node->n.info & WZ_TYPE) == WZ_IMG) {
        uint32_t len;
        wznode * nodes;
        if ((node->n.info & WZ_TYPE) == WZ_ARY) {
          wzary * ary = node->n.val.ary;
          len   = ary->len;
          nodes = ary->nodes;
        } else {
          wzimg * img = node->n.val.img;
          len   = img->len;
          nodes = img->nodes;
        }
        size_t req = stack_len + 2 + len;
        if (req > stack_capa) {
          size_t l = stack_capa;
          do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
          wznode ** mem;
          if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
            goto free_stack;
          stack = mem, stack_capa = l;
        }
        stack[stack_len++] = node;
        stack[stack_len++] = NULL;
        for (uint32_t i = 0; i < len; i++)
          stack[stack_len++] = nodes + len - i - 1;
      } else if ((node->n.info & WZ_TYPE) == WZ_VEX) {
        wz_free_lv1(node);
      } else if ((node->n.info & WZ_TYPE) == WZ_VEC) {
        wz_free_lv1(node);
      } else if ((node->n.info & WZ_TYPE) == WZ_AO) {
        wz_free_lv1(node);
      } else if ((node->n.info & WZ_TYPE) == WZ_UOL) {
        wz_free_lv1(node);
      }
    } else if ((node->n.info & WZ_TYPE) == WZ_NIL) {
    } else if ((node->n.info & WZ_TYPE) == WZ_I16 ||
               (node->n.info & WZ_TYPE) == WZ_I32 ||
               (node->n.info & WZ_TYPE) == WZ_I64) {
    } else if ((node->n.info & WZ_TYPE) == WZ_F32 ||
               (node->n.info & WZ_TYPE) == WZ_F64) {
    } else if ((node->n.info & WZ_TYPE) == WZ_STR) {
    }
  }
  if (!err)
    ret = 0;
free_stack:
  free(stack);
  return ret;
}

int
wz_read_node_thrd_r(wznode * root, wzfile * file, wzctx * ctx, uint8_t tcapa) {
  int ret = 1;
  int node_err = 0;
  int err = 0;
  pthread_mutex_t mutex;
  pthread_cond_t work_cond;
  pthread_cond_t done_cond;
  pthread_attr_t attr;
  struct wz_read_lv1_thrd_arg * targs;
  pthread_t * thrds;
  uint8_t tlen = 0;
  uint8_t exit = 0;
  size_t remain = 0;
  if ((err = pthread_mutex_init(&mutex, NULL)) != 0)
    return ret;
  if ((err = pthread_cond_init(&work_cond, NULL)) != 0)
    goto destroy_mutex;
  if ((err = pthread_cond_init(&done_cond, NULL)) != 0)
    goto destroy_work_cond;
  if ((err = pthread_attr_init(&attr)) != 0)
    goto destroy_done_cond;
  if ((err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE)) != 0)
    goto destroy_attr;
  if (tcapa == 0)
    tcapa = 1;
  if ((targs = malloc(tcapa * sizeof(* targs))) == NULL)
    goto destroy_attr;
  if ((thrds = malloc(tcapa * sizeof(* thrds))) == NULL)
    goto free_targs;
  if ((err = pthread_mutex_lock(&mutex)) != 0)
    goto free_thrds;
  for (uint8_t i = 0; i < tcapa; i++) {
    struct wz_read_lv1_thrd_arg * targ = targs + i;
    targ->id = i;
    targ->mutex = &mutex;
    targ->work_cond = &work_cond;
    targ->done_cond = &done_cond;
    targ->exit = &exit;
    targ->nodes = NULL;
    targ->len = 0;
    targ->remain = &remain;
    if ((err = pthread_create(thrds + i, &attr, wz_read_lv1_thrd, targ)) != 0)
      goto broadcast_work_cond;
    tlen++;
  }
  int unlock_err;
  if ((unlock_err = pthread_mutex_unlock(&mutex)) != 0)
    goto broadcast_work_cond;
  assert(tlen == tcapa);
  size_t stack_capa = 1;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    goto broadcast_work_cond;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  uint32_t * sizes = NULL;
  size_t sizes_size = 0;
  size_t sizes_len = 0;
  size_t stack_max_len = 0;
  while (stack_len) {
    wznode * node = stack[--stack_len];
    if (node == NULL) {
      wz_free_lv0(stack[--stack_len]);
      continue;
    }
    printf("node      ");
    for (wznode * n = node; (n = n->n.parent) != NULL;)
      printf(" ");
    uint8_t * name;
    uint32_t  addr;
    if (node->n.info & WZ_EMBED) {
      name = node->n.name_e;
      addr = node->na_e.addr;
    } else {
      name = node->n.name;
      addr = node->na.addr;
    }
    printf("%-30s [%8x]", name, addr);
    for (wznode * n = node; (n = n->n.parent) != NULL;)
      printf(" < %s", n->n.info & WZ_EMBED ? n->n.name_e : n->n.name);
    printf("\n");
    fflush(stdout);
    if ((node->n.info & WZ_TYPE) == WZ_ARY) {
      if (wz_read_lv0(node, file, ctx->keys)) {
        node_err = 1;
        continue;
      }
      wzary * ary = node->n.val.ary;
      uint32_t len = ary->len;
      wznode * nodes = ary->nodes;
      size_t req = stack_len + 2 + len;
      if (req > stack_capa) {
        size_t l = stack_capa;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        wznode ** mem;
        if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
          goto free_sizes;
        stack = mem, stack_capa = l;
      }
      stack[stack_len++] = node;
      stack[stack_len++] = NULL;
      for (uint32_t i = 0; i < len; i++)
        stack[stack_len++] = nodes + len - i - 1;
      req = sizes_len + 1;
      if (req > sizes_size) {
        size_t l = sizes_size;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        void * mem;
        if ((mem = realloc(sizes, l * sizeof(* sizes))) == NULL)
          goto free_sizes;
        sizes = mem, sizes_size = l;
      }
      sizes[sizes_len++] = len;
      if (stack_len > stack_max_len) stack_max_len = stack_len;
    } else if ((node->n.info & WZ_TYPE) == WZ_UNK) {
      if (wz_read_lv1_thrd_r(node, file, ctx, tlen, targs,
                             &mutex, &work_cond, &done_cond, &remain))
        node_err = 1;
    }
  }
  printf("node usage: %"PRIu32" / %"PRIu32"\n",
         (uint32_t) stack_max_len, (uint32_t) stack_capa);
  for (uint32_t i = 0; i < sizes_len; i++) {
    printf("lv0 len %"PRIu32"\n", sizes[i]);
  }
  if (!node_err)
    ret = 0;
free_sizes:
  free(sizes);
  free(stack);
  if ((err = pthread_mutex_lock(&mutex)) != 0) {
    ret = 1;
    goto free_thrds;
  }
broadcast_work_cond:
  exit = 1;
  if ((err = pthread_cond_broadcast(&work_cond)) != 0)
    ret = 1;
  if ((unlock_err = pthread_mutex_unlock(&mutex)) != 0) {
    ret = 1;
    goto free_thrds;
  }
  // if broadcast failed, give up safely joining the threads
  if (!err)
    for (uint8_t i = 0; i < tlen; i++) {
      void * status;
      if ((err = pthread_join(thrds[i], &status)) != 0 ||
          status != NULL)
        ret = 1;
    }
free_thrds:
  free(thrds);
free_targs:
  free(targs);
destroy_attr:
  if ((err = pthread_attr_destroy(&attr)) != 0)
    ret = 1;
destroy_done_cond:
  if ((err = pthread_cond_destroy(&done_cond)) != 0)
    ret = 1;
destroy_work_cond:
  if ((err = pthread_cond_destroy(&work_cond)) != 0)
    ret = 1;
destroy_mutex:
  if ((err = pthread_mutex_destroy(&mutex)) != 0)
    ret = 1;
  return ret;
}

typedef struct {
  uint32_t  w;
  uint32_t  h;
  uint16_t  depth;
  uint16_t  scale;
  uint32_t  size;
  uint8_t * data;
  uint8_t * key;
} wz_iter_node2_thrd_node;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  uint32_t capa;
  uint32_t len;
  wz_iter_node2_thrd_node * nodes;
  uint8_t exit;
  uint8_t _[sizeof(void *) - 1];
} wz_iter_node2_thrd_queue;

typedef struct {
  pthread_t tid;
  uint16_t id;
  uint8_t _[sizeof(void *) - 2]; // padding
  wz_iter_node2_thrd_queue * queue;
} wz_iter_node2_thrd_data;

enum {WZ_ITER_NODE_CAPA = 4};

void *
wz_iter_node2_thrd(wz_iter_node2_thrd_data * data) {
  uint8_t err = 0;
  wz_iter_node2_thrd_queue * queue = data->queue;
  for (;;) {
    if (pthread_mutex_lock(&queue->mutex))
      WZ_ERR_GOTO(exit);
    uint8_t exit;
    wz_iter_node2_thrd_node nodes[WZ_ITER_NODE_CAPA];
    uint8_t nodes_len;
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
      goto exit;
    for (uint8_t i = 0; i < nodes_len; i++) {
      wz_iter_node2_thrd_node * node = nodes + i;
      if (wz_read_bitmap((wzcolor **) &node->data, node->w, node->h,
                         node->depth, node->scale, node->size, node->key))
        err = 1;
      free(node->data);
    }
  }
exit:
  return err ? (void *) !NULL : NULL;
}

int
wz_iter_node2(wznode * node) {
  int ret = 1;
  int err = 0;
  wznode * root;
  wzfile * file;
  if (node->n.info & WZ_LEVEL) {
    root = node->n.root.node;
    file = root->n.root.file;
  } else if (node->n.info & WZ_LEAF) {
    root = node;
    file = root->n.root.file;
  } else {
    root = NULL;
    file = node->n.root.file;
  }
  uint8_t * keys = file->ctx->keys;
#ifndef WZ_NO_THRD
  wz_iter_node2_thrd_queue queue;
  queue.capa = 0;
  queue.len = 0;
  queue.nodes = NULL;
  queue.exit = 0;
  if (pthread_mutex_init(&queue.mutex, NULL))
    WZ_ERR_RET(ret);
  if (pthread_cond_init(&queue.cond, NULL))
    WZ_ERR_GOTO(destroy_mutex);
  long thrds_avail_l;
  if ((thrds_avail_l = sysconf(_SC_NPROCESSORS_ONLN)) < 1)
    WZ_ERR_GOTO(destroy_cond);
  uint16_t thrds_len = (uint16_t) thrds_avail_l;
  uint16_t thrds_init = 0;
  uint8_t attr_err = 1;
  pthread_attr_t attr;
  wz_iter_node2_thrd_data * thrds = NULL;
  if (pthread_attr_init(&attr))
    WZ_ERR_GOTO(destroy_cond);
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
    WZ_ERR_GOTO(destroy_attr);
  if ((thrds = malloc(thrds_len * sizeof(* thrds))) == NULL)
    WZ_ERR_GOTO(destroy_attr);
  for (uint16_t i = 0; i < thrds_len; i++) {
    wz_iter_node2_thrd_data * thrd = thrds + i;
    thrd->id = i;
    thrd->queue = &queue;
    if (pthread_create(&thrd->tid, &attr,
                       (void * (*)(void *)) wz_iter_node2_thrd, thrd))
      WZ_ERR_GOTO(destroy_attr);
    thrds_init++;
  }
  attr_err = 0;
destroy_attr:
  if (pthread_attr_destroy(&attr))
    WZ_ERR_GOTO(join_thrds);
  if (attr_err)
    goto join_thrds;
#endif
  uint32_t stack_capa = 1;
  uint32_t stack_len = 0;
  uint32_t stack_max_len;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    WZ_ERR_GOTO(join_thrds);
  stack[stack_len++] = node;
  stack_max_len = stack_len;
  while (stack_len) {
    node = stack[--stack_len];
    if (node == NULL) {
      node = stack[--stack_len];
      if (node->n.info & (WZ_LEVEL | WZ_LEAF))
        wz_free_lv1(node);
      else
        wz_free_lv0(node);
      continue;
    }
    if (node->n.info & WZ_LEAF) {
      //wznode * root_ = wz_invert_node(node);
      //printf("[%8x] ", (node->n.info & WZ_EMBED ?
      //                  node->na_e.addr : node->na.addr));
      //for (wznode * n = root_; (n = n->n.parent) != NULL;)
      //  printf("/%s", n->n.info & WZ_EMBED ? n->n.name_e : n->n.name);
      //printf("\n");
      //wz_invert_node(root_);
      root = node;
    }
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
    uint8_t type = node->n.info & WZ_TYPE;
    if (type < WZ_UNK)
      continue;
    if (type > WZ_IMG) {
      wz_free_lv1(node);
      continue;
    }
    uint32_t len;
    wznode * nodes;
    if (type == WZ_ARY) {
      wzary * ary = node->n.val.ary;
      len   = ary->len;
      nodes = ary->nodes;
    } else {
      wzimg * img = node->n.val.img;
      len   = img->len;
      nodes = img->nodes;
#ifndef WZ_NO_THRD
      if (pthread_mutex_lock(&queue.mutex))
        WZ_ERR_GOTO(free_stack);
      uint32_t req = queue.len + 1;
      if (req > queue.capa) {
        uint32_t l = queue.capa;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        wz_iter_node2_thrd_node * mem;
        if ((mem = realloc(queue.nodes, l * sizeof(* queue.nodes))) == NULL)
          WZ_ERR_GOTO(free_stack);
        queue.nodes = mem, queue.capa = l;
      }
      wz_iter_node2_thrd_node * tnode = queue.nodes + queue.len;
      tnode->w     = img->w;
      tnode->h     = img->h;
      tnode->depth = img->depth;
      tnode->scale = img->scale;
      tnode->size  = img->size;
      tnode->data  = img->data;
      tnode->key   = keys + ((root->n.info & WZ_EMBED ?
                              root->na_e.key : root->na.key) *
                             WZ_KEY_UTF8_MAX_LEN);
      img->data = NULL;
      queue.len++;
      if (queue.len >= WZ_ITER_NODE_CAPA)
        if (pthread_cond_signal(&queue.cond))
          WZ_ERR_GOTO(free_stack);
      if (pthread_mutex_unlock(&queue.mutex))
        WZ_ERR_GOTO(free_stack);
#endif
    }
    uint32_t req = stack_len + 2 + len;
    if (req > stack_capa) {
      uint32_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      wznode ** mem;
      if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
        WZ_ERR_GOTO(free_stack);
      stack = mem, stack_capa = l;
    }
    stack_len++;
    stack[stack_len++] = NULL;
    for (uint32_t i = len; i--;)
      stack[stack_len++] = nodes + i;
    if (stack_len > stack_max_len)
      stack_max_len = stack_len;
  }
  printf("node usage: %"PRIu32" / %"PRIu32"\n",
         (uint32_t) stack_max_len, (uint32_t) stack_capa);
  if (!err)
    ret = 0;
free_stack:
  free(stack);
join_thrds:
#ifndef WZ_NO_THRD
  if (pthread_mutex_lock(&queue.mutex))
    ret = 1;
  queue.exit = 1;
  if (pthread_cond_broadcast(&queue.cond))
    ret = 1;
  if (pthread_mutex_unlock(&queue.mutex))
    ret = 1;
  for (uint16_t i = 0; i < thrds_init; i++) {
    wz_iter_node2_thrd_data * thrd = thrds + i;
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
  free(queue.nodes);
#endif
  return ret;
}

typedef struct {
  uint32_t  w;
  uint32_t  h;
  uint16_t  depth;
  uint16_t  scale;
  uint32_t  size;
  uint8_t * data;
  uint8_t * key;
} wz_iter_node_thrd_node;

typedef struct {
  pthread_t tid;
  uint16_t id;
  uint8_t _[4 - 2]; // padding
  uint32_t len;
  wz_iter_node_thrd_node * nodes;
} wz_iter_node_thrd_data;

void *
wz_iter_node_thrd(void * arg) {
  int err = 0;
  wz_iter_node_thrd_data * data = arg;
  wz_iter_node_thrd_node * nodes = data->nodes;
  uint32_t len = data->len;
  for (uint32_t i = 0; i < len; i++) {
    wz_iter_node_thrd_node * node = nodes + i;
    if (wz_read_bitmap((wzcolor **) &node->data, node->w, node->h,
                       node->depth, node->scale, node->size, node->key))
      err = 1;
    free(node->data);
  }
  return err ? (void *) !NULL : NULL;
}

int
wz_iter_node(wznode * node) {
  int ret = 1;
  int err = 0;
  wznode * root;
  wzfile * file;
  if (node->n.info & WZ_LEVEL) {
    root = node->n.root.node;
    file = root->n.root.file;
  } else if (node->n.info & WZ_LEAF) {
    root = node;
    file = root->n.root.file;
  } else {
    root = NULL;
    file = node->n.root.file;
  }
  uint8_t * keys = file->ctx->keys;
#ifndef WZ_NO_THRD
  uint32_t queue_capa = 0;
  uint32_t queue_len = 0;
  wz_iter_node_thrd_node * queue = NULL;
  uint64_t queue_size = 0;
  uint8_t resume = 0;
#endif
  uint32_t stack_capa = 1;
  uint32_t stack_len = 0;
  uint32_t stack_max_len;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    WZ_ERR_RET(ret);
  stack[stack_len++] = node;
  stack_max_len = stack_len;
  while (stack_len) {
    node = stack[--stack_len];
    if (node == NULL) {
      node = stack[--stack_len];
      if (node->n.info & (WZ_LEVEL | WZ_LEAF))
        wz_free_lv1(node);
      else
        wz_free_lv0(node);
      continue;
    }
    if (node->n.info & WZ_LEAF) {
      //wznode * root_ = wz_invert_node(node);
      //printf("[%8x] ", (node->n.info & WZ_EMBED ?
      //                  node->na_e.addr : node->na.addr));
      //for (wznode * n = root_; (n = n->n.parent) != NULL;)
      //  printf("/%s", n->n.info & WZ_EMBED ? n->n.name_e : n->n.name);
      //printf("\n");
      //wz_invert_node(root_);
      root = node;
    }
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
    uint8_t type = node->n.info & WZ_TYPE;
    if (type < WZ_UNK)
      continue;
    if (type > WZ_IMG) {
      wz_free_lv1(node);
      continue;
    }
    uint32_t len;
    wznode * nodes;
    if (type == WZ_ARY) {
      wzary * ary = node->n.val.ary;
      len   = ary->len;
      nodes = ary->nodes;
    } else {
      wzimg * img = node->n.val.img;
      len   = img->len;
      nodes = img->nodes;
#ifndef WZ_NO_THRD
      uint32_t req = queue_len + 1;
      if (req > queue_capa) {
        uint32_t l = queue_capa;
        do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
        wz_iter_node_thrd_node * mem;
        if ((mem = realloc(queue, l * sizeof(* queue))) == NULL)
          WZ_ERR_GOTO(free_queue);
        queue = mem, queue_capa = l;
      }
      wz_iter_node_thrd_node * tnode = queue + queue_len;
      tnode->w     = img->w;
      tnode->h     = img->h;
      tnode->depth = img->depth;
      tnode->scale = img->scale;
      tnode->size  = img->size;
      tnode->data  = img->data;
      tnode->key   = keys + ((root->n.info & WZ_EMBED ?
                              root->na_e.key : root->na.key) *
                             WZ_KEY_UTF8_MAX_LEN);
      img->data = NULL;
      queue_len++;
      queue_size += (img->w * img->h) << 2;
      if (queue_size >= INT32_MAX) {
        resume = 1;
        goto clear_queue;
      }
resume:
      ;
#endif
    }
    uint32_t req = stack_len + 2 + len;
    if (req > stack_capa) {
      uint32_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      wznode ** mem;
      if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
        WZ_ERR_GOTO(free_queue);
      stack = mem, stack_capa = l;
    }
    stack_len++;
    stack[stack_len++] = NULL;
    for (uint32_t i = len; i--;)
      stack[stack_len++] = nodes + i;
    if (stack_len > stack_max_len)
      stack_max_len = stack_len;
  }
#ifndef WZ_NO_THRD
  if (queue_len) {
clear_queue:
    ;
    long thrds_avail_l;
    if ((thrds_avail_l = sysconf(_SC_NPROCESSORS_ONLN)) < 1)
      WZ_ERR_GOTO(free_queue);
    uint16_t thrds_avail = (uint16_t) thrds_avail_l;
    uint16_t thrds_len = (uint16_t) (queue_len < thrds_avail ?
                                     queue_len : thrds_avail);
    uint16_t thrds_init = 0;
    uint32_t start = 0;
    uint32_t slice = queue_len / thrds_len;
    uint32_t extra = queue_len % thrds_len;
    pthread_attr_t attr;
    wz_iter_node_thrd_data * thrds;
    if (pthread_attr_init(&attr))
      WZ_ERR_GOTO(free_queue);
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
      WZ_ERR_GOTO(destroy_attr);
    if ((thrds = malloc(thrds_len * sizeof(* thrds))) == NULL)
      WZ_ERR_GOTO(destroy_attr);
    for (uint16_t i = 0; i < thrds_len; i++) {
      wz_iter_node_thrd_data * thrd = thrds + i;
      thrd->id = i;
      thrd->nodes = queue + start;
      thrd->len = slice + (extra > 0);
      if (pthread_create(&thrd->tid, &attr, wz_iter_node_thrd, thrd))
        WZ_ERR_GOTO(join_thrds);
      thrds_init++;
      if (extra)
        extra--;
      start += thrd->len;
    }
join_thrds:
    for (uint16_t i = 0; i < thrds_init; i++) {
      wz_iter_node_thrd_data * thrd = thrds + i;
      void * status;
      if (pthread_join(thrd->tid, &status) ||
          status != NULL)
        err = 1;
    }
    free(thrds);
destroy_attr:
    if (pthread_attr_destroy(&attr))
      err = 1;
    if (resume) {
      queue_len = 0;
      queue_size = 0;
      resume = 0;
      goto resume;
    }
  }
#endif
  printf("node usage: %"PRIu32" / %"PRIu32"\n",
         (uint32_t) stack_max_len, (uint32_t) stack_capa);
  if (!err)
    ret = 0;
free_queue:
#ifndef WZ_NO_THRD
  free(queue);
#endif
  free(stack);
  return ret;
}

size_t // [^\0{delim}]+
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

int16_t wz_get_i16(wznode * node) { return node->n16.val; }
int32_t wz_get_i32(wznode * node) { return node->n32.val.i; }
int64_t wz_get_i64(wznode * node) { return node->n64.val.i; }
float   wz_get_f32(wznode * node) { return node->n32.val.f; }
double  wz_get_f64(wznode * node) { return node->n64.val.f; }
char *  wz_get_str(wznode * node) { return (char *) node->n.val.str->bytes; }
wzimg * wz_get_img(wznode * node) { return node->n.val.img; }
wzvex * wz_get_vex(wznode * node) { return node->n.val.vex; }
wzvec * wz_get_vec(wznode * node) { return &node->n64.val.vec; }
wzao *  wz_get_ao(wznode * node)  { return node->n.val.ao; }

wznode *
wz_open_node(wznode * node, const char * path) {
  int       found = 0;
  wznode *  root;
  wzfile *  file;
  uint8_t * keys;
  if (!(node->n.info & WZ_LEVEL)) {
    file = node->n.root.file;
    keys = file->ctx->keys;
    for (;;) {
      if (node->n.info & WZ_LEAF)
        break;
      if (node->n.val.ary == NULL)
        if (wz_read_lv0(node, file, keys))
          WZ_ERR_GOTO(exit);
      const char * name;
      size_t name_len = wz_next_tok(&name, &path, path, '/');
      if (name == NULL) {
        found = 1;
        goto exit;
      }
      wzary * ary = node->n.val.ary;
      uint32_t len = ary->len;
      wznode * nodes = ary->nodes;
      wznode * next = NULL;
      for (uint32_t i = 0; i < len; i++) {
        wznode * child = nodes + i;
        uint32_t name_len_ = child->n.name_len;
        uint8_t * name_ = (child->n.info & WZ_EMBED ?
                           child->n.name_e : child->n.name);
        if (name_len_ == name_len &&
            !strncmp((char *) name_, name, name_len)) {
          next = child;
          break;
        }
      }
      if (next == NULL)
        WZ_ERR_GOTO(exit);
      node = next;
    }
    root = node;
  } else {
    root = node->n.root.node;
    file = root->n.root.file;
    keys = file->ctx->keys;
  }
  char * search = NULL;
  size_t slen = 0;
  for (;;) {
    if ((node->n.info & WZ_TYPE) >= WZ_UNK &&
        node->n.val.ary == NULL) {
      if (wz_read_lv1(node, root, file, keys, 1))
        WZ_ERR_GOTO(free_search);
      if ((node->n.info & WZ_TYPE) == WZ_UOL) {
        wzstr * uol = node->n.val.str;
        if (path == NULL) {
          path = (char *) uol->bytes;
        } else {
          char * str = search;
          size_t plen = strlen(path);
          size_t len = uol->len + 1 + plen + 1;
          if (len > slen) {
            if ((str = realloc(str, len)) == NULL)
              WZ_ERR_GOTO(free_search);
            search = str;
            slen = len;
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
    }
    const char * name;
    size_t name_len = wz_next_tok(&name, &path, path, '/');
    if (name_len == 2 && name[0] == '.' && name[1] == '.') {
      if ((node = node->n.parent) == NULL)
        WZ_ERR_GOTO(free_search);
      continue;
    }
    if (name == NULL) {
      found = 1;
      break;
    }
    uint32_t len;
    wznode * nodes;
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
    wznode * next = NULL;
    for (uint32_t i = 0; i < len; i++) {
      wznode * child = nodes + i;
      uint32_t name_len_ = child->n.name_len;
      uint8_t * name_ = (child->n.info & WZ_EMBED ?
                         child->n.name_e : child->n.name);
      if (name_len_ == name_len &&
          !strncmp((char *) name_, name, name_len)) {
        next = child;
        break;
      }
    }
    if (next == NULL)
      WZ_ERR_GOTO(free_search);
    node = next;
  }
free_search:
  free(search);
exit:
  return found ? node : NULL;
}

int
wz_close_node(wznode * node) {
  int ret = 1;
  uint32_t stack_capa = 1;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    WZ_ERR_RET(ret);
  uint32_t stack_len = 0;
  stack[stack_len++] = node;
  while (stack_len) {
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
    uint32_t len;
    wznode * nodes;
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
    uint32_t req = stack_len + 2 + len;
    if (req > stack_capa) {
      uint32_t l = stack_capa;
      do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
      wznode ** fit;
      if ((fit = realloc(stack, l * sizeof(* stack))) == NULL)
        WZ_ERR_GOTO(free_stack);
      stack = fit, stack_capa = l;
    }
    stack_len++, stack[stack_len++] = NULL;
    for (uint32_t i = 0; i < len; i++)
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

uint32_t
wz_get_len(wznode * node) {
  if ((node->n.info & WZ_TYPE) == WZ_ARY)
    return node->n.val.ary->len;
  else
    return node->n.val.img->len;
}

wznode *
wz_open_node_at(wznode * node, uint32_t i) {
  if ((node->n.info & WZ_TYPE) == WZ_ARY)
    return wz_open_node(node->n.val.ary->nodes + i, "");
  else
    return wz_open_node(node->n.val.img->nodes + i, "");
}

int
wz_open_file(wzfile * ret_file, const char * filename, wzctx * ctx) {
  int ret = 1;
  FILE * raw;
  if ((raw = fopen(filename, "rb")) == NULL) {
    perror(filename);
    return ret;
  }
  if (fseek(raw, 0, SEEK_END)) {
    perror(filename);
    goto close_raw;
  }
  long size;
  if ((size = ftell(raw)) < 0) {
    perror(filename);
    goto close_raw;
  }
  if (size > INT32_MAX) {
    wz_error("The file is too large: %s\n", filename);
    goto close_raw;
  }
  if (fseek(raw, 0, SEEK_SET)) {
    perror(filename);
    goto close_raw;
  }
  wzfile file;
  file.raw = raw;
  file.pos = 0;
  file.size = (uint32_t) size;
  uint32_t start;
  uint16_t enc;
  if (wz_seek(4 + 4 + 4, SEEK_CUR, &file) || // ident + size + unk
      wz_read_le32(&start, &file) ||
      wz_seek(start - file.pos, SEEK_CUR, &file) || // copyright
      wz_read_le16(&enc, &file)) {
    perror(filename);
    goto close_raw;
  }
  uint32_t addr = file.pos;
  uint16_t dec;
  uint32_t hash;
  uint8_t  key;
  if (wz_deduce_ver(&dec, &hash, &key,
                    enc, addr, start, file.size, raw, ctx->keys))
    WZ_ERR_GOTO(close_raw);
  ret_file->ctx = ctx;
  ret_file->raw = raw;
  ret_file->pos = 0;
  ret_file->size = file.size;
  ret_file->start = start;
  ret_file->hash = hash;
  ret_file->key = key;
  ret_file->root.n.parent = NULL;
  ret_file->root.n.root.file = ret_file;
  ret_file->root.n.info = WZ_ARY | WZ_EMBED;
  ret_file->root.n.name_len = 0;
  ret_file->root.n.name_e[0] = '\0';
  ret_file->root.na_e.addr = addr;
  ret_file->root.n.val.ary = NULL;
  ret = 0;
close_raw:
  if (ret)
    fclose(raw);
  return ret;
}

int
wz_close_file(wzfile * file) {
  int ret = 0;
  if (wz_close_node(&file->root))
    ret = 1;
  if (fclose(file->raw))
    ret = 1;
  return ret;
}

void // aes ofb
wz_encode_aes(uint8_t * cipher, uint32_t len,
              uint8_t * key, const uint8_t * iv) {
  aes256_context ctx;
  aes256_init(&ctx, key);
  len >>= 4;
  for (uint32_t i = 0; i < len; i++) {
    for (uint8_t j = 0; j < 16 / 4; j++)
      ((uint32_t *) cipher)[j] = ((const uint32_t *) iv)[j];
    aes256_encrypt_ecb(&ctx, cipher);
    iv = cipher, cipher += 16;
  }
  aes256_done(&ctx);
}

int
wz_init_ctx(wzctx * ctx) {
  uint8_t aes_key[32];
  for (uint8_t i = 0; i < 32 / 4; i++)
    ((uint32_t *) aes_key)[i] = WZ_HTOLE32(wz_aes_key[i]);
  uint8_t * keys;
  if ((keys = malloc(WZ_KEYS_LEN * WZ_KEY_UTF8_MAX_LEN)) == NULL)
    WZ_ERR_RET(1);
  for (uint8_t i = 0; i < WZ_KEYS_LEN; i++) {
    uint32_t aes_iv4 = wz_aes_ivs[i];
    uint8_t aes_iv[16];
    for (uint8_t j = 0; j < 16 / 4; j++)
      ((uint32_t *) aes_iv)[j] = WZ_HTOLE32(aes_iv4);
    wz_encode_aes(keys + i * WZ_KEY_UTF8_MAX_LEN, WZ_KEY_UTF8_MAX_LEN,
                  aes_key, aes_iv);
  }
  ctx->keys = keys;
  return 0;
}

void
wz_free_ctx(wzctx * ctx) {
  free(ctx->keys);
}
