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

#define WZ_IS_NODE_NIL(type)  ((type) == 0x01)
#define WZ_IS_NODE_LINK(type) ((type) == 0x02)
#define WZ_IS_NODE_DIR(type)  ((type) == 0x03)
#define WZ_IS_NODE_FILE(type) ((type) == 0x04)

#define WZ_IS_VAR_NIL(type)   ((type) == 0x00)
#define WZ_IS_VAR_INT16(type) ((type) == 0x02 || (type) == 0x0b)
#define WZ_IS_VAR_INT32(type) ((type) == 0x03 || (type) == 0x13)
#define WZ_IS_VAR_INT64(type) ((type) == 0x14)
#define WZ_IS_VAR_FLT32(type) ((type) == 0x04)
#define WZ_IS_VAR_FLT64(type) ((type) == 0x05)
#define WZ_IS_VAR_STR(type)   ((type) == 0x08)
#define WZ_IS_VAR_OBJ(type)   ((type) == 0x09)

#define WZ_IS_OBJ_PROPERTY(type) (!wz_strcmp((type), "Property"))
#define WZ_IS_OBJ_CANVAS(type)   (!wz_strcmp((type), "Canvas"))
#define WZ_IS_OBJ_CONVEX(type)   (!wz_strcmp((type), "Shape2D#Convex2D"))
#define WZ_IS_OBJ_VECTOR(type)   (!wz_strcmp((type), "Shape2D#Vector2D"))
#define WZ_IS_OBJ_SOUND(type)    (!wz_strcmp((type), "Sound_DX8"))
#define WZ_IS_OBJ_UOL(type)      (!wz_strcmp((type), "UOL"))

#define WZ_KEY_JSON_LEN 0x10000  // giant json data <= 0x10000
#define WZ_KEY_LUA_LEN  0x20000 // giant lua script > 0x10000
#define WZ_KEY_MAX_LEN  WZ_KEY_LUA_LEN

#define WZ_ERR \
    fprintf(stderr, "Error: %s at %s:%d\n", __func__, __FILE__, __LINE__)

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
  if (file->pos + len > file->size) { WZ_ERR; return 1; }
  if (!len) return 0;
  if (fread(bytes, len, 1, file->raw) != 1) { WZ_ERR; return 1; }
  return file->pos += len, 0;
}

int
wz_read_byte(uint8_t * byte, wzfile * file) {
  return wz_read_bytes(byte, sizeof(* byte), file);
}

int
wz_read_le16(uint16_t * le16, wzfile * file) {
  if (wz_read_bytes(le16, sizeof(* le16), file)) { WZ_ERR; return 1; }
  return * le16 = WZ_LE16TOH(* le16), 0;
}

int
wz_read_le32(uint32_t * le32, wzfile * file) {
  if (wz_read_bytes(le32, sizeof(* le32), file)) { WZ_ERR; return 1; }
  return * le32 = WZ_LE32TOH(* le32), 0;
}

int
wz_read_le64(uint64_t * le64, wzfile * file) {
  if (wz_read_bytes(le64, sizeof(* le64), file)) { WZ_ERR; return 1; }
  return * le64 = WZ_LE64TOH(* le64), 0;
}

int // read packed integer (int8 or int32)
wz_read_int32(uint32_t * int32, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) { WZ_ERR; return 1; }
  if (byte == INT8_MIN) return wz_read_le32(int32, file);
  return * (int32_t *) int32 = byte, 0;
}

int // read packed long (int8 or int64)
wz_read_int64(uint64_t * int64, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) { WZ_ERR; return 1; }
  if (byte == INT8_MIN) return wz_read_le64(int64, file);
  return * (int64_t *) int64 = byte, 0;
}

int
wz_read_str_embed(uint8_t * bytes, uint32_t capa, uint32_t len, wzfile * file) {
  if (len >= capa) { WZ_ERR; return 1; }
  if (wz_read_bytes(bytes, len, file)) { WZ_ERR; return 1; }
  bytes[len] = '\0';
  return 0;
}

int // read string with malloc
wz_read_str(uint8_t ** ret_bytes, uint32_t len, wzfile * file) {
  if (len > INT32_MAX) { WZ_ERR; return 1; }
  uint8_t * bytes;
  if ((bytes = malloc(len + 1)) == NULL) { WZ_ERR; return 1; }
  if (wz_read_bytes(bytes, len, file)) { WZ_ERR; return free(bytes), 1; }
  bytes[len] = '\0';
  * ret_bytes = bytes;
  return 0;
}

void
wz_free_str(uint8_t * bytes) {
  free(bytes);
}

int
wz_utf16le_to_utf8_1(uint8_t * ret_u8_bytes, uint8_t * ret_u8_size,
                     uint8_t * ret_u16_size,
                     const uint8_t * u16_bytes, uint32_t u16_len) {
  uint8_t  u16_size;
  uint32_t code; // unicode
  if (u16_len < 2) { WZ_ERR; return 1; }
  if ((u16_bytes[1] & 0xfc) == 0xd8) {
    if (u16_len < 4) { WZ_ERR; return 1; }
    if ((u16_bytes[3] & 0xfc) == 0xdc) {
      u16_size = 4;
      code = (uint32_t) ((u16_bytes[1] & 0x03) << 18 |
                         (u16_bytes[0]       ) << 10 |
                         (u16_bytes[3] & 0x03) <<  8 |
                         (u16_bytes[2]       ) <<  0);
    } else {
      WZ_ERR;
      return 1;
    }
  } else {
    u16_size = 2;
    code = (uint32_t) ((u16_bytes[1] << 8) |
                       (u16_bytes[0]     ));
  }
  uint8_t u8_size;
  if (code < 0x80) {
    u8_size = 1;
    if (ret_u8_bytes != NULL) {
      ret_u8_bytes[0] = (uint8_t) code;
    }
  } else if (code < 0x800) {
    u8_size = 2;
    if (ret_u8_bytes != NULL) {
      ret_u8_bytes[0] = (uint8_t) (((code >> 6) & 0x1f) | 0xc0);
      ret_u8_bytes[1] = (uint8_t) (((code     ) & 0x3f) | 0x80);
    }
  } else if (code < 0x10000) {
    u8_size = 3;
    if (ret_u8_bytes != NULL) {
      ret_u8_bytes[0] = (uint8_t) (((code >> 12) & 0x0f) | 0xe0);
      ret_u8_bytes[1] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
      ret_u8_bytes[2] = (uint8_t) (((code      ) & 0x3f) | 0x80);
    }
  } else if (code < 0x110000) {
    u8_size = 4;
    if (ret_u8_bytes != NULL) {
      ret_u8_bytes[0] = (uint8_t) (((code >> 18) & 0x07) | 0xf0);
      ret_u8_bytes[1] = (uint8_t) (((code >> 12) & 0x3f) | 0x80);
      ret_u8_bytes[2] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
      ret_u8_bytes[3] = (uint8_t) (((code      ) & 0x3f) | 0x80);
    }
  } else {
    WZ_ERR;
    return 1;
  }
  * ret_u16_size = u16_size;
  * ret_u8_size = u8_size;
  return 0;
}

int // malloc new string only if capa == 0 && u8_len > u16_len
wz_utf16le_to_utf8(uint8_t ** ret_u8_bytes, uint32_t * ret_u8_len,
                   uint8_t * u16_bytes, uint32_t u16_len, uint32_t u16_capa) {
  uint8_t * u16_ptr = u16_bytes;
  uint32_t u16_last = u16_len;
  uint32_t u8_len = 0;
  while (u16_last) {
    uint8_t u16_size;
    uint8_t u8_size;
    if (wz_utf16le_to_utf8_1(NULL, &u8_size, &u16_size, u16_ptr, u16_last)) {
      WZ_ERR;
      return 1;
    }
    u16_ptr += u16_size;
    u16_last -= u16_size;
    u8_len += u8_size;
  }
  if (u16_capa && (u8_len >= u16_capa)) { WZ_ERR; return 1; }
  uint8_t u8_buf[256];
  uint8_t * u8_bytes;
  if (u8_len < sizeof(u8_buf) && (u16_capa || u8_len <= u16_len)) {
    u8_bytes = u8_buf;
  } else {
    if ((u8_bytes = malloc(u8_len + 1)) == NULL) { WZ_ERR; return 1; }
  }
  u16_ptr = u16_bytes;
  u16_last = u16_len;
  uint8_t * u8_ptr = u8_bytes;
  while (u16_last) {
    uint8_t u16_size;
    uint8_t u8_size;
    if (wz_utf16le_to_utf8_1(u8_ptr, &u8_size, &u16_size, u16_ptr, u16_last)) {
      WZ_ERR;
      if (u8_bytes != u8_buf)
        free(u8_bytes);
      return 1;
    }
    u16_ptr += u16_size;
    u16_last -= u16_size;
    u8_ptr += u8_size;
  }
  u8_bytes[u8_len] = '\0';
  if (u16_capa || u8_len <= u16_len) {
    for (uint32_t i = 0; i < u8_len; i++)
      u16_bytes[i] = u8_bytes[i];
    u16_bytes[u8_len] = '\0';
    if (u8_bytes != u8_buf)
      free(u8_bytes);
  } else {
    * ret_u8_bytes = u8_bytes;
  }
  * ret_u8_len = u8_len;
  return 0;
}

int
wz_decode_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                uint8_t * bytes, uint32_t len, uint32_t capa,
                wzkey * key, wzenc enc) {
  if (key == NULL) return 0;
  if (enc == WZ_ENC_ASCII) {
    uint8_t * kbytes = key->bytes;
    uint8_t  mask = 0xaa;
    uint32_t klen = WZ_KEY_JSON_LEN;
    uint32_t min_len = len < WZ_KEY_JSON_LEN ? len : WZ_KEY_JSON_LEN;
    for (uint32_t i = 0; i < min_len; i++)
      bytes[i] ^= (uint8_t) (mask++ ^ kbytes[i]);
    for (uint32_t i = klen; i < len; i++)
      bytes[i] ^= (uint8_t) (mask++);
    return 0;
  } else if (enc == WZ_ENC_UTF16LE) {
    uint16_t * blocks = (uint16_t *) bytes;
    uint16_t * kblocks = (uint16_t *) key->bytes;
    uint16_t mask = 0xaaaa;
    uint32_t blen = len >> 1;
    uint32_t klen = WZ_KEY_JSON_LEN >> 1;
    uint32_t min_len = blen < WZ_KEY_JSON_LEN ? blen : WZ_KEY_JSON_LEN;
    for (uint32_t i = 0; i < min_len; i++)
      blocks[i] = WZ_HTOLE16(blocks[i] ^ mask++ ^ WZ_LE16TOH(kblocks[i]));
    for (uint32_t i = klen; i < len; i++)
      blocks[i] = WZ_HTOLE16(blocks[i] ^ mask++);
    return wz_utf16le_to_utf8(ret_bytes, ret_len, bytes, len, capa);
  } else {
    assert(enc == WZ_ENC_UTF8);
    uint8_t * kbytes = key->bytes;
    uint32_t klen = key->len;
    if (len > klen) { WZ_ERR; return 1; }
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= kbytes[i];
    return 0;
  }
}

int // read characters (ascii, utf16le, or utf8)
wz_read_chars(uint8_t ** ret_bytes, uint32_t * ret_len, uint32_t capa,
              wzkey * key, wzenc enc, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) { WZ_ERR; return 1; }
  int32_t size = byte;
  uint8_t ascii = size < 0;
  if (ascii) { // ASCII
    if (size == INT8_MIN) {
      if (wz_read_le32((uint32_t *) &size, file)) { WZ_ERR; return 1; }
    } else {
      size *= -1;
    }
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_ASCII;
  } else { // UTF16-LE
    if (size == INT8_MAX) {
      if (wz_read_le32((uint32_t *) &size, file)) { WZ_ERR; return 1; }
    }
    size *= 2;
    if (enc == WZ_ENC_AUTO)
      enc = WZ_ENC_UTF16LE;
  }
  uint32_t len = (uint32_t) size;
  uint8_t * bytes;
  if (capa) {
    bytes = * ret_bytes;
    if (wz_read_str_embed(bytes, capa, len, file)) { WZ_ERR; return 1; }
  } else {
    if (wz_read_str(&bytes, len, file)) { WZ_ERR; return 1; }
  }
  uint8_t * utf8_bytes = NULL;
  uint32_t utf8_len = 0;
  if (wz_decode_chars(&utf8_bytes, &utf8_len, bytes, len, capa, key, enc)) {
    WZ_ERR;
    if (!capa) wz_free_str(bytes);
    return 1;
  }
  if (utf8_bytes == NULL) {
    if (!capa)
      * ret_bytes = bytes;
    * ret_len = utf8_len ? utf8_len : len;
  } else {
    wz_free_str(bytes);
    * ret_bytes = utf8_bytes;
    * ret_len = utf8_len;
  }
  return 0;
}

int
wz_read_chars_else(uint8_t ** bytes, uint32_t * len, uint32_t capa,
                   uint32_t addr, wzkey * key, wzenc enc, wzfile * file) {
  uint32_t offset;
  if (wz_read_le32(&offset, file)) return 1;
  uint32_t pos = file->pos;
  if (wz_seek(addr + offset, SEEK_SET, file) ||
      wz_read_chars(bytes, len, capa, key, enc, file)) return 1;
  if (wz_seek(pos, SEEK_SET, file))
    return wz_free_chars(* bytes), 1;
  return 0;
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

int // This function do not decode if hash == 0
wz_read_addr(wzaddr * addr, wzfile * file) {
  uint32_t pos = file->pos;
  if (wz_read_le32(&addr->val, file)) return 1;
  addr->pos = pos;
  if (file->ver.hash == 0) return 0;
  return wz_decode_addr(&addr->val, addr->val, addr->pos,
                        file->start, file->ver.hash), 0;
}

int
wz_seek(uint32_t pos, int origin, wzfile * file) {
  if (pos > INT32_MAX) return 1;
  if (fseek(file->raw, pos, origin)) return 1;
  if (origin == SEEK_CUR) return file->pos += pos, 0;
  return file->pos = pos, 0;
}

int
wz_read_node_body(wznode * node, uint8_t type, wzfile * file) {
  if (wz_read_int32(&node->size, file) ||
      wz_read_int32(&node->check, file) ||
      wz_read_addr(&node->addr, file)) return 1;
  if (WZ_IS_NODE_DIR(type)) {
    return node->data.grp = NULL, node->type = WZ_NODE_DIR, 0;
  } else if (WZ_IS_NODE_FILE(type)) {
    wzvar * var = malloc(sizeof(* var));
    if (var == NULL) return 1;
    var->parent = NULL, var->node = node;
    var->name = (wzstr) {.len = 0, .bytes = NULL};
    var->type = WZ_VAR_UNK;
    wzobj * obj = malloc(sizeof(* obj));
    if (obj == NULL) return free(var), 1;
    obj->alloc = 0, obj->pos = node->addr.val;
    var->val.obj = obj;
    return node->data.var = var, node->key = NULL, node->type = WZ_NODE_FILE, 0;
  } else {
    return wz_error("Unsupported node type: 0x%02hhx\n", node->type), 1;
  }
}

int
wz_read_grp(wzgrp ** ret_grp, wznode * node, wzfile * file, wzctx * ctx) {
  int ret = 1;
  if (node->data.grp != NULL)
    return ret = 0, ret;
  if (wz_seek(node->addr.val, SEEK_SET, file))
    return ret;
  uint32_t len;
  if (wz_read_int32(&len, file))
    return ret;
  wzgrp * grp;
  if ((grp = malloc(sizeof(* grp) + len * sizeof(* grp->nodes))) == NULL)
    return ret;
  wznode * nodes = (wznode *) (grp + 1);
  for (uint32_t i = 0; i < len; i++) {
    int err = 1;
    wznode * child = nodes + i;
    uint8_t type;
    if (wz_read_byte(&type, file))
      goto free_child;
    if (WZ_IS_NODE_NIL(type)) {
      if (wz_seek(10, SEEK_CUR, file)) // unknown 10 bytes
        goto free_child;
      child->type = WZ_NODE_NIL;
      child->data.grp = NULL;
    } else if (WZ_IS_NODE_LINK(type)) {
      int name_err = 1;
      uint32_t addr;
      if (wz_read_le32(&addr, file))
        goto free_child;
      uint32_t pos = file->pos;
      if (wz_seek(file->start + addr, SEEK_SET, file) ||
          wz_read_byte(&type, file) || // type and name are in the other place
          wz_read_chars(&child->name.bytes, &child->name.len, 0,
                        file->key, WZ_ENC_AUTO, file))
        goto free_child;
      if (wz_deduce_key(&file->key, &child->name, ctx->keys, ctx->klen) ||
          wz_seek(pos, SEEK_SET, file) ||
          wz_read_node_body(child, type, file))
        goto free_child_link_name;
      name_err = 0;
free_child_link_name:
      if (name_err) {
        wz_free_chars(child->name.bytes);
        goto free_child;
      }
    } else if (WZ_IS_NODE_DIR(type) ||
               WZ_IS_NODE_FILE(type)) {
      int name_err = 1;
      if (wz_read_chars(&child->name.bytes, &child->name.len, 0,
                        file->key, WZ_ENC_AUTO, file))
        goto free_child;
      if (wz_deduce_key(&file->key, &child->name, ctx->keys, ctx->klen) ||
          wz_read_node_body(child, type, file))
        goto free_child_dir_name;
      name_err = 0;
free_child_dir_name:
      if (name_err) {
        wz_free_chars(child->name.bytes);
        goto free_child;
      }
    } else {
      wz_error("Unsupported node type: 0x%02hhx\n", child->type);
      goto free_child;
    }
    child->parent = node;
    child->file = file;
    err = 0;
free_child:
    if (err) {
      for (uint32_t j = 0; j < i; j++) {
        wznode * child_f = nodes + j;
        if (child_f->type == WZ_NODE_DIR ||
            child_f->type == WZ_NODE_FILE)
          wz_free_chars(child_f->name.bytes);
        if (child_f->type == WZ_NODE_FILE) {
          if (child_f->data.var->type == WZ_VAR_STR)
            wz_free_chars(child_f->data.var->val.str.bytes);
          else // WZ_VAR_OBJ
            free(child_f->data.var->val.obj);
          free(child_f->data.var);
        }
      }
      goto free_grp;
    }
  }
  grp->nodes = nodes;
  grp->len = len;
  * ret_grp = grp;
  ret = 0;
free_grp:
  if (ret)
    free(grp);
  return ret;
}

void
wz_free_grp(wzgrp ** ret_grp) {
  wzgrp * grp = * ret_grp;
  for (uint32_t i = 0; i < grp->len; i++) {
    wznode * child = grp->nodes + i;
    if (child->type == WZ_NODE_DIR ||
        child->type == WZ_NODE_FILE)
      wz_free_chars(child->name.bytes);
    if (child->type == WZ_NODE_FILE) {
      if (child->data.var->type == WZ_VAR_STR)
        wz_free_chars(child->data.var->val.str.bytes);
      else // WZ_VAR_OBJ
        free(child->data.var->val.obj);
      free(child->data.var);
    }
  }
  * ret_grp = NULL;
  free(grp);
}

void
wz_encode_ver(uint16_t * ret_enc, uint32_t * ret_hash, uint16_t dec) {
  uint8_t chars[5 + 1]; // 0xffff.to_s.size == 5
  int len = sprintf((char *) chars, "%"PRIu16, dec);
  assert(len >= 0);
  uint32_t hash = 0;
  for (int i = 0; i < len; i++)
    hash = (hash << 5) + chars[i] + 1;
  uint16_t enc = 0xff;
  for (size_t i = 0; i < sizeof(hash); i++)
    enc = (enc ^ ((uint8_t *) &hash)[i]) & 0xff;
  * ret_enc = enc, * ret_hash = hash;
}

int
wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash, uint16_t enc,
              uint32_t addr, uint32_t start, uint32_t size, FILE * raw,
              wzctx * ctx) {
  int ret = 1;
  wzfile file;
  file.raw = raw;
  file.size = size; // used in read_grp/int32/byte/bytes
  file.start = start; // used in read_grp/node
  file.root.addr.val = addr; // used in read_grp
  file.root.data.grp = NULL; // used in read_grp
  file.ver.hash = 0; // do not decode addr in read_grp/node/node_body/addr
  file.key = NULL;   // do not decode chars in read_grp/node/chars/decode_chars
                     // but deduce file->key in read_grp/node/deduce_key
  if (wz_read_grp(&file.root.data.grp, &file.root, &file, ctx))
    return ret;
  for (uint16_t g_dec = 0; g_dec < 512; g_dec++) { // guess dec
    uint32_t g_hash;
    uint16_t g_enc;
    wz_encode_ver(&g_enc, &g_hash, g_dec);
    if (g_enc != enc)
      continue;
    int err = 0;
    wzgrp * grp = file.root.data.grp;
    for (uint32_t i = 0; i < grp->len; i++) {
      wznode * node = grp->nodes + i;
      if (node->type == WZ_NODE_DIR ||
          node->type == WZ_NODE_FILE) {
        uint32_t val;
        wz_decode_addr(&val, node->addr.val, node->addr.pos, start, g_hash);
        if (val > size) {
          err = 1;
          break;
        }
      }
    }
    if (!err) {
      * ret_dec = g_dec;
      * ret_hash = g_hash;
      ret = 0;
      break;
    }
  }
  wz_free_grp(&file.root.data.grp);
  return ret;
}

void
wz_encode_aes(uint8_t * cipher, const uint8_t * plain, uint32_t len,
              uint8_t * key, const uint8_t * iv) {
  aes256_context ctx;
  aes256_init(&ctx, key);
  for (uint32_t i = 0; i < len; i += 16) {
    for (uint8_t j = 0; j < 16; j++)
      cipher[j] = plain[j] ^ iv[j];
    aes256_encrypt_ecb(&ctx, cipher);
    plain += 16, iv = cipher, cipher += 16;
  }
  aes256_done(&ctx);
}

int
wz_init_keys(wzkey ** ret_wkeys, size_t * ret_wklen) {
  int ret = 1;
  uint8_t ivs[][4] = { // These values is used for generating iv (aes)
    {0x4d, 0x23, 0xc7, 0x2b},
    {0xb9, 0x7d, 0x63, 0xe9} // used to decode UTF8 (lua script)
  };
  size_t wklen = sizeof(ivs) / sizeof(* ivs) + 1;
  wzkey * wkeys;
  if ((wkeys = malloc(sizeof(* wkeys) * wklen)) == NULL)
    return ret;
  uint32_t len = WZ_KEY_MAX_LEN; // supported image chunk or string size
  uint8_t * plain;
  if ((plain = malloc(len * 2)) == NULL)
    goto free_wkeys;
  memset(plain, 0, len);
  uint8_t * cipher = plain + len;
  uint8_t key[32] =
    "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
    "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00";
  for (size_t i = 0; i < wklen; i++) {
    int err = 1;
    uint8_t * bytes;
    if ((bytes = malloc(len)) == NULL)
      goto free_wkey;
    if (i + 1 < wklen) {
      uint8_t * iv4 = ivs[i];
      uint8_t iv[16];
      for (size_t j = 0; j < 16; j += 4)
        memcpy(iv + j, iv4, 4);
      wz_encode_aes(cipher, plain, len, key, iv);
      memcpy(bytes, cipher, len);
    } else {
      memset(bytes, 0, len); // an empty cipher
    }
    wzkey * wkey = wkeys + i;
    wkey->bytes = bytes;
    wkey->len = len;
    err = 0;
free_wkey:
    if (err) {
      for (size_t k = 0; k < i; k++)
        free(wkeys[i].bytes);
      goto free_plain;
    }
  }
  * ret_wkeys = wkeys;
  * ret_wklen = wklen;
  ret = 0;
free_plain:
  free(plain);
free_wkeys:
  if (ret)
    free(wkeys);
  return ret;
}

void
wz_free_keys(wzkey * keys, size_t len) {
  for (size_t i = 0; i < len; i++)
    free(keys[i].bytes);
  free(keys);
}

int // if string key is found, the string is also decoded.
wz_deduce_key(wzkey ** ret_key, wzstr * name, wzkey * keys, size_t klen) {
  if (* ret_key != NULL) return 0;
  uint8_t * bytes = name->bytes;
  uint32_t len = name->len;
  for (size_t i = 0; i < klen; i++) {
    wzkey * key = keys + i;
    if (wz_decode_chars(NULL, 0, bytes, len, 0, key, WZ_ENC_ASCII)) continue;
    for (uint32_t j = 0; j < len && isprint(bytes[j]); j++)
      if (j == len - 1) return * ret_key = key, 0;
    if (wz_decode_chars(NULL, 0, bytes, len, 0, key, WZ_ENC_ASCII)) continue;
  }
  return wz_error("Cannot deduce the string key\n"), 1;
}

int // variable related, used in var's name, var's str, or uol 
wz_read_var_chars(uint8_t ** bytes, uint32_t * len, uint32_t capa,
                  wznode * node, wzfile * file) {
  uint8_t fmt;
  if (wz_read_byte(&fmt, file)) return 1;
  switch (fmt) {
  case 0x00: return wz_read_chars(bytes, len, capa, node->key, WZ_ENC_AUTO, file);
  case 0x01: return wz_read_chars_else(bytes, len, capa, node->addr.val, node->key,
                                       WZ_ENC_AUTO, file);
  default:   return wz_error("Unsupported string type: 0x%02hhx\n", fmt), 1;
  }
}

void *
wz_invert(void * base, size_t offset) { // base must not be NULL
  uint8_t * root;
  uint8_t * c = (uint8_t *) base;
  uint8_t * v = * (uint8_t **) (c + offset); // get parent
  uint8_t * p;
  for (;;) {
    if (v == NULL) {
      root = c;
      break;
    }
    p = * (uint8_t **) (v + offset);
    * (uint8_t **) (v + offset) = c; // set parent
    if (p == NULL) {
      root = v;
      break;
    }
    c = v;
    v = p;
  }
  * (uint8_t **) ((uint8_t *) base + offset) = NULL;
  return root;
}

wzvar *
wz_invert_var(wzvar * base) {
  return wz_invert(base, offsetof(wzvar, parent));
}

wznode *
wz_invert_node(wznode * base) {
  return wz_invert(base, offsetof(wznode, parent));
}

int
wz_strcmp(wzstr * a, const char * b) {
  return strncmp((char *) a->bytes, b, a->len);
}

int
wz_strncmp(wzstr * a, const char * b, size_t blen) {
  return a->len != blen || strncmp((char *) a->bytes, b, blen);
}

int
wz_read_list(wzlist * list, wzvar * var,
             wznode * node, wzfile * file) {
  int ret = 1;
  if (wz_seek(2, SEEK_CUR, file))
    return ret;
  uint32_t len;
  if (wz_read_int32(&len, file))
    return ret;
  if (len) {
    int err = 1;
    wzvar * vars;
    if ((vars = malloc(sizeof(* vars) * len)) == NULL)
      return ret;
    for (uint32_t i = 0; i < len; i++) {
      int var_err = 1;
      wzvar * child = vars + i;
      wzstr name;
      if (wz_read_var_chars(&name.bytes, &name.len, 0, node, file))
        goto free_child;
      uint8_t type;
      if (wz_read_byte(&type, file))
        goto free_name;
      if (WZ_IS_VAR_NIL(type)) {
        child->type = WZ_VAR_NIL;
      } else if (WZ_IS_VAR_INT16(type)) {
        int16_t int16;
        if (wz_read_le16((uint16_t *) &int16, file))
          goto free_name;
        child->type = WZ_VAR_INT16;
        child->val.i = int16;
      } else if (WZ_IS_VAR_INT32(type)) {
        int32_t int32;
        if (wz_read_int32((uint32_t *) &int32, file))
          goto free_name;
        child->type = WZ_VAR_INT32;
        child->val.i = int32;
      } else if (WZ_IS_VAR_INT64(type)) {
        int64_t int64;
        if (wz_read_int64((uint64_t *) &int64, file))
          goto free_name;
        child->type = WZ_VAR_INT64;
        child->val.i = int64;
      } else if (WZ_IS_VAR_FLT32(type)) {
        int8_t float8;
        if (wz_read_byte((uint8_t *) &float8, file))
          goto free_name;
        if (float8 == INT8_MIN) {
          union { uint32_t i; float f; } float32;
          if (wz_read_le32(&float32.i, file))
            goto free_name;
          child->val.f = float32.f;
        } else {
          child->val.f = float8;
        }
        child->type = WZ_VAR_FLT32;
      } else if (WZ_IS_VAR_FLT64(type)) {
        union { uint64_t i; double f; } float64;
        if (wz_read_le64(&float64.i, file))
          goto free_name;
        child->type = WZ_VAR_FLT64;
        child->val.f = float64.f;
      } else if (WZ_IS_VAR_STR(type)) {
        wzstr str;
        if (wz_read_var_chars(&str.bytes, &str.len, 0, node, file))
          goto free_name;
        child->type = WZ_VAR_STR;
        child->val.str = str;
      } else if (WZ_IS_VAR_OBJ(type)) {
        int obj_err = 1;
        uint32_t size;
        if (wz_read_le32(&size, file))
          goto free_name;
        wzobj * obj;
        if ((obj = malloc(sizeof(* obj))) == NULL)
          goto free_name;
        obj->alloc = 0;
        obj->pos = file->pos;
        if (wz_seek(size, SEEK_CUR, file))
          goto free_obj;
        child->type = WZ_VAR_OBJ;
        child->val.obj = obj;
        obj_err = 0;
free_obj:
        if (obj_err) {
          free(obj);
          goto free_name;
        }
      } else {
        wz_error("Unsupported primitive type: 0x%02hhx\n", type);
        goto free_name;
      }
      child->parent = var;
      child->node = node;
      child->name = name;
      var_err = 0;
free_name:
      if (var_err)
        wz_free_chars(name.bytes);
free_child:
      if (var_err) {
        for (uint32_t j = 0; j < i; j++) {
          wzvar * child_f = vars + j;
          if (child_f->type == WZ_VAR_STR)
            wz_free_chars(child_f->val.str.bytes);
          else if (child_f->type == WZ_VAR_OBJ)
            free(child_f->val.obj);
          wz_free_chars(child_f->name.bytes);
        }
        goto free_vars;
      }
    }
    list->vars = vars;
    err = 0;
free_vars:
    if (err) {
      free(vars);
      goto exit;
    }
  } else {
    list->vars = NULL;
  }
  list->len = len;
  ret = 0;
exit:
  return ret;
}

void
wz_free_list(wzlist * list) {
  for (uint32_t i = 0; i < list->len; i++) {
    wzvar * var = list->vars + i;
    if (var->type == WZ_VAR_STR)
      wz_free_chars(var->val.str.bytes);
    else if (var->type == WZ_VAR_OBJ)
      free(var->val.obj);
    wz_free_chars(var->name.bytes);
  }
  free(list->vars);
}

int
wz_decode_bitmap(uint32_t * written,
                 uint8_t * out, uint8_t * in, uint32_t size, wzkey * key) {
  uint8_t * kbytes = key->bytes;
  uint32_t klen = key->len;
  uint32_t read = 0;
  uint32_t wrote = 0;
  while (read < size) {
    uint32_t len = WZ_LE32TOH(* (uint32_t *) (in + read));
    read += (uint32_t) sizeof(len);
    if (len > klen)
      return wz_error("Image chunk size %"PRIu32" > %"PRIu32"\n", len, klen), 1;
    for (uint32_t i = 0; i < len; i++)
      out[wrote++] = in[read++] ^ kbytes[i];
  }
  return * written = wrote, 0;
}

int
wz_inflate_bitmap(uint32_t * written,
                  uint8_t * out, uint32_t out_len,
                  uint8_t * in, uint32_t in_len) {
  z_stream strm = {.zalloc = Z_NULL, .zfree = Z_NULL, .opaque = Z_NULL};
  strm.next_in = in;
  strm.avail_in = in_len;
  if (inflateInit(&strm) != Z_OK) return 1;
  strm.next_out = out;
  strm.avail_out = out_len;
  if (inflate(&strm, Z_NO_FLUSH) != Z_OK)
    return inflateEnd(&strm), 1;
  * written = (uint32_t) strm.total_out;
  return inflateEnd(&strm), 0;
}

int
wz_init_plt(wzplt ** plt) {
  wzplt * p;
  if ((p = malloc(sizeof(* p))) == NULL)
    return 1;
  uint8_t * u4               = p->u4;
  uint8_t * u5               = p->u5;
  uint8_t * u6               = p->u6;
  wzcolor * u4444            = p->u4444;
  wzcolor * u565             = p->u565;
  wzcolor (* c)[256][256]    = p->c;
  uint8_t (* a)[256][256][6] = p->a;
  for (uint8_t i = 0; i < 0x10; i++) u4[i] = (uint8_t) ((i << 4) | (i     ));
  for (uint8_t i = 0; i < 0x20; i++) u5[i] = (uint8_t) ((i << 3) | (i >> 2));
  for (uint8_t i = 0; i < 0x40; i++) u6[i] = (uint8_t) ((i << 2) | (i >> 4));
  for (uint32_t i = 0; i < 0x10000; i++) {
    u4444[i].b = u4[(i      ) & 0x0f];
    u4444[i].g = u4[(i >>  4) & 0x0f];
    u4444[i].r = u4[(i >>  8) & 0x0f];
    u4444[i].a = u4[(i >> 12) & 0x0f];
    u565[i].b = u5[(i      ) & 0x1f];
    u565[i].g = u6[(i >>  5) & 0x3f];
    u565[i].r = u5[(i >> 11) & 0x1f];
    u565[i].a = 0xff;
  }
  for (uint32_t i = 0; i < 256; i++)
    for (uint32_t j = 0; j < 256; j++) {
      c[0][i][j].b = (uint8_t) (((i << 1) + j) / 3); // code 2
      c[0][i][j].g = (uint8_t) (((i << 1) + j) / 3);
      c[0][i][j].r = (uint8_t) (((i << 1) + j) / 3);
      c[0][i][j].a = 0;
      c[1][i][j].b = (uint8_t) ((i + (j << 1)) / 3); // code 3
      c[1][i][j].g = (uint8_t) ((i + (j << 1)) / 3);
      c[1][i][j].r = (uint8_t) ((i + (j << 1)) / 3);
      c[1][i][j].a = 0;
      a[0][i][j][0] = (uint8_t) ((i * 6 + j    ) / 7); // alpha 2 if a0 > a1
      a[0][i][j][1] = (uint8_t) ((i * 5 + j * 2) / 7); // alpha 3 if a0 > a1
      a[0][i][j][2] = (uint8_t) ((i * 4 + j * 3) / 7); // alpha 4 if a0 > a1
      a[0][i][j][3] = (uint8_t) ((i * 3 + j * 4) / 7); // alpha 5 if a0 > a1
      a[0][i][j][4] = (uint8_t) ((i * 2 + j * 5) / 7); // alpha 6 if a0 > a1
      a[0][i][j][5] = (uint8_t) ((i     + j * 6) / 7); // alpha 7 if a0 > a1
      a[1][i][j][0] = (uint8_t) ((i * 4 + j    ) / 5); // alpha 2 if a0 <= a1
      a[1][i][j][1] = (uint8_t) ((i * 3 + j * 2) / 5); // alpha 3 if a0 <= a1
      a[1][i][j][2] = (uint8_t) ((i * 2 + j * 3) / 5); // alpha 4 if a0 <= a1
      a[1][i][j][3] = (uint8_t) ((i     + j * 4) / 5); // alpha 5 if a0 <= a1
      a[1][i][j][4] = 0;                               // alpha 6 if a0 <= a1
      a[1][i][j][5] = 0xff;                            // alpha 7 if a0 <= a1
    }
  * plt = p;
  return 0;
}

void
wz_swap_ptr(uint8_t ** a, uint8_t ** b) {
  uint8_t * tmp = * a;
  * a = * b;
  * b = tmp;
}

void
wz_unpack_4444(wzcolor * out, uint8_t * in, uint32_t pixels,
               wzcolor * unpack4444) {
  for (uint32_t i = 0; i < pixels; i++, in += 2, out++)
    * out = unpack4444[WZ_LE16TOH(* (uint16_t *) in)];
}

void
wz_unpack_565(wzcolor * out, uint8_t * in, uint32_t pixels,
              wzcolor * unpack565) {
  for (uint32_t i = 0; i < pixels; i++, in += 2, out++)
    * out = unpack565[WZ_LE16TOH(* (uint16_t *) in)];
}

void
wz_unpack_dxt(wzcolor * out, uint8_t * in, uint32_t w, uint32_t h, wzplt * p,
              char dxt3) {
  uint8_t * u4                = p->u4;
  wzcolor * u565              = p->u565;
  wzcolor (* c2)[256]         = p->c[0];
  wzcolor (* c3)[256]         = p->c[1];
  uint8_t (* pa)[256][256][6] = p->a;
  for (uint32_t y = 0; y < h; y += 4, out += w << 2) // goto the next row
    for (uint32_t x = 0; x < w; x += 4, in += 16) { // goto the next block
      wzcolor pixels[16]; // inflate 4x4 block
      wzcolor c[4]; // 4 codes
      wzcolor c0 = c[0] = u565[WZ_LE16TOH(* (uint16_t *) (in + 8))]; // code 0
      wzcolor c1 = c[1] = u565[WZ_LE16TOH(* (uint16_t *) (in + 10))]; // code 1
      c[2].b = c2[c0.b][c1.b].b; // code 2
      c[2].g = c2[c0.g][c1.g].g;
      c[2].r = c2[c0.r][c1.r].r;
      c[2].a = c2[c0.a][c1.a].a;
      c[3].b = c3[c0.b][c1.b].b; // code 3
      c[3].g = c3[c0.g][c1.g].g;
      c[3].r = c3[c0.r][c1.r].r;
      c[3].a = c3[c0.a][c1.a].a;
      uint32_t color = WZ_LE32TOH(* (uint32_t *) (in + 12)); // get indices
      for (uint8_t i = 0; i < 16; i++) // choose code by using indice
        pixels[i] = c[color & 0x03], color >>= 2;
      uint64_t alpha = WZ_LE64TOH(* (uint64_t *) in); // get alpha values
      if (dxt3) {
        for (uint8_t i = 0; i < 16; i++)
          pixels[i].a = u4[alpha & 0x0f], alpha >>= 4; // unpack alpha value
      } else { // dxt5
        uint8_t a[8];
        uint8_t a0 = a[0] = in[0]; // alpha 0
        uint8_t a1 = a[1] = in[1]; // alpha 1
        uint8_t * a2_7 = pa[a0 <= a1][a0][a1];
        a[2] = a2_7[0]; // alpha 2
        a[3] = a2_7[1]; // alpha 3
        a[4] = a2_7[2]; // alpha 4
        a[5] = a2_7[3]; // alpha 5
        a[6] = a2_7[4]; // alpha 6
        a[7] = a2_7[5]; // alpha 7
        alpha >>= 16;
        for (uint8_t i = 0; i < 16; i++)
          pixels[i].a = a[alpha & 0x07], alpha >>= 3; // unpack alpha value
      }
      wzcolor * bin = pixels;
      wzcolor * bout = out + x;
      uint32_t ph = h - y < 4 ? h - y : 4; // check the pixel is out of image
      uint32_t pw = w - x < 4 ? w - x : 4;
      for (uint32_t py = 0; py < ph; py++, bout += w, bin += 4)
        for (uint32_t px = 0; px < pw; px++)
          bout[px] = bin[px]; // write to correct location
    }
}

int
wz_read_bitmap(wzcolor ** data, uint32_t w, uint32_t h,
               uint16_t depth, uint16_t scale, uint32_t size,
               wzkey * key, wzplt * p) {
  int ret = 1;
  uint32_t pixels = w * h;
  uint32_t full_size = pixels * (uint32_t) sizeof(wzcolor);
  uint32_t max_size = size > full_size ? size : full_size; // inflated > origin
  uint8_t * in = (uint8_t *) * data;
  uint8_t * out;
  if ((out = malloc(max_size)) == NULL)
    return ret;
  if (wz_inflate_bitmap(&size, out, full_size, in, size)) {
    if (wz_decode_bitmap(&size, out, in, size, key) ||
        wz_inflate_bitmap(&size, in, full_size, out, size))
      goto free_out;
    wz_swap_ptr(&in, &out);
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
  if (size != pixels * depth_size / (scale_size * scale_size))
    goto free_out;
  uint32_t pw = w / scale_size, ph = h / scale_size;
  wzcolor * pin = (wzcolor *) in; // cast to pixel based type
  switch (depth) {
  case WZ_COLOR_8888: wz_swap_ptr(&in, &out);                      break;
  case WZ_COLOR_4444: wz_unpack_4444(pin, out, pw * ph, p->u4444); break;
  case WZ_COLOR_565:  wz_unpack_565(pin, out, pw * ph, p->u565);   break;
  case WZ_COLOR_DXT3: wz_unpack_dxt(pin, out, pw, ph, p, 1);       break;
  case WZ_COLOR_DXT5: wz_unpack_dxt(pin, out, pw, ph, p, 0);       break;
  default: {
    wz_error("Unsupported color depth %hhd\n", depth);
    goto free_out;
  }}
  if (scale_size == 1) {
    wz_swap_ptr(&in, &out);
  } else if (pw) {
    pin = (wzcolor *) in; // cast to pixel based type
    wzcolor * pout = (wzcolor *) out;
    uint32_t col = scale_size * (w - 1); // goto next col (block based)
    uint32_t row = scale_size * (pw - 1); // goto next row (block based)
    for (uint32_t y = 0; y < ph; y++)
      for (uint32_t x = 0;;) {
        wzcolor pixel = * pin++;
        for (uint32_t py = 0; py < scale_size; py++, pout += w)
          for (uint32_t px = 0; px < scale_size; px++)
            pout[px] = pixel;
        if (++x < pw) {
          pout -= col;
        } else {
          pout -= row;
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

void
wz_init_guid(wzguid * guid) {
  memcpy(guid->wav,
         "\x81\x9f\x58\x05""\x56\xc3""\xce\x11""\xbf\x01"
         "\x00\xaa\x00\x55\x59\x5a", sizeof(guid->wav));
  memset(guid->empty, 0, sizeof(guid->wav));
}

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
wz_decode_wav(uint8_t * wav, uint8_t size, wzkey * key) {
  uint8_t * bytes = key->bytes;
  for (uint8_t i = 0; i < size; i++)
    wav[i] ^= bytes[i];
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
  out->data            = pcm;
}

int
wz_read_obj(wzobj ** ret_obj, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx, uint8_t eager) {
  int ret = 1;
  if (var->type == WZ_VAR_STR ||
      var->val.obj->alloc)
    return ret = 0, ret;
  wzobj * obj = var->val.obj;
  if (wz_seek(obj->pos, SEEK_SET, file))
    return ret;
  uint8_t fmt; // format
  if (wz_read_byte(&fmt, file))
    return ret;
  wzstr type;
  switch (fmt) {
  case 0x01: {
    wzstr str;
    if (wz_read_chars(&str.bytes, &str.len, 0,
                      ctx->keys + 1, WZ_ENC_UTF8, file))
      return ret;
    var->type = WZ_VAR_STR;
    var->val.str = str;
    free(obj);
    return ret = 0, ret;
  }
  case 0x1b:
    if (wz_read_chars_else(&type.bytes, &type.len, 0,
                           node->addr.val, node->key, WZ_ENC_AUTO, file))
      return ret;
    break;
  case 0x73:
    if (wz_read_chars(&type.bytes, &type.len, 0, node->key, WZ_ENC_AUTO, file))
      return ret;
    break;
  default:
    return wz_error("Unsupported string type: 0x%02hhx\n", fmt), 1;
  }
  if (wz_deduce_key(&node->key, &type, ctx->keys, ctx->klen))
    goto free_type;
  wzobj * o;
  if (WZ_IS_OBJ_PROPERTY(&type)) {
    int err = 1;
    wzlist * list;
    if ((list = malloc(sizeof(* list))) == NULL)
      goto free_type;
    if (wz_read_list(list, var, node, file))
      goto free_list;
    o = (wzobj *) list;
    o->type = WZ_OBJ_LIST;
    err = 0;
free_list:
    if (err) {
      free(list);
      goto free_type;
    }
  } else if (WZ_IS_OBJ_CANVAS(&type)) {
    int err = 1;
    wzimg * img;
    if ((img = malloc(sizeof(* img))) == NULL)
      goto free_type;
    if (wz_seek(1, SEEK_CUR, file))
      goto free_img;
    uint8_t list;
    if (wz_read_byte(&list, file))
      goto free_img;
    img->len = 0;
    img->vars = NULL;
    if (list == 1 && wz_read_list((wzlist *) img, var, node, file))
      goto free_img;
    uint32_t w;
    uint32_t h;
    uint32_t depth;
    uint8_t  scale;
    uint32_t size;
    uint32_t blank1;
    uint8_t  blank2;
    if (wz_read_int32(&w, file)   ||
        wz_read_int32(&h, file)   ||
        wz_read_int32(&depth, file)  || depth > UINT16_MAX ||
        wz_read_byte(&scale, file)   ||
        wz_read_le32(&blank1, file)  || blank1 ||
        wz_read_le32(&size, file)    ||
        wz_read_byte(&blank2, file)  || blank2)
      goto free_img_list;
    if (size <= 1)
      goto free_img_list;
    size--; // remove null terminator
    uint32_t pixels = w * h;
    uint32_t full_size = pixels * (uint32_t) sizeof(wzcolor);
    uint32_t max_size = size > full_size ? size : full_size; // inflated > origin
    wzcolor * data;
    if ((data = malloc(max_size)) == NULL)
      goto free_img_list;
    if (wz_read_bytes((uint8_t *) data, size, file))
      goto free_img_data;
    if (eager && wz_read_bitmap(&data, w, h, (uint16_t) depth, scale, size,
                                node->key, ctx->plt))
      goto free_img_data;
    img->w = w;
    img->h = h;
    img->depth = (uint16_t) depth;
    img->scale = scale;
    img->size = size;
    img->data = data;
    o = (wzobj *) img;
    o->type = WZ_OBJ_IMG;
    err = 0;
free_img_data:
    if (err)
      free(data);
free_img_list:
    if (err)
      wz_free_list((wzlist *) img);
free_img:
    if (err) {
      free(img);
      goto free_type;
    }
  } else if (WZ_IS_OBJ_CONVEX(&type)) {
    int err = 1;
    wzvex * vex;
    if ((vex = malloc(sizeof(* vex))) == NULL)
      goto free_type;
    uint32_t len;
    if (wz_read_int32(&len, file))
      goto free_vex;
    wz2d * vals;
    if ((vals = malloc(sizeof(* vals) * len)) == NULL)
      goto free_vex;
    wzkey * key = node->key;
    uint32_t addr = node->addr.val;
    for (uint32_t i = 0; i < len; i++) {
      int val_err = 1;
      wz2d * val = vals + i;
      uint8_t vfmt; // vex's val format
      if (wz_read_byte(&vfmt, file))
        goto free_vals;
      wzstr vtype; // vex's val type
      switch (vfmt) {
      case 0x1b:
        if (wz_read_chars_else(&vtype.bytes, &vtype.len, 0,
                               addr, key, WZ_ENC_AUTO, file))
          goto free_vals;
        break;
      case 0x73:
        if (wz_read_chars(&vtype.bytes, &vtype.len, 0, key, WZ_ENC_AUTO, file))
          goto free_vals;
        break;
      default:
        wz_error("Unsupported string type: 0x%02hhx\n", vfmt);
        goto free_vals;
      }
      if (!WZ_IS_OBJ_VECTOR(&vtype)) {
        wz_error("Convex should contain only vectors\n");
        goto free_vex_type;
      }
      if (wz_read_int32((uint32_t *) &val->x, file) ||
          wz_read_int32((uint32_t *) &val->y, file))
        goto free_vex_type;
      val_err = 0;
free_vex_type:
      wz_free_chars(vtype.bytes);
      if (val_err)
        goto free_vals;
    }
    vex->vals = vals;
    vex->len = len;
    o = (wzobj *) vex;
    o->type = WZ_OBJ_VEX;
    err = 0;
free_vals:
    if (err)
      free(vals);
free_vex:
    if (err) {
      free(vex);
      goto free_type;
    }
  } else if (WZ_IS_OBJ_VECTOR(&type)) {
    int err = 1;
    wzvec * vec;
    if ((vec = malloc(sizeof(* vec))) == NULL)
      goto free_type;
    if (wz_read_int32((uint32_t *) &vec->val.x, file) ||
        wz_read_int32((uint32_t *) &vec->val.y, file))
      goto free_vec;
    o = (wzobj *) vec;
    o->type = WZ_OBJ_VEC;
    err = 0;
free_vec:
    if (err) {
      free(vec);
      goto free_type;
    }
  } else if (WZ_IS_OBJ_SOUND(&type)) {
    int err = 1;
    wzao * ao;
    if ((ao = malloc(sizeof(* ao))) == NULL)
      goto free_type;
    uint32_t size;
    uint32_t ms;
    uint8_t  guid[16];
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_int32(&size, file) ||
        wz_read_int32(&ms, file) ||
        wz_seek(1 + 16 * 2 + 2, SEEK_CUR, file) || // major and subtype GUID
        wz_read_bytes(guid, sizeof(guid), file))
      goto free_ao;
    if (memcmp(guid, ctx->guid.wav, sizeof(guid)) == 0) {
      int hdr_err = 1;
      uint8_t hsize; // header size
      if (wz_read_byte(&hsize, file))
        goto free_ao;
      uint8_t * hdr; // header
      if ((hdr = malloc(hsize)) == NULL)
        goto free_ao;
      if (wz_read_bytes(hdr, hsize, file))
        goto free_hdr;
      wzwav wav;
      wz_read_wav(&wav, hdr);
      if (wav.extra_size != hsize - WZ_AUDIO_WAV_SIZE) {
        wz_decode_wav(hdr, hsize, node->key);
        wz_read_wav(&wav, hdr);
        if (wav.extra_size != hsize - WZ_AUDIO_WAV_SIZE)
          goto free_hdr;
      }
      hdr_err = 0;
free_hdr:
      free(hdr);
      if (hdr_err)
        goto free_ao;
      if (wav.format == WZ_AUDIO_PCM) {
        int pcm_err = 1;
        uint8_t * pcm;
        if ((pcm = malloc(WZ_AUDIO_PCM_SIZE + size)) == NULL)
          goto free_ao;
        wz_write_pcm(pcm, &wav, size);
        if (wz_read_bytes(pcm + WZ_AUDIO_PCM_SIZE, size, file))
          goto free_pcm;
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
          goto free_ao;
        if (wz_read_bytes(data, size, file))
          goto free_ao_data;
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
    } else if (memcmp(guid, ctx->guid.empty, sizeof(guid)) == 0) {
      int data_err = 1;
      uint8_t * data;
      if ((data = malloc(size)) == NULL)
        goto free_ao;
      if (wz_read_bytes(data, size, file))
        goto free_data_;
      ao->data = data;
      ao->size = size;
      ao->format = WZ_AUDIO_MP3;
      data_err = 0;
free_data_:
      if (data_err) {
        free(data);
        goto free_ao;
      }
    } else {
      wz_error("Unsupport audio GUID type: %.16s\n", guid);
      goto free_ao;
    }
    ao->ms = ms;
    o = (wzobj *) ao;
    o->type = WZ_OBJ_AO;
    err = 0;
free_ao:
    if (err) {
      free(ao);
      goto free_type;
    }
  } else if (WZ_IS_OBJ_UOL(&type)) {
    int err = 1;
    wzuol * uol;
    if ((uol = malloc(sizeof(* uol))) == NULL)
      goto free_type;
    if (wz_seek(1, SEEK_CUR, file) ||
        wz_read_var_chars(&uol->path.bytes, &uol->path.len, 0, node, file))
      goto free_uol;
    o = (wzobj *) uol;
    o->type = WZ_OBJ_UOL;
    err = 0;
free_uol:
    if (err) {
      free(uol);
      goto free_type;
    }
  } else {
    wz_error("Unsupported object type: %s\n", type.bytes);
    goto free_type;
  }
  var->type = WZ_VAR_OBJ;
  o->alloc = 1;
  o->pos = obj->pos;
  * ret_obj = o;
  free(obj);
  ret = 0;
free_type:
  wz_free_chars(type.bytes);
  return ret;
}

void
wz_free_obj(wzobj * obj) {
  if (obj->type == WZ_OBJ_LIST) {
    wz_free_list((wzlist *) obj);
  } else if (obj->type == WZ_OBJ_IMG) {
    free(((wzimg *) obj)->data);
    wz_free_list((wzlist *) obj);
  } else if (obj->type == WZ_OBJ_VEX) {
    free(((wzvex *) obj)->vals);
  } else if (obj->type == WZ_OBJ_AO) {
    free(((wzao *) obj)->data);
  } else if (obj->type == WZ_OBJ_UOL) {
    wz_free_chars(((wzuol *) obj)->path.bytes);
  }
  obj->alloc = 0;
}

struct wz_read_obj_thrd_var {
  wznode *  node;
  uint32_t  w;
  uint32_t  h;
  uint16_t  depth;
  uint16_t  scale;
  uint32_t  size;
  wzcolor * data;
};

struct wz_read_obj_thrd_arg {
  uint8_t id;
  pthread_mutex_t * mutex;
  pthread_cond_t * work_cond;
  pthread_cond_t * done_cond;
  uint8_t * exit;
  struct wz_read_obj_thrd_var * vars;
  size_t len;
  size_t * remain;
};

void *
wz_read_obj_thrd(void * arg) {
  struct wz_read_obj_thrd_arg * targ = arg;
  pthread_mutex_t * mutex = targ->mutex;
  pthread_cond_t * work_cond = targ->work_cond;
  pthread_cond_t * done_cond = targ->done_cond;
  uint8_t * exit = targ->exit;
  size_t * remain = targ->remain;
  size_t len = 0;
  int var_err = 0;
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
    struct wz_read_obj_thrd_var * vars;
    while (!(leave = * exit) && !(len = targ->len))
      if ((err = pthread_cond_wait(work_cond, mutex)) != 0)
        goto unlock_mutex;
    if (!leave && len)
      vars = targ->vars;
    int unlock_err;
unlock_mutex:
    if ((unlock_err = pthread_mutex_unlock(mutex)) != 0)
      return (void *) !NULL;
    if (err)
      return (void *) !NULL;
    if (leave)
      break;
    for (uint32_t i = 0; i < len; i++) {
      struct wz_read_obj_thrd_var * var = vars + i;
      wznode * node = var->node;
      wzfile * file = node->file;
      wzctx * ctx = file->ctx;
      if (wz_read_bitmap(&var->data, var->w, var->h,
                         var->depth, var->scale, var->size,
                         node->key, ctx->plt))
        var_err = 1;
    }
  }
  if (var_err)
    return (void *) !NULL;
  return NULL;
}

int // Non recursive DFS
wz_read_obj_thrd_r(wzvar * root, wznode * node, wzfile * file, wzctx * ctx,
                   uint8_t tlen, struct wz_read_obj_thrd_arg * targs,
                   pthread_mutex_t * mutex,
                   pthread_cond_t * work_cond,
                   pthread_cond_t * done_cond, size_t * remain) {
  int ret = 1;
  int var_err = 0;
  size_t stack_capa = 1;
  wzvar ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    return ret;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  char * blank = NULL;
  size_t blank_capa = 0;
  size_t blank_len = 0;
  struct wz_read_obj_thrd_var * queue = NULL;
  size_t queue_capa = 0;
  size_t queue_len = 0;
  while (stack_len) {
    wzvar * var = stack[--stack_len];
    if (var == NULL) {
      wz_free_obj(stack[--stack_len]->val.obj);
      continue;
    }
    size_t blank_req = 0;
    for (wzvar * v = var; (v = v->parent) != NULL;)
      blank_req++;
    if (blank_req + 1 > blank_capa) { // null byte
      size_t l = blank_capa;
      do { l = l < 9 ? 9 : l + l / 2; } while (l < blank_req + 1); // null byte
      void * mem;
      if ((mem = realloc(blank, l)) == NULL)
        goto free_queue;
      blank = mem, blank_capa = l;
    }
    while (blank_len < blank_req)
      blank[blank_len++] = ' ';
    blank[blank_len = blank_req] = '\0';
    //printf("%s name   %s\n", blank, var->name.bytes);
    if (var->type != WZ_VAR_UNK &&
        var->type != WZ_VAR_OBJ)
      continue;
    if (wz_read_obj(&var->val.obj, var, node, file, ctx, 0)) {
      var_err = 1;
      continue;
    }
    if (var->type != WZ_VAR_OBJ)
      continue;
    wzobj * obj = var->val.obj;
    if (obj->type != WZ_OBJ_LIST &&
        obj->type != WZ_OBJ_IMG) {
      wz_free_obj(obj);
      continue;
    }
    if (obj->type == WZ_OBJ_IMG) {
      size_t req = queue_len + 1;
      if (req > queue_capa) {
        size_t l = queue_capa;
        do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
        struct wz_read_obj_thrd_var * mem;
        if ((mem = realloc(queue, l * sizeof(* queue))) == NULL)
          goto free_queue;
        queue = mem, queue_capa = l;
      }
      wzimg * img = (wzimg *) obj;
      struct wz_read_obj_thrd_var * tvar = queue + queue_len;
      tvar->node = node;
      tvar->w = img->w;
      tvar->h = img->h;
      tvar->depth = img->depth;
      tvar->scale = img->scale;
      tvar->size = img->size;
      tvar->data = img->data;
      img->data = NULL;
      queue_len++;
    }
    wzlist * list = (wzlist *) obj;
    size_t req = stack_len + 2 + list->len;
    if (req > stack_capa) {
      size_t l = stack_capa;
      do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
      wzvar ** mem;
      if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
        goto free_queue;
      stack = mem, stack_capa = l;
    }
    stack[stack_len++] = var;
    stack[stack_len++] = NULL;
    for (uint32_t i = 0; i < list->len; i++) {
      wzvar * child = &list->vars[list->len - i - 1];
      child->parent = var;
      stack[stack_len++] = child;
    }
  }
  if (queue_len) {
    int err;
    if ((err = pthread_mutex_lock(mutex)) != 0)
      goto free_queue;
    size_t start = 0;
    size_t slice = (queue_len + tlen - 1) / tlen;
    for (uint8_t i = 0; i < tlen; i++) {
      struct wz_read_obj_thrd_arg * targ = targs + i;
      if (start < queue_len) {
        targ->vars = queue + start;
        targ->len = start + slice < queue_len ? slice : queue_len - start;
      } else {
        targ->vars = NULL;
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
  if (!var_err)
    ret = 0;
free_queue:
  free(queue);
  free(blank);
  free(stack);
  return ret;
}

int // Non recursive DFS
wz_read_obj_r(wzvar * root, wznode * node, wzfile * file, wzctx * ctx) {
  int ret = 1;
  int err = 0;
  size_t stack_capa = 1;
  wzvar ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    return ret;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  char * blank = NULL;
  size_t blank_capa = 0;
  size_t blank_len = 0;
  while (stack_len) {
    wzvar * var = stack[--stack_len];
    if (var == NULL) {
      wz_free_obj(stack[--stack_len]->val.obj);
      continue;
    }
    size_t blank_req = 0;
    for (wzvar * v = var; (v = v->parent) != NULL;)
      blank_req++;
    if (blank_req + 1 > blank_capa) { // null byte
      size_t l = blank_capa;
      do { l = l < 9 ? 9 : l + l / 2; } while (l < blank_req + 1); // null byte
      void * mem;
      if ((mem = realloc(blank, l)) == NULL)
        goto free_blank;
      blank = mem, blank_capa = l;
    }
    while (blank_len < blank_req)
      blank[blank_len++] = ' ';
    blank[blank_len = blank_req] = '\0';
    //printf("%s name   %s\n", blank, var->name.bytes);
    if (var->type == WZ_VAR_UNK ||
        var->type == WZ_VAR_OBJ) {
      if (wz_read_obj(&var->val.obj, var, node, file, ctx, 1)) {
        err = 1;
      } else {
        if (var->type == WZ_VAR_STR) {
        } else {
          wzobj * obj = var->val.obj;
          if (obj->type == WZ_OBJ_LIST ||
              obj->type == WZ_OBJ_IMG) {
            wzlist * list = (wzlist *) obj;
            size_t req = stack_len + 2 + list->len;
            if (req > stack_capa) {
              size_t l = stack_capa;
              do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
              wzvar ** mem;
              if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
                goto free_blank;
              stack = mem, stack_capa = l;
            }
            stack[stack_len++] = var;
            stack[stack_len++] = NULL;
            for (uint32_t i = 0; i < list->len; i++) {
              wzvar * child = &list->vars[list->len - i - 1];
              child->parent = var;
              stack[stack_len++] = child;
            }
          } else if (obj->type == WZ_OBJ_VEX) {
            //wzvex * vex = (wzvex *) obj;
            //for (uint32_t i = 0; i < vex->len; i++) {
            //  wz2d * val = &vex->vals[i];
            //  printf("%s %"PRId32"\n", blank, i);
            //  printf("%s  %"PRId32"\n", blank, val->x);
            //  printf("%s  %"PRId32"\n", blank, val->y);
            //}
            wz_free_obj(obj);
          } else if (obj->type == WZ_OBJ_VEC) {
            //wzvec * vec = (wzvec *) obj;
            //printf("%s %"PRId32"\n", blank, vec->val.x);
            //printf("%s %"PRId32"\n", blank, vec->val.y);
            wz_free_obj(obj);
          } else if (obj->type == WZ_OBJ_AO) {
            wz_free_obj(obj);
          } else if (obj->type == WZ_OBJ_UOL) {
            wz_free_obj(obj);
          }
          //printf("%s type   %.*s [%p]\n", blank,
          //       (int) obj->type.len, obj->type.bytes, obj);
        }
      }
    } else if (var->type == WZ_VAR_NIL) {
      //printf("%s (nil)\n", blank);
    } else if (var->type == WZ_VAR_INT16 ||
               var->type == WZ_VAR_INT32 ||
               var->type == WZ_VAR_INT64) {
      //printf("%s %"PRId64"\n", blank, var->val.i);
    } else if (var->type == WZ_VAR_FLT32 ||
               var->type == WZ_VAR_FLT64) {
      //printf("%s %f\n", blank, var->val.f);
    } else if (var->type == WZ_VAR_STR) {
      //wzstr * val = &var->val.str;
      //printf("%s %s\n", blank, val->bytes);
    }
  }
  if (!err)
    ret = 0;
free_blank:
  free(blank);
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
  struct wz_read_obj_thrd_arg * targs;
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
    struct wz_read_obj_thrd_arg * targ = targs + i;
    targ->id = i;
    targ->mutex = &mutex;
    targ->work_cond = &work_cond;
    targ->done_cond = &done_cond;
    targ->exit = &exit;
    targ->vars = NULL;
    targ->len = 0;
    targ->remain = &remain;
    if ((err = pthread_create(thrds + i, &attr, wz_read_obj_thrd, targ)) != 0)
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
      wz_free_grp(&stack[--stack_len]->data.grp);
      continue;
    }
    printf("node      ");
    for (wznode * n = node; (n = n->parent) != NULL;)
      printf(" ");
    printf("%-30s [%8x]", node->name.bytes, node->addr.val);
    for (wznode * n = node; (n = n->parent) != NULL;)
      printf(" < %s", n->name.bytes);
    printf("\n");
    fflush(stdout);
    if (node->type == WZ_NODE_DIR) {
      if (wz_read_grp(&node->data.grp, node, file, ctx)) {
        node_err = 1;
        continue;
      }
      wzgrp * grp = node->data.grp;
      size_t req = stack_len + 2 + grp->len;
      if (req > stack_capa) {
        size_t l = stack_capa;
        do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
        wznode ** mem;
        if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
          goto free_sizes;
        stack = mem, stack_capa = l;
      }
      stack[stack_len++] = node;
      stack[stack_len++] = NULL;
      for (uint32_t i = 0; i < grp->len; i++)
        stack[stack_len++] = &grp->nodes[grp->len - i - 1];
      req = sizes_len + 1;
      if (req > sizes_size) {
        size_t l = sizes_size;
        do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
        void * mem;
        if ((mem = realloc(sizes, l * sizeof(* sizes))) == NULL)
          goto free_sizes;
        sizes = mem, sizes_size = l;
      }
      sizes[sizes_len++] = grp->len;
      if (stack_len > stack_max_len) stack_max_len = stack_len;
    } else if (node->type == WZ_NODE_FILE) {
      //if (!wz_strcmp(&node->name, "WorldMap21.img")) {
      //if (!wz_strcmp(&node->name, "000020000.img")) {
      //if (!wz_strcmp(&node->name, "NightMarketTW.img")) { // convex and image
      //if (!wz_strcmp(&node->name, "acc8.img")) { // vector
      //if (!wz_strcmp(&node->name, "926120300.img")) { // multiple string key
      //if (!wz_strcmp(&node->name, "926120200.img")) { // multiple string key ? and minimap
      //if (!wz_strcmp(&node->name, "Effect2.img")) { // multiple string key x
      //if (!wz_strcmp(&node->name, "dryRock.img")) { // canvas, scale 4
      //if (!wz_strcmp(&node->name, "vicportTown.img")) { // last canvas
      //if (!wz_strcmp(&node->name, "MapHelper.img")) { // audio
      //if (!wz_strcmp(&node->name, "BgmGL.img")) { // audio
      //if (!wz_strcmp(&node->name, "8881000.img")) { // large string
      //if (!wz_strcmp(&node->name, "main.lua")) { // lua script
      if (wz_read_obj_thrd_r(node->data.var, node, file, ctx, tlen, targs,
                             &mutex, &work_cond, &done_cond, &remain))
        node_err = 1;
      //int64_t i = ((wzlist *) ((wzlist *) ((wzlist *) ((wzlist *) node->data.var->val.obj)->vars[2].val.obj)->vars[0].val.obj)->vars[2].val.obj)->vars[0].val.i;
      // MapList/0/mapNo/0 => 211040300
      //printf("i = %ld\n", i);
      // wzlist * list = (wzlist *) node->data.var->val.obj;
      // get_list(list, "MapList");
      //
      // wzlist * ret;
      // get_list(&ret, list, 2);
      // # ((wzlist *) list->vars[2].val.obj)
      //
      // wzlist * ret;
      // get_list(&ret, list, "MapList");
      //
      // int64 ret;
      // get_int(&ret, list, "MapList/0/mapNo/0");
      // get_float
      // get_chars
      //
      // get_list
      // get_img
      // get_vex
      // get_vec
      // get_snd
      // get_uol
      //}
    }
  }
  printf("node usage: %"PRIu32" / %"PRIu32"\n",
         (uint32_t) stack_max_len, (uint32_t) stack_capa);
  for (uint32_t i = 0; i < sizes_len; i++) {
    printf("grp len %"PRIu32"\n", sizes[i]);
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

int
wz_read_node_r(wznode * root, wzfile * file, wzctx * ctx) {
  int ret = 1;
  int err = 0;
  size_t stack_capa = 1;
  wznode ** stack;
  if ((stack = malloc(stack_capa * sizeof(* stack))) == NULL)
    return ret;
  size_t stack_len = 0;
  stack[stack_len++] = root;
  uint32_t * sizes = NULL;
  size_t sizes_size = 0;
  size_t sizes_len = 0;
  size_t stack_max_len = 0;
  while (stack_len) {
    wznode * node = stack[--stack_len];
    if (node == NULL) {
      wz_free_grp(&stack[--stack_len]->data.grp);
      continue;
    }
    printf("node      ");
    for (wznode * n = node; (n = n->parent) != NULL;)
      printf(" ");
    printf("%-30s [%8x]", node->name.bytes, node->addr.val);
    for (wznode * n = node; (n = n->parent) != NULL;)
      printf(" < %s", n->name.bytes);
    printf("\n");
    fflush(stdout);
    if (node->type == WZ_NODE_DIR) {
      if (wz_read_grp(&node->data.grp, node, file, ctx)) {
        err = 1;
        continue;
      }
      wzgrp * grp = node->data.grp;
      size_t req = stack_len + 2 + grp->len;
      if (req > stack_capa) {
        size_t l = stack_capa;
        do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
        wznode ** mem;
        if ((mem = realloc(stack, l * sizeof(* stack))) == NULL)
          goto free_sizes;
        stack = mem, stack_capa = l;
      }
      stack[stack_len++] = node;
      stack[stack_len++] = NULL;
      for (uint32_t i = 0; i < grp->len; i++)
        stack[stack_len++] = &grp->nodes[grp->len - i - 1];
      req = sizes_len + 1;
      if (req > sizes_size) {
        size_t l = sizes_size;
        do { l = l < 9 ? 9 : l + l / 2; } while (l < req);
        void * mem;
        if ((mem = realloc(sizes, l * sizeof(* sizes))) == NULL)
          goto free_sizes;
        sizes = mem, sizes_size = l;
      }
      sizes[sizes_len++] = grp->len;
      if (stack_len > stack_max_len) stack_max_len = stack_len;
    } else if (node->type == WZ_NODE_FILE) {
      //if (!wz_strcmp(&node->name, "WorldMap21.img")) {
      //if (!wz_strcmp(&node->name, "000020000.img")) {
      //if (!wz_strcmp(&node->name, "NightMarketTW.img")) { // convex and image
      //if (!wz_strcmp(&node->name, "acc8.img")) { // vector
      //if (!wz_strcmp(&node->name, "926120300.img")) { // multiple string key
      //if (!wz_strcmp(&node->name, "926120200.img")) { // multiple string key ? and minimap
      //if (!wz_strcmp(&node->name, "Effect2.img")) { // multiple string key x
      //if (!wz_strcmp(&node->name, "dryRock.img")) { // canvas, scale 4
      //if (!wz_strcmp(&node->name, "vicportTown.img")) { // last canvas
      //if (!wz_strcmp(&node->name, "MapHelper.img")) { // audio
      //if (!wz_strcmp(&node->name, "BgmGL.img")) { // audio
      //if (!wz_strcmp(&node->name, "8881000.img")) { // large string
      //if (!wz_strcmp(&node->name, "main.lua")) { // lua script
      if (wz_read_obj_r(node->data.var, node, file, ctx))
        err = 1;
      //int64_t i = ((wzlist *) ((wzlist *) ((wzlist *) ((wzlist *) node->data.var->val.obj)->vars[2].val.obj)->vars[0].val.obj)->vars[2].val.obj)->vars[0].val.i;
      // MapList/0/mapNo/0 => 211040300
      //printf("i = %ld\n", i);
      // wzlist * list = (wzlist *) node->data.var->val.obj;
      // get_list(list, "MapList");
      //
      // wzlist * ret;
      // get_list(&ret, list, 2);
      // # ((wzlist *) list->vars[2].val.obj)
      //
      // wzlist * ret;
      // get_list(&ret, list, "MapList");
      //
      // int64 ret;
      // get_int(&ret, list, "MapList/0/mapNo/0");
      // get_float
      // get_chars
      //
      // get_list
      // get_img
      // get_vex
      // get_vec
      // get_snd
      // get_uol
      //}
    }
  }
  printf("node usage: %"PRIu32" / %"PRIu32"\n",
         (uint32_t) stack_max_len, (uint32_t) stack_capa);
  for (uint32_t i = 0; i < sizes_len; i++) {
    printf("grp len %"PRIu32"\n", sizes[i]);
  }
  if (!err)
    ret = 0;
free_sizes:
  free(sizes);
  free(stack);
  return ret;
}

size_t // [^\0{delim}]+
wz_next_tok(const char * str, const char ** begin, const char ** end,
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

int64_t
wz_get_int(wzvar * var) {
  if (!(var->type == WZ_VAR_INT16 ||
        var->type == WZ_VAR_INT32 ||
        var->type == WZ_VAR_INT64)) return 0;
  return var->val.i;
}

double
wz_get_flt(wzvar * var) {
  if (!(var->type == WZ_VAR_FLT32 ||
        var->type == WZ_VAR_FLT64)) return 0;
  return var->val.f;
}

char *
wz_get_str(wzvar * var) {
  if (var->type != WZ_VAR_STR) return NULL;
  return (char *) var->val.str.bytes;
}

wzimg *
wz_get_img(wzvar * var) {
  if (var->type != WZ_VAR_OBJ ||
      var->val.obj->type != WZ_OBJ_IMG) return NULL;
  return (wzimg *) var->val.obj;
}

wzvex *
wz_get_vex(wzvar * var) {
  if (var->type != WZ_VAR_OBJ ||
      var->val.obj->type != WZ_OBJ_VEX) return NULL;
  return (wzvex *) var->val.obj;
}

wzvec *
wz_get_vec(wzvar * var) {
  if (var->type != WZ_VAR_OBJ ||
      var->val.obj->type != WZ_OBJ_VEC) return NULL;
  return (wzvec *) var->val.obj;
}

wzao *
wz_get_ao(wzvar * var) {
  if (var->type != WZ_VAR_OBJ ||
      var->val.obj->type != WZ_OBJ_AO) return NULL;
  return (wzao *) var->val.obj;
}

wzvar *
wz_open_var(wzvar * var, const char * path) {
  int ret = 1;
  char * search = NULL;
  size_t slen = 0;
  wznode * node = var->node;
  wzfile * file = node->file;
  for (;;) {
    if (var->type == WZ_VAR_UNK ||
        var->type == WZ_VAR_OBJ) {
      if (wz_read_obj(&var->val.obj, var, node, file, file->ctx, 1))
        break;
      if (var->type == WZ_VAR_OBJ &&
          var->val.obj->type == WZ_OBJ_UOL) {
        wzstr * uol = &((wzuol *) var->val.obj)->path;
        if (path == NULL) {
          path = (char *) uol->bytes;
        } else {
          char * str = search;
          size_t plen = strlen(path);
          size_t len = uol->len + 1 + plen + 1;
          if (len > slen) {
            if ((str = realloc(str, len)) == NULL)
              break;
            search = str;
            slen = len;
          }
          strcpy(str, (char *) uol->bytes), str += uol->len;
          strcat(str, "/"),                 str += 1;
          strcat(str, path);
          path = search;
        }
        if ((var = var->parent) == NULL)
          break;
        continue;
      }
    }
    const char * name;
    size_t len = wz_next_tok(path, &name, &path, '/');
    if (len == 2 && name[0] == '.' && name[1] == '.') {
      if ((var = var->parent) == NULL)
        break;
      continue;
    }
    if (name == NULL) {
      ret = 0;
      break;
    }
    if (var->type != WZ_VAR_OBJ ||
        (var->val.obj->type != WZ_OBJ_LIST &&
         var->val.obj->type != WZ_OBJ_IMG))
      break;
    wzlist * list = (wzlist *) var->val.obj;
    wzvar * found = NULL;
    for (uint32_t i = 0; i < list->len; i++) {
      wzvar * child = list->vars + i;
      if (!wz_strncmp(&child->name, name, len)) {
        found = child;
        break;
      }
    }
    if (found == NULL)
      break;
    var = found;
  }
  free(search);
  return ret ? NULL : var;
}

int
wz_close_var(wzvar * var) {
  int ret = 1;
  uint32_t capa = 2;
  wzvar ** stack;
  if ((stack = malloc(capa * sizeof(* stack))) == NULL)
    return ret;
  uint32_t len = 0;
  stack[len++] = var;
  while (len) {
    var = stack[--len];
    if (var == NULL) {
      wzvar * child = stack[--len];
      wz_free_obj(child->val.obj);
      continue;
    }
    if (var->type != WZ_VAR_OBJ ||
        !var->val.obj->alloc)
      continue;
    if (var->val.obj->type != WZ_OBJ_LIST &&
        var->val.obj->type != WZ_OBJ_IMG) {
      wz_free_obj(var->val.obj);
      continue;
    }
    wzlist * list = (wzlist *) var->val.obj;
    uint32_t req = len + 2 + list->len;
    if (req > capa) {
      wzvar ** fit;
      if ((fit = realloc(stack, req * sizeof(* stack))) == NULL)
        goto free_stack;
      stack = fit, capa = req;
    }
    len++, stack[len++] = NULL;
    for (uint32_t i = 0; i < list->len; i++)
      stack[len++] = &list->vars[i];
  }
  ret = 0;
free_stack:
  free(stack);
  return ret;
}

wzvar *
wz_open_root_var(wznode * node) {
  return wz_open_var(node->data.var, "");
}

char *
wz_get_var_name(wzvar * var) {
  return (char *) var->name.bytes;
}

uint32_t
wz_get_vars_len(wzvar * var) {
  uint32_t len = 0;
  if (var->type != WZ_VAR_OBJ ||
      (var->val.obj->type != WZ_OBJ_LIST &&
       var->val.obj->type != WZ_OBJ_IMG)) return len;
  return ((wzlist *) var->val.obj)->len;
}

wzvar *
wz_open_var_at(wzvar * var, uint32_t i) {
  if (var->type != WZ_VAR_OBJ ||
      (var->val.obj->type != WZ_OBJ_LIST &&
       var->val.obj->type != WZ_OBJ_IMG)) return NULL;
  wzvar * child = &((wzlist *) var->val.obj)->vars[i];
  return wz_open_var(child, "");
}

wznode *
wz_open_node(wznode * node, const char * path) {
  int ret = 1;
  wzfile * file = node->file;
  for (;;) {
    if (node->type == WZ_NODE_DIR)
      if (wz_read_grp(&node->data.grp, node, file, file->ctx))
        break;
    const char * name;
    size_t len = wz_next_tok(path, &name, &path, '/');
    if (name == NULL) {
      ret = 0;
      break;
    }
    if (node->type != WZ_NODE_DIR)
      break;
    wzgrp * grp = node->data.grp;
    wznode * found = NULL;
    for (uint32_t i = 0; i < grp->len; i++) {
      wznode * child = grp->nodes + i;
      if (!wz_strncmp(&child->name, name, len)) {
        found = child;
        break;
      }
    }
    if (found == NULL)
      break;
    node = found;
  }
  return ret ? NULL : node;
}

int
wz_close_node(wznode * node) {
  int ret = 1;
  uint32_t capa = 2;
  wznode ** stack;
  if ((stack = malloc(capa * sizeof(* stack))) == NULL)
    return ret;
  uint32_t len = 0;
  stack[len++] = node;
  while (len) {
    node = stack[--len];
    if (node == NULL) {
      wznode * child = stack[--len];
      wz_free_grp(&child->data.grp);
      continue;
    }
    if (!node->data.grp) continue;
    if (node->type == WZ_NODE_NIL) continue;
    if (node->type == WZ_NODE_FILE) {
      if (wz_close_var(node->data.var))
        goto free_stack;
      continue;
    }
    wzgrp * grp = node->data.grp;
    uint32_t req = len + 2 + grp->len;
    if (req > capa) {
      wznode ** fit;
      if ((fit = realloc(stack, req * sizeof(* stack))) == NULL)
        goto free_stack;
      stack = fit, capa = req;
    }
    len++, stack[len++] = NULL;
    for (uint32_t i = 0; i < grp->len; i++)
      stack[len++] = &grp->nodes[i];
  }
  ret = 0;
free_stack:
  free(stack);
  return ret;
}

wznode *
wz_open_root_node(wzfile * file) {
  return wz_open_node(&file->root, "");
}

char *
wz_get_node_name(wznode * node) {
  return (char *) node->name.bytes;
}

uint32_t
wz_get_nodes_len(wznode * node) {
  if (node->type != WZ_NODE_DIR) return (uint32_t) 0;
  return node->data.grp->len;
}

wznode *
wz_open_node_at(wznode * node, uint32_t i) {
  if (node->type != WZ_NODE_DIR) return NULL;
  wznode * child = &node->data.grp->nodes[i];
  return wz_open_node(child, "");
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
  if ((unsigned long) size > SIZE_MAX) {
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
  uint8_t  ident[4];
  uint32_t size_;
  uint32_t start;
  wzstr    copy;
  if (wz_read_bytes(&ident, sizeof(ident), &file) ||
      wz_read_le32(&size_, &file) ||
      wz_seek(4, SEEK_CUR, &file) ||
      wz_read_le32(&start, &file)) {
    perror(filename);
    goto close_raw;
  }
  copy.len = start - file.pos;
  if (wz_read_str(&copy.bytes, copy.len, &file)) {
    perror(filename);
    goto close_raw;
  }
  uint16_t enc;
  if (wz_read_le16(&enc, &file)) {
    perror(filename);
    goto free_copy;
  }
  uint32_t addr = file.pos;
  uint16_t dec;
  uint32_t hash;
  if (wz_deduce_ver(&dec, &hash, enc, addr, start, file.size, raw, ctx))
    goto free_copy;
  ret_file->ctx = ctx;
  ret_file->raw = raw;
  ret_file->pos = 0;
  ret_file->size = file.size;
  memcpy(ret_file->ident, ident, sizeof(ident));
  ret_file->size_ = size_;
  ret_file->start = start;
  ret_file->copy = copy;
  ret_file->ver.enc = enc;
  ret_file->ver.dec = dec;
  ret_file->ver.hash = hash;
  ret_file->key = NULL;
  ret_file->root.parent = NULL;
  ret_file->root.file = ret_file;
  ret_file->root.type = WZ_NODE_DIR;
  ret_file->root.name.len = 0;
  ret_file->root.name.bytes = NULL;
  ret_file->root.addr.val = addr;
  ret_file->root.data.grp = NULL;
  ret = 0;
free_copy:
  if (ret)
    wz_free_chars(copy.bytes);
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
  wz_free_str(file->copy.bytes);
  if (fclose(file->raw))
    ret = 1;
  return ret;
}

int
wz_init_ctx(wzctx * ctx) {
  int ret = 1;
  if (wz_init_keys(&ctx->keys, &ctx->klen))
    return ret;
  if (wz_init_plt(&ctx->plt))
    goto free_keys;
  wz_init_guid(&ctx->guid);
  ret = 0;
free_keys:
  if (ret)
    wz_free_keys(ctx->keys, ctx->klen);
  return ret;
}

void
wz_free_ctx(wzctx * ctx) {
  wz_free_keys(ctx->keys, ctx->klen);
  free(ctx->plt);
}
