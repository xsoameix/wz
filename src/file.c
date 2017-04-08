// Standard Library

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
#include "unicode.h"
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

void
wz_error(const char * format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int
wz_read_data(void * buffer, uint32_t len, wzfile * file) {
  if (file->pos + len > file->size ||
      fread(buffer, 1, len, file->raw) != len) return 1;
  return file->pos += len, 0;
}

int
wz_read_byte(uint8_t * buffer, wzfile * file) {
  return wz_read_data(buffer, sizeof(* buffer), file);
}

int
wz_read_le16(uint16_t * buffer, wzfile * file) {
  if (wz_read_data(buffer, sizeof(* buffer), file)) return 1;
  return * buffer = wz_le16toh(* buffer), 0;
}

int
wz_read_le32(uint32_t * buffer, wzfile * file) {
  if (wz_read_data(buffer, sizeof(* buffer), file)) return 1;
  return * buffer = wz_le32toh(* buffer), 0;
}

int
wz_read_le64(uint64_t * buffer, wzfile * file) {
  if (wz_read_data(buffer, sizeof(* buffer), file)) return 1;
  return * buffer = wz_le64toh(* buffer), 0;
}

int // read packed integer (int8 or int32)
wz_read_int(uint32_t * buffer, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) return 1;
  if (byte == INT8_MIN) return wz_read_le32(buffer, file);
  return * (int32_t *) buffer = byte, 0;
}

int // read packed long (int8 or int64)
wz_read_long(uint64_t * buffer, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) return 1;
  if (byte == INT8_MIN) return wz_read_le64(buffer, file);
  return * (int64_t *) buffer = byte, 0;
}

int // read string without malloc
wz_read_bytes(uint8_t * buffer, uint32_t len, wzfile * file) {
  return wz_read_data(buffer, len, file);
}

void
wz_init_str(wzstr * buffer) {
  buffer->bytes = NULL;
}

int // read string with malloc
wz_read_str(wzstr * buffer, uint32_t len, wzfile * file) {
  if (len > INT32_MAX) return wz_error("String length > INT32_MAX"), 1;
  uint8_t * bytes = malloc(len + 1);
  if (bytes == NULL) return 1;
  if (wz_read_bytes(bytes, len, file)) return free(bytes), 1;
  bytes[len] = '\0';
  return buffer->bytes = bytes, buffer->len = len, 0;
}

void
wz_free_str(wzstr * buffer) {
  free(buffer->bytes);
}

int
wz_utf16le_to_utf8(wzstr * val) {
  uint32_t len = 0;
  for (uint32_t i = 0; i < val->len;) {
    uint8_t  utf16le[WZ_UTF16LE_MAX_LEN] = {0};
    uint8_t  utf16le_len;
    uint32_t code;
    uint8_t  utf8_len;
    memcpy(utf16le, val->bytes + i,
           val->len - i < sizeof(utf16le) ?
           val->len - i : sizeof(utf16le));
    if (wz_utf16le_len(&utf16le_len, utf16le) ||
        wz_utf16le_to_code(&code, utf16le) ||
        wz_code_to_utf8_len(&utf8_len, code)) return 1;
    i += utf16le_len;
    len += utf8_len;
  }
  uint8_t * bytes = malloc(len + 1);
  if (bytes == NULL) return 1;
  uint8_t * utf8 = bytes;
  for (uint32_t i = 0; i < val->len;) {
    uint8_t   utf16le[WZ_UTF16LE_MAX_LEN] = {0};
    uint8_t   utf16le_len;
    uint32_t  code;
    uint8_t   utf8_len;
    memcpy(utf16le, val->bytes + i,
           val->len - i < sizeof(utf16le) ?
           val->len - i : sizeof(utf16le));
    if (wz_utf16le_len(&utf16le_len, utf16le) ||
        wz_utf16le_to_code(&code, utf16le) ||
        wz_code_to_utf8(utf8, code) ||
        wz_code_to_utf8_len(&utf8_len, code)) return free(bytes), 1;
    i += utf16le_len;
    utf8 += utf8_len;
  }
  return bytes[len] = '\0', val->bytes = bytes, val->len = len, 0;
}

int
wz_decode_chars(wzstr * buffer, int ascii, wzkey * key) {
  if (key == NULL) return 0;
  if (buffer->len > key->len)
    return wz_error("String length %"PRIu32" > %"PRIu32"\n",
                    buffer->len, key->len), 1;
  if (ascii) { // ASCII
    uint8_t * bytes = buffer->bytes;
    uint8_t mask = 0xaa;
    uint32_t len = buffer->len / sizeof(mask);
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= mask++ ^ key->bytes[i];
    return 0;
  } else { // UTF16-LE
    uint16_t * bytes = (uint16_t *) buffer->bytes;
    uint16_t mask = 0xaaaa;
    uint32_t len = buffer->len / sizeof(mask);
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= wz_htole16(mask++ ^ wz_le16toh(((uint16_t *) key->bytes)[i]));
    return wz_utf16le_to_utf8(buffer);
  }
}

int // read characters (ascii or utf16le)
wz_read_chars(wzstr * buffer, wzkey * key, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) return 1;
  int32_t size = byte;
  int ascii = size < 0;
  if (ascii) { // ASCII
    if (size == INT8_MIN) {
      if (wz_read_le32((uint32_t *) &size, file)) return 1;
    } else {
      size *= -1;
    }
  } else { // UTF16-LE
    if (size == INT8_MAX) {
      if (wz_read_le32((uint32_t *) &size, file)) return 1;
    }
    size *= 2;
  }
  wzstr str;
  if (wz_read_str(&str, (uint32_t) size, file)) return 1;
  wzstr chars = str;
  if (wz_decode_chars(&chars, ascii, key)) return wz_free_chars(&chars), 1;
  if (chars.bytes != str.bytes) wz_free_str(&str);
  return * buffer = chars, 0;
}

void
wz_free_chars(wzstr * buffer) {
  free(buffer->bytes);
}

void
wz_decode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
               uint32_t start, uint32_t hash) {
  uint32_t key = 0x581c3f6d;
  uint32_t x = (~(pos - start) & 0xffffffff) * hash - key;
  uint32_t n = x & 0x1f;
  x = (x << n) | (x >> (32 - n)); // rotate left n bit
  * ret_val = (x ^ val) + start * 2;
}

int // This function should not be called after address decoded
wz_read_addr(wzaddr * addr, wzfile * file) {
  uint32_t pos = file->pos;
  if (wz_read_le32(&addr->val, file)) return 1;
  addr->pos = pos;
  if (file->ver.hash == 0) return 0;
  return wz_decode_addr(&addr->val, addr->val, addr->pos,
                        file->head.start, file->ver.hash), 0;
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
  if (wz_read_int(&node->size, file) ||
      wz_read_int(&node->check, file) ||
      wz_read_addr(&node->addr, file)) return 1;
  if (WZ_IS_NODE_DIR(type)) {
    return node->data.grp = NULL, node->type = WZ_NODE_DIR, 0;
  } else if (WZ_IS_NODE_FILE(type)) {
    wzvar * var = malloc(sizeof(* var));
    if (var == NULL) return 1;
    var->parent = NULL, var->node = node;
    var->name = (wzstr) {.len = 0, .bytes = NULL};
    var->type = WZ_VAR_OBJ;
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
wz_read_node(wznode * node, wzfile * file, wzctx * ctx) {
  uint8_t type;
  if (wz_read_byte(&type, file)) return 1;
  if (WZ_IS_NODE_NIL(type)) { // unknown 10 bytes
    if (wz_seek(10, SEEK_CUR, file)) return 1;
    return node->data.grp = NULL, node->type = WZ_NODE_NIL, 0;
  } else if (WZ_IS_NODE_LINK(type)) {
    uint32_t addr;
    if (wz_read_le32(&addr, file)) return 1;
    uint32_t pos = file->pos;
    if (wz_seek(file->head.start + addr, SEEK_SET, file) ||
        wz_read_byte(&type, file) ||
        wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, ctx) ||
        wz_seek(pos, SEEK_SET, file) ||
        wz_read_node_body(node, type, file))
      return wz_free_chars(&node->name), 1;
    return 0;
  } else if (WZ_IS_NODE_DIR(type) ||
             WZ_IS_NODE_FILE(type)) {
    if (wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, ctx) ||
        wz_read_node_body(node, type, file))
      return wz_free_chars(&node->name), 1;
    return 0;
  } else {
    return wz_error("Unsupported node type: 0x%02hhx\n", node->type), 1;
  }
}

void
wz_free_node(wznode * node) {
  if (node->type == WZ_NODE_DIR ||
      node->type == WZ_NODE_FILE)
    wz_free_chars(&node->name);
  if (node->type == WZ_NODE_FILE)
    free(node->data.var->val.obj), free(node->data.var);
}

int
wz_read_grp(wzgrp ** buffer, wznode * node, wzfile * file, wzctx * ctx) {
  if (node->data.grp) return 0;
  if (wz_seek(node->addr.val, SEEK_SET, file)) return 1;
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wzgrp * grp = malloc(sizeof(* grp) + len * sizeof(* grp->nodes));
  if (grp == NULL) return 1;
  wznode * nodes = (wznode *) (grp + 1);
  for (uint32_t i = 0; i < len; i++) {
    if (wz_read_node(nodes + i, file, ctx)) {
      for (uint32_t j = 0; j < i; j++)
        wz_free_node(nodes + j);
      return free(grp), 1;
    }
    nodes[i].parent = node, nodes[i].file = file;
  }
  return grp->nodes = nodes, grp->len = len, * buffer = grp, 0;
}

void
wz_free_grp(wzgrp ** buffer) {
  wzgrp * grp = * buffer;
  for (uint32_t i = 0; i < grp->len; i++)
    wz_free_node(&grp->nodes[i]);
  free(grp), * buffer = NULL;
}

int
wz_read_head(wzhead * head, wzfile * file) {
  wz_init_str(&head->copy);
  if (wz_read_bytes(head->ident, sizeof(head->ident), file) ||
      wz_read_le32(&head->size, file) ||
      wz_seek(4, SEEK_CUR, file) ||
      wz_read_le32(&head->start, file) ||
      wz_read_str(&head->copy, head->start - file->pos, file)) return 1;
  file->root = (wznode) {
    .parent = NULL,
    .file = file,
    .type = WZ_NODE_DIR,
    .name = {.len = 0, .bytes = NULL},
    .data = {.grp = NULL},
    .addr = {.val = head->start + (uint32_t) sizeof(file->ver.enc)}
  };
  printf("ident      %.4s\n",          head->ident);
  printf("size       0x%08"PRIu32"\n", head->size);
  printf("start      0x%08"PRIu32"\n", head->start);
  printf("copyright  %.*s\n",          head->copy.len, head->copy.bytes);
  return 0;
}

void
wz_free_head(wzhead * head) {
  wz_free_str(&head->copy);
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
wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash,
              uint16_t enc, wzfile * file, wzctx * ctx) {
  int ret = 1;
  file->ver.hash = 0; // do not decode addr in read_grp/node/node_body/addr
  file->key = NULL;   // do not decode chars in read_grp/node/chars/decode_chars
                      // but deduce file->key in read_grp/node/deduce_key
  wznode root = file->root;
  if (wz_read_grp(&root.data.grp, &root, file, ctx))
    return ret;
  for (uint16_t g_dec = 0; g_dec < 512; g_dec++) { // guess dec
    uint32_t g_hash;
    uint16_t g_enc;
    wz_encode_ver(&g_enc, &g_hash, g_dec);
    if (g_enc != enc)
      continue;
    int err = 0;
    wzgrp * grp = root.data.grp;
    for (uint32_t i = 0; i < grp->len; i++) {
      wznode * node = grp->nodes + i;
      if (node->type == WZ_NODE_DIR ||
          node->type == WZ_NODE_FILE) {
        wzaddr * addr = &node->addr;
        uint32_t val;
        wz_decode_addr(&val, addr->val, addr->pos, file->head.start, g_hash);
        if (val > file->size) {
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
  wz_free_grp(&root.data.grp);
  return ret;
}

void
wz_decode_aes(uint8_t * plain, const uint8_t * cipher, uint32_t len,
              uint8_t * key, const uint8_t * iv) {
  aes256_context ctx;
  aes256_init(&ctx, key);
  for (uint32_t i = 0; i < len; i += 16) {
    memcpy(plain, cipher, 16);
    aes256_decrypt_ecb(&ctx, plain);
    for (uint8_t j = 0; j < 16; j++)
      plain[j] ^= iv[j];
    plain += 16, iv = cipher, cipher += 16;
  }
  aes256_done(&ctx);
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
    {0xb9, 0x7d, 0x63, 0xe9}
  };
  size_t wklen = sizeof(ivs) / sizeof(* ivs) + 1;
  wzkey * wkeys;
  if ((wkeys = malloc(sizeof(* wkeys) * wklen)) == NULL)
    return ret;
  uint32_t len = 0x10000; // supported image chunk or string size
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
wz_deduce_key(wzkey ** buffer, wzstr * name, wzctx * ctx) {
  if (* buffer != NULL) return 0;
  for (size_t i = 0; i < ctx->klen; i++) {
    wzkey * key = &ctx->keys[i];
    if (wz_decode_chars(name, 1, key)) continue;
    for (uint32_t j = 0; j < name->len && isprint(name->bytes[j]); j++)
      if (j == name->len - 1) return * buffer = key, 0;
    if (wz_decode_chars(name, 1, key)) continue;
  }
  return wz_error("Cannot deduce the string key\n"), 1;
}

int // read packed string
wz_read_pack_chars(wzstr * buffer, wznode * node, wzfile * file) {
  uint8_t type;
  if (wz_read_byte(&type, file)) return 1;
  switch (type) {
  case 0x00: case 0x73: return wz_read_chars(buffer, node->key, file);
  case 0x01: case 0x1b: {
    uint32_t addr;
    if (wz_read_le32(&addr, file)) return 1;
    uint32_t pos = file->pos;
    if (wz_seek(node->addr.val + addr, SEEK_SET, file) ||
        wz_read_chars(buffer, node->key, file)) return 1;
    if (wz_seek(pos, SEEK_SET, file))
      return wz_free_chars(buffer), 1;
    return 0;
  }
  default: {
    return wz_error("Unsupported string type: 0x%02hhx\n", type), 1;
  }
  };
}

int
wz_strcmp(wzstr * a, const char * b) {
  return strncmp((char *) a->bytes, b, a->len);
}

int
wz_strncmp(wzstr * a, const char * b, size_t blen) {
  return a->len != blen || strncmp((char *) a->bytes, b, blen);
}

size_t indent = 0;
int debugging = 0;
//#define debug(...) do { if (debugging) printf(__VA_ARGS__); } while (0)
//#define debug(...) printf(__VA_ARGS__), fflush(stdout)
// #define debug(...) while(0)
void
debug(const char * format, ...) {
  va_list args;
  va_start(args, format);
  vprintf(format, args), fflush(stdout);
  va_end(args);
}

void
pindent(void) {
  for (size_t i = 0; i < indent; i++)
    debug(" ");
}

int
wz_read_prim(wzprim * val, uint8_t * type, wznode * node, wzfile * file) {
  uint8_t byte;
  if (wz_read_byte(&byte, file)) return 1;
  if (WZ_IS_VAR_NIL(byte)) {
    return * type = WZ_VAR_NIL, 0;
  } else if (WZ_IS_VAR_INT16(byte)) {
    int16_t int16;
    if (wz_read_le16((uint16_t *) &int16, file)) return 1;
    return val->i = int16, * type = WZ_VAR_INT16, 0;
  } else if (WZ_IS_VAR_INT32(byte)) {
    int32_t int32;
    if (wz_read_int((uint32_t *) &int32, file)) return 1;
    return val->i = int32, * type = WZ_VAR_INT32, 0;
  } else if (WZ_IS_VAR_INT64(byte)) {
    int64_t int64;
    if (wz_read_long((uint64_t *) &int64, file)) return 1;
    return val->i = int64, * type = WZ_VAR_INT64, 0;
  } else if (WZ_IS_VAR_FLT32(byte)) {
    int8_t float8;
    if (wz_read_byte((uint8_t *) &float8, file)) return 1;
    if (float8 == INT8_MIN) {
      union { uint32_t i; float f; } float32;
      if (wz_read_le32(&float32.i, file)) return 1;
      return val->f = float32.f, * type = WZ_VAR_FLT32, 0;
    } else {
      return val->f = float8, * type = WZ_VAR_FLT32, 0;
    }
  } else if (WZ_IS_VAR_FLT64(byte)) {
    union { uint64_t i; double f; } float64;
    if (wz_read_le64(&float64.i, file)) return 1;
    return val->f = float64.f, * type = WZ_VAR_FLT64, 0;
  } else if (WZ_IS_VAR_STR(byte)) {
    if (wz_read_pack_chars(&val->str, node, file)) return 1;
    return * type = WZ_VAR_STR, 0;
  } else if (WZ_IS_VAR_OBJ(byte)) {
    uint32_t size;
    if (wz_read_le32(&size, file)) return 1;
    wzobj * obj = malloc(sizeof(* obj));
    if (obj == NULL) return 1;
    obj->alloc = 0, obj->pos = file->pos;
    if (wz_seek(size, SEEK_CUR, file)) return free(obj), 1;
    return val->obj = obj, * type = WZ_VAR_OBJ, 0;
  } else {
    return wz_error("Unsupported primitive type: 0x%02hhx\n", type), 1;
  }
}

void
wz_free_prim(wzprim * val, uint8_t type) {
  if (type == WZ_VAR_STR)      wz_free_chars(&val->str);
  else if (type == WZ_VAR_OBJ) free(val->obj);
}

int
wz_read_var(wzvar * var, wznode * node, wzfile * file) {
  if (wz_read_pack_chars(&var->name, node, file)) return 1;
  if (wz_read_prim(&var->val, &var->type, node, file))
    return wz_free_chars(&var->name), 1;
  return 0;
}

void
wz_free_var(wzvar * var) {
  wz_free_prim(&var->val, var->type);
  wz_free_chars(&var->name);
}

int
wz_read_list(wzlist * list, wzvar * var,
             wznode * node, wzfile * file, wzctx * ctx) {
  (void) ctx;
  if (wz_seek(2, SEEK_CUR, file)) return 1;
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wzvar * vars = malloc(sizeof(* vars) * len);
  if (vars == NULL) return 1;
  for (uint32_t i = 0; i < len; i++) {
    if (wz_read_var(vars + i, node, file)) {
      for (uint32_t j = 0; j < i; j++)
        wz_free_var(vars + j);
      return free(vars), 1;
    }
    vars[i].parent = var, vars[i].node = node;
  }
  return list->vars = vars, list->len = len, 0;
}

void
wz_free_list(wzlist * list) {
  for (uint32_t i = 0; i < list->len; i++)
    wz_free_var(list->vars + i);
  free(list->vars);
}

int
wz_decode_bitmap(uint32_t * written,
                 uint8_t * out, uint8_t * in, uint32_t size, wzkey * key) {
  uint32_t read = 0, write = 0;
  while (read < size) {
    uint32_t len = wz_le32toh(* (uint32_t *) (in + read));
    read += (uint32_t) sizeof(len);
    if (len > key->len)
      return wz_error("Image chunk size %"PRIu32" > %"PRIu32"\n",
                      len, key->len), 1;
    for (uint32_t i = 0; i < len; i++)
      out[write++] = in[read++] ^ key->bytes[i];
  }
  return * written = write, 0;
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

void
wz_init_palette(wzpalette * palette) {
  uint8_t i;
  for (i = 0; i < 0x10; i++) palette->table4[i] = (uint8_t) (i << 4) | (i >> 0);
  for (i = 0; i < 0x20; i++) palette->table5[i] = (uint8_t) (i << 3) | (i >> 2);
  for (i = 0; i < 0x40; i++) palette->table6[i] = (uint8_t) (i << 2) | (i >> 4);
}

int
wz_scale_size(uint32_t * scale_size, uint8_t scale) {
  switch (scale) {
  case 0: return * scale_size =  1, 0; // pow(2, 0) == 1
  case 4: return * scale_size = 16, 0; // pow(2, 4) == 16
  default: {
    return wz_error("Unsupported scale %hhd\n", scale), 1;
  }
  };
}

int
wz_depth_size(uint32_t * depth_size, uint32_t depth) {
  switch (depth) {
  case WZ_COLOR_4444: return * depth_size = 2, 0;
  case WZ_COLOR_8888: return * depth_size = 4, 0;
  case WZ_COLOR_565:  return * depth_size = 2, 0;
  case WZ_COLOR_DXT3: return * depth_size = 1, 0;
  default: {
    return wz_error("Unsupported color depth %"PRIu32"\n", depth), 1;
  }
  };
}

void
wz_swap_ptr(uint8_t ** a, uint8_t ** b) {
  uint8_t * tmp = * a;
  * a = * b;
  * b = tmp;
}

void
wz_unpack_4444(wzcolor * out, uint8_t * in, uint32_t pixels, wzctx * ctx) {
  uint8_t * unpack4 = ctx->palette.table4;
  for (uint32_t i = 0; i < pixels; i++) {
    uint16_t pixel = wz_le16toh(* ((uint16_t *) in + i));
    uint8_t b = (pixel >>  0) & 0x0f;
    uint8_t g = (pixel >>  4) & 0x0f;
    uint8_t r = (pixel >>  8) & 0x0f;
    uint8_t a = (pixel >> 12) & 0x0f;
    out[i] = (wzcolor) {unpack4[b], unpack4[g], unpack4[r], unpack4[a]};
  }
}

void
wz_unpack_565(wzcolor * out, uint8_t * in, uint32_t pixels, wzctx * ctx) {
  uint8_t * unpack5 = ctx->palette.table5;
  uint8_t * unpack6 = ctx->palette.table6;
  for (uint32_t i = 0; i < pixels; i++) {
    uint16_t pixel = wz_le16toh(* ((uint16_t *) in + i));
    uint8_t b = (pixel >>  0) & 0x1f;
    uint8_t g = (pixel >>  5) & 0x3f;
    uint8_t r = (pixel >> 11) & 0x1f;
    out[i] = (wzcolor) {unpack5[b], unpack6[g], unpack5[r], 0xff};
  }
}

void
wz_inflate_dxt3_color(wzcolor * out, uint8_t * in, wzctx * ctx) {
  wzcolor codes[4];
  wz_unpack_565(codes, in, 2, ctx); // the first two codes
  codes[2].b = (uint8_t) ((codes[0].b * 2 + codes[1].b) / 3); // the third code
  codes[2].g = (uint8_t) ((codes[0].g * 2 + codes[1].g) / 3);
  codes[2].r = (uint8_t) ((codes[0].r * 2 + codes[1].r) / 3);
  codes[2].a = 0xff;
  codes[3].b = (uint8_t) ((codes[0].b + codes[1].b * 2) / 3); // the fourth code
  codes[3].g = (uint8_t) ((codes[0].g + codes[1].g * 2) / 3);
  codes[3].r = (uint8_t) ((codes[0].r + codes[1].r * 2) / 3);
  codes[3].a = 0xff;
  uint32_t indices = wz_le32toh(* (uint32_t *) (in + 4)); // get indices
  for (size_t i = 0; i < 16; i++) // choose code by using indice
    out[i] = codes[indices & 0x03], indices >>= 2;
}

void
wz_inflate_dxt3_alpha(wzcolor * out, uint8_t * in, wzctx * ctx) {
  uint8_t * unpack4 = ctx->palette.table4;
  uint64_t alpha = wz_le64toh(* (uint64_t *) in); // get alpha values
  for (size_t i = 0; i < 16; i++)
    out[i].a = unpack4[alpha & 0x0f], alpha >>= 4; // unpack alpha value
}

void
wz_inflate_dxt3(wzcolor * out, uint8_t * in, wzctx * ctx) {
  wz_inflate_dxt3_color(out, in + 8, ctx);
  wz_inflate_dxt3_alpha(out, in, ctx);
}

void
wz_unpack_dxt3(wzcolor * out, uint8_t * in, uint32_t w, uint32_t h,
               wzctx * ctx) {
  uint32_t bw = (w + 3) / 4 * 4; // increased to blocks width
  for (uint32_t y = 0; y < h; y += 4) // loop over blocks
    for (uint32_t x = 0; x < w; x += 4) {
      wzcolor pixels[16];
      wz_inflate_dxt3(pixels, &in[y * bw + x * 4], ctx); // inflate 4x4 block
      // check the pixel is outside of image
      uint8_t ph = h - y < 4 ? (uint8_t) (h - y) : 4;
      uint8_t pw = w - x < 4 ? (uint8_t) (w - x) : 4;
      for (uint32_t py = 0; py < ph; py++) // write to correct location
        for (uint32_t px = 0; px < pw; px++)
          out[(y + py) * w + x + px] = pixels[py * 4 + px];
    }
}

int
wz_unpack_bitmap(wzcolor ** dst, uint8_t ** src,
                 uint32_t w, uint32_t h, uint32_t depth, wzctx * ctx) {
  uint8_t * in = * src;
  wzcolor * out = * dst;
  switch (depth) {
  case WZ_COLOR_4444: return wz_unpack_4444(out, in, w * h, ctx), 0;
  case WZ_COLOR_8888: return wz_swap_ptr((uint8_t **) dst, src), 0;
  case WZ_COLOR_565:  return wz_unpack_565(out, in, w * h, ctx), 0;
  case WZ_COLOR_DXT3: return wz_unpack_dxt3(out, in, w, h, ctx), 0;
  default: {
    return wz_error("Unsupported color depth %"PRIu32"\n", depth), 1;
  }
  };
}

void
wz_scale_bitmap(uint8_t ** dst, uint8_t ** src,
                uint32_t w, uint32_t h, uint32_t n) {
  if (n == 1) { wz_swap_ptr(dst, src); return; }
  uint8_t * in = * src, * out = * dst;
  uint32_t pw = w * n;
  for (uint32_t y = 0; y < h; y++)
    for (uint32_t x = 0; x < w; x++) {
      uint8_t pixel = in[y * w + x];
      for (uint32_t py = y * n; py < (y + 1) * n; py++)
        for (uint32_t px = x * n; px < (x + 1) * n; px++)
          out[py * pw + px] = pixel;
    }
}

int
wz_read_bitmap(wzcolor ** data, uint32_t w, uint32_t h,
               uint32_t depth, uint8_t scale, uint32_t size,
               wznode * node, wzfile * file, wzctx * ctx) {
  size--; // remove null terminator
  uint32_t pixels = w * h;
  uint32_t full_size = pixels * (uint32_t) sizeof(wzcolor);
  uint32_t max_size = size > full_size ? size : full_size; // inflated > origin
  uint8_t * in = malloc(max_size);
  if (in == NULL) return 1;
  if (wz_read_bytes(in, size, file)) return free(in), 1;
  uint8_t * out = malloc(max_size);
  if (out == NULL) return free(in), 1;
  if (wz_inflate_bitmap(&size, out, full_size, in, size)) {
    if (wz_decode_bitmap(&size, out, in, size, node->key) ||
        wz_inflate_bitmap(&size, in, full_size, out, size))
      return free(out), free(in), 1;
    wz_swap_ptr(&in, &out);
  }
  uint32_t depth_size, scale_size;
  if (wz_depth_size(&depth_size, depth) ||
      wz_scale_size(&scale_size, scale) ||
      size != pixels * depth_size / (scale_size * scale_size))
    return free(out), free(in), 1;
  uint32_t pw = w / scale_size, ph = h / scale_size;
  if (wz_unpack_bitmap((wzcolor **) &in, &out, pw, ph, depth, ctx))
    return free(out), free(in), 1;
  wz_scale_bitmap(&out, &in, pw, ph, scale_size);
  return free(in), * data = (wzcolor *) out, 0;
}

int
wz_read_img(wzimg * img, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx) {
  if (wz_seek(1, SEEK_CUR, file)) return 1;
  uint8_t list;
  if (wz_read_byte(&list, file)) return 1;
  img->len = 0, img->vars = NULL;
  if (list == 1 && wz_read_list((wzlist *) img, var, node, file, ctx)) return 1;
  uint32_t depth;
  uint8_t  scale;
  uint32_t size;
  uint32_t blank1;
  uint8_t  blank2;
  if (wz_read_int(&img->w, file)   ||
      wz_read_int(&img->h, file)   ||
      wz_read_int(&depth, file)    ||
      wz_read_byte(&scale, file)   ||
      wz_read_le32(&blank1, file)  || blank1 ||
      wz_read_le32(&size, file)    ||
      wz_read_byte(&blank2, file)  || blank2 ||
      wz_read_bitmap(&img->data, img->w, img->h, depth, scale, size,
                     node, file, ctx))
    return wz_free_list((wzlist *) img), 1;
  //static int id = 0;
  //char filename[100];
  //snprintf(filename, sizeof(filename), "out/%d-%"PRIu32"-%"PRIu32".data",
  //         id++, img->w, img->h);
  //FILE * outfile = fopen(filename, "wb");
  //fwrite(img->data, 1, img->w * img->h * 4, outfile);
  //fclose(outfile);
  //printf("img raw size %"PRIu32"\n", size);
  return 0;
}

void
wz_free_img(wzimg * img) {
  free(img->data);
  wz_free_list((wzlist *) img);
}

int
wz_read_2d(wz2d * val, wzfile * file) {
  return (wz_read_int((uint32_t *) &val->x, file) ||
          wz_read_int((uint32_t *) &val->y, file));
}

int
wz_read_vex_item(wz2d * val, wznode * node, wzfile * file) {
  wzstr type;
  if (wz_read_pack_chars(&type, node, file)) return 1;
  if (WZ_IS_OBJ_VECTOR(&type))
    return wz_free_chars(&type),
           wz_read_2d(val, file);
  else
    return wz_free_chars(&type),
           wz_error("Convex should contain only vectors\n"), 1;
}

int
wz_read_vex(wzvex * vex, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx) {
  (void) var;
  (void) ctx;
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wz2d * vals = malloc(sizeof(* vals) * len);
  if (vals == NULL) return 1;
  for (uint32_t i = 0; i < len; i++)
    if (wz_read_vex_item(vals + i, node, file))
      return free(vals), 1;
  return vex->vals = vals, vex->len = len, 0;
}

void
wz_free_vex(wzvex * vex) {
  free(vex->vals);
}

int
wz_read_vec(wzvec * vec, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx) {
  (void) var;
  (void) node;
  (void) ctx;
  return wz_read_2d(&vec->val, file);
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
  wav->format          = wz_le16toh(* (uint16_t *) data), data += 2;
  wav->channels        = wz_le16toh(* (uint16_t *) data), data += 2;
  wav->sample_rate     = wz_le32toh(* (uint32_t *) data), data += 4;
  wav->byte_rate       = wz_le32toh(* (uint32_t *) data), data += 4;
  wav->block_align     = wz_le16toh(* (uint16_t *) data), data += 2;
  wav->bits_per_sample = wz_le16toh(* (uint16_t *) data), data += 2;
  wav->extra_size      = wz_le16toh(* (uint16_t *) data), data += 2;
}

void
wz_decode_wav(uint8_t * wav, uint8_t size, wzkey * key) {
  for (uint8_t i = 0; i < size; i++)
    wav[i] ^= key->bytes[i];
}

void
wz_write_pcm(uint8_t * pcm, wzwav * wav, uint32_t size) {
  * (uint32_t *) pcm = wz_htobe32(0x52494646),           pcm += 4; // "RIFF"
  * (uint32_t *) pcm = wz_htole32(36 + size),            pcm += 4; // following
  * (uint32_t *) pcm = wz_htobe32(0x57415645),           pcm += 4; // "WAVE"
  * (uint32_t *) pcm = wz_htobe32(0x666d7420),           pcm += 4; // "fmt "
  * (uint32_t *) pcm = wz_htole32(16),                   pcm += 4; // PCM = 16
  * (uint16_t *) pcm = wz_htole16(wav->format),          pcm += 2;
  * (uint16_t *) pcm = wz_htole16(wav->channels),        pcm += 2;
  * (uint32_t *) pcm = wz_htole32(wav->sample_rate),     pcm += 4;
  * (uint32_t *) pcm = wz_htole32(wav->byte_rate),       pcm += 4;
  * (uint16_t *) pcm = wz_htole16(wav->block_align),     pcm += 2;
  * (uint16_t *) pcm = wz_htole16(wav->bits_per_sample), pcm += 2;
  * (uint32_t *) pcm = wz_htobe32(0x64617461),           pcm += 4; // "data"
  * (uint32_t *) pcm = wz_htole32(size),                 pcm += 4;
}

void
wz_read_pcm(wzpcm * out, uint8_t * pcm) {
  out->chunk_id        = wz_htobe32(* (uint32_t *) pcm), pcm += 4; // "RIFF"
  out->chunk_size      = wz_htole32(* (uint32_t *) pcm), pcm += 4; // following
  out->format          = wz_htobe32(* (uint32_t *) pcm), pcm += 4; // "WAVE"
  out->subchunk1_id    = wz_htobe32(* (uint32_t *) pcm), pcm += 4; // "fmt "
  out->subchunk1_size  = wz_htole32(* (uint32_t *) pcm), pcm += 4; // PCM = 16
  out->audio_format    = wz_htole16(* (uint16_t *) pcm), pcm += 2;
  out->channels        = wz_htole16(* (uint16_t *) pcm), pcm += 2;
  out->sample_rate     = wz_htole32(* (uint32_t *) pcm), pcm += 4;
  out->byte_rate       = wz_htole32(* (uint32_t *) pcm), pcm += 4;
  out->block_align     = wz_htole16(* (uint16_t *) pcm), pcm += 2;
  out->bits_per_sample = wz_htole16(* (uint16_t *) pcm), pcm += 2;
  out->subchunk2_id    = wz_htobe32(* (uint32_t *) pcm), pcm += 4; // "data"
  out->subchunk2_size  = wz_htole32(* (uint32_t *) pcm), pcm += 4;
  out->data            = pcm;
}

int
wz_read_ao(wzao * ao, wzvar * var,
           wznode * node, wzfile * file, wzctx * ctx) {
  (void) var;
  uint32_t size;
  uint32_t ms;
  uint8_t  guid[16];
  if (wz_seek(1, SEEK_CUR, file) ||
      wz_read_int(&size, file) ||
      wz_read_int(&ms, file) ||
      wz_seek(1 + 16 * 2 + 2, SEEK_CUR, file) || // major GUID and subtype GUID
      wz_read_bytes(guid, sizeof(guid), file)) return 1;
  if (memcmp(guid, ctx->guid.wav, sizeof(guid)) == 0) {
    uint8_t hsize; // header size
    if (wz_read_byte(&hsize, file)) return 1;
    uint8_t * hdr = malloc(hsize); // header
    if (hdr == NULL) return 1;
    if (wz_read_bytes(hdr, hsize, file)) return free(hdr), 1;
    wzwav wav;
    wz_read_wav(&wav, hdr);
    if (wav.extra_size != hsize - WZ_AUDIO_WAV_SIZE) {
      wz_decode_wav(hdr, hsize, node->key), wz_read_wav(&wav, hdr);
      if (wav.extra_size != hsize - WZ_AUDIO_WAV_SIZE) return free(hdr), 1;
    }
    free(hdr);
    if (wav.format == WZ_AUDIO_PCM) {
      uint8_t * pcm = malloc(WZ_AUDIO_PCM_SIZE + size);
      if (pcm == NULL) return 1;
      wz_write_pcm(pcm, &wav, size);
      if (wz_read_bytes(pcm + WZ_AUDIO_PCM_SIZE, size, file))
        return free(pcm), 1;
      ao->data = pcm, ao->size = WZ_AUDIO_PCM_SIZE + size;
      //static int id = 0;
      //char filename[100];
      //snprintf(filename, sizeof(filename), "out/%d.wav", id++);
      //FILE * outfile = fopen(filename, "wb");
      //fwrite(ao->data, 1, ao->size, outfile);
      //fclose(outfile);
      return ao->ms = ms, ao->format = wav.format, 0;
    } else if (wav.format == WZ_AUDIO_MP3) {
      uint8_t * data = malloc(size);
      if (data == NULL) return 1;
      if (wz_read_bytes(data, size, file)) return free(data), 1;
      ao->data = data, ao->size = size;
      //static int id = 0;
      //char filename[100];
      //snprintf(filename, sizeof(filename), "out/%d.mp3", id++);
      //FILE * outfile = fopen(filename, "wb");
      //fwrite(ao->data, 1, ao->size, outfile);
      //fclose(outfile);
      return ao->ms = ms, ao->format = wav.format, 0;
    } else {
      return wz_error("Unsupported audio format: 0x%hhx\n", wav.format), 1;
    }
  } else if (memcmp(guid, ctx->guid.empty, sizeof(guid)) == 0) {
    uint8_t * data = malloc(size);
    if (data == NULL) return 1;
    if (wz_read_bytes(data, size, file)) return free(data), 1;
    ao->data = data, ao->size = size;
    //static int id = 0;
    //char filename[100];
    //snprintf(filename, sizeof(filename), "out/%d.mp3", id++);
    //FILE * outfile = fopen(filename, "wb");
    //fwrite(ao->data, 1, ao->size, outfile);
    //fclose(outfile);
    return ao->ms = ms, ao->format = WZ_AUDIO_MP3, 0;
  } else {
    return wz_error("Unsupport audio GUID type: %.16s\n", guid), 1;
  }
}

void
wz_free_ao(wzao * ao) {
  free(ao->data);
}

int
wz_read_uol(wzuol * uol, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx) {
  (void) var;
  (void) ctx;
  return (wz_seek(1, SEEK_CUR, file) ||
          wz_read_pack_chars(&uol->path, node, file));
}

void
wz_free_uol(wzuol * uol) {
  wz_free_chars(&uol->path);
}

int
wz_read_obj(wzobj ** ret_obj, wzvar * var,
            wznode * node, wzfile * file, wzctx * ctx) {
  int ret = 1;
  wzobj * obj = var->val.obj;
  if (obj->alloc)
    return ret = 0, ret;
  wzstr type;
  if (wz_seek(obj->pos, SEEK_SET, file) ||
      wz_read_pack_chars(&type, node, file))
    return ret;
  if (wz_deduce_key(&node->key, &type, ctx))
    goto free_type;
  typedef int read_t(wzobj *, wzvar *, wznode *, wzfile *, wzctx *);
  static struct {
    uint8_t type;
    const char * name;
    size_t size;
    read_t * read;
  } types[] = {
    {WZ_OBJ_LIST, "Property",         sizeof(wzlist), (read_t *) wz_read_list},
    {WZ_OBJ_IMG,  "Canvas",           sizeof(wzimg),  (read_t *) wz_read_img},
    {WZ_OBJ_VEX,  "Shape2D#Convex2D", sizeof(wzvex),  (read_t *) wz_read_vex},
    {WZ_OBJ_VEC,  "Shape2D#Vector2D", sizeof(wzvec),  (read_t *) wz_read_vec},
    {WZ_OBJ_AO,   "Sound_DX8",        sizeof(wzao),   (read_t *) wz_read_ao},
    {WZ_OBJ_UOL,  "UOL",              sizeof(wzuol),  (read_t *) wz_read_uol}
  };
  assert(sizeof(types) / sizeof(types[0]) == WZ_OBJ_LEN);
  int found = 0;
  for (uint8_t i = 0; i < WZ_OBJ_LEN; i++)
    if (!wz_strcmp(&type, types[i].name)) {
      wzobj * o;
      if ((o = malloc(types[i].size)) == NULL)
        goto free_type;
      if (types[i].read(o, var, node, file, ctx)) {
        wz_error("Unable to read %s\n", types[i].name);
        goto free_obj;
      }
      o->alloc = 1;
      o->type = types[i].type;
      o->pos = obj->pos;
      * ret_obj = o;
      free(obj);
      ret = 0;
free_obj:
      if (ret)
        free(o);
      found = 1;
      break;
    }
  if (!found)
    wz_error("Unsupported object type: %.*s\n", type.len, type.bytes);
free_type:
  wz_free_chars(&type);
  return ret;
}

void
wz_free_obj(wzobj * obj) {
  if (obj->type == WZ_OBJ_LIST) wz_free_list((wzlist *) obj);
  else if (obj->type == WZ_OBJ_IMG) wz_free_img((wzimg *) obj);
  else if (obj->type == WZ_OBJ_VEX) wz_free_vex((wzvex *) obj);
  else if (obj->type == WZ_OBJ_AO) wz_free_ao((wzao *) obj);
  else if (obj->type == WZ_OBJ_UOL) wz_free_uol((wzuol *) obj);
  obj->alloc = 0;
}

int // Non recursive DFS
wz_read_obj_r(wzvar * buffer, wznode * node, wzfile * file, wzctx * ctx) {
  wzvar ** stack = malloc(100000 * sizeof(* stack));
  if (stack == NULL) return 1;
  stack[0] = buffer;
  for (uint32_t len = 1; len;) {
    wzvar * var = stack[--len];
    if (var == NULL) {
      wz_free_obj(stack[--len]->val.obj);
      continue;
    }
    indent = 0;
    for (wzvar * parent = var; parent != NULL; parent = parent->parent)
      indent += 1;
    indent -= 1;
    //pindent();//, debug(" name   ");
    //debug("%.*s\n", var->name.len, var->name.bytes);
    if (var->type == WZ_VAR_OBJ) {
      if (wz_read_obj(&var->val.obj, var, node, file, ctx)) {
        printf("failed!\n");
      } else {
        wzobj * obj = var->val.obj;
        if (obj->type == WZ_OBJ_LIST ||
            obj->type == WZ_OBJ_IMG) {
          stack[len++] = var;
          stack[len++] = NULL;
          wzlist * list = (wzlist *) obj;
          for (uint32_t i = 0; i < list->len; i++) {
            wzvar * child = &list->vars[list->len - i - 1];
            child->parent = var;
            stack[len++] = child;
          }
        } else if (obj->type == WZ_OBJ_VEX) {
          //wzvex * vex = (wzvex *) obj;
          //for (uint32_t i = 0; i < vex->len; i++) {
          //  wz2d * val = &vex->vals[i];
          //  pindent(), debug(" %"PRId32"\n", i);
          //  pindent(), debug("  %"PRId32"\n", val->x);
          //  pindent(), debug("  %"PRId32"\n", val->y);
          //}
          wz_free_obj(obj);
        } else if (obj->type == WZ_OBJ_VEC) {
          //wzvec * vec = (wzvec *) obj;
          //pindent(), debug(" %"PRId32"\n", vec->val.x);
          //pindent(), debug(" %"PRId32"\n", vec->val.y);
          wz_free_obj(obj);
        } else if (obj->type == WZ_OBJ_AO) {
          wz_free_obj(obj);
        } else if (obj->type == WZ_OBJ_UOL) {
          wz_free_obj(obj);
        }
        //pindent(), debug(" type   %.*s [%p]\n",
        //                 obj->type.len, obj->type.bytes, obj);
      }
    } else if (var->type == WZ_VAR_NIL) {
      //pindent(), debug(" (nil)\n");
    } else if (var->type == WZ_VAR_INT16 ||
               var->type == WZ_VAR_INT32 ||
               var->type == WZ_VAR_INT64) {
      //pindent(), debug(" %"PRId64"\n", var->val.i);
    } else if (var->type == WZ_VAR_FLT32 ||
               var->type == WZ_VAR_FLT64) {
      //pindent(), debug(" %f\n", var->val.f);
    } else if (var->type == WZ_VAR_STR) {
      //wzstr * val = &var->val.str;
      //pindent(), debug(" %.*s\n", val->len, val->bytes);
    }
  }
  free(stack);
  return 0;
}

int
wz_read_node_r(wznode * root, wzfile * file, wzctx * ctx) {
  wznode ** stack = malloc(10000 * sizeof(* stack));
  if (stack == NULL) return 1;
  stack[0] = root;
  uint32_t * sizes = malloc(10000 * sizeof(* sizes));
  size_t sizes_len = 0;
  uint32_t max = 0;
  //debugging = 1;
  for (uint32_t len = 1; len;) {
    wznode * node = stack[--len];
    if (node == NULL) {
      wz_free_grp(&stack[--len]->data.grp);
      continue;
    }
    wznode * parent = node;
    debug("node      ");
    while ((parent = parent->parent) != NULL)
      debug(" ");
    debug("%-30.*s [%8x]",
          node->name.len, node->name.bytes, node->addr.val);
    parent = node;
    while ((parent = parent->parent) != NULL)
      debug(" < %.*s", parent->name.len, parent->name.bytes);
    debug("\n");
    if (node->type == WZ_NODE_DIR) {
      if (wz_read_grp(&node->data.grp, node, file, ctx)) {
        printf("failed to read group!\n");
        continue;
      }
      stack[len++] = node;
      stack[len++] = NULL;
      wzgrp * grp = node->data.grp;
      for (uint32_t i = 0; i < grp->len; i++)
        stack[len++] = &grp->nodes[grp->len - i - 1];
      sizes[sizes_len++] = grp->len;
      if (max < len) max = len;
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
        debugging = 1;
      wz_read_obj_r(node->data.var, node, file, ctx);
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
        debugging = 0;
      //}
    }
  }
  printf("max node: %"PRIu32"\n", max);
  for (uint32_t i = 0; i < sizes_len; i++) {
    printf("size %"PRIu32"\n", sizes[i]);
  }
  //printf("memory used  %lu\n", memused());
  free(sizes), free(stack);
  return 0;
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
    if (var->type == WZ_VAR_OBJ) {
      if (wz_read_obj(&var->val.obj, var, node, file, file->ctx))
        break;
      if (var->val.obj->type == WZ_OBJ_UOL) {
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

void
wz_close_var(wzvar * var) {
  uint32_t capa = 2;
  wzvar ** stack = malloc(capa * sizeof(* stack));
  if (stack == NULL) return;
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
    uint32_t need = len + 2 + list->len;
    if (need > capa) {
      wzvar ** fit = realloc(stack, need * sizeof(* stack));
      if (fit == NULL) { free(stack); return; }
      stack = fit, capa = need;
    }
    len++, stack[len++] = NULL;
    for (uint32_t i = 0; i < list->len; i++)
      stack[len++] = &list->vars[i];
  }
  free(stack);
}

wzvar *
wz_open_root_var(wznode * node) {
  return wz_open_var(node->data.var, "");
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

char *
wz_get_var_name(wzvar * var) {
  return (char *) var->name.bytes;
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

void
wz_close_node(wznode * node) {
  uint32_t capa = 2;
  wznode ** stack = malloc(capa * sizeof(* stack));
  if (stack == NULL) return;
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
      wz_close_var(node->data.var);
      continue;
    }
    wzgrp * grp = node->data.grp;
    uint32_t need = len + 2 + grp->len;
    if (need > capa) {
      wznode ** fit = realloc(stack, need * sizeof(* stack));
      if (fit == NULL) { free(stack); return; }
      stack = fit, capa = need;
    }
    len++, stack[len++] = NULL;
    for (uint32_t i = 0; i < grp->len; i++)
      stack[len++] = &grp->nodes[i];
  }
  free(stack);
}

wznode *
wz_open_root_node(wzfile * file) {
  return wz_open_node(&file->root, "");
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

char *
wz_get_node_name(wznode * node) {
  return (char *) node->name.bytes;
}

int
wz_read_file(wzfile * file, FILE * raw, wzctx * ctx) {
  file->raw = raw, file->pos = 0;
  if (fseek(raw, 0, SEEK_END)) return 1;
  long size = ftell(raw);
  if (size < 0) return 1;
  file->size = (uint32_t) size;
  rewind(raw);
  if (wz_read_head(&file->head, file) ||
      wz_read_le16(&file->ver.enc, file)) return 1;
  if (wz_deduce_ver(&file->ver.dec, &file->ver.hash, file->ver.enc, file, ctx))
    return wz_free_head(&file->head), 1;
  //printf("memory used  %lu\n", memused());
  return file->ctx = ctx, 0;
}

void
wz_free_file(wzfile * file) {
  wz_close_node(&file->root);
  wz_free_head(&file->head);
}

int
wz_open_file(wzfile * file, const char * filename, wzctx * ctx) {
  file->raw = fopen(filename, "rb");
  if (file->raw == NULL) return perror(filename), 1;
  if (wz_read_file(file, file->raw, ctx)) return fclose(file->raw) != 0;
  return 0;
}

int
wz_close_file(wzfile * file) {
  wz_free_file(file);
  if (fclose(file->raw)) return perror("Cannot close file"), 1;
  return 0;
}

int
wz_init_ctx(wzctx * ctx) {
  if (wz_init_keys(&ctx->keys, &ctx->klen)) return 1;
  wz_init_palette(&ctx->palette);
  wz_init_guid(&ctx->guid);
  return 0;
}

void
wz_free_ctx(wzctx * ctx) {
  wz_free_keys(ctx->keys, ctx->klen);
}
