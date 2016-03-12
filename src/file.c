// Standard Library

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

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
wz_decode_chars(wzchr * buffer, wzkey * key) {
  if (key == NULL) return 0;
  if (buffer->len > key->len)
    return wz_error("String length %"PRIu32" > %"PRIu32"\n",
                    buffer->len, key->len), 1;
  if (buffer->enc == WZ_ENC_ASCII) {
    uint8_t * bytes = buffer->bytes;
    uint8_t mask = 0xaa;
    uint32_t len = buffer->len / sizeof(mask);
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= mask++ ^ key->bytes[i];
  } else { // WZ_ENC_UTF16LE
    uint16_t * bytes = (uint16_t *) buffer->bytes;
    uint16_t mask = 0xaaaa;
    uint32_t len = buffer->len / sizeof(mask);
    for (uint32_t i = 0; i < len; i++)
      bytes[i] ^= wz_htole16(mask++ ^ wz_le16toh(((uint16_t *) key->bytes)[i]));
  }
  return 0;
}

int // read characters (ascii or utf16le)
wz_read_chars(wzchr * buffer, wzkey * key, wzfile * file) {
  int8_t byte;
  if (wz_read_byte((uint8_t *) &byte, file)) return 1;
  int32_t size = byte;
  int ascii = size < 0;
  if (ascii) { // ascii
    if (size == INT8_MIN) {
      if (wz_read_le32((uint32_t *) &size, file)) return 1;
    } else {
      size *= -1;
    }
  } else { // utf16le
    if (size == INT8_MAX) {
      if (wz_read_le32((uint32_t *) &size, file)) return 1;
    }
    size *= 2;
  }
  wzstr str;
  if (wz_read_str(&str, (uint32_t) size, file)) return 1;
  wzchr chars = {
    .len   = str.len,
    .bytes = str.bytes,
    .enc   = ascii ? WZ_ENC_ASCII : WZ_ENC_UTF16LE
  };
  if (wz_decode_chars(&chars, key)) return wz_free_chars(&chars), 1;
  return * buffer = chars, 0;
}

void
wz_free_chars(wzchr * buffer) {
  free(buffer->bytes);
}

uint32_t
wz_rotl32(uint32_t x, uint32_t n) {
  return (x << n) | (x >> (32 - n));
}

void
wz_decode_addr(wzaddr * addr, wzfile * file) {
  uint32_t key = 0x581c3f6d;
  uint32_t decoded = ~(addr->pos - file->head.start);
  decoded = decoded * file->ver.hash - key;
  decoded = wz_rotl32(decoded, decoded & 0x1f);
  decoded = (decoded ^ addr->val) + file->head.start * 2;
  addr->val = decoded;
}

int // This function should not be called after address decoded
wz_read_addr(wzaddr * addr, wzfile * file) {
  uint32_t pos = file->pos;
  if (wz_read_le32(&addr->val, file)) return 1;
  addr->pos = pos;
  if (file->ver.hash == 0) return 0;
  return wz_decode_addr(addr, file), 0;
}

int
wz_seek(uint32_t pos, int origin, wzfile * file) {
  if (pos > INT32_MAX) return 1;
  if (fseek(file->raw, pos, origin)) return 1;
  if (origin == SEEK_CUR) return file->pos += pos, 0;
  return file->pos = pos, 0;
}

int
wz_read_node_body(wznode * node, wzfile * file) {
  if (wz_read_int(&node->size, file) ||
      wz_read_int(&node->check, file) ||
      wz_read_addr(&node->addr, file)) return 1;
  if (WZ_IS_NODE_DIR(node->type)) {
    return node->data.grp = NULL, 0;
  } else if (WZ_IS_NODE_FILE(node->type)) {
    wzvar * var = malloc(sizeof(* var));
    if (var == NULL) return 1;
    var->parent = NULL;
    var->name = (wzchr) {.len = 0, .bytes = NULL, .enc = WZ_ENC_ASCII};
    var->type = 0x09;
    wzobj * obj = malloc(sizeof(* obj));
    if (obj == NULL) return free(var), 1;
    obj->alloc = 0, obj->pos = node->addr.val;
    var->val.obj = obj;
    return node->data.var = var, node->key = NULL, 0;
  } else {
    return wz_error("Unsupported node type: 0x%02hhx\n", node->type), 1;
  }
}

int
wz_read_node(wznode * node, wzfile * file, wzctx * ctx) {
  if (wz_read_byte(&node->type, file)) return 1;
  if (WZ_IS_NODE_NONE(node->type)) { // unknown 10 bytes
    return wz_seek(10, SEEK_CUR, file);
  } else if (WZ_IS_NODE_LINK(node->type)) {
    uint32_t addr;
    if (wz_read_le32(&addr, file)) return 1;
    uint32_t pos = file->pos;
    if (wz_seek(file->head.start + addr, SEEK_SET, file) ||
        wz_read_byte(&node->type, file) ||
        wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, ctx) ||
        wz_seek(pos, SEEK_SET, file) ||
        wz_read_node_body(node, file))
      return wz_free_chars(&node->name), 1;
    return 0;
  } else if (WZ_IS_NODE_DIR(node->type) ||
             WZ_IS_NODE_FILE(node->type)) {
    if (wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, ctx) ||
        wz_read_node_body(node, file))
      return wz_free_chars(&node->name), 1;
    return 0;
  } else {
    return wz_error("Unsupported node type: 0x%02hhx\n", node->type), 1;
  }
}

void
wz_free_node(wznode * node) {
  if (WZ_IS_NODE_DIR(node->type) ||
      WZ_IS_NODE_FILE(node->type))
    wz_free_chars(&node->name);
  if (WZ_IS_NODE_FILE(node->type))
    free(node->data.var->val.obj), free(node->data.var);
}

int
wz_read_grp(wzgrp ** buffer, wznode * node, wzfile * file, wzctx * ctx) {
  if (node->alloc) return 0;
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
    nodes[i].parent = node, nodes[i].alloc = 0;
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
    .alloc = 0,
    .type = 0x03,
    .name = {.len = 0, .bytes = NULL, .enc = WZ_ENC_ASCII},
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

int
wz_encode_ver(wzver * ver) {
  uint8_t chars[5 + 1]; // 0xffff.to_s.size == 5
  int len = sprintf((char *) chars, "%"PRIu16, ver->dec);
  if (len < 0) return 1;
  ver->hash = 0;
  for (int i = 0; i < len; i++) ver->hash = (ver->hash << 5) + chars[i] + 1;
  ver->enc = (uint16_t) (0xff ^
                         (ver->hash >> 24 & 0xff) ^
                         (ver->hash >> 16 & 0xff) ^
                         (ver->hash >>  8 & 0xff) ^
                         (ver->hash       & 0xff));
  return 0;
}

int
wz_valid_ver(wzver * ver, wznode * root, wzfile * file) {
  wzfile copy = * file;
  copy.ver.hash = ver->hash;
  wzgrp * grp = root->data.grp;
  for (uint32_t i = 0; i < grp->len; i++) {
    wznode * node = &grp->nodes[i];
    if (WZ_IS_NODE_DIR(node->type) ||
        WZ_IS_NODE_FILE(node->type)) {
      wzaddr addr = node->addr;
      wz_decode_addr(&addr, &copy);
      if (addr.val > copy.size) return 1;
    }
  }
  return 0;
}

int
wz_guess_ver(wzver * ver, wznode * root, wzfile * file) {
  wzver guess;
  for (guess.dec = 0; guess.dec < 512; guess.dec++) {
    if (wz_encode_ver(&guess)) return 1;
    if (guess.enc == ver->enc && !wz_valid_ver(&guess, root, file))
      return * ver = guess, 0;
  }
  return 1;
}

int
wz_deduce_ver(wzver * ver, wzfile * file, wzctx * ctx) {
  file->ver.hash = 0, file->key = NULL;
  wznode root = file->root;
  if (wz_read_grp(&root.data.grp, &root, file, ctx)) return 1;
  if (wz_guess_ver(ver, &root, file))
    return wz_free_grp(&root.data.grp), 1;
  return wz_free_grp(&root.data.grp), 0;
}

void
wz_decode_aes(uint8_t * plain, uint8_t * cipher, size_t len,
              uint8_t * key, uint8_t * iv) {
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
wz_encode_aes(wzaes * aes) {
  uint8_t * plain = aes->plain;
  uint8_t * cipher = aes->cipher;
  uint8_t * iv = aes->iv;
  uint32_t len = aes->len;
  aes256_context ctx;
  aes256_init(&ctx, aes->key);
  for (uint32_t i = 0; i < len; i += 16) {
    memcpy(cipher, plain, 16);
    for (uint8_t j = 0; j < 16; j++)
      cipher[j] ^= iv[j];
    aes256_encrypt_ecb(&ctx, cipher);
    plain += 16, iv = cipher, cipher += 16;
  }
  aes256_done(&ctx);
}

int
wz_init_aes(wzaes * aes) {
  uint8_t key[] =
    "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
    "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00";
  memcpy(aes->key, key, sizeof(key));
  aes->len = 0x10000; // supported image chunk or string size
  if ((aes->plain = malloc(aes->len * 2)) == NULL) return 1;
  memset(aes->plain, 0, aes->len);
  aes->cipher = aes->plain + aes->len;
  return 0;
}

void
wz_free_aes(wzaes * aes) {
  free(aes->plain);
}

int
wz_init_key(wzkey * key, wzaes * aes) {
  uint8_t * bytes = malloc(aes->len);
  if (bytes == NULL) return 1;
  return key->bytes = bytes, 0;
}

void
wz_set_key(wzkey * key, wzaes * aes) {
  memcpy(key->bytes, aes->cipher, aes->len);
  key->len = aes->len;
}

void
wz_free_key(wzkey * key) {
  free(key->bytes);
}

int
wz_init_keys(wzkey ** buffer, size_t * len) {
  uint8_t * values[] = { // These values is used for generating iv (aes)
    (uint8_t *) "\x4d\x23\xc7\x2b",
    (uint8_t *) "\xb9\x7d\x63\xe9"
  };
  size_t vlen = sizeof(values) / sizeof(* values);
  wzkey * keys = malloc(sizeof(* keys) * (vlen + 1));
  if (keys == NULL) return 1;
  wzaes aes;
  if (wz_init_aes(&aes)) return free(keys), 1;
  for (size_t i = 0; i < vlen; i++) {
    for (size_t j = 0; j < 16; j += 4) memcpy(aes.iv + j, values[i], 4);
    wzkey * key = &keys[i];
    if (wz_init_key(key, &aes)) {
      for (size_t k = 0; k < i; k++)
        wz_free_key(keys + k);
      return wz_free_aes(&aes), free(keys), 1;
    }
    wz_encode_aes(&aes);
    wz_set_key(key, &aes);
  }
  wzkey * key = &keys[vlen];
  if (wz_init_key(key, &aes)) {
    for (size_t k = 0; k < vlen; k++)
      wz_free_key(keys + k);
    return wz_free_aes(&aes), free(keys), 1;
  }
  // plain can be used as an empty cipher
  aes.cipher = aes.plain;
  wz_set_key(key, &aes);
  return wz_free_aes(&aes), * buffer = keys, * len = vlen + 1, 0;
}

void
wz_free_keys(wzkey * keys, size_t len) {
  for (size_t i = 0; i < len; i++)
    wz_free_key(keys + i);
  free(keys);
}

int // if string key is found, the string is also decoded.
wz_deduce_key(wzkey ** buffer, wzchr * name, wzctx * ctx) {
  if (* buffer != NULL) return 0;
  for (size_t i = 0; i < ctx->klen; i++) {
    wzkey * key = &ctx->keys[i];
    if (wz_decode_chars(name, key)) continue;
    for (uint32_t j = 0; j < name->len && isprint(name->bytes[j]); j++)
      if (j == name->len - 1) return * buffer = key, 0;
    if (wz_decode_chars(name, key)) continue;
  }
  return wz_error("Cannot deduce the string key\n"), 1;
}

int // read packed string
wz_read_pack_chars(wzchr * buffer, wznode * node, wzfile * file) {
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
wz_is_chars(wzchr * actual, const char * expected) {
  return (actual->len == strlen(expected) &&
          !memcmp(actual->bytes, expected, actual->len));
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
wz_read_prim(wzprim * val, uint8_t type, wznode * node, wzfile * file) {
  if (WZ_IS_VAR_NONE(type)) {
    return 0;
  } else if (WZ_IS_VAR_INT16(type)) {
    int16_t int16;
    if (wz_read_le16((uint16_t *) &int16, file)) return 1;
    return val->i = int16, 0;
  } else if (WZ_IS_VAR_INT32(type)) {
    int32_t int32;
    if (wz_read_int((uint32_t *) &int32, file)) return 1;
    return val->i = int32, 0;
  } else if (WZ_IS_VAR_INT64(type)) {
    int64_t int64;
    if (wz_read_long((uint64_t *) &int64, file)) return 1;
    return val->i = int64, 0;
  } else if (WZ_IS_VAR_FLOAT32(type)) {
    int8_t set;
    if (wz_read_byte((uint8_t *) &set, file)) return 1;
    if (set == INT8_MIN) {
      uint32_t float32;
      if (wz_read_le32(&float32, file)) return 1;
      return val->f = * (float *) &float32, 0;
    } else {
      return val->f = 0.0, 0;
    }
  } else if (WZ_IS_VAR_FLOAT64(type)) {
    uint64_t float64;
    if (wz_read_le64(&float64, file)) return 1;
    return val->f = * (double *) &float64, 0;
  } else if (WZ_IS_VAR_STRING(type)) {
    return wz_read_pack_chars(&val->str, node, file);
  } else if (WZ_IS_VAR_OBJECT(type)) {
    uint32_t size;
    if (wz_read_le32(&size, file)) return 1;
    wzobj * obj = malloc(sizeof(* obj));
    if (obj == NULL) return 1;
    obj->alloc = 0, obj->pos = file->pos;
    if (wz_seek(size, SEEK_CUR, file)) return free(obj), 1;
    return val->obj = obj, 0;
  } else {
    return wz_error("Unsupported primitive type: 0x%02hhx\n", type), 1;
  }
}

void
wz_free_prim(wzprim * val, uint8_t type) {
  if (WZ_IS_VAR_STRING(type))      wz_free_chars(&val->str);
  else if (WZ_IS_VAR_OBJECT(type)) free(val->obj);
}

int
wz_read_var(wzvar * var, wznode * node, wzfile * file) {
  if (wz_read_pack_chars(&var->name, node, file)) return 1;
  if (wz_read_byte(&var->type, file) ||
      wz_read_prim(&var->val, var->type, node, file))
    return wz_free_chars(&var->name), 1;
  return 0;
}

void
wz_free_var(wzvar * var) {
  wz_free_prim(&var->val, var->type);
  wz_free_chars(&var->name);
}

int
wz_read_list(wzlist * list, wznode * node, wzfile * file) {
  if (wz_seek(2, SEEK_CUR, file)) return 1;
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wzvar * vars = malloc(sizeof(* vars) * len);
  if (vars == NULL) return 1;
  for (uint32_t i = 0; i < len; i++)
    if (wz_read_var(vars + i, node, file)) {
      for (uint32_t j = 0; j < i; j++)
        wz_free_var(vars + j);
      return free(vars), 1;
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
  codes[2].b = (uint8_t) (codes[0].b * 2 + codes[1].b) / 3; // the third code
  codes[2].g = (uint8_t) (codes[0].g * 2 + codes[1].g) / 3;
  codes[2].r = (uint8_t) (codes[0].r * 2 + codes[1].r) / 3;
  codes[2].a = 0xff;
  codes[3].b = (uint8_t) (codes[0].b + codes[1].b * 2) / 3; // the fourth code
  codes[3].g = (uint8_t) (codes[0].g + codes[1].g * 2) / 3;
  codes[3].r = (uint8_t) (codes[0].r + codes[1].r * 2) / 3;
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
wz_read_img(wzimg * img, wznode * node, wzfile * file, wzctx * ctx) {
  if (wz_seek(1, SEEK_CUR, file)) return 1;
  uint8_t list;
  if (wz_read_byte(&list, file)) return 1;
  img->len = 0, img->vars = NULL;
  if (list == 1 && wz_read_list((wzlist *) img, node, file)) return 1;
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
  wzchr type;
  if (wz_read_pack_chars(&type, node, file)) return 1;
  if (WZ_IS_OBJ_VECTOR(&type))
    return wz_free_chars(&type),
           wz_read_2d(val, file);
  else
    return wz_free_chars(&type),
           wz_error("Convex should contain only vectors\n"), 1;
}

int
wz_read_vex(wzvex * vex, wznode * node, wzfile * file) {
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
wz_read_vec(wzvec * vec, wzfile * file) {
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
wz_read_ao(wzao * ao, wznode * node, wzfile * file, wzctx * ctx) {
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
wz_read_uol(wzuol * uol, wznode * node, wzfile * file) {
  return (wz_seek(1, SEEK_CUR, file) ||
          wz_read_pack_chars(&uol->path, node, file));
}

void
wz_free_uol(wzuol * uol) {
  wz_free_chars(&uol->path);
}

int
wz_read_obj(wzobj ** buffer, wznode * node, wzfile * file, wzctx * ctx) {
  wzobj * obj = * buffer;
  if (obj->alloc) return 0;
  wzchr type;
  if (wz_seek(obj->pos, SEEK_SET, file) ||
      wz_read_pack_chars(&type, node, file)) return 1;
  if (wz_deduce_key(&node->key, &type, ctx))
    return wz_free_chars(&type), 1;
  if (WZ_IS_OBJ_PROPERTY(&type)) {
    wzlist * list = malloc(sizeof(* list));
    if (list == NULL) return wz_free_chars(&type), 1;
    if (wz_read_list(list, node, file)) {
      wz_error("Unable to read list\n");
      return free(list), wz_free_chars(&type), 1;
    }
    list->alloc = 0, list->pos = obj->pos, list->type = type;
    return * buffer = (wzobj *) list, free(obj), 0;
  } else if (WZ_IS_OBJ_CANVAS(&type)) {
    wzimg * img = malloc(sizeof(* img));
    if (img == NULL) return wz_free_chars(&type), 1;
    if (wz_read_img(img, node, file, ctx)) {
      wz_error("Unable to read canvas\n");
      return free(img), wz_free_chars(&type), 1;
    }
    img->alloc = 0, img->pos = obj->pos, img->type = type;
    return * buffer = (wzobj *) img, free(obj), 0;
  } else if (WZ_IS_OBJ_CONVEX(&type)) {
    wzvex * vex = malloc(sizeof(* vex));
    if (vex == NULL) return wz_free_chars(&type), 1;
    if (wz_read_vex(vex, node, file)) {
      wz_error("Unable to read convex\n");
      return free(vex), wz_free_chars(&type), 1;
    }
    vex->alloc = 0, vex->pos = obj->pos, vex->type = type;
    return * buffer = (wzobj *) vex, free(obj), 0;
  } else if (WZ_IS_OBJ_VECTOR(&type)) {
    wzvec * vec = malloc(sizeof(* vec));
    if (vec == NULL) return wz_free_chars(&type), 1;
    if (wz_read_vec(vec, file)) {
      wz_error("Unable to read vector\n");
      return free(vec), wz_free_chars(&type), 1;
    }
    vec->alloc = 0, vec->pos = obj->pos, vec->type = type;
    return * buffer = (wzobj *) vec, free(obj), 0;
  } else if (WZ_IS_OBJ_SOUND(&type)) {
    wzao * ao = malloc(sizeof(* ao));
    if (ao == NULL) return wz_free_chars(&type), 1;
    if (wz_read_ao(ao, node, file, ctx)) {
      wz_error("Unable to read audio\n");
      return free(ao), wz_free_chars(&type), 1;
    }
    ao->alloc = 0, ao->pos = ao->pos, ao->type = type;
    return * buffer = (wzobj *) ao, free(obj), 0;
  } else if (WZ_IS_OBJ_UOL(&type)) {
    wzuol * uol = malloc(sizeof(* uol));
    if (uol == NULL) return wz_free_chars(&type), 1;
    if (wz_read_uol(uol, node, file)) {
      wz_error("Unable to read uol\n");
      return free(uol), wz_free_chars(&type), 1;
    }
    uol->alloc = 0, uol->pos = obj->pos, uol->type = type;
    return * buffer = (wzobj *) uol, free(obj), 0;
  } else {
    return wz_error("Unsupported object type: %.*s\n", type.len, type.bytes), 1;
  }
}

void
wz_free_obj(wzobj * obj) {
  if (WZ_IS_OBJ_PROPERTY(&obj->type)) wz_free_list((wzlist *) obj);
  else if (WZ_IS_OBJ_CANVAS(&obj->type)) wz_free_img((wzimg *) obj);
  else if (WZ_IS_OBJ_CONVEX(&obj->type)) wz_free_vex((wzvex *) obj);
  else if (WZ_IS_OBJ_SOUND(&obj->type)) wz_free_ao((wzao *) obj);
  else if (WZ_IS_OBJ_UOL(&obj->type)) wz_free_uol((wzuol *) obj);
  wz_free_chars(&obj->type);
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
    if (WZ_IS_VAR_OBJECT(var->type)) {
      if (wz_read_obj(&var->val.obj, node, file, ctx)) {
        printf("failed!\n");
      } else {
        wzobj * obj = var->val.obj;
        if (WZ_IS_OBJ_PROPERTY(&obj->type) ||
            WZ_IS_OBJ_CANVAS(&obj->type)) {
          stack[len++] = var;
          stack[len++] = NULL;
          wzlist * list = (wzlist *) obj;
          for (uint32_t i = 0; i < list->len; i++) {
            wzvar * child = &list->vars[list->len - i - 1];
            child->parent = var;
            stack[len++] = child;
          }
        } else if (WZ_IS_OBJ_CONVEX(&obj->type)) {
          //wzvex * vex = (wzvex *) obj;
          //for (uint32_t i = 0; i < vex->len; i++) {
          //  wz2d * val = &vex->vals[i];
          //  pindent(), debug(" %"PRId32"\n", i);
          //  pindent(), debug("  %"PRId32"\n", val->x);
          //  pindent(), debug("  %"PRId32"\n", val->y);
          //}
          wz_free_obj(obj);
        } else if (WZ_IS_OBJ_VECTOR(&obj->type)) {
          //wzvec * vec = (wzvec *) obj;
          //pindent(), debug(" %"PRId32"\n", vec->val.x);
          //pindent(), debug(" %"PRId32"\n", vec->val.y);
          wz_free_obj(obj);
        } else if (WZ_IS_OBJ_SOUND(&obj->type)) {
          wz_free_obj(obj);
        } else if (WZ_IS_OBJ_UOL(&obj->type)) {
          wz_free_obj(obj);
        }
        //pindent(), debug(" type   %.*s [%p]\n",
        //                 obj->type.len, obj->type.bytes, obj);
      }
    } else if (WZ_IS_VAR_NONE(var->type)) {
      //pindent(), debug(" (nil)\n");
    } else if (WZ_IS_VAR_INT16(var->type) ||
               WZ_IS_VAR_INT32(var->type) ||
               WZ_IS_VAR_INT64(var->type)) {
      //pindent(), debug(" %"PRId64"\n", var->val.i);
    } else if (WZ_IS_VAR_FLOAT32(var->type) ||
               WZ_IS_VAR_FLOAT64(var->type)) {
      //pindent(), debug(" %f\n", var->val.f);
    } else if (WZ_IS_VAR_STRING(var->type)) {
      wzchr * val = &var->val.str;
      if (val->enc == WZ_ENC_ASCII) {
        //pindent(), debug(" %.*s\n", val->len, val->bytes);
      } else if (val->len > 0) {
        pindent(), printf(" ");
        for (uint32_t i = 0; i < val->len;) {
          uint8_t  utf16le[WZ_UTF16LE_MAX_LEN] = {0};
          size_t   utf16le_len;
          uint32_t code;
          uint8_t  utf8[WZ_UTF8_MAX_LEN];
          size_t   utf8_len;
          memcpy(utf16le, val->bytes + i,
                 val->len - i < sizeof(utf16le) ?
                 val->len - i : sizeof(utf16le));
          if (wz_utf16le_len(&utf16le_len, utf16le) ||
              wz_utf16le_to_code(&code, utf16le) ||
              wz_code_to_utf8(utf8, code) ||
              wz_code_to_utf8_len(&utf8_len, code)) return 1;
          printf("%.*s", (int) utf8_len, utf8);
          i += (uint32_t) utf16le_len;
        }
        printf("\n");
      }
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
    if (WZ_IS_NODE_DIR(node->type)) {
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
    } else if (WZ_IS_NODE_FILE(node->type)) {
      //if (wz_is_chars(&node->name, "WorldMap21.img")) {
      //if (wz_is_chars(&node->name, "000020000.img")) {
      //if (wz_is_chars(&node->name, "NightMarketTW.img")) { // convex and image
      //if (wz_is_chars(&node->name, "acc8.img")) { // vector
      //if (wz_is_chars(&node->name, "926120300.img")) { // multiple string key
      //if (wz_is_chars(&node->name, "926120200.img")) { // multiple string key ? and minimap
      //if (wz_is_chars(&node->name, "Effect2.img")) { // multiple string key x
      //if (wz_is_chars(&node->name, "dryRock.img")) { // canvas, scale 4
      //if (wz_is_chars(&node->name, "vicportTown.img")) { // last canvas
      //if (wz_is_chars(&node->name, "MapHelper.img")) { // audio
      //if (wz_is_chars(&node->name, "BgmGL.img")) { // audio
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
  if (wz_deduce_ver(&file->ver, file, ctx))
    return wz_free_head(&file->head), 1;
  //printf("memory used  %lu\n", memused());
  return 0;
}

void
wz_free_file(wzfile * file) {
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
