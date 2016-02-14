#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <iconv.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <zlib.h>
#include "byteorder.h"
#include "file.h"

void
wz_error(const char * format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int
wz_read_data(void * buffer, size_t len, wzfile * file) {
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
wz_read_bytes(uint8_t * buffer, size_t len, wzfile * file) {
  return wz_read_data(buffer, len, file);
}

void
wz_init_str(wzstr * buffer) {
  buffer->bytes = NULL;
}

int // read string with malloc
wz_read_str(wzstr * buffer, size_t len, wzfile * file) {
  if (len > INT32_MAX) return wz_error("String length > INT32_MAX"), 1;
  uint8_t * bytes = malloc(len);
  if (bytes == NULL ||
      wz_read_bytes(bytes, len, file)) return free(bytes), 1;
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
  if (wz_read_str(&str, size, file)) return 1;
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
  decoded = wz_rotl32(decoded, decoded & 0x1F);
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
wz_seek(uint64_t pos, int origin, wzfile * file) {
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
    var->type = 0x09, var->val.pos = node->addr.val;
    return node->data.var = var, node->key = NULL, 0;
  } else {
    return wz_error("Unsupported node type: 0x%02hhx\n", node->type), 1;
  }
}

int
wz_read_node(wznode * node, wzfile * file) {
  if (wz_read_byte(&node->type, file)) return 1;
  if (WZ_IS_NODE_NONE(node->type)) { // unknown 10 bytes
    return wz_seek(10, SEEK_CUR, file);
  } else if (WZ_IS_NODE_LINK(node->type)) {
    uint32_t addr;
    if (wz_read_le32(&addr, file)) return 1;
    uint64_t pos = file->pos;
    if (wz_seek(file->head.start + addr, SEEK_SET, file) ||
        wz_read_byte(&node->type, file) ||
        wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, file) ||
        wz_seek(pos, SEEK_SET, file) ||
        wz_read_node_body(node, file))
      return wz_free_chars(&node->name), 1;
    return 0;
  } else if (WZ_IS_NODE_DIR(node->type) ||
             WZ_IS_NODE_FILE(node->type)) {
    if (wz_read_chars(&node->name, file->key, file)) return 1;
    if (wz_deduce_key(&file->key, &node->name, file) ||
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
    free(node->data.var);
}

void
wz_decode_node_body(wznode * node, wzfile * file) {
  wz_decode_addr(&node->addr, file);
  if (WZ_IS_NODE_FILE(node->type))
    node->data.var->val.pos = node->addr.val;
}

int
wz_decode_node(wznode * node, wzfile * file) {
  if (WZ_IS_NODE_NONE(node->type)) {
    return 0;
  } else if (WZ_IS_NODE_DIR(node->type) ||
             WZ_IS_NODE_FILE(node->type)) {
    return wz_decode_node_body(node, file), 0;
  } else {
    return 1;
  }
}

int
wz_read_grp(wzgrp ** buffer, wznode * node, wzfile * file) {
  if (* buffer != NULL) return 0;
  if (node != NULL && wz_seek(node->addr.val, SEEK_SET, file)) return 1;
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wzgrp * grp = malloc(sizeof(* grp) + len * sizeof(* grp->nodes));
  if (grp == NULL) return 1;
  wznode * nodes = (wznode *) (grp + 1);
  for (uint32_t i = 0; i < len; i++) {
    if (wz_read_node(nodes + i, file)) {
      for (uint32_t j = 0; j < i; j++)
        wz_free_node(nodes + j);
      return free(grp), 1;
    }
    nodes[i].parent = node;
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
wz_decode_grp(wzgrp * grp, wzfile * file) {
  for (uint32_t i = 0; i < grp->len; i++)
    if (wz_decode_node(grp->nodes + i, file)) return 1;
  return 0;
}

int
wz_read_head(wzhead * head, wzfile * file) {
  wz_init_str(&head->copy);
  if (wz_read_bytes(head->ident, sizeof(head->ident), file) ||
      wz_read_le64(&head->size, file) ||
      wz_read_le32(&head->start, file) ||
      wz_read_str(&head->copy, head->start - file->pos, file)) return 1;
  printf("ident      %.4s\n",      head->ident);
  printf("size       %"PRIu64"\n", head->size);
  printf("start      %08X\n",      head->start);
  printf("copyright  %.*s\n",      head->copy.len, head->copy.bytes);
  return 0;
}

void
wz_free_head(wzhead * head) {
  wz_free_str(&head->copy);
}

int
wz_encode_ver(wzver * ver) {
  char chars[5 + 1]; // 0xffff.to_s.size == 5
  int len = sprintf(chars, "%"PRIu16, ver->dec);
  if (len < 0) return 1;
  ver->hash = 0;
  for (int i = 0; i < len; i++) ver->hash = (ver->hash << 5) + chars[i] + 1;
  ver->enc = 0xff ^
    (ver->hash >> 24 & 0xff) ^
    (ver->hash >> 16 & 0xff) ^
    (ver->hash >>  8 & 0xff) ^
    (ver->hash       & 0xff);
  return 0;
}

int
wz_valid_ver(wzver * ver, wzfile * file) {
  uint32_t copy = file->ver.hash;
  file->ver.hash = ver->hash;
  uint32_t len = file->root.data.grp->len;
  for (uint32_t i = 0; i < len; i++) {
    wznode * node = &file->root.data.grp->nodes[i];
    if (WZ_IS_NODE_DIR(node->type) ||
        WZ_IS_NODE_FILE(node->type)) {
      wzaddr addr = node->addr;
      wz_decode_addr(&addr, file);
      if (addr.val > file->size)
        return file->ver.hash = copy, 1;
    }
  }
  return file->ver.hash = copy, 0;
}

int
wz_decode_ver(wzver * ver, wzfile * file) {
  wzver guess;
  for (guess.dec = 0; guess.dec < 512; guess.dec++) {
    if (wz_encode_ver(&guess)) return 1;
    if (guess.enc == ver->enc && !wz_valid_ver(&guess, file))
      return * ver = guess, 0;
  }
  return 1;
}

int
wz_alloc_crypto(void) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  return CONF_modules_load_file(NULL, NULL,
                                CONF_MFLAGS_DEFAULT_SECTION |
                                CONF_MFLAGS_IGNORE_MISSING_FILE) != 1;
}

void
wz_dealloc_crypto(void) {
  CONF_modules_unload(1);
  CRYPTO_cleanup_all_ex_data();
  EVP_cleanup();
  ERR_remove_state(0);
  ERR_free_strings();
}

int
wz_decode_aes(uint8_t * plain, uint8_t * cipher, size_t len,
              uint8_t * key, uint8_t * iv) {
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return ERR_print_errors_fp(stderr), 1;
  const EVP_CIPHER * impl = EVP_aes_256_cbc();
  int size;
  if (EVP_DecryptInit_ex(ctx, impl, NULL, key, iv) != 1 ||
      EVP_DecryptUpdate(ctx, plain, &size, cipher, len) != 1)
    return ERR_print_errors_fp(stderr), EVP_CIPHER_CTX_free(ctx), 1;
  return EVP_CIPHER_CTX_free(ctx), 0;
}

int
wz_encode_aes(wzaes * aes) {
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return ERR_print_errors_fp(stderr), 1;
  const EVP_CIPHER * impl = EVP_aes_256_cbc();
  int size;
  if (EVP_EncryptInit_ex(ctx, impl, NULL, aes->key, aes->iv) != 1 ||
      EVP_EncryptUpdate(ctx, aes->cipher, &size, aes->plain, aes->len) != 1)
    return ERR_print_errors_fp(stderr), EVP_CIPHER_CTX_free(ctx), 1;
  return EVP_CIPHER_CTX_free(ctx), 0;
}

int
wz_init_aes(wzaes * aes) {
  uint8_t key[32] =
    "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
    "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00";
  memcpy(aes->key, key, sizeof(key));
  aes->len = 0x10000; // supported image chunk or string size
  if ((aes->plain = malloc(aes->len * 2)) == NULL) return 1;
  memset(aes->plain, 0, aes->len);
  aes->cipher = aes->plain + aes->len;
  wz_alloc_crypto();
  return 0;
}

void
wz_free_aes(wzaes * aes) {
  wz_dealloc_crypto();
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
wz_init_keys(wzkey * keys) {
  uint8_t values[][4] = { // These values is used for generating iv (aes)
    "\x4d\x23\xc7\x2b",
    "\xb9\x7d\x63\xe9"
  };
  wzaes aes;
  if (wz_init_aes(&aes)) return 1;
  size_t times = sizeof(values) / sizeof(* values);
  for (size_t i = 0; i < times; i++) {
    for (size_t j = 0; j < 16; j += 4) memcpy(aes.iv + j, values[i], 4);
    wzkey * key = &keys[i];
    if (wz_init_key(key, &aes)) {
      for (size_t k = 0; k < i; k++)
        wz_free_key(keys + k);
      return wz_free_aes(&aes), 1;
    }
    if (wz_encode_aes(&aes)) {
      for (size_t k = 0; k <= i; k++)
        wz_free_key(keys + k);
      return wz_free_aes(&aes), 1;
    }
    wz_set_key(key, &aes);
  }
  wzkey * key = &keys[times];
  if (wz_init_key(key, &aes)) {
    for (size_t k = 0; k < times; k++)
      wz_free_key(keys + k);
    return wz_free_aes(&aes), 1;
  }
  // plain can be used as an empty cipher
  aes.cipher = aes.plain;
  wz_set_key(key, &aes);
  return wz_free_aes(&aes), 0;
}

void
wz_free_keys(wzfile * file) {
  size_t len = sizeof(file->keys) / sizeof(* file->keys);
  for (size_t i = 0; i < len; i++)
    wz_free_key(file->keys + i);
}

int // if string key is found, the string is also decoded.
wz_deduce_key(wzkey ** buffer, wzchr * name, wzfile * file) {
  if (* buffer != NULL) return 0;
  size_t len = sizeof(file->keys) / sizeof(* file->keys);
  for (size_t i = 0; i < len; i++) {
    wzkey * key = &file->keys[i];
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
    uint64_t pos = file->pos;
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
wz_is_chars(wzchr * actual, char * expected) {
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
    uint16_t int16;
    if (wz_read_le16(&int16, file)) return 1;
    return val->i = int16, 0;
  } else if (WZ_IS_VAR_INT32(type)) {
    uint32_t int32;
    if (wz_read_int(&int32, file)) return 1;
    return val->i = int32, 0;
  } else if (WZ_IS_VAR_INT64(type)) {
    uint64_t int64;
    if (wz_read_long(&int64, file)) return 1;
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
    val->pos = file->pos;
    return wz_seek(size, SEEK_CUR, file);
  } else {
    return wz_error("Unsupported primitive type: 0x%02hhx\n", type), 1;
  }
}

void
wz_free_prim(wzprim * val, uint8_t type) {
  if (WZ_IS_VAR_STRING(type))
    wz_free_chars(&val->str);
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
wz_read_prop(wzprop * prop, wznode * node, wzfile * file) {
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
  return prop->vars = vars, prop->len = len, 0;
}

void
wz_free_prop(wzprop * prop) {
  for (uint32_t i = 0; i < prop->len; i++)
    wz_free_var(prop->vars + i);
  free(prop->vars);
}

int
wz_decode_bitmap(uint32_t * written,
                 uint8_t * out, uint8_t * in, uint32_t size, wzkey * key) {
  uint32_t read = 0, write = 0; size--; // a null terminator
  while (read < size) {
    uint32_t len = wz_le32toh(* (uint32_t *) (in + read)); read += sizeof(len);
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
  * written = strm.total_out;
  return inflateEnd(&strm), 0;
}

void
wz_init_palette(wzpalette * palette) {
  for (size_t i = 0; i < 0x10; i++) palette->table4[i] = (i << 4) | (i >> 0);
  for (size_t i = 0; i < 0x20; i++) palette->table5[i] = (i << 3) | (i >> 2);
  for (size_t i = 0; i < 0x40; i++) palette->table6[i] = (i << 2) | (i >> 4);
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
wz_unpack_4444(wzcolor * out, uint8_t * in, uint32_t pixels, wzfile * file) {
  uint8_t * unpack4 = file->palette.table4;
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
wz_unpack_565(wzcolor * out, uint8_t * in, uint32_t pixels, wzfile * file) {
  uint8_t * unpack5 = file->palette.table5;
  uint8_t * unpack6 = file->palette.table6;
  for (uint32_t i = 0; i < pixels; i++) {
    uint16_t pixel = wz_le16toh(* ((uint16_t *) in + i));
    uint8_t b = (pixel >>  0) & 0x1f;
    uint8_t g = (pixel >>  5) & 0x3f;
    uint8_t r = (pixel >> 11) & 0x1f;
    out[i] = (wzcolor) {unpack5[b], unpack6[g], unpack5[r], 0xff};
  }
}

void
wz_inflate_dxt3_color(wzcolor * out, uint8_t * in, wzfile * file) {
  wzcolor codes[4];
  wz_unpack_565(codes, in, 2, file); // get first two codes
  codes[2].b = (codes[0].b * 2 + codes[1].b) / 3; // get the third code
  codes[2].g = (codes[0].g * 2 + codes[1].g) / 3;
  codes[2].r = (codes[0].r * 2 + codes[1].r) / 3;
  codes[2].a = 0xff;
  codes[3].b = (codes[0].b + codes[1].b * 2) / 3; // get the fourth code
  codes[3].g = (codes[0].g + codes[1].g * 2) / 3;
  codes[3].r = (codes[0].r + codes[1].r * 2) / 3;
  codes[3].a = 0xff;
  uint32_t indices = wz_le32toh(* (uint32_t *) (in + 4)); // get indices
  for (size_t i = 0; i < 16; i++) // choose code by using indice
    out[i] = codes[indices & 0x03], indices >>= 2;
}

void
wz_inflate_dxt3_alpha(wzcolor * out, uint8_t * in, wzfile * file) {
  uint8_t * unpack4 = file->palette.table4;
  uint64_t alpha = wz_le64toh(* (uint64_t *) in); // get alpha values
  for (size_t i = 0; i < 16; i++)
    out[i].a = unpack4[alpha & 0x0f], alpha >>= 4; // unpack alpha value
}

void
wz_inflate_dxt3(wzcolor * out, uint8_t * in, wzfile * file) {
  wz_inflate_dxt3_color(out, in + 8, file);
  wz_inflate_dxt3_alpha(out, in, file);
}

void
wz_unpack_dxt3(wzcolor * out, uint8_t * in, uint32_t w, uint32_t h,
               wzfile * file) {
  uint32_t bw = (w + 3) / 4 * 4; // increased to blocks width
  for (uint32_t y = 0; y < h; y += 4) // loop over blocks
    for (uint32_t x = 0; x < w; x += 4) {
      wzcolor pixels[16];
      wz_inflate_dxt3(pixels, &in[y * bw + x * 4], file); // inflate 4x4 block
      uint8_t ph = h - y < 4 ? h - y : 4; // check the pixel is outside of image
      uint8_t pw = w - x < 4 ? w - x : 4;
      for (uint32_t py = 0; py < ph; py++) // write to correct location
        for (uint32_t px = 0; px < pw; px++)
          out[(y + py) * w + x + px] = pixels[py * 4 + px];
    }
}

int
wz_unpack_bitmap(wzcolor ** dst, uint8_t ** src,
                 uint32_t w, uint32_t h, uint32_t depth, wzfile * file) {
  uint8_t * in = * src;
  wzcolor * out = * dst;
  switch (depth) {
  case WZ_COLOR_4444: return wz_unpack_4444(out, in, w * h, file), 0;
  case WZ_COLOR_8888: return wz_swap_ptr((uint8_t **) dst, src), 0;
  case WZ_COLOR_565:  return wz_unpack_565(out, in, w * h, file), 0;
  case WZ_COLOR_DXT3: return wz_unpack_dxt3(out, in, w, h, file), 0;
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
wz_read_bitmap(wzcolor ** data,
               uint32_t w, uint32_t h,
               uint32_t depth, uint8_t scale, uint32_t size,
               wznode * node, wzfile * file) {
  uint32_t pixels = w * h;
  uint32_t full_size = pixels * sizeof(wzcolor);
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
      size != pixels * depth_size / scale_size) {
    return free(out), free(in), 1;
  }
  if (
      wz_unpack_bitmap((wzcolor **) &in, &out, w, h, depth, file)) {
    printf("w %"PRIu32" h %"PRIu32" size %"PRIu32" %"PRIu32" "
           "depth %"PRIu32" scale %"PRIu8"\n",
           w, h, size, pixels * depth_size / scale_size, depth, scale);
    fflush(stdout);
    return free(out), free(in), 1;
  }
  wz_scale_bitmap(&out, &in, w / scale_size, h / scale_size, scale_size);
  if (full_size < max_size) out = realloc(out, full_size);
  return free(in), * data = (wzcolor *) out, 0;
}

int
wz_read_img(wzimg * img, wznode * node, wzfile * file) {
  if (wz_seek(1, SEEK_CUR, file)) return 1;
  uint8_t prop;
  if (wz_read_byte(&prop, file)) return 1;
  img->len = 0, img->vars = NULL;
  if (prop == 1 && wz_read_prop((wzprop *) img, node, file)) return 1;
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
      wz_read_bitmap(&img->data,
                     img->w, img->h, depth, scale, size, node, file))
    return wz_free_prop((wzprop *) img), 1;
  //static int id = 0;
  //char filename[100];
  //snprintf(filename, sizeof(filename), "out/%d-%"PRIu32"-%"PRIu32".data",
  //         id++, img->w, img->h);
  //FILE * outfile = fopen(filename, "wb");
  //fwrite(img->data, 1, img->w * img->h * 4, outfile);
  //fclose(outfile);
  free(img->data);
  //printf("img raw size %"PRIu32"\n", size);
  return 0;
}

void
wz_free_img(wzimg * img) {
  wz_free_prop((wzprop *) img);
}

int
wz_read_2d(wz2d * val, wzfile * file) {
  return (wz_read_int(&val->x, file) ||
          wz_read_int(&val->y, file));
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
wz_read_vec(wzvec * vec, wznode * node, wzfile * file) {
  return wz_read_2d(&vec->val, file);
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
wz_read_obj(wzobj ** buffer, wznode * node, wzfile * file) {
  wzchr type;
  if (wz_read_pack_chars(&type, node, file) ||
      wz_deduce_key(&node->key, &type, file)) {
    debug(" x\n");
    return 1;
  }
  if (WZ_IS_OBJ_PROPERTY(&type)) {
    wzprop * prop = malloc(sizeof(* prop));
    if (prop == NULL) return wz_free_chars(&type), 1;
    if (wz_read_prop(prop, node, file)) {
      wz_error("Unable to read property\n");
      return free(prop), wz_free_chars(&type), 1;
    }
    return prop->type = type, * buffer = (wzobj *) prop, 0;
  } else if (WZ_IS_OBJ_CANVAS(&type)) {
    wzimg * img = malloc(sizeof(* img));
    if (img == NULL) return wz_free_chars(&type), 1;
    if (wz_read_img(img, node, file)) {
      wz_error("Unable to read canvas\n");
      return free(img), wz_free_chars(&type), 1;
    }
    return img->type = type, * buffer = (wzobj *) img, 0;
  } else if (WZ_IS_OBJ_CONVEX(&type)) {
    wzvex * vex = malloc(sizeof(* vex));
    if (vex == NULL) return wz_free_chars(&type), 1;
    if (wz_read_vex(vex, node, file)) {
      wz_error("Unable to read convex\n");
      return free(vex), wz_free_chars(&type), 1;
    }
    return vex->type = type, * buffer = (wzobj *) vex, 0;
  } else if (WZ_IS_OBJ_VECTOR(&type)) {
    wzvec * vec = malloc(sizeof(* vec));
    if (vec == NULL) return wz_free_chars(&type), 1;
    if (wz_read_vec(vec, node, file)) {
      wz_error("Unable to read vector\n");
      return free(vec), wz_free_chars(&type), 1;
    }
    return vec->type = type, * buffer = (wzobj *) vec, 0;
  } else if (WZ_IS_OBJ_SOUND(&type)) {
    printf("Sound is unsupported\n");
    return wz_free_chars(&type), 1;
  } else if (WZ_IS_OBJ_UOL(&type)) {
    wzuol * uol = malloc(sizeof(* uol));
    if (uol == NULL) return wz_free_chars(&type), 1;
    if (wz_read_uol(uol, node, file)) {
      wz_error("Unable to read uol\n");
      return free(uol), wz_free_chars(&type), 1;
    }
    return uol->type = type, * buffer = (wzobj *) uol, 0;
  } else {
    return wz_error("Unsupported object type: %.*s\n", type.len, type.bytes), 1;
  }
}

void
wz_free_obj(wzobj * obj) {
  if (WZ_IS_OBJ_PROPERTY(&obj->type)) wz_free_prop((wzprop *) obj);
  else if (WZ_IS_OBJ_CANVAS(&obj->type)) wz_free_img((wzimg *) obj);
  else if (WZ_IS_OBJ_CONVEX(&obj->type)) wz_free_vex((wzvex *) obj);
  else if (WZ_IS_OBJ_SOUND(&obj->type)) {}
  else if (WZ_IS_OBJ_UOL(&obj->type)) wz_free_uol((wzuol *) obj);
  wz_free_chars(&obj->type);
  free(obj);
}

int // Non recursive DFS
wz_read_obj_r(wzvar * buffer, wznode * node, wzfile * file) {
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
      if (wz_seek(var->val.pos, SEEK_SET, file))
        continue;
      wzobj * obj;
      if (wz_read_obj(&obj, node, file)) {
        printf("failed!\n");
      } else {
        if (WZ_IS_OBJ_PROPERTY(&obj->type)) {
          stack[len++] = var;
          stack[len++] = NULL;
          wzprop * prop = (wzprop *) obj;
          for (uint32_t i = 0; i < prop->len; i++) {
            wzvar * child = &prop->vars[prop->len - i - 1];
            child->parent = var;
            stack[len++] = child;
          }
          var->val.obj = obj;
        } else if (WZ_IS_OBJ_CANVAS(&obj->type)) {
          wz_free_obj(obj);
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
        //iconv_t conv = iconv_open("UTF-8", "UTF-16LE");
        //if (conv == (iconv_t) -1) return 1;
        //pindent(), printf(" ");
        //for (uint32_t i = 0; i < val->len; i += 2) {
        //  char buf[4];
        //  char * utf8 = buf;
        //  size_t utf8_len = 4;
        //  char * utf16le = (char *) &val->bytes[i];
        //  size_t utf16le_len = 2;
        //  size_t ret = iconv(conv, &utf16le, &utf16le_len, &utf8, &utf8_len);
        //  if (ret == (size_t) -1) return 1;
        //  printf("%.*s", 4 - (int) utf8_len, buf);
        //}
        //if (iconv_close(conv) == -1) return 1;
        //printf("\n");
      }
    }
  }
  free(stack);
  return 0;
}
#include "../tests/mem.h"

int
wz_read_node_r(wznode * node, wzfile * file) {
  wznode ** stack = malloc(10000 * sizeof(* stack));
  if (stack == NULL) return 1;
  stack[0] = node;
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
      if (wz_read_grp(&node->data.grp, node, file))
        return printf("failed to read grp!\n"), 1;
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
        debugging = 1;
      wz_read_obj_r(node->data.var, node, file);
      //int64_t i = ((wzprop *) ((wzprop *) ((wzprop *) ((wzprop *) node->data.var->val.obj)->vars[2].val.obj)->vars[0].val.obj)->vars[2].val.obj)->vars[0].val.i;
      // MapList/0/mapNo/0 => 211040300
      //printf("i = %ld\n", i);
      // wzprop * prop = (wzprop *) node->data.var->val.obj;
      // get_prop(prop, "MapList");
      //
      // wzprop * ret;
      // get_prop(&ret, prop, 2);
      // # ((wzprop *) prop->vars[2].val.obj)
      //
      // wzprop * ret;
      // get_prop(&ret, prop, "MapList");
      //
      // int64 ret;
      // get_int(&ret, prop, "MapList/0/mapNo/0");
      // get_float
      // get_chars
      //
      // get_prop
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
wz_read_root(wznode * root, wzfile * file) {
  root->addr.val = file->head.start + sizeof(file->ver.enc);
  return wz_read_grp(&root->data.grp, root, file);
}

int
wz_decode_root(wznode * root, wzfile * file) {
  return wz_decode_grp(root->data.grp, file);
}

void
wz_free_root(wznode * root) {
  wz_free_grp(&root->data.grp);
}

int
wz_read_file(wzfile * file, FILE * raw) {
  file->raw = raw, file->pos = 0;
  if (fseek(raw, 0, SEEK_END) ||
      (file->size = ftell(raw)) < 0) return 1;
  rewind(raw);
  file->ver.hash = 0, file->key = NULL;
  file->root = (wznode) {
    .parent = NULL,
    .type = 0x03,
    .name = (wzchr) {.len = 0, .enc = WZ_ENC_ASCII},
    .data = {.grp = NULL}
  };
  wz_init_keys(file->keys);
  wz_init_palette(&file->palette);
  if (wz_read_head(&file->head, file)) return wz_free_keys(file), 1;
  if (wz_read_le16(&file->ver.enc, file) ||
      wz_read_root(&file->root, file))
    return wz_free_head(&file->head), wz_free_keys(file), 1;
  if (wz_decode_ver(&file->ver, file) ||
      wz_decode_root(&file->root, file))
    return 0;
    //return wz_free_root(&file->root), wz_free_head(&file->head), 2;
  //printf("memory used  %lu\n", memused());
  if (!wz_read_node_r(&file->root, file))
    printf("all read !\n");
  return 0;
}

void
wz_free_file(wzfile * file) {
  wz_free_root(&file->root);
  wz_free_head(&file->head);
  wz_free_keys(file);
}

int
wz_open_file(wzfile * file, char * filename) {
  file->raw = fopen(filename, "rb");
  if (file->raw == NULL) return perror(filename), 1;
  if (wz_read_file(file, file->raw)) return fclose(file->raw) != 0;
  return 0;
}

int
wz_close_file(wzfile * file) {
  wz_free_file(file);
  if (fclose(file->raw)) return perror("Cannot close file"), 1;
  return 0;
}
