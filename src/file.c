#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../lib/endian.h"
#include "file.h"

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
  return * buffer = le16toh(* buffer), 0;
}

int
wz_read_le32(uint32_t * buffer, wzfile * file) {
  if (wz_read_data(buffer, sizeof(* buffer), file)) return 1;
  return * buffer = le32toh(* buffer), 0;
}

int
wz_read_le64(uint64_t * buffer, wzfile * file) {
  if (wz_read_data(buffer, sizeof(* buffer), file)) return 1;
  return * buffer = le64toh(* buffer), 0;
}

int // read packed integer (int8 or int32)
wz_read_int(uint32_t * buffer, wzfile * file) {
  int8_t byte;
  if (wz_read_byte(&byte, file)) return 1;
  if (byte == INT8_MIN) return wz_read_le32(buffer, file);
  return * (int32_t *) buffer = byte, 0;
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
  if (len > INT32_MAX) return fprintf(stderr, "String length > INT32_MAX"), 1;
  char * bytes = malloc(len);
  if (bytes == NULL ||
      wz_read_bytes(bytes, len, file)) return free(bytes), 1;
  return buffer->bytes = bytes, buffer->len = len, 0;
}

void
wz_free_str(wzstr * buffer) {
  free(buffer->bytes);
}

void
wz_decode_chars(wzchr * buffer, wzfile * file) {
  if (file->strk.ascii == NULL) return;
  uint8_t * strk = buffer->enc == WZ_ENC_ASCII ?
    file->strk.ascii : file->strk.unicode;
  size_t i;
  for (i = 0; i < buffer->len; i++)
    buffer->bytes[i] ^= strk[i];
}

int // read characters (ascii or unicode)
wz_read_chars(wzchr * buffer, wzfile * file) {
  int8_t byte;
  if (wz_read_byte(&byte, file)) return 1;
  int32_t size = byte;
  int ascii = size < 0;
  if (ascii) { // ascii
    if (size == INT8_MIN) {
      if (wz_read_le32(&size, file)) return 1;
    } else {
      size *= -1;
    }
  } else { // unicode
    if (size == INT8_MAX) {
      if (wz_read_le32(&size, file)) return 1;
    }
    size *= 2;
  }
  wzstr str;
  if (wz_read_str(&str, size, file)) return 1;
  buffer->bytes = str.bytes;
  buffer->len = str.len;
  buffer->enc = ascii ? WZ_ENC_ASCII : WZ_ENC_UNICODE;
  wz_decode_chars(buffer, file);
  return 0;
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
  uint32_t decoded = ~(addr->pos - file->head.start) * file->ver.hash - key;
  decoded = wz_rotl32(decoded, decoded & 0x1F);
  decoded = (decoded ^ addr->val) + file->head.start * 2;
  addr->val = decoded;
}

int
wz_read_addr(wzaddr * addr, wzfile * file) {
  uint32_t pos = file->pos;
  if (wz_read_le32(&addr->val, file)) return 1;
  addr->pos = pos;
  if (file->ver.hash == 0) return 0;
  return 0;
}

int
wz_read_obj(wzobj * obj, wzfile * file) {
  if (wz_read_byte(&obj->type, file)) return 1;
  if (obj->type == 1) { // unknown 10 bytes
    printf("inspect 1 %ld\n", ftell(file->raw));
    if (fseek(file->raw, 10, SEEK_CUR)) return 1;
    return 0;
  } else if (obj->type == 2) {
    printf("inspect 2 %ld\n", ftell(file->raw));
    return 1;
  } else if (obj->type == 3 || obj->type == 4) {
    if (wz_read_chars(&obj->name, file)) return 1;
    if (wz_read_int(&obj->size, file) ||
        wz_read_int(&obj->check, file) ||
        wz_read_addr(&obj->addr, file)) return wz_free_chars(&obj->name), 1;
  } else {
    printf("inspect >= 5 %ld\n", ftell(file->raw));
    return 1;
  }
  return 0;
}

void
wz_free_obj(wzobj * obj) {
  wz_free_chars(&obj->name);
}

int
wz_decode_obj(wzobj * obj, wzfile * file) {
  if (obj->type == 3 || obj->type == 4) {
    wz_decode_chars(&obj->name, file);
    printf(" type   %d\n", obj->type);
    printf(" name   %.*s\n", obj->name.len, obj->name.bytes);
    printf(" size   %"PRIu32"\n", obj->size);
    printf(" check  %08X\n", obj->check);
    printf(" addr   %08X\n", obj->addr.val);
  } else {
  }
  return 0;
}

int
wz_read_dir(wzdir * dir, wzfile * file) {
  uint32_t len;
  if (wz_read_int(&len, file)) return 1;
  wzobj * objs = malloc(len * sizeof(* objs));
  if (objs == NULL) return 1;
  size_t i, j;
  for (i = 0; i < len; i++) {
    if (wz_read_obj(objs + i, file)) {
      for (j = 0; j < i; j++)
        wz_free_obj(objs + j);
      return free(objs), 1;
    }
  }
  return dir->objs = objs, dir->len = len, 0;
}

void
wz_free_dir(wzdir * dir) {
  size_t i;
  for (i = 0; i < dir->len; i++)
    wz_free_obj(&dir->objs[i]);
  free(dir->objs);
}

int
wz_decode_dir(wzdir * dir, wzfile * file) {
  size_t i;
  printf("[%"PRIu32"]\n", dir->len);
  for (i = 0; i < dir->len; i++) {
    printf("[%zu]\n", i);
    if (wz_decode_obj(dir->objs + i, file)) return 1;
  }
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
  printf("copyright  %s\n",        head->copy.bytes);
  return 0;
}

void
wz_free_head(wzhead * head) {
  wz_free_str(&head->copy);
}

int
wz_encode_ver(wzver * ver) {
  char chars[6]; // 0xffff.to_s.size + 1 == 6
  if (snprintf(chars, sizeof(chars), "%"PRIu32, ver->dec) < 0) return 1;
  ver->hash = 0;
  size_t i, len = strlen(chars);
  for (i = 0; i < len; i++) ver->hash = (ver->hash << 5) + chars[i] + 1;
  ver->enc = 0xff ^
    ver->hash >> 24 & 0xff ^
    ver->hash >> 16 & 0xff ^
    ver->hash >>  8 & 0xff ^
    ver->hash       & 0xff;
  return 0;
}

int
wz_valid_ver(wzver * ver, wzfile * file) {
  uint32_t copy = file->ver.hash;
  file->ver.hash = ver->hash;
  uint32_t i, len = file->root.len;
  for (i = 0; i < len; i++) {
    wzobj * obj = &file->root.objs[i];
    if (obj->type == 3 || obj->type == 4) {
      wzaddr addr = obj->addr;
      wz_decode_addr(&addr, file);
      if (addr.val > file->size) break;
    }
  }
  file->ver.hash = copy;
  return i == len;
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

void
wz_alloc_crypto(void) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  CONF_modules_load_file(NULL, NULL,
                         CONF_MFLAGS_DEFAULT_SECTION |
                         CONF_MFLAGS_IGNORE_MISSING_FILE);
}

void
wz_dealloc_crypto(void) {
  CRYPTO_cleanup_all_ex_data();
  EVP_cleanup();
  ERR_free_strings();
  ERR_remove_state(0);
}

int
wz_decode_aes(uint8_t * plain, uint8_t * cipher, size_t len,
              uint8_t * key, uint8_t * iv) {
  int size;
  EVP_CIPHER_CTX * ctx;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return ERR_print_errors_fp(stderr), 1;
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
      !EVP_DecryptUpdate(ctx, plain, &size, cipher, len))
    return ERR_print_errors_fp(stderr), EVP_CIPHER_CTX_free(ctx), 1;
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int
wz_encode_aes(wzaes * aes) {
  int size;
  EVP_CIPHER_CTX * ctx;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return ERR_print_errors_fp(stderr), 1;
  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes->key, aes->iv) ||
      !EVP_EncryptUpdate(ctx, aes->cipher, &size, aes->plain, aes->len))
    return ERR_print_errors_fp(stderr), EVP_CIPHER_CTX_free(ctx), 1;
  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int
wz_init_aes(wzaes * aes) {
  uint8_t key[32] =
    "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
    "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00";
  memcpy(aes->key, key, sizeof(key));
  aes->len = 0x1000;
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
wz_init_strk(wzstrk * strk, wzaes * aes) {
  if ((strk->ascii = malloc(aes->len * 2)) == NULL) return wz_free_aes(aes), 1;
  return strk->unicode = strk->ascii + aes->len, 0;
}

int
wz_valid_strk(wzstrk * strk, wzfile * file) {
  wzstrk copy = file->strk;
  file->strk = * strk;
  size_t i, j;
  for (i = 0; i < file->root.len; i++) {
    wzobj * obj = &file->root.objs[i];
    if ((obj->type == 3 || obj->type == 4) && obj->name.enc == WZ_ENC_ASCII) {
      wz_decode_chars(&obj->name, file);
      for (j = 0; j < obj->name.len; j++)
        if (!isprint(obj->name.bytes[j])) break;
      wz_decode_chars(&obj->name, file);
      if (j != obj->name.len)
        return file->strk = copy, 1;
    }
  }
  return file->strk = copy, 0;
}

int
wz_set_strk(wzstrk * strk, uint8_t * cipher, size_t len, wzfile * file) {
  uint8_t * ascii = strk->ascii;
  uint16_t * unicode = (uint16_t *) strk->unicode;
  uint8_t amask = 0xaa;
  uint16_t umask = 0xaaaa;
  size_t j;
  for (j = 0; j < len / sizeof(amask); j++)
    ascii[j]   =         amask++  ^               cipher[j];
  for (j = 0; j < len / sizeof(umask); j++)
    unicode[j] = htobe16(umask++) ^ ((uint16_t *) cipher)[j];
  return wz_valid_strk(strk, file);
}

void
wz_free_strk(wzstrk * strk) {
  free(strk->ascii);
}

int
wz_decode_strk(wzstrk * strk, wzfile * file) {
  uint8_t values[][4] = { // These values is used for generating iv (aes)
    "\x4d\x23\xc7\x2b",   // GMS
    "\xb9\x7d\x63\xe9"    // KMS, TMS
  };                      // JMS can be decoded with empty cipher :)
  size_t i, j, times = sizeof(values) / sizeof(values[i]);
  wzaes aes; wzstrk guess;
  if (wz_init_aes(&aes)) return 1;
  if (wz_init_strk(&guess, &aes)) return wz_free_aes(&aes), 1;
  for (i = 0; i < times; i++) {
    for (j = 0; j < 16; j += 4) memcpy(aes.iv + j, values[i], 4);
    if (!wz_encode_aes(&aes) &&
        !wz_set_strk(&guess, aes.cipher, aes.len, file)) break;
  }
  // plain is a string of zeros and is used as an empty cipher
  if (i == times && wz_set_strk(&guess, aes.plain, aes.len, file))
    return wz_free_aes(&aes), wz_free_strk(&guess), 1;
  return wz_free_aes(&aes), * strk = guess, 0;
}

int
wz_read_file(wzfile * file, FILE * raw) {
  file->raw = raw, file->pos = 0, file->ver.hash = 0, file->strk.ascii = NULL;
  if (fseek(raw, 0, SEEK_END) ||
      (file->size = ftell(raw)) < 0) return 1;
  rewind(raw);
  if (wz_read_head(&file->head, file)) return 1;
  if (wz_read_le16(&file->ver.enc, file) ||
      wz_read_dir(&file->root, file))
    return wz_free_head(&file->head), 1;
  if (!wz_decode_ver(&file->ver, file))
    printf("version decoded !\n");
  if (!wz_decode_strk(&file->strk, file))
    printf("string key decoded !\n");
  if (!wz_decode_dir(&file->root, file))
    printf("dir decoded !\n");
  return 0;
}

void
wz_free_file(wzfile * file) {
  wz_free_strk(&file->strk);
  wz_free_dir(&file->root);
  wz_free_head(&file->head);
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
