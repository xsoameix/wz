#ifndef _WZLIB_FILE_H
#define _WZLIB_FILE_H

#include <stdio.h>
#include <stdint.h>

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzstr;

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
  uint8_t   enc;      // encoding
} wzchr;

typedef struct {
  uint32_t  val;
  uint32_t  pos;
} wzaddr;

typedef struct {
  uint8_t   type;
  wzchr     name;
  uint32_t  size;
  uint32_t  check;    // checksum
  wzaddr    addr;
} wzobj;

typedef struct {
  uint32_t  len;
  wzobj *   objs;
} wzdir;

typedef struct {
  char      ident[4];
  uint64_t  size;
  uint32_t  start;
  wzstr     copy;     // copyright
} wzhead;

typedef struct {
  int16_t   enc;      // encoded version
  int16_t   dec;      // decoded version
  uint32_t  hash;     // hash of the version
} wzver;

typedef struct {
  uint8_t   key[32];
  uint8_t   iv[16];
  uint8_t * plain;
  uint8_t * cipher;
  size_t    len;
} wzaes;

typedef struct {
  uint8_t * ascii;
  uint8_t * unicode;
} wzstrk;

typedef struct {
  FILE *    raw;
  uint64_t  size;
  uint64_t  pos;
  wzhead    head;
  wzdir     root;
  wzver     ver;
  wzstrk    strk;     // string key
} wzfile;

#define WZ_ENC_ASCII   0
#define WZ_ENC_UNICODE 1

int      read_data(void * buffer, size_t len, wzfile * file);
int      read_byte(uint8_t * buffer, wzfile * file);
int      read_le16(uint16_t * buffer, wzfile * file);
int      read_le32(uint32_t * buffer, wzfile * file);
int      read_le64(uint64_t * buffer, wzfile * file);
int      read_int(uint32_t * buffer, wzfile * file);
int      read_bytes(uint8_t * buffer, size_t len, wzfile * file);
void     init_str(wzstr * buffer);
int      read_str(wzstr * buffer, size_t len, wzfile * file);
void     free_str(wzstr * buffer);
void     decode_chars(wzchr * buffer, wzfile * file);
int      read_chars(wzchr * buffer, wzfile * file);
uint32_t rotl32(uint32_t x, uint32_t n);
void     decode_addr(wzaddr * addr, wzfile * file);
int      read_addr(wzaddr * addr, wzfile * file);
int      read_obj(wzobj * obj, wzfile * file);
void     free_obj(wzobj * obj);
int      read_dir(wzdir * dir, wzfile * file);
void     free_dir(wzdir * dir);
int      read_head(wzhead * head, wzfile * file);
void     free_head(wzhead * head);
int      encode_ver(wzver * ver);
int      valid_ver(wzver * ver, wzfile * file);
int      decode_ver(wzver * ver, wzfile * file);
int      read_file(wzfile * file, FILE * raw);
void     free_file(wzfile * file);
int      open_file(wzfile * file, char * filename);
int      close_file(wzfile * file);

#endif
