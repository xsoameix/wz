#ifndef WZ_FILE_H
#define WZ_FILE_H

#include <stdio.h>
#include <stdint.h>

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzstr;

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
  uint8_t   enc;  // encoding
} wzchr;

typedef struct {
  uint32_t  val;
  uint32_t  pos;
} wzaddr;

typedef struct {
  uint32_t  pos;
  wzchr     type;
} wzobj;

typedef union {
  int64_t   i;
  double    f;
  wzchr     str;
  wzobj *   obj;
} wzprim;

typedef struct wzvar {
  struct wzvar * parent;
  wzchr     name;
  uint8_t   type;
  wzprim    val;
} wzvar;

typedef struct {
  uint32_t  pos;
  wzchr     type;
  uint32_t  len;
  wzvar *   vars;
} wzlist;

typedef struct {
  uint8_t   b;
  uint8_t   g;
  uint8_t   r;
  uint8_t   a;
} wzcolor;

typedef struct {
  uint32_t  pos;
  wzchr     type;
  uint32_t  len;
  wzvar *   vars;
  uint32_t  w;
  uint32_t  h;
  wzcolor * data; // size == w * h * sizeof(wzcolor)
} wzimg;

typedef struct {
  uint32_t  x;
  uint32_t  y;
} wz2d;

typedef struct {
  uint32_t  pos;
  wzchr     type;
  uint32_t  len;
  wz2d *    vals;
} wzvex;

typedef struct {
  uint32_t  pos;
  wzchr     type;
  wz2d      val;     
} wzvec;

typedef struct {
  uint32_t  pos;
  wzchr     type;
  wzchr     path;
} wzuol;

typedef union {
  struct wzvar * var;
  struct wzgrp * grp;
} wzdata;

typedef struct {
  uint8_t   key[32];
  uint8_t   iv[16];
  uint8_t * plain;
  uint8_t * cipher;
  size_t    len;
} wzaes;

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzkey;  // decode string and image

typedef struct wznode {
  struct wznode * parent;
  uint8_t   type;
  wzchr     name;
  uint32_t  size;
  uint32_t  check;  // checksum
  wzaddr    addr;
  wzdata    data;
  wzkey *   key;    // decode object (list, image, convex, ...)
} wznode;

typedef struct wzgrp {
  uint32_t  len;
  wznode *  nodes;
} wzgrp;

typedef struct {
  uint8_t   ident[4];
  uint64_t  size;
  uint32_t  start;
  wzstr     copy;  // copyright
} wzhead;

typedef struct {
  uint16_t  enc;   // encoded version
  uint16_t  dec;   // decoded version
  uint32_t  hash;  // hash of the version
} wzver;

typedef struct {
  uint8_t   table4[0x10];  // scale 4 bit color to 8 bit color
  uint8_t   table5[0x20];  // scale 5 bit color to 8 bit color
  uint8_t   table6[0x40];  // scale 6 bit color to 8 bit color
} wzpalette;

typedef struct {
  FILE *    raw;
  uint64_t  size;
  uint64_t  pos;
  wzhead    head;
  wznode    root;
  wzver     ver;
  wzkey *   key;  // decode node name
} wzfile;

typedef struct {
  size_t    klen; // keys length
  wzkey *   keys;
  wzpalette palette;
} wzctx;

#define WZ_ENC_ASCII   0
#define WZ_ENC_UTF16LE 1

#define WZ_COLOR_4444    1
#define WZ_COLOR_8888    2
#define WZ_COLOR_565   513
#define WZ_COLOR_DXT3 1026

#define WZ_IS_VAR_NONE(x)    ((x) == 0)
#define WZ_IS_VAR_INT16(x)   ((x) == 0x02 || (x) == 0x0b)
#define WZ_IS_VAR_INT32(x)   ((x) == 0x03 || (x) == 0x13)
#define WZ_IS_VAR_INT64(x)   ((x) == 0x14)
#define WZ_IS_VAR_FLOAT32(x) ((x) == 0x04)
#define WZ_IS_VAR_FLOAT64(x) ((x) == 0x05)
#define WZ_IS_VAR_STRING(x)  ((x) == 0x08)
#define WZ_IS_VAR_OBJECT(x)  ((x) == 0x09)

#define WZ_IS_OBJ_PROPERTY(type) wz_is_chars((type), "Property")
#define WZ_IS_OBJ_CANVAS(type)   wz_is_chars((type), "Canvas")
#define WZ_IS_OBJ_CONVEX(type)   wz_is_chars((type), "Shape2D#Convex2D")
#define WZ_IS_OBJ_VECTOR(type)   wz_is_chars((type), "Shape2D#Vector2D")
#define WZ_IS_OBJ_SOUND(type)    wz_is_chars((type), "Sound_DX8")
#define WZ_IS_OBJ_UOL(type)      wz_is_chars((type), "UOL")

#define WZ_IS_NODE_NONE(type) ((type) == 0x01)
#define WZ_IS_NODE_LINK(type) ((type) == 0x02)
#define WZ_IS_NODE_DIR(type)  ((type) == 0x03)
#define WZ_IS_NODE_FILE(type) ((type) == 0x04)

int      wz_read_data(void * buffer, size_t len, wzfile * file);
int      wz_read_byte(uint8_t * buffer, wzfile * file);
int      wz_read_le16(uint16_t * buffer, wzfile * file);
int      wz_read_le32(uint32_t * buffer, wzfile * file);
int      wz_read_le64(uint64_t * buffer, wzfile * file);
int      wz_read_int(uint32_t * buffer, wzfile * file);
int      wz_read_long(uint64_t * buffer, wzfile * file);
int      wz_read_bytes(uint8_t * buffer, size_t len, wzfile * file);

void     wz_init_str(wzstr * buffer);
int      wz_read_str(wzstr * buffer, size_t len, wzfile * file);
void     wz_free_str(wzstr * buffer);

int      wz_decode_chars(wzchr * buffer, wzkey * key);
int      wz_read_chars(wzchr * buffer, wzkey * key, wzfile * file);
void     wz_free_chars(wzchr * buffer);

uint32_t wz_rotl32(uint32_t x, uint32_t n);
void     wz_decode_addr(wzaddr * addr, wzfile * file);
int      wz_read_addr(wzaddr * addr, wzfile * file);

int      wz_seek(uint64_t pos, int origin, wzfile * file);
int      wz_read_node(wznode * node, wzfile * file, wzctx * ctx);
void     wz_free_node(wznode * node);

int      wz_read_grp(wzgrp ** buffer, wznode * node, wzfile * file,
                     wzctx * ctx);
void     wz_free_grp(wzgrp ** buffer);

int      wz_read_head(wzhead * head, wzfile * file);
void     wz_free_head(wzhead * head);

int      wz_encode_ver(wzver * ver);
int      wz_valid_ver(wzver * ver, wznode * node, wzfile * file);
int      wz_guess_ver(wzver * ver, wznode * node, wzfile * file);
int      wz_deduce_ver(wzver * ver, wzfile * file, wzctx * ctx);

int      wz_alloc_crypto(void);
void     wz_dealloc_crypto(void);

int      wz_decode_aes(uint8_t * plain, uint8_t * cipher, size_t len,
                       uint8_t * key, uint8_t * iv);
int      wz_encode_aes(wzaes * aes);
int      wz_init_aes(wzaes * aes);
void     wz_free_aes(wzaes * aes);

int      wz_init_key(wzkey * key, wzaes * aes);
void     wz_set_key(wzkey * key, wzaes * aes);
void     wz_free_key(wzkey * key);
int      wz_deduce_key(wzkey ** buffer, wzchr * name,
                       wzfile * file, wzctx * ctx);

int      wz_read_file(wzfile * file, FILE * raw, wzctx * ctx);
void     wz_free_file(wzfile * file);
int      wz_open_file(wzfile * file, char * filename, wzctx * ctx);
int      wz_close_file(wzfile * file);

int      wz_init_ctx(wzctx * ctx);
void     wz_free_ctx(wzctx * ctx);

#endif
