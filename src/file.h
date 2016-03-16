#ifndef WZ_FILE_H
#define WZ_FILE_H

#include <stdio.h>
#include <stdint.h>

// Structures

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4820) // C89: struct padding
#endif

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzstr;

typedef struct {
  uint32_t  val;
  uint32_t  pos;
} wzaddr;

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
} wzobj;

typedef union {
  int64_t   i;
  double    f;
  wzstr     str;
  wzobj *   obj;
} wzprim;

typedef struct wzvar {
  struct wzvar *  parent;
  struct wznode * node;
  wzstr     name;
  uint8_t   type;
  wzprim    val;
} wzvar;

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
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
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
  uint32_t  len;
  wzvar *   vars;
  uint32_t  w;
  uint32_t  h;
  wzcolor * data; // size == w * h * sizeof(wzcolor)
} wzimg;

typedef struct {
  int32_t  x;
  int32_t  y;
} wz2d;

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
  uint32_t  len;
  wz2d *    vals;
} wzvex;

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
  wz2d      val;     
} wzvec;

typedef struct {
  uint16_t  format;
  uint16_t  channels;
  uint32_t  sample_rate;
  uint32_t  byte_rate;
  uint16_t  block_align;
  uint16_t  bits_per_sample;
  uint16_t  extra_size;
} wzwav;  // microsoft WAVEFORMATEX structure

typedef struct {
  wzwav     wav;
  uint16_t  id;
  uint32_t  flags;
  uint16_t  block_size;
  uint16_t  frames_per_block;
  uint16_t  codec_delay;
} wzmp3;  // microsoft MPEGLAYER3WAVEFORMAT structure

typedef struct {
  uint32_t  chunk_id;
  uint32_t  chunk_size;
  uint32_t  format;
  uint32_t  subchunk1_id;
  uint32_t  subchunk1_size;
  uint16_t  audio_format;
  uint16_t  channels;
  uint32_t  sample_rate;
  uint32_t  byte_rate;
  uint16_t  block_align;
  uint16_t  bits_per_sample;
  uint32_t  subchunk2_id;
  uint32_t  subchunk2_size;
  uint8_t * data;
} wzpcm;

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
  uint32_t  size;
  uint32_t  ms;
  uint16_t  format;
  uint8_t * data;
} wzao;  // audio

typedef struct {
  uint8_t   alloc;
  uint8_t   type;
  uint32_t  pos;
  wzstr     path;
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
  uint32_t  len;
} wzaes;

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzkey;  // decode string and image

typedef struct wznode {
  struct wznode * parent;
  struct wzfile * file;
  uint8_t   alloc;
  uint8_t   type;
  wzstr     name;
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
  uint32_t  size;
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

typedef struct wzfile {
  FILE *    raw;
  uint32_t  size;
  uint32_t  pos;
  wzhead    head;
  wznode    root;
  wzver     ver;
  wzkey *   key;  // decode node name
  struct wzctx * ctx;
} wzfile;

typedef struct {
  uint8_t   wav[16];
  uint8_t   empty[16];
} wzguid;

typedef struct wzctx {
  size_t    klen; // keys length
  wzkey *   keys;
  wzpalette palette;
  wzguid    guid;
} wzctx;

#ifdef _WIN32
#pragma warning(pop)
#endif

// Macro Definitions

#define WZ_COLOR_4444    1
#define WZ_COLOR_8888    2
#define WZ_COLOR_565   513
#define WZ_COLOR_DXT3 1026

// microsoft define these values in Mmreg.h
#define WZ_AUDIO_PCM 0x0001
#define WZ_AUDIO_MP3 0x0055

#define WZ_AUDIO_WAV_SIZE 18 // sizeof(packed wzwav)
#define WZ_AUDIO_MP3_SIZE 30 // sizeof(packed wzmp3)
#define WZ_AUDIO_PCM_SIZE 44 // sizeof(packed wzpcm)

#define WZ_VAR_NIL   0x00
#define WZ_VAR_INT16 0x01
#define WZ_VAR_INT32 0x02
#define WZ_VAR_INT64 0x03
#define WZ_VAR_FLT32 0x04
#define WZ_VAR_FLT64 0x05
#define WZ_VAR_STR   0x06
#define WZ_VAR_OBJ   0x07

#define WZ_OBJ_LIST 0x00 // "Property"
#define WZ_OBJ_IMG  0x01 // "Canvas"
#define WZ_OBJ_VEX  0x02 // "Shape2D#Convex2D"
#define WZ_OBJ_VEC  0x03 // "Shape2D#Vector2D"
#define WZ_OBJ_AO   0x04 // "Sound_DX8"
#define WZ_OBJ_UOL  0x05 // "UOL"

#define WZ_NODE_NIL  0x00
#define WZ_NODE_DIR  0x01
#define WZ_NODE_FILE 0x02

int      wz_read_data(void * buffer, uint32_t len, wzfile * file);
int      wz_read_byte(uint8_t * buffer, wzfile * file);
int      wz_read_le16(uint16_t * buffer, wzfile * file);
int      wz_read_le32(uint32_t * buffer, wzfile * file);
int      wz_read_le64(uint64_t * buffer, wzfile * file);
int      wz_read_int(uint32_t * buffer, wzfile * file);
int      wz_read_long(uint64_t * buffer, wzfile * file);
int      wz_read_bytes(uint8_t * buffer, uint32_t len, wzfile * file);

void     wz_init_str(wzstr * buffer);
int      wz_read_str(wzstr * buffer, uint32_t len, wzfile * file);
void     wz_free_str(wzstr * buffer);

int      wz_decode_chars(wzstr * buffer, int ascii, wzkey * key);
int      wz_read_chars(wzstr * buffer, wzkey * key, wzfile * file);
void     wz_free_chars(wzstr * buffer);

uint32_t wz_rotl32(uint32_t x, uint32_t n);
void     wz_decode_addr(wzaddr * addr, wzfile * file);
int      wz_read_addr(wzaddr * addr, wzfile * file);

int      wz_seek(uint32_t pos, int origin, wzfile * file);
int      wz_read_node(wznode * node, wzfile * file, wzctx * ctx);
void     wz_free_node(wznode * node);

int      wz_read_grp(wzgrp ** buffer, wznode * node, wzfile * file,
                     wzctx * ctx);
void     wz_free_grp(wzgrp ** buffer);

int      wz_read_head(wzhead * head, wzfile * file);
void     wz_free_head(wzhead * head);

int      wz_encode_ver(wzver * ver);
int      wz_valid_ver(wzver * ver, wznode * root, wzfile * file);
int      wz_guess_ver(wzver * ver, wznode * root, wzfile * file);
int      wz_deduce_ver(wzver * ver, wzfile * file, wzctx * ctx);

void     wz_decode_aes(uint8_t * plain, uint8_t * cipher, size_t len,
                       uint8_t * key, uint8_t * iv);
void     wz_encode_aes(wzaes * aes);
int      wz_init_aes(wzaes * aes);
void     wz_free_aes(wzaes * aes);

int      wz_init_key(wzkey * key, wzaes * aes);
void     wz_set_key(wzkey * key, wzaes * aes);
void     wz_free_key(wzkey * key);
int      wz_deduce_key(wzkey ** buffer, wzstr * name, wzctx * ctx);

void     wz_read_pcm(wzpcm * out, uint8_t * pcm);

int      wz_read_obj(wzobj ** buffer, wzvar * var,
                     wznode * node, wzfile * file, wzctx * ctx);
void     wz_free_obj(wzobj * obj);

int      wz_read_node_r(wznode * root, wzfile * file, wzctx * ctx);

int64_t  wz_get_int(wzvar * var);
double   wz_get_flt(wzvar * var);
char *   wz_get_str(wzvar * var);
wzimg *  wz_get_img(wzvar * var);
wzvex *  wz_get_vex(wzvar * var);
wzvec *  wz_get_vec(wzvar * var);
wzao *   wz_get_ao(wzvar * var);

wzvar *  wz_open_var(wzvar * var, const char * path);
void     wz_close_var(wzvar * var);
wzvar *  wz_open_root_var(wznode * node);

uint32_t wz_get_vars_len(wzvar * var);
wzvar *  wz_open_var_at(wzvar * var, uint32_t i);
char *   wz_get_var_name(wzvar * var);

wznode * wz_open_node(wznode * node, const char * path);
void     wz_close_node(wznode * node);
wznode * wz_open_root_node(wzfile * file);

uint32_t wz_get_nodes_len(wznode * node);
wznode * wz_open_node_at(wznode * node, uint32_t i);
char *   wz_get_node_name(wznode * node);

int      wz_read_file(wzfile * file, FILE * raw, wzctx * ctx);
void     wz_free_file(wzfile * file);
int      wz_open_file(wzfile * file, const char * filename, wzctx * ctx);
int      wz_close_file(wzfile * file);

int      wz_init_ctx(wzctx * ctx);
void     wz_free_ctx(wzctx * ctx);

#endif
