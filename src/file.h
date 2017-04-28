#ifndef WZ_FILE_H
#define WZ_FILE_H

#include <stdio.h>
#include <stdint.h>

// Structures

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4820) // C89: struct padding
#endif

// 0    4    8    12   16   20   24   28   32   36   40
// p--- ---- n--- ---- tlb- ---- b--- ---- ---- --2-
// p--- ---- n--- ---- tlb- ---- b--- ---- ---- 4---
// p--- ---- n--- ---- tlb- ---- b--- ---- 8--- ----
// p--- ---- n--- ---- tlb- ---- b--- ---- o--- ----
// p--- ---- f--- ---- tlb- ---- b--- ---- d--- ----
// p--- ---- f--- ---- tlb- ---- ---k a--- d--- ----
// p--- ---- f--- ---- tlk. a--- b--- ---- d--- ----
// 
// p--- n--- tlb- b--- ---- --2-
// p--- n--- tlb- b--- ---- 4---
// p--- n--- tlb- b--- 8--- ----
// p--- n--- tlb- b--- ---- o---
// p--- f--- tlb- b--- ---- d---
// p--- f--- tlb- ---k a--- d---
// p--- f--- tlk. b--- a--- d---

#pragma GCC diagnostic warning "-Wpadded"

typedef struct { int32_t x; int32_t y; } wzn_vec;

typedef union { int32_t i; float f; } wzv32;
typedef union { int64_t i; double f; wzn_vec v; } wzv64;
typedef union {
  struct wzn_str * str;
  struct wzn_ary * ary;
  struct wzn_img * img;
  struct wzn_vex * vex;
  struct wzn_ao  * ao;
  uint32_t         addr;
} wzv;

typedef union {
  union  wzn      * node;
  struct wzn_file * file;
} wzn_root;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   name[sizeof(void *) - 2 + sizeof(void *) + 8 - 2];
  uint16_t  val;
} wzn16_embed;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   _1[sizeof(void *) - 2]; // padding
  uint8_t * name;
  uint8_t   _2[8 - 2]; // padding
  uint16_t  val;
} wzn16;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   name[sizeof(void *) - 2 + sizeof(void *) + 8 - 4];
  wzv32     val;
} wzn32_embed;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   _1[sizeof(void *) - 2]; // padding
  uint8_t * name;
  uint8_t   _2[8 - 4]; // padding
  wzv32     val;
} wzn32;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   name[sizeof(void *) - 2 + sizeof(void *)];
  wzv64     val;
} wzn64_embed;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   _[sizeof(void *) - 2]; // padding
  uint8_t * name;
  wzv64     val;
} wzn64;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   name[sizeof(void *) - 2 + sizeof(void *) + 8 - sizeof(void *)];
  wzv       val;
} wznv_embed;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   _1[sizeof(void *) - 2]; // padding
  uint8_t * name;
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t   _2[4]; // padding
#endif
  wzv       val;
} wznv;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   name[sizeof(void *) - 2 + 4 - 1];
  uint8_t   key;
  uint32_t  addr;
  wzv       val;
} wzna_embed;

typedef struct {
  union wzn * parent;
  wzn_root  root;
  uint8_t   type;
  uint8_t   name_len;
  uint8_t   key;
  uint8_t   _[1]; // padding
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t * name;
  uint32_t  addr;
#else
  uint32_t  addr;
  uint8_t * name;
#endif
  wzv       val;
} wzna;

typedef union wzn {
  wzn16_embed n16_e;
  wzn16       n16;
  wzn32_embed n32_e;
  wzn32       n32;
  wzn64_embed n64_e;
  wzn64       n64;
  wznv_embed  nv_e;
  wznv        nv;
  wzna_embed  na_e;
  wzna        na;
} wzn;

typedef struct wzn_str {
  uint32_t  len;
  uint8_t   bytes[4]; // variable array
} wzn_str;

typedef struct wzn_ary {
  uint32_t  len;
  uint8_t   _[4]; // padding
  wzn       nodes[1]; // variable array
} wzn_ary;

typedef struct wzn_img {
  uint32_t  w;
  uint32_t  h;
  uint8_t * data;
  uint32_t  len;
#if UINTPTR_MAX > UINT32_MAX
  uint8_t   _[4]; // padding
#endif
  wzn       nodes[1]; // variable array
} wzn_img;

typedef struct wzn_vex {
  uint32_t  len;
  wzn_vec   ary[1]; // variable array
} wzn_vex;

typedef struct wzn_ao {
  uint32_t  size;
  uint32_t  ms;
  uint16_t  format;
  uint8_t   _[sizeof(void *) - 2]; // padding
  uint8_t * data;
} wzn_ao;

typedef struct wzn_file {
  struct wzctx * ctx;
  FILE *   raw;
  uint32_t pos;
  uint32_t size;
  uint32_t start;
  uint32_t hash;
  uint8_t  key;
  uint8_t  _[sizeof(void *) - 1]; // padding
  wzn      root;
} wzn_file;

#pragma GCC diagnostic ignored "-Wpadded"

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
  uint16_t  depth;
  uint16_t  scale;
  uint32_t  size;
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
  uint8_t * bytes;
  uint32_t  len;
} wzkey;  // decode string and image

typedef struct wznode {
  struct wznode * parent;
  struct wzfile * file;
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
  uint16_t  enc;   // encoded version
  uint16_t  dec;   // decoded version
  uint32_t  hash;  // hash of the version
} wzver;

typedef struct {
  uint8_t   u4[0x10];          // scale 4 bit color to 8 bit color
  uint8_t   u5[0x20];          // scale 5 bit color to 8 bit color
  uint8_t   u6[0x40];          // scale 6 bit color to 8 bit color
  wzcolor   u4444[0x10000];    // unpack rgba 4444 pixel
  wzcolor   u565[0x10000];     // unpack rgb 565 pixel
  wzcolor   c[2][256][256];    // unpack color code 2 and 3 of dxt3
  uint8_t   a[2][256][256][6]; // unpack alpha code 2 ~ 7 of dxt5
} wzplt;  // palette

typedef struct wzfile {
  struct wzctx * ctx;
  FILE *    raw;
  uint32_t  size;
  uint32_t  pos;
  uint8_t   ident[4];
  uint32_t  size_; // the size specified in the header of wz file
  uint32_t  start;
  wzstr     copy;  // copyright
  wzver     ver;
  wzkey *   key;  // decode node name
  wznode    root;
} wzfile;

typedef struct {
  uint8_t   wav[16];
  uint8_t   empty[16];
} wzguid;

typedef struct wzctx {
  size_t    klen; // keys length
  wzkey *   keys;
  wzplt *   plt;
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
#define WZ_COLOR_DXT5 2050

// microsoft define these values in Mmreg.h
#define WZ_AUDIO_PCM 0x0001
#define WZ_AUDIO_MP3 0x0055

#define WZ_AUDIO_WAV_SIZE 18 // sizeof(packed wzwav)
#define WZ_AUDIO_MP3_SIZE 30 // sizeof(packed wzmp3)
#define WZ_AUDIO_PCM_SIZE 44 // sizeof(packed wzpcm)

typedef enum {
  WZ_ENC_AUTO,
  WZ_ENC_ASCII,
  WZ_ENC_UTF16LE,
  WZ_ENC_UTF8
} wzenc;

enum {
  WZ_VAR_UNK,  // not read yet
  WZ_VAR_NIL,
  WZ_VAR_INT16,
  WZ_VAR_INT32,
  WZ_VAR_INT64,
  WZ_VAR_FLT32,
  WZ_VAR_FLT64,
  WZ_VAR_STR,
  WZ_VAR_OBJ
};

enum {
  WZ_OBJ_LIST, // "Property"
  WZ_OBJ_IMG,  // "Canvas"
  WZ_OBJ_VEX,  // "Shape2D#Convex2D"
  WZ_OBJ_VEC,  // "Shape2D#Vector2D"
  WZ_OBJ_AO,   // "Sound_DX8"
  WZ_OBJ_UOL,  // "UOL"
  WZ_OBJ_LEN
};

enum {
  WZ_NODE_NIL,
  WZ_NODE_DIR,
  WZ_NODE_FILE
};

int      wz_read_bytes(void * bytes, uint32_t len, wzfile * file);
int      wz_read_byte(uint8_t * byte, wzfile * file);
int      wz_read_le16(uint16_t * le16, wzfile * file);
int      wz_read_le32(uint32_t * le32, wzfile * file);
int      wz_read_le64(uint64_t * le64, wzfile * file);
int      wz_read_int32(uint32_t * int32, wzfile * file);
int      wz_read_int64(uint64_t * int64, wzfile * file);

int      wz_read_str(uint8_t ** ret_bytes, uint32_t len, wzfile * file);
void     wz_free_str(uint8_t * bytes);

int      wz_decode_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                         uint8_t * bytes, uint32_t len, uint32_t capa,
                         wzkey * key, wzenc enc);
int      wz_read_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                       wzenc * ret_enc,
                       uint32_t capa, wzkey * key, wzenc enc, wzfile * file);
void     wz_free_chars(uint8_t * bytes);

void     wz_decode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
                        uint32_t start, uint32_t hash);
int      wz_read_addr(wzaddr * addr, wzfile * file);

int      wz_seek(uint32_t pos, int origin, wzfile * file);

int      wz_read_grp(wzgrp ** ret_grp, wznode * node,
                     wzfile * file, wzctx * ctx);
void     wz_free_grp(wzgrp ** ret_grp, wznode * node);

void     wz_encode_ver(uint16_t * ret_enc, uint32_t * ret_hash, uint16_t dec);
int      wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash,
                       wzkey ** ret_key, uint16_t enc,
                       uint32_t addr, uint32_t start, uint32_t size, FILE * raw,
                       wzctx * ctx);

void     wz_decode_aes(uint8_t * plain, const uint8_t * cipher, uint32_t len,
                       uint8_t * key, const uint8_t * iv);
void     wz_encode_aes(uint8_t * cipher, const uint8_t * plain, uint32_t len,
                       uint8_t * key, const uint8_t * iv);

int      wz_deduce_key(wzkey ** ret_key, wzstr * name,
                       wzkey * keys, size_t klen);

void     wz_read_pcm(wzpcm * out, uint8_t * pcm);

int      wz_read_obj(wzobj ** ret_obj, wzvar * var,
                     wznode * node, wzfile * file, wzctx * ctx, uint8_t eager);
void     wz_free_obj(wzobj * obj);

int      wz_read_node_r(wznode * root, wzfile * file, wzctx * ctx);
int      wz_read_node_thrd_r(wznode * root, wzfile * file, wzctx * ctx,
                             uint8_t tcapa);

int64_t  wz_get_int(wzvar * var);
double   wz_get_flt(wzvar * var);
char *   wz_get_str(wzvar * var);
wzimg *  wz_get_img(wzvar * var);
wzvex *  wz_get_vex(wzvar * var);
wzvec *  wz_get_vec(wzvar * var);
wzao *   wz_get_ao(wzvar * var);

wzvar *  wz_open_var(wzvar * var, const char * path);
int      wz_close_var(wzvar * var);
wzvar *  wz_open_root_var(wznode * node);

char *   wz_get_var_name(wzvar * var);
uint32_t wz_get_vars_len(wzvar * var);
wzvar *  wz_open_var_at(wzvar * var, uint32_t i);

wznode * wz_open_node(wznode * node, const char * path);
int      wz_close_node(wznode * node);
wznode * wz_open_root_node(wzfile * file);

char *   wz_get_node_name(wznode * node);
uint32_t wz_get_nodes_len(wznode * node);
wznode * wz_open_node_at(wznode * node, uint32_t i);

int      wz_read_file(wzfile * file, FILE * raw, wzctx * ctx);
void     wz_free_file(wzfile * file);
int      wz_open_file(wzfile * file, const char * filename, wzctx * ctx);
int      wz_close_file(wzfile * file);

int      wz_init_ctx(wzctx * ctx);
void     wz_free_ctx(wzctx * ctx);

#endif
