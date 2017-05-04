#ifndef WZ_FILE_H
#define WZ_FILE_H

#include <stdio.h>
#include <stdint.h>

// Structures

typedef struct {
  uint8_t   b;
  uint8_t   g;
  uint8_t   r;
  uint8_t   a;
} wzcolor;

typedef struct {
  uint16_t  format;
  uint16_t  channels;
  uint32_t  sample_rate;
  uint32_t  byte_rate;
  uint16_t  block_align;
  uint16_t  bits_per_sample;
  uint16_t  extra_size;
  uint8_t   _[2]; // padding
} wzwav;  // microsoft WAVEFORMATEX structure

typedef struct {
  wzwav     wav;
  uint16_t  id;
  uint8_t   _1[2]; // padding
  uint32_t  flags;
  uint16_t  block_size;
  uint16_t  frames_per_block;
  uint16_t  codec_delay;
  uint8_t   _2[2]; // padding
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
} wzpcm;

typedef struct { int32_t x; int32_t y; } wzvec;

// wznode format:
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

typedef struct {
  uint8_t   _[4 * sizeof(void *) + 8 - 2]; // padding
  int16_t   val;
} wznode_16;

typedef struct {
  uint8_t   _[4 * sizeof(void *) + 8 - 4]; // padding
  union     { int32_t i; float f; } val;
} wznode_32;

typedef struct {
  uint8_t   _[4 * sizeof(void *)]; // padding
  union     { int64_t i; double f; wzvec vec; } val;
} wznode_64;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8];
} wznode_nil_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 2];
} wznode_16_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 4];
} wznode_32_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *)];
} wznode_64_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - sizeof(void *)];
} wznode_ptr_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + 4 - 1];
  uint8_t   key;
  uint32_t  addr;
} wznode_addr_embed;

typedef struct {
  uint8_t   _1[2 * sizeof(void *) + 2]; // padding
  uint8_t   key;
  uint8_t   _2[1]; // padding
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t   _3[sizeof(void *)]; // name in prototype
#endif
  uint32_t  addr;
} wznode_addr;

typedef struct {
  union {
    union  wznode * node;
    struct wzfile * file;
  }              root;
  union wznode * parent;
  uint8_t        info;
  uint8_t        name_len;
  uint8_t        name_e[sizeof(void *) - 2];
  uint8_t *      name;
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t        _[4]; // addr in wznode_addr
#endif
  union {
    struct wzstr * str;
    struct wzary * ary;
    struct wzimg * img;
    struct wzvex * vex;
    struct wzao  * ao;
  }              val;
} wznode_proto; // prototype

typedef union wznode {
  wznode_nil_embed   nil_e;
  wznode_16_embed    n16_e;
  wznode_32_embed    n32_e;
  wznode_64_embed    n64_e;
  wznode_16          n16;
  wznode_32          n32;
  wznode_64          n64;
  wznode_ptr_embed   np_e;
  wznode_addr_embed  na_e;
  wznode_addr        na;
  wznode_proto       n;
} wznode;

typedef struct wzstr {
  uint32_t  len;
  uint8_t   bytes[4]; // variable array
} wzstr;

typedef struct wzary {
  uint32_t  len;
  uint8_t   _[4]; // padding
  wznode    nodes[1]; // variable array
} wzary;

typedef struct wzimg {
  uint32_t  w;
  uint32_t  h;
  uint8_t * data;
  uint16_t  depth;
  uint8_t   scale;
  uint8_t   _1[1]; // padding
  uint32_t  size;
  uint32_t  len;
#if UINTPTR_MAX > UINT32_MAX
  uint8_t   _2[4]; // padding
#endif
  wznode    nodes[1]; // variable array
} wzimg;

typedef struct wzvex {
  uint32_t  len;
  wzvec     ary[1]; // variable array
} wzvex;

typedef struct wzao {
  uint32_t  size;
  uint32_t  ms;
  uint16_t  format;
  uint8_t   _[sizeof(void *) - 2]; // padding
  uint8_t * data;
} wzao;

typedef struct wzfile {
  struct wzctx * ctx;
  FILE *   raw;
  uint32_t pos;
  uint32_t size;
  uint32_t start;
  uint32_t hash;
  uint8_t  key;
  uint8_t  _[sizeof(void *) - 1]; // padding
  wznode   root;
} wzfile;

typedef struct wzctx {
  uint8_t * keys;
} wzctx;

enum { // bit fields of wznode->info
  WZ_TYPE  = 0x0f,
  WZ_LEVEL = 0x10,
  WZ_LEAF  = 0x20, // is it a leaf in level 0 or not
  WZ_EMBED = 0x40
};

enum {
  WZ_LV0_NAME,
  WZ_LV1_NAME,
  WZ_LV1_STR,
  WZ_LV1_TYPENAME,
  WZ_LV1_TYPENAME_OR_STR
};

enum {
  WZ_NIL,
  WZ_I16,
  WZ_I32,
  WZ_I64,
  WZ_F32,
  WZ_F64,
  WZ_VEC,  // "Shape2D#Vector2D"
  WZ_UNK,  // not read yet
  WZ_STR,
  WZ_ARY,  // "Property"
  WZ_IMG,  // "Canvas"
  WZ_VEX,  // "Shape2D#Convex2D"
  WZ_AO,   // "Sound_DX8"
  WZ_UOL,  // "UOL"
  WZ_LEN
};

enum {
  WZ_COLOR_4444 =    1,
  WZ_COLOR_8888 =    2,
  WZ_COLOR_565  =  513,
  WZ_COLOR_DXT3 = 1026,
  WZ_COLOR_DXT5 = 2050
};

enum { // microsoft define these values in Mmreg.h
  WZ_AUDIO_PCM = 0x0001,
  WZ_AUDIO_MP3 = 0x0055
};

enum {
  WZ_AUDIO_WAV_SIZE = 18, // sizeof(packed wzwav)
  WZ_AUDIO_PCM_SIZE = 44  // sizeof(packed wzpcm)
};

enum {
  WZ_ENC_AUTO,
  WZ_ENC_CP1252,
  WZ_ENC_UTF16LE,
  WZ_ENC_UTF8
};

int      wz_read_bytes(void * bytes, uint32_t len, wzfile * file);
int      wz_read_byte(uint8_t * byte, wzfile * file);
int      wz_read_le16(uint16_t * le16, wzfile * file);
int      wz_read_le32(uint32_t * le32, wzfile * file);
int      wz_read_le64(uint64_t * le64, wzfile * file);
int      wz_read_int32(uint32_t * int32, wzfile * file);
int      wz_read_int64(uint64_t * int64, wzfile * file);

int      wz_decode_chars(uint8_t * bytes, uint32_t len,
                         uint8_t key_i, const uint8_t * keys, uint8_t enc);
int      wz_read_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                       uint8_t * ret_enc,
                       uint32_t capa, uint32_t addr, uint8_t type,
                       uint8_t key, uint8_t * keys, wzfile * file);
void     wz_free_chars(uint8_t * bytes);

void     wz_decode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
                        uint32_t start, uint32_t hash);

int      wz_seek(uint32_t pos, int origin, wzfile * file);

int      wz_read_lv0(wznode * node, uint8_t * keys, wzfile * file);
void     wz_free_lv0(wznode * node);

void     wz_encode_ver(uint16_t * ret_enc, uint32_t * ret_hash, uint16_t dec);
int      wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash,
                       uint8_t * ret_key, uint16_t enc,
                       uint32_t addr, uint32_t start, uint32_t size, FILE * raw,
                       const uint8_t * keys);

void     wz_encode_aes(uint8_t * cipher, uint32_t len,
                       uint8_t * key, const uint8_t * iv);

int      wz_read_lv1(wznode * node, wznode * root, wzfile * file,
                     uint8_t * keys, uint8_t eager);
void     wz_free_lv1(wznode * node);

int      wz_read_node_r(wznode * root, wzfile * file, wzctx * ctx);
int      wz_read_node_thrd_r(wznode * root, wzfile * file, wzctx * ctx,
                             uint8_t tcapa);

int16_t  wz_get_i16(wznode * node);
int32_t  wz_get_i32(wznode * node);
int64_t  wz_get_i64(wznode * node);
float    wz_get_f32(wznode * node);
double   wz_get_f64(wznode * node);
char *   wz_get_str(wznode * node);
wzimg *  wz_get_img(wznode * node);
wzvex *  wz_get_vex(wznode * node);
wzvec *  wz_get_vec(wznode * node);
wzao *   wz_get_ao(wznode * node);

wznode * wz_open_node(wznode * node, const char * path);
int      wz_close_node(wznode * node);
wznode * wz_open_root(wzfile * file);

char *   wz_get_name(wznode * node);
uint32_t wz_get_len(wznode * node);
wznode * wz_open_node_at(wznode * node, uint32_t i);

int      wz_open_file(wzfile * file, const char * filename, wzctx * ctx);
int      wz_close_file(wzfile * file);

int      wz_init_ctx(wzctx * ctx);
void     wz_free_ctx(wzctx * ctx);

#endif
