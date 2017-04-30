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

typedef struct { int32_t x; int32_t y; } wzn_vec;

typedef struct {
  uint8_t   _[4 * sizeof(void *) + 8 - 2]; // padding
  int16_t   val;
} wzn16;

typedef struct {
  uint8_t   _[4 * sizeof(void *) + 8 - 4]; // padding
  union     { int32_t i; float f; } val;
} wzn32;

typedef struct {
  uint8_t   _[4 * sizeof(void *)]; // padding
  union     { int64_t i; double f; wzn_vec vec; } val;
} wzn64;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8];
} wznil_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 2];
} wzn16_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - 4];
} wzn32_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *)];
} wzn64_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + sizeof(void *) + 8 - sizeof(void *)];
} wznv_embed;

typedef struct {
  uint8_t   _[2 * sizeof(void *) + 2]; // padding
  uint8_t   name_buf[sizeof(void *) - 2 + 4 - 1];
  uint8_t   key;
  uint32_t  addr;
} wzna_embed;

typedef struct {
  uint8_t   _1[2 * sizeof(void *) + 2]; // padding
  uint8_t   key;
  uint8_t   _2[1]; // padding
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t   _3[sizeof(void *)]; // name in prototype
#endif
  uint32_t  addr;
} wzna;

typedef struct {
  union {
    union  wzn      * node;
    struct wzn_file * file;
  }           root;
  union wzn * parent;
  unsigned    type  : 5;
  unsigned    level : 2;
  unsigned    embed : 1;
  uint8_t     name_len;
  uint8_t     name_e[sizeof(void *) - 2];
  uint8_t *   name;
#if UINTPTR_MAX <= UINT32_MAX
  uint8_t     _[4]; // addr in wzna
#endif
  union {
    struct wzn_str * str;
    struct wzn_ary * ary;
    struct wzn_img * img;
    struct wzn_vex * vex;
    struct wzn_ao  * ao;
  }           val;
} wznp; // prototype

typedef union wzn {
  wznil_embed nil_e;
  wzn16_embed n16_e;
  wzn32_embed n32_e;
  wzn64_embed n64_e;
  wzn16       n16;
  wzn32       n32;
  wzn64       n64;
  wznv_embed  nv_e;
  wzna_embed  na_e;
  wzna        na;
  wznp        n;
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
  uint16_t  depth;
  uint8_t   scale;
  uint8_t   _1[1]; // padding
  uint32_t  size;
  uint32_t  len;
#if UINTPTR_MAX > UINT32_MAX
  uint8_t   _2[4]; // padding
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

typedef enum {
  WZN_CHARS,
  WZN_FMT_CHARS,
  WZN_FMT_CHARS_WITH_LEN,
  WZN_TYPE_CHARS,
  WZN_FMT_OR_TYPE_CHARS
} wzn_chars;

enum {
  WZN_NIL,
  WZN_I16,
  WZN_I32,
  WZN_I64,
  WZN_F32,
  WZN_F64,
  WZN_VEC,  // "Shape2D#Vector2D"
  WZN_UNK,  // not read yet
  WZN_STR,
  WZN_ARY,  // "Property"
  WZN_IMG,  // "Canvas"
  WZN_VEX,  // "Shape2D#Convex2D"
  WZN_AO,   // "Sound_DX8"
  WZN_UOL,  // "UOL"
  WZN_LEN
};

#pragma GCC diagnostic ignored "-Wpadded"

typedef struct {
  uint8_t * bytes;
  uint32_t  len;
} wzkey;  // decode string and image

typedef struct {
  uint8_t   u4[0x10];          // scale 4 bit color to 8 bit color
  uint8_t   u5[0x20];          // scale 5 bit color to 8 bit color
  uint8_t   u6[0x40];          // scale 6 bit color to 8 bit color
  wzcolor   u4444[0x10000];    // unpack rgba 4444 pixel
  wzcolor   u565[0x10000];     // unpack rgb 565 pixel
  wzcolor   c[2][256][256];    // unpack color code 2 and 3 of dxt3
  uint8_t   a[2][256][256][6]; // unpack alpha code 2 ~ 7 of dxt5
} wzplt;  // palette

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

int      wz_read_bytes(void * bytes, uint32_t len, wzn_file * file);
int      wz_read_byte(uint8_t * byte, wzn_file * file);
int      wz_read_le16(uint16_t * le16, wzn_file * file);
int      wz_read_le32(uint32_t * le32, wzn_file * file);
int      wz_read_le64(uint64_t * le64, wzn_file * file);
int      wz_read_int32(uint32_t * int32, wzn_file * file);
int      wz_read_int64(uint64_t * int64, wzn_file * file);

int      wz_read_str(uint8_t ** ret_bytes, uint32_t len, wzn_file * file);
void     wz_free_str(uint8_t * bytes);

int      wz_decode_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                         uint8_t * bytes, uint32_t len, uint32_t capa,
                         uint32_t padding, wzkey * key, wzenc enc);
int      wz_read_chars(uint8_t ** ret_bytes, uint32_t * ret_len,
                       wzenc * ret_enc,
                       uint32_t capa, uint32_t addr, wzn_chars type,
                       uint8_t key, wzkey * keys, wzn_file * file);
void     wz_free_chars(uint8_t * bytes);

void     wz_decode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
                        uint32_t start, uint32_t hash);

int      wz_seek(uint32_t pos, int origin, wzn_file * file);

int      wz_read_grp(wzn * node, wzkey * keys, wzn_file * file);
void     wz_free_grp(wzn * node);

void     wz_encode_ver(uint16_t * ret_enc, uint32_t * ret_hash, uint16_t dec);
int      wz_deduce_ver(uint16_t * ret_dec, uint32_t * ret_hash,
                       uint8_t * ret_key, uint16_t enc,
                       uint32_t addr, uint32_t start, uint32_t size, FILE * raw,
                       wzctx * ctx);

void     wz_decode_aes(uint8_t * plain, const uint8_t * cipher, uint32_t len,
                       uint8_t * key, const uint8_t * iv);
void     wz_encode_aes(uint8_t * cipher, const uint8_t * plain, uint32_t len,
                       uint8_t * key, const uint8_t * iv);

int      wz_deduce_key(uint8_t * ret_key, uint8_t * bytes, uint32_t len,
                       wzkey * keys, size_t klen);

void     wz_read_pcm(wzpcm * out, uint8_t * pcm);

int      wz_read_obj(wzn * node, wzn * root, wzn_file * file, wzctx * ctx,
                     uint8_t eager);
void     wz_free_obj(wzn * node);

int      wz_read_node_r(wzn * root, wzn_file * file, wzctx * ctx);
int      wz_read_node_thrd_r(wzn * root, wzn_file * file, wzctx * ctx,
                             uint8_t tcapa);

int64_t   wz_get_int(wzn * node);
double    wz_get_flt(wzn * node);
char *    wz_get_str(wzn * node);
wzn_img * wz_get_img(wzn * node);
wzn_vex * wz_get_vex(wzn * node);
wzn_vec * wz_get_vec(wzn * node);
wzn_ao *  wz_get_ao(wzn * node);

wzn *    wz_open_var(wzn * node, const char * path);
int      wz_close_var(wzn * node);
wzn *    wz_open_root_var(wzn * node);

char *   wz_get_var_name(wzn * node);
uint32_t wz_get_vars_len(wzn * node);
wzn *    wz_open_var_at(wzn * node, uint32_t i);

wzn    * wz_open_node(wzn * node, const char * path);
int      wz_close_node(wzn * node);
wzn    * wz_open_root_node(wzn_file * file);

char *   wz_get_node_name(wzn * node);
uint32_t wz_get_nodes_len(wzn * node);
wzn    * wz_open_node_at(wzn * node, uint32_t i);

int      wz_open_file(wzn_file * file, const char * filename, wzctx * ctx);
int      wz_close_file(wzn_file * file);

int      wz_init_ctx(wzctx * ctx);
void     wz_free_ctx(wzctx * ctx);

#endif
