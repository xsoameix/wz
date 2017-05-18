#ifndef WZ_FILE_H
#define WZ_FILE_H

typedef union wznode wznode;
typedef struct wzfile wzfile;
typedef struct wzctx wzctx;

enum {
  WZ_NIL,
  WZ_I16,
  WZ_I32,
  WZ_I64,
  WZ_F32,
  WZ_F64,
  WZ_VEC,  // "Shape2D#Vector2D"
  WZ_UNK,  // not read yet
  WZ_ARY,  // "Property"
  WZ_IMG,  // "Canvas"
  WZ_VEX,  // "Shape2D#Convex2D"
  WZ_AO,   // "Sound_DX8"
  WZ_UOL,  // "UOL"
  WZ_STR,
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

uint8_t   wz_get_type(wznode * node);
int       wz_get_int(int32_t * val, wznode * node);
int       wz_get_i64(int64_t * val, wznode * node);
int       wz_get_f32(float * val, wznode * node);
int       wz_get_f64(double * val, wznode * node);
char *    wz_get_str(wznode * node);
uint8_t * wz_get_img(uint32_t * w, uint32_t * h,
                     uint16_t * depth, uint8_t * scale, wznode * node);
int       wz_get_vex_len(uint32_t * len, wznode * node);
int       wz_get_vex_at(int32_t * x, int32_t * y, uint32_t i, wznode * node);
int       wz_get_vec(int32_t * x, int32_t * y, wznode * node);
uint8_t * wz_get_ao(uint32_t * size, uint32_t * ms, uint16_t * format,
                    wznode * node);

wznode *  wz_open_node(wznode * node, const char * path);
int       wz_close_node(wznode * node);
wznode *  wz_open_root(wzfile * file);

char *    wz_get_name(wznode * node);
int       wz_get_len(uint32_t * len, wznode * node);
wznode *  wz_open_node_at(wznode * node, uint32_t i);

wzfile *  wz_open_file(const char * filename, wzctx * ctx);
int       wz_parse_file(wzfile * file);
int       wz_close_file(wzfile * file);

wzctx *   wz_init_ctx(void);
int       wz_free_ctx(wzctx * ctx);

#endif
