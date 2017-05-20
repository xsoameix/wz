/** @file wz.h
 * @author Lien Chiang
 * @date 20 May 2017
 * @brief wz library public interface */
#ifndef WZ_H
#define WZ_H

#if defined(_WIN64) || defined(__x86_64__) || \
    defined(__aarch64__) || defined(__ppc64__)
#  define WZ_ARCH_64
#else
#  define WZ_ARCH_32
#endif

typedef   signed char  wz_int8_t;   /**< 8 bit signed integer */
typedef   signed short wz_int16_t;  /**< 16 bit signed integer */
typedef   signed int   wz_int32_t;  /**< 32 bit signed integer */
typedef unsigned char  wz_uint8_t;  /**< 8 bit unsigned integer */
typedef unsigned short wz_uint16_t; /**< 16 bit unsigned integer */
typedef unsigned int   wz_uint32_t; /**< 32 bit unsigned integer */

#if defined(_MSC_VER)
typedef   signed __int64 wz_int64_t;
typedef unsigned __int64 wz_uint64_t;
#elif defined(WZ_ARCH_32)
typedef   signed long long wz_int64_t;  /**< 64 bit signed integer */
typedef unsigned long long wz_uint64_t; /**< 64 bit unsigned integer */
#else
typedef   signed long wz_int64_t;
typedef unsigned long wz_uint64_t;
#endif

/** wznode is the node in the tree data structure of wz file.
 * wznode is used to store data, which can be integer (#WZ_I16,
 * #WZ_I32, or #WZ_I64), floating point (#WZ_F32 or #WZ_F64),
 * string (#WZ_STR), vector (#WZ_VEC), convex (#WZ_VEX), image (#WZ_IMG),
 * or audio (#WZ_AO). These types and data of wznode can be accessed
 * by wz_get_*() functions. Also, wznode may has child wznodes,
 * which can be accessed by wz_open_node() function with specified path
 * string. The number of children can be accessed by wz_get_len(). The
 * root wznode of wz file can be accessed by wz_open_root(). */
typedef union wznode wznode;

/** wzfile is used to open and close wz file. After opened the wz file,
 * the root of wznode can be accessed by wz_open_root(). wzfile can be
 * accessed by wz_open_file() with already initialized wzctx. */
typedef struct wzfile wzfile;

/** wzctx is used to prepare the context that every wzfile needed. For example,
 * the AES keys for decrypting the wz file are stored in wzctx. wzfile uses
 * these keys to decrypt the wz file. One wzctx is enough for one program
 * though multiple wzctx is safe because each wzctx is individual and has no
 * side effect. */
typedef struct wzctx wzctx;

enum {
  WZ_NIL, /**< a node with nothing */
  WZ_I16, /**< a node with wz_int16_t */
  WZ_I32, /**< a node with wz_int32_t */
  WZ_I64, /**< a node with wz_int64_t */
  WZ_F32, /**< a node with float */
  WZ_F64, /**< a node with double */
  WZ_VEC, /**< a node with vector (pair of #wz_int32_t x and #wz_int32_t y) */
  WZ_UNK, /**< a node which is not read yet */
  WZ_ARY, /**< a node with array (children of #wznode) */
  WZ_IMG, /**< a node with image (#wz_uint8_t * data, #wz_uint32_t w,
           * #wz_uint32_t h, #wz_uint16_t depth, and #wz_uint8_t scale),
           * which may have children of #wznode */
  WZ_VEX, /**< a node with convex (multiple pairs of #wz_int32_t x and
           * #wz_int32_t y) */
  WZ_AO,  /**< a node with audio (#wz_uint8_t * data, #wz_uint32_t size,
           * #wz_uint32_t ms, and #wz_uint16_t format) */
  WZ_UOL, /**< used in wz library internally */
  WZ_STR, /**< a node with string (const char * utf8) */
  WZ_LEN  /**< used in wz library internally */
};

enum {
  WZ_COLOR_4444 =    1, /**< The format of image in wz file is BGRA4444. */
  WZ_COLOR_8888 =    2, /**< The format of image in wz file is BGRA8888. */
  WZ_COLOR_565  =  513, /**< The format of image in wz file is BGR565. */
  WZ_COLOR_DXT3 = 1026, /**< The format of image in wz file is DXT3. */
  WZ_COLOR_DXT5 = 2050  /**< The format of image in wz file is DXT5. */
};

enum { /* microsoft define these values in Mmreg.h */
  WZ_AUDIO_PCM = 0x0001, /**< The format of audio is WAVE PCM
                          * (https://en.wikipedia.org/wiki/WAV). */
  WZ_AUDIO_MP3 = 0x0055  /**< The format of audio is MP3
                          * (https://en.wikipedia.org/wiki/MP3). */
};

/** Get type of wznode. The type can be #WZ_NIL, #WZ_I16, #WZ_I32, #WZ_I64,
 * #WZ_F32, #WZ_F64, #WZ_VEC, #WZ_UNK, #WZ_ARY, #WZ_IMG, #WZ_VEX, #WZ_AO,
 * or #WZ_STR. */
wz_uint8_t   wz_get_type(wznode * node);

/** Get the integer of wznode with type #WZ_I16 or #WZ_I32.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_int(wz_int32_t * val, wznode * node);

/** Get the integer of wznode with type #WZ_I64.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_i64(wz_int64_t * val, wznode * node);

/** Get the floting point of wznode with type #WZ_F32.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_f32(float * val, wznode * node);

/** Get the floting point of wznode with type #WZ_F64.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_f64(double * val, wznode * node);

/** Get the characters (UTF-8 encoded, null byte terminated) of wznode
 * with type #WZ_STR.
 * @return the characters. Return NULL if error occurred. */
char *       wz_get_str(wznode * node);

/** Get the image of wznode with type #WZ_IMG. The parameters @p depth and
 * @p scale indicate what format of image was stored in wz file, not the
 * format of image this function returned. The image returned is always
 * be BGRA8888, transformed from the image stored in wz file.
 * @param[out] w the width of image
 * @param[out] h the height of image
 * @param[out] depth the depth of image, which can be #WZ_COLOR_4444,
 * #WZ_COLOR_8888, #WZ_COLOR_565, #WZ_COLOR_DXT3, or #WZ_COLOR_DXT5.
 * This param can be NULL.
 * @param[out] scale the scale of image. This param can be NULL.
 * @param[in] node the node
 * @return the pixels of image. Return NULL if error occurred. */
wz_uint8_t * wz_get_img(wz_uint32_t * w, wz_uint32_t * h,
                        wz_uint16_t * depth, wz_uint8_t * scale, wznode * node);

/** Get the number of children of convex of wznode with type #WZ_VEX.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_vex_len(wz_uint32_t * len, wznode * node);

/** Get the \p i th child of convex of wznode with type #WZ_VEX.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_vex_at(wz_int32_t * x, wz_int32_t * y, wz_uint32_t i,
                           wznode * node);

/** Get the vector of wznode with type #WZ_VEC.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_vec(wz_int32_t * x, wz_int32_t * y, wznode * node);

/** Get the audio of wznode with type #WZ_AO. Returned audio data can be
 * #WZ_AUDIO_PCM or #WZ_AUDIO_MP3, based on the paramter @p format.
 * @param[out] size the size of audio including header
 * @param[out] ms the length of audio in milliseconds
 * @param[out] format the format of audio, which can be #WZ_AUDIO_PCM, or
 * #WZ_AUDIO_MP3.
 * @param[in] node the node
 * @return the audio including header. Return NULL if error occurred. */
wz_uint8_t * wz_get_ao(wz_uint32_t * size, wz_uint32_t * ms,
                       wz_uint16_t * format, wznode * node);

/** Get the child wznode of wznode with given @p path.
 * @note the children of wznode would be freed after wz_close_node()
 * or wz_close_file() called. The pointer to any child of wznode would
 * be invalid and should not be used. If you want accessed the wznode again,
 * please ensure wzfile is opened and call wz_open_node().
 * @return the child wznode. Return NULL if not found or error occurred. */
wznode *     wz_open_node(wznode * node, const char * path);

/** Get the @p i th child wznode of wznode with given index @p i.
 * @return the child wznode. Return NULL if error occurred. */
wznode *     wz_open_node_at(wznode * node, wz_uint32_t i);

/** Get the name (UTF-8 encoded, null byte terminated) of wznode.
 * This function always succeed.
 * @return the name of wznode. */
char *       wz_get_name(wznode * node);

/** Get the number of children of wznode.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_get_len(wz_uint32_t * len, wznode * node);

/** Close the children of wznode. The function has no effect if wznode
 * has no child wznodes.
 * @note The function is optional because wz_close_file() will automatically
 * call this function to free all of wznode under the wzfile.
 * Call this function only when memory is not enough.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_close_node(wznode * node);

/** Open the wz file with given @p filename.
 * @note To prevent memory leak, please make sure wz_close_file() is
 * called after wz_open_file() succeed.
 * @return the wzfile. Return NULL if error occurred. */
wzfile *     wz_open_file(const char * filename, wzctx * ctx);

/** Get the root wznode of wzfile.
 * @return the root wznode. Return NULL if error occurred. */
wznode *     wz_open_root(wzfile * file);

/** Parse the whole wz file.
 * @note The function is intended for benchmarking the parsing speed.
 * If you want to get data from wz file, please use wz_open_root() instead.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_parse_file(wzfile * file);

/** Close the wzfile.
 * @note This function will call wz_close_node() to free all of wznode
 * under the wzfile.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_close_file(wzfile * file);

/** Initialize the wzctx.
 * @return the wzctx. Return NULL if error occurred. */
wzctx *      wz_init_ctx(void);

/** Free the wzctx.
 * @return 0 if succeed, 1 if error occurred. */
int          wz_free_ctx(wzctx * ctx);

#endif
