#ifndef WZ_UNICODE_H
#define WZ_UNICODE_H

#include <string.h>
#include <stdint.h>

#define WZ_UTF16LE_MAX_LEN 4
#define WZ_UTF8_MAX_LEN    4

int wz_code_to_utf8_len(uint8_t * len, uint32_t code);
int wz_code_to_utf8(uint8_t * bytes, uint32_t code);
int wz_utf16le_len(uint8_t * len, uint8_t * bytes);
int wz_utf16le_to_code(uint32_t * code, uint8_t * bytes);

#endif
