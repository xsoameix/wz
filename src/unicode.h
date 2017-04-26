#ifndef WZ_UNICODE_H
#define WZ_UNICODE_H

#include <string.h>
#include <stdint.h>

#define WZ_UTF16LE_MAX_SIZE 4
#define WZ_UTF8_MAX_SIZE    4

int wz_utf16le_size(uint8_t * size, const uint8_t * bytes);
int wz_utf16le_to_unicode(uint32_t * code, const uint8_t * bytes);
int wz_unicode_to_utf8_size(uint8_t * size, uint32_t code);
int wz_unicode_to_utf8(uint8_t * bytes, uint32_t code);

#endif
