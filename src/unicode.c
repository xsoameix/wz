#include <string.h>
#include <stdint.h>

int
wz_code_to_utf8_len(uint8_t * len, uint32_t code) {
  if ((code & 0xffffff80) == 0)      return * len = 1, 0;
  else if ((code & 0xfffff800) == 0) return * len = 2, 0;
  else if ((code & 0xffff0000) == 0) return * len = 3, 0;
  else if (code < 0x00110000)        return * len = 4, 0;
  else return 1;
}

int
wz_code_to_utf8(uint8_t * bytes, uint32_t code) {
  if ((code & 0xffffff80) == 0) {
    bytes[0] = (uint8_t) code;
  } else if ((code & 0xfffff800) == 0) {
    bytes[0] = (uint8_t) (((code >> 6) & 0x1f) | 0xc0);
    bytes[1] = (uint8_t) (((code >> 0) & 0x3f) | 0x80);
  } else if ((code & 0xffff0000) == 0) {
    bytes[0] = (uint8_t) (((code >> 12) & 0x0f) | 0xe0);
    bytes[1] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
    bytes[2] = (uint8_t) (((code >>  0) & 0x3f) | 0x80);
  } else if (code < 0x00110000) {
    bytes[0] = (uint8_t) (((code >> 18) & 0x07) | 0xf0);
    bytes[1] = (uint8_t) (((code >> 12) & 0x3f) | 0x80);
    bytes[2] = (uint8_t) (((code >>  6) & 0x3f) | 0x80);
    bytes[3] = (uint8_t) (((code >>  0) & 0x3f) | 0x80);
  } else return 1;
  return 0;
}

int
wz_utf16le_len(uint8_t * len, uint8_t * bytes) {
  if ((bytes[1] & 0xfc) == 0xd8)
    if ((bytes[3] & 0xfc) == 0xdc)
      return * len = 4, 0;
    else
      return 1;
  else
    return * len = 2, 0;
}

int
wz_utf16le_to_code(uint32_t * code, uint8_t * bytes) {
  if ((bytes[1] & 0xfc) == 0xd8)
    if ((bytes[3] & 0xfc) == 0xdc)
      return * code = (uint32_t) ((bytes[1] & 0x03) << 18 |
                                  (bytes[0]       ) << 10 |
                                  (bytes[3] & 0x03) <<  8 |
                                  (bytes[2]       ) <<  0), 0;
    else
      return 1;
  else
    return * code = (uint32_t) ((bytes[1] << 8) |
                                (bytes[0] << 0)), 0;
}
