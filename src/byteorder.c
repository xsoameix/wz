#include "byteorder.h"

uint16_t
wz_swap16(uint16_t in) {
  uint16_t out;
  ((uint8_t *) &out)[1] = ((uint8_t *) &in)[0];
  ((uint8_t *) &out)[0] = ((uint8_t *) &in)[1];
  return out;
}

uint32_t
wz_swap32(uint32_t in) {
  uint32_t out;
  ((uint8_t *) &out)[3] = ((uint8_t *) &in)[0];
  ((uint8_t *) &out)[2] = ((uint8_t *) &in)[1];
  ((uint8_t *) &out)[1] = ((uint8_t *) &in)[2];
  ((uint8_t *) &out)[0] = ((uint8_t *) &in)[3];
  return out;
}

uint64_t
wz_swap64(uint64_t in) {
  uint32_t out;
  ((uint8_t *) &out)[7] = ((uint8_t *) &in)[0];
  ((uint8_t *) &out)[6] = ((uint8_t *) &in)[1];
  ((uint8_t *) &out)[5] = ((uint8_t *) &in)[2];
  ((uint8_t *) &out)[4] = ((uint8_t *) &in)[3];
  ((uint8_t *) &out)[3] = ((uint8_t *) &in)[4];
  ((uint8_t *) &out)[2] = ((uint8_t *) &in)[5];
  ((uint8_t *) &out)[1] = ((uint8_t *) &in)[6];
  ((uint8_t *) &out)[0] = ((uint8_t *) &in)[7];
  return out;
}

#define WZ_IS_BIG_ENDIAN (* (uint16_t *) "\x00\xff" == 0x00ff)

uint16_t wz_htole16(uint16_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap16(x) : x; }
uint32_t wz_htole32(uint32_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap32(x) : x; }
uint64_t wz_htole64(uint64_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap64(x) : x; }
uint16_t wz_htobe16(uint16_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap16(x); }
uint32_t wz_htobe32(uint32_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap32(x); }
uint64_t wz_htobe64(uint64_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap64(x); }
uint16_t wz_le16toh(uint16_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap16(x) : x; }
uint32_t wz_le32toh(uint32_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap32(x) : x; }
uint64_t wz_le64toh(uint64_t x) { return WZ_IS_BIG_ENDIAN ? wz_swap64(x) : x; }
uint16_t wz_be16toh(uint16_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap16(x); }
uint32_t wz_be32toh(uint32_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap32(x); }
uint64_t wz_be64toh(uint64_t x) { return WZ_IS_BIG_ENDIAN ? x : wz_swap64(x); }
