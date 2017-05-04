#include "byteorder.h"

#ifdef WZ_SWAP_NO_BUILTIN
uint16_t
wz_swap16(uint16_t x16) {
  return (uint16_t) ((x16 << 8) | (x16 >> 8));
}

uint32_t
wz_swap32(uint32_t x32) {
  uint32_t x16 = (x32 << 16) | (x32 >> 16);
  return (((x16 << 8) & 0xff00ff00) |
          ((x16 >> 8) & 0x00ff00ff));
}

uint64_t
wz_swap64(uint64_t x64) {
  uint64_t x32 = (x64 << 32) | (x64 >> 32);
  uint64_t x16 = (((x32 << 16) & 0xffff0000ffff0000) |
                  ((x32 >> 16) & 0x0000ffff0000ffff));
  return (((x16 << 8) & 0xff00ff00ff00ff00) |
          ((x16 >> 8) & 0x00ff00ff00ff00ff));
}
#endif
