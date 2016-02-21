#include <inttypes.h>
#include <file.h>

int
main(void) {
  uint32_t start    = 0;
  uint16_t version  = 0x00ce;
  uint32_t address  = 0x00000000;
  uint32_t position = 7;
  printf("start:           0x%08"PRIx32"\n", start);
  printf("version:         0x%04"PRIx16"\n", version);
  printf("position:        0x%08"PRIx32"\n", position);
  printf("address:         0x%08"PRIx32"\n", address);
  wzver ver = {.dec = version};
  if (wz_encode_ver(&ver)) return 1;
  printf("hash:            0x%04"PRIx16"\n", ver.hash);
  printf("encoded version: 0x%04"PRIx16"\n", ver.enc);
  wzfile file = {.head = {.start = start}, .ver = ver};
  wzaddr addr = {.pos = position};
  for (uint64_t encoded = 0; encoded <= UINT32_MAX; encoded++) {
    addr.val = (uint32_t) encoded;
    wz_decode_addr(&addr, &file);
    if (addr.val == address) {
      printf("encoded address: 0x%08"PRIx32"\n", (uint32_t) encoded);
      break;
    }
  }
  return 0;
}
