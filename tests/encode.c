#include <inttypes.h>
#include <file.h>

int
main(void) {
  wzver ver = {.dec = 0x00ce};
  printf("decoded version: 0x%04"PRIx16"\n", ver.dec);
  if (wz_encode_ver(&ver)) return 1;
  printf("encoded version: 0x%04"PRIx16"\n", ver.enc);
  uint32_t decoded = 0x00000000;
  printf("decoded address: 0x%08"PRIx32"\n", decoded);
  for (uint64_t encoded = 0; encoded <= UINT32_MAX; encoded++) {
    wzfile file = {.head = {.start = 18}, .ver = ver};
    wzaddr addr = {.pos = 27, .val = encoded};
    wz_decode_addr(&addr, &file);
    if (addr.val == decoded) {
      printf("encoded address: 0x%08"PRIx32"\n", (uint32_t) encoded);
      break;
    }
  }
  return 0;
}
