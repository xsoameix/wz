#ifndef WZ_BYTEORDER_H
#define WZ_BYTEORDER_H

#include <stdint.h>

uint16_t wz_htole16(uint16_t x);
uint32_t wz_htole32(uint32_t x);
uint64_t wz_htole64(uint64_t x);
uint16_t wz_htobe16(uint16_t x);
uint32_t wz_htobe32(uint32_t x);
uint64_t wz_htobe64(uint64_t x);
uint16_t wz_le16toh(uint16_t x);
uint32_t wz_le32toh(uint32_t x);
uint64_t wz_le64toh(uint64_t x);
uint16_t wz_be16toh(uint16_t x);
uint32_t wz_be32toh(uint32_t x);
uint64_t wz_be64toh(uint64_t x);

#endif
