#include "predef.h"

#ifdef WZ_MSVC
#  pragma warning(push, 3)
#endif

#include <stdlib.h>
#include "check_fix.h"

#ifdef WZ_MSVC
#  pragma warning(pop)
#endif

#include "test_file.h"
#include "wrap_alloc.h"

#define malloc wrap_malloc
#define free wrap_free
#include "file.c"
#undef free
#undef malloc

START_TEST(test_node) {
#define offof(a, b) (size_t) ((char *) (&(&(a))->b) - (char *) &(a))
  wznode n;
#if UINTPTR_MAX <= UINT32_MAX
  ck_assert(sizeof(n.n16_e)          == 22);
  ck_assert(offof(n, n16_e.name_buf) == 10);
  ck_assert(sizeof(n.n16_e.name_buf) == 12);

  ck_assert(sizeof(n.n32_e)          == 20);
  ck_assert(offof(n, n32_e.name_buf) == 10);
  ck_assert(sizeof(n.n32_e.name_buf) == 10);

  ck_assert(sizeof(n.n64_e)          == 16);
  ck_assert(offof(n, n64_e.name_buf) == 10);
  ck_assert(sizeof(n.n64_e.name_buf) ==  6);

  ck_assert(sizeof(n.n16)            == 24);
  ck_assert(offof(n, n16.val)        == 22);

  ck_assert(sizeof(n.n32)            == 24);
  ck_assert(offof(n, n32.val)        == 20);

  ck_assert(sizeof(n.n64)            == 24);
  ck_assert(offof(n, n64.val)        == 16);

  ck_assert(sizeof(n.np_e)           == 20);
  ck_assert(offof(n, np_e.name_buf)  == 10);
  ck_assert(sizeof(n.np_e.name_buf)  == 10);

  ck_assert(sizeof(n.na_e)           == 20);
  ck_assert(offof(n, na_e.name_buf)  == 10);
  ck_assert(sizeof(n.na_e.name_buf)  ==  5);
  ck_assert(offof(n, na_e.key)       == 15);
  ck_assert(offof(n, na_e.addr)      == 16);

  ck_assert(sizeof(n.na)             == 20);
  ck_assert(offof(n, na.key)         == 10);
  ck_assert(offof(n, na.addr)        == 16);

  ck_assert(sizeof(n.n)              == 24);
  ck_assert(offof(n, n.root)         ==  0);
  ck_assert(offof(n, n.parent)       ==  4);
  ck_assert(offof(n, n.info)         ==  8);
  ck_assert(offof(n, n.name_len)     ==  9);
  ck_assert(offof(n, n.name_e)       == 10);
  ck_assert(offof(n, n.name)         == 12);
  ck_assert(offof(n, n.val)          == 20);
#else
  ck_assert(sizeof(n.n16_e)          == 38);
  ck_assert(offof(n, n16_e.name_buf) == 18);
  ck_assert(sizeof(n.n16_e.name_buf) == 20);

  ck_assert(sizeof(n.n32_e)          == 36);
  ck_assert(offof(n, n32_e.name_buf) == 18);
  ck_assert(sizeof(n.n32_e.name_buf) == 18);

  ck_assert(sizeof(n.n64_e)          == 32);
  ck_assert(offof(n, n64_e.name_buf) == 18);
  ck_assert(sizeof(n.n64_e.name_buf) == 14);

  ck_assert(sizeof(n.n16)            == 40);
  ck_assert(offof(n, n16.val)        == 38);

  ck_assert(sizeof(n.n32)            == 40);
  ck_assert(offof(n, n32.val)        == 36);

  ck_assert(sizeof(n.n64)            == 40);
  ck_assert(offof(n, n64.val)        == 32);

  ck_assert(sizeof(n.np_e)           == 32);
  ck_assert(offof(n, np_e.name_buf)  == 18);
  ck_assert(sizeof(n.np_e.name_buf)  == 14);

  ck_assert(sizeof(n.na_e)           == 32);
  ck_assert(offof(n, na_e.name_buf)  == 18);
  ck_assert(sizeof(n.na_e.name_buf)  ==  9);
  ck_assert(offof(n, na_e.key)       == 27);
  ck_assert(offof(n, na_e.addr)      == 28);

  ck_assert(sizeof(n.na)             == 24);
  ck_assert(offof(n, na.key)         == 18);
  ck_assert(offof(n, na.addr)        == 20);

  ck_assert(sizeof(n.n)              == 40);
  ck_assert(offof(n, n.root)         ==  0);
  ck_assert(offof(n, n.parent)       ==  8);
  ck_assert(offof(n, n.info)         == 16);
  ck_assert(offof(n, n.name_len)     == 17);
  ck_assert(offof(n, n.name_e)       == 18);
  ck_assert(offof(n, n.name)         == 24);
  ck_assert(offof(n, n.val)          == 32);
#endif
#undef offof
} END_TEST

static const char tmp_fname[] = "tmpfile";

static void
create_file(wzfile * file, const uint8_t * bytes, uint32_t len) {
  FILE * raw;
  ck_assert((raw = fopen(tmp_fname, "w+b")) != NULL);
  if (len) {
    ck_assert(fwrite(bytes, len, 1, raw) == 1);
    ck_assert(fseek(raw, 0, SEEK_SET) == 0);
  }
  file->raw = raw;
  file->pos = 0;
  file->size = len;
}

static void
close_file(wzfile * file) {
  ck_assert(memerr() == 0);
  ck_assert(fclose(file->raw) == 0);
}

static void
delete_file(wzfile * file) {
  ck_assert(memerr() == 0);
  ck_assert(fclose(file->raw) == 0);
  ck_assert(remove(tmp_fname) == 0);
}

START_TEST(test_read_bytes) {
  static const uint8_t normal[] = {'a', 'b'};
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint8_t buffer[sizeof(normal)];

  // It should be ok if len == 0
  ck_assert(wz_read_bytes(buffer, 0, &file) == 0);

  // It should be ok
  ck_assert(wz_read_bytes(buffer, sizeof(normal), &file) == 0);
  ck_assert(memcmp(buffer, normal, sizeof(normal)) == 0);

  // It should not change position and data if error occured
  ck_assert(wz_read_bytes(buffer, sizeof(normal), &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(memcmp(buffer, normal, sizeof(normal)) == 0);

  delete_file(&file);
} END_TEST

START_TEST(test_read_byte) {
  static const uint8_t normal[] = {'a'};
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint8_t buffer;

  // It should be ok
  ck_assert(wz_read_byte(&buffer, &file) == 0);
  ck_assert(buffer == normal[0]);

  // It should not change position and data if error occured
  ck_assert(wz_read_byte(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == normal[0]);

  delete_file(&file);
} END_TEST

START_TEST(test_read_le16) {
  static const uint8_t normal[] = {0x01, 0x23};
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint16_t buffer;

  // It should be ok
  ck_assert(wz_read_le16(&buffer, &file) == 0);
  ck_assert(buffer == 0x2301);

  // It should not change position and data if error occured
  uint16_t copy = buffer;
  ck_assert(wz_read_le16(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == copy);

  delete_file(&file);
} END_TEST

START_TEST(test_read_le32) {
  static const uint8_t normal[] = {0x01, 0x23, 0x45, 0x67};
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint32_t buffer;

  // It should be ok
  ck_assert(wz_read_le32(&buffer, &file) == 0);
  ck_assert(buffer == 0x67452301);

  // It should not change position and data if error occured
  uint32_t copy = buffer;
  ck_assert(wz_read_le32(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == copy);

  delete_file(&file);
} END_TEST

START_TEST(test_read_le64) {
  static const uint8_t normal[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
  };
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint64_t buffer;

  // It should be ok
  ck_assert(wz_read_le64(&buffer, &file) == 0);
  ck_assert(buffer == 0xefcdab8967452301);

  // It should not change position and data if error occured
  uint64_t copy = buffer;
  ck_assert(wz_read_le64(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == copy);

  delete_file(&file);
} END_TEST

START_TEST(test_read_int32) {
  static const uint8_t normal[] = {0x01, 0xfe, 0x80, 0x23, 0x45, 0x67, 0x89};
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint32_t buffer;

  // It should read positive int8
  ck_assert(wz_read_int32(&buffer, &file) == 0);
  ck_assert(buffer == 1);

  // It should read negative int8
  ck_assert(wz_read_int32(&buffer, &file) == 0);
  ck_assert(buffer == 0xfffffffe);

  // It should read postive int32
  ck_assert(wz_read_int32(&buffer, &file) == 0);
  ck_assert(buffer == 0x89674523);

  // It should not change position and data if error occured
  uint32_t copy = buffer;
  ck_assert(wz_read_int32(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == copy);

  delete_file(&file);
} END_TEST

START_TEST(test_read_int64) {
  static const uint8_t normal[] = {
    0x01, 0xfe, 0x80, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01
  };
  wzfile file;
  create_file(&file, normal, sizeof(normal));
  uint64_t buffer;

  // It should read positive int8
  ck_assert(wz_read_int64(&buffer, &file) == 0);
  ck_assert(buffer == 1);

  // It should read negative int8
  ck_assert(wz_read_int64(&buffer, &file) == 0);
  ck_assert(buffer == 0xfffffffffffffffe);

  // It should read postive int64
  ck_assert(wz_read_int64(&buffer, &file) == 0);
  ck_assert(buffer == 0x01efcdab89674523);

  // It should not change position and data if error occured
  uint64_t copy = buffer;
  ck_assert(wz_read_int64(&buffer, &file) == 1);
  ck_assert(file.pos == sizeof(normal));
  ck_assert(buffer == copy);

  delete_file(&file);
} END_TEST

static uint32_t
numgen(uint32_t x) {
  static const uint32_t prime = 4294967291;
  if (x < prime) {
    uint32_t residue = (uint32_t) (((uint64_t) x * x) % prime);
    return (x <= prime / 2) ? residue : prime - residue;
  } else {
    return x;
  }
}

static void
keygen(uint8_t * key, uint32_t len) {
  static const uint32_t seed_base   = 0xca63ad9a;
  static const uint32_t seed_offset = 0x77c85c28;
  uint32_t index  = numgen(numgen(seed_base)   + 0x9a0e1793);
  uint32_t offset = numgen(numgen(seed_offset) + 0x28d1f9c7);
  for (uint32_t i = 0; i < len; i++)
    key[i] = numgen((numgen(index++) + offset) ^ 0xdf53971e) & 0xff;
}

START_TEST(test_decode_chars) {
  uint32_t key_len = 0x12000;
  uint8_t * key;
  ck_assert((key = malloc(key_len)) != NULL);
  keygen(key, key_len);
  uint8_t * enc;
  ck_assert((enc = malloc(key_len)) != NULL);

  // It should decode ascii/cp1252
  {
    static const uint8_t dec[] = {'f', 'i', 'a', 'n', 'c', 0xe9, 'e'};
    uint8_t mask;

    mask = 0xaa;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      enc[i] = dec[i] ^ mask++ ^ key[i];

    // when the first key is used
    ck_assert(wz_decode_chars(enc, sizeof(dec),
                              0, key, WZ_ENC_CP1252) == 0);
    ck_assert(memcmp(enc, dec, sizeof(dec)) == 0);

    mask = 0xaa;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      enc[i] = dec[i] ^ mask++;

    // when the empty key is used
    ck_assert(wz_decode_chars(enc, sizeof(dec),
                              2, key, WZ_ENC_CP1252) == 0);
    ck_assert(memcmp(enc, dec, sizeof(dec)) == 0);

    mask = 0xaa;
    for (uint32_t i = 0; i < key_len; i++)
      if (i < 0x10000)
        enc[i] = (uint8_t) (('a' + i % 26) ^ mask++ ^ key[i]);
      else
        enc[i] = (uint8_t) (('a' + i % 26) ^ mask++);

    // when len > 0x10000
    ck_assert(wz_decode_chars(enc, key_len,
                              0, key, WZ_ENC_CP1252) == 0);
    mask = 0xaa;
    uint8_t same = 1;
    for (uint32_t i = 0; i < key_len; i++)
      if (enc[i] != 'a' + i % 26) {
        same = 0;
        break;
      }
    ck_assert(same == 1);
  }

  // It should decode utf16le
  {
    static const uint8_t dec[] = {0x42, 0x30, 0x44, 0x30}; // love in japanese
    uint16_t mask;

    mask = 0xaaaa;
    for (uint8_t i = 0; i < sizeof(dec); i = (uint8_t) (i + 2)) {
      enc[i + 1] = (uint8_t) (dec[i + 1] ^ (mask >> 8)   ^ key[i + 1]);
      enc[i]     = (uint8_t) (dec[i]     ^ (mask & 0xff) ^ key[i]);
      mask++;
    }

    // when the first key is used
    ck_assert(wz_decode_chars(enc, sizeof(dec),
                              0, key, WZ_ENC_UTF16LE) == 0);
    ck_assert(memcmp(enc, dec, sizeof(dec)) == 0);

    mask = 0xaaaa;
    for (uint8_t i = 0; i < sizeof(dec); i = (uint8_t) (i + 2)) {
      enc[i + 1] = (uint8_t) (dec[i + 1] ^ (mask >> 8));
      enc[i]     = (uint8_t) (dec[i]     ^ (mask & 0xff));
      mask++;
    }

    // when the empty key is used
    ck_assert(wz_decode_chars(enc, sizeof(dec),
                              2, key, WZ_ENC_UTF16LE) == 0);
    ck_assert(memcmp(enc, dec, sizeof(dec)) == 0);

    // It should fail when len > 0x10000
    ck_assert(wz_decode_chars(enc, key_len,
                              0, key, WZ_ENC_UTF16LE) == 1);
  }

  // It should decode utf8
  {
    static const uint8_t dec[] = {
      ' ', 0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84, ' ' // love in japanese
    };
    for (uint32_t i = 0; i < key_len;)
      for (uint8_t j = 0; j < sizeof(dec); j++) {
        enc[i] = dec[j] ^ key[i];
        i++;
      }

    // when len > 0x10000
    ck_assert(wz_decode_chars(enc, key_len,
                              0, key, WZ_ENC_UTF8) == 0);
    uint8_t same = 1;
    for (uint32_t i = 0; i < key_len;) {
      for (uint8_t j = 0; j < sizeof(dec); j++) {
        if (enc[i] != dec[j]) {
          same = 0;
          break;
        }
        i++;
      }
      if (!same)
        break;
    }
    ck_assert(same == 1);
  }

  free(enc);
  free(key);
} END_TEST

START_TEST(test_read_chars) {
  wzfile file;
  uint8_t * bytes;
  uint32_t len;
  uint8_t encoding;

  // It should be ok
  {
    static const uint8_t enc[] = {0x01, 0x23};
    uint8_t str[1 + sizeof(enc)];

    str[0] = (~sizeof(enc) + 1) & 0xff;
    for (uint8_t i = 0; i < sizeof(enc); i++)
      str[i + 1] = enc[i];

    create_file(&file, str, sizeof(str));

    // when it is a short cp1252/ascii/utf8 string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0xff, NULL, &file) == 0);
    ck_assert(len == sizeof(enc));
    ck_assert(memcmp(bytes, enc, sizeof(enc)) == 0);
    ck_assert(bytes[sizeof(enc)] == '\0');
    ck_assert(encoding == WZ_ENC_CP1252);
    ck_assert(memused() == sizeof(enc) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t enc[] = {0x45, 0x67};
    uint8_t str[1 + 4 + sizeof(enc)];

    str[0] = (uint8_t) INT8_MIN;
    str[1] = sizeof(enc);
    str[2] = 0;
    str[3] = 0;
    str[4] = 0;
    for (uint8_t i = 0; i < sizeof(enc); i++)
      str[i + 5] = enc[i];

    create_file(&file, str, sizeof(str));

    // when it is a long cp1252/ascii/utf8 string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0xff, NULL, &file) == 0);
    ck_assert(len == sizeof(enc));
    ck_assert(memcmp(bytes, enc, sizeof(enc)) == 0);
    ck_assert(bytes[sizeof(enc)] == '\0');
    ck_assert(encoding == WZ_ENC_CP1252);
    ck_assert(memused() == sizeof(enc) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t enc[] = {0x89, 0xab};
    uint8_t str[1 + sizeof(enc)];

    str[0] = sizeof(enc) >> 1;
    for (uint8_t i = 0; i < sizeof(enc); i++)
      str[i + 1] = enc[i];

    create_file(&file, str, sizeof(str));

    // when it is a short utf16le string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0xff, NULL, &file) == 0);
    ck_assert(len == sizeof(enc));
    ck_assert(memcmp(bytes, enc, sizeof(enc)) == 0);
    ck_assert(bytes[sizeof(enc)] == '\0');
    ck_assert(encoding == WZ_ENC_UTF16LE);
    ck_assert(memused() == sizeof(enc) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t enc[] = {0x89, 0xab};
    uint8_t str[1 + 4 + sizeof(enc)];

    str[0] = INT8_MAX;
    str[1] = sizeof(enc) >> 1;
    str[2] = 0;
    str[3] = 0;
    str[4] = 0;
    for (uint8_t i = 0; i < sizeof(enc); i++)
      str[i + 5] = enc[i];

    create_file(&file, str, sizeof(str));

    // when it is a long utf16le string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0xff, NULL, &file) == 0);
    ck_assert(len == sizeof(enc));
    ck_assert(memcmp(bytes, enc, sizeof(enc)) == 0);
    ck_assert(bytes[sizeof(enc)] == '\0');
    ck_assert(encoding == WZ_ENC_UTF16LE);
    ck_assert(memused() == sizeof(enc) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }

  // It should decode if key is set
  {
    static const uint8_t u8[] = {'f', 'i', 'a', 'n', 'c', 0xc3, 0xa9, 'e'};
    static const uint8_t dec[] = {'f', 'i', 'a', 'n', 'c', 0xe9, 'e'};
    uint8_t enc[1 + sizeof(dec)];
    uint8_t key[sizeof(dec)];
    keygen(key, sizeof(dec));
    uint8_t mask = 0xaa;

    enc[0] = (~sizeof(dec) + 1) & 0xff;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      enc[i + 1] = dec[i] ^ mask++ ^ key[i];

    create_file(&file, enc, sizeof(enc));

    // when it is a cp1252 string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0, key, &file) == 0);
    ck_assert(len == sizeof(u8));
    ck_assert(memcmp(bytes, u8, sizeof(u8)) == 0);
    ck_assert(bytes[sizeof(u8)] == '\0');
    ck_assert(encoding == WZ_ENC_CP1252);
    ck_assert(memused() == sizeof(u8) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t u8[] = {0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84};
    static const uint8_t dec[] = {0x42, 0x30, 0x44, 0x30}; // love in japanese
    uint8_t enc[1 + sizeof(dec)];
    uint8_t key[sizeof(dec)];
    keygen(key, sizeof(dec));
    uint16_t mask = 0xaaaa;

    enc[0] = sizeof(dec) >> 1;
    for (uint8_t i = 0; i < sizeof(dec); i = (uint8_t) (i + 2)) {
      enc[i + 2] = (uint8_t) (dec[i + 1] ^ (mask >> 8)   ^ key[i + 1]);
      enc[i + 1] = (uint8_t) (dec[i]     ^ (mask & 0xff) ^ key[i]);
      mask++;
    }

    create_file(&file, enc, sizeof(enc));

    // when it is a utf16le string
    ck_assert(wz_read_chars(&bytes, &len, &encoding, 0, 0,
                            WZ_LV0_NAME, 0, key, &file) == 0);
    ck_assert(len == sizeof(u8));
    ck_assert(memcmp(bytes, u8, sizeof(u8)) == 0);
    ck_assert(bytes[sizeof(u8)] == '\0');
    ck_assert(encoding == WZ_ENC_UTF16LE);
    ck_assert(memused() == sizeof(u8) + 1);
    wz_free_chars(bytes);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
} END_TEST

static void
wz_encode_addr(uint32_t * ret_val, uint32_t val, uint32_t pos,
               uint32_t start, uint32_t hash) {
  uint32_t key = 0x581c3f6d;
  uint32_t x = ~(pos - start) * hash - key;
  uint32_t n = x & 0x1f;
  x = (x << n) | (x >> (32 - n)); // rotate left n bit
  * ret_val = x ^ (val - start * 2);
}

START_TEST(test_decode_addr) {
  // It should be ok
  uint32_t hash = 0x713;
  uint32_t start = 0x3c;
  uint32_t pos = 0x51;
  uint32_t dec = 0x2ed;
  uint32_t enc;
  wz_encode_addr(&enc, dec, pos, start, hash);
  ck_assert(enc != dec);
  wz_decode_addr(&enc, enc, pos, start, hash);
  ck_assert(enc == 0x2ed);
} END_TEST

START_TEST(test_seek) {
  static const uint8_t str[] = {0x01, 0x23, 0x45, 0x67, 0x89};
  wzfile file;
  create_file(&file, str, sizeof(str));

  // It should seek relative address
  ck_assert(wz_seek(3, SEEK_CUR, &file) == 0);
  ck_assert(wz_seek(1, SEEK_CUR, &file) == 0);
  ck_assert(ftell(file.raw) == 4);
  ck_assert(file.pos == 4);

  // It should seek absolute address
  ck_assert(wz_seek(2, SEEK_SET, &file) == 0);
  ck_assert(ftell(file.raw) == 2);
  ck_assert(file.pos == 2);

  // It should not seek invalid address
  ck_assert(wz_seek(sizeof(str) + 1, SEEK_SET, &file) == 1);
  ck_assert(ftell(file.raw) == 2);
  ck_assert(file.pos == 2);

  delete_file(&file);
} END_TEST

START_TEST(test_read_lv0) {
  uint8_t head[5];
  for (uint8_t i = 0; i < sizeof(head); i++)
    head[i] = i;
  const uint32_t root_addr = sizeof(head);
  const uint32_t start = root_addr - 3;
  wznode node;
  node.n.info = WZ_EMBED;
  node.na_e.addr = root_addr;
  const uint32_t addr_dec = 0x01234567;
  uint32_t addr_pos;
  uint32_t addr_enc;
  const uint32_t hash = 0xc5e3;
  wzfile file;
  file.key = 0;
  file.start = start;
  file.hash = hash;

  // It should be ok
  {
    uint8_t key[1];

    uint8_t str[sizeof(head) + 1 + 1 + 10];
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[i] = head[i];
    str[sizeof(head) + 0] = 0x01; // len
    str[sizeof(head) + 1] = 0x01; // type
    for (uint8_t i = 0; i < 10; i++)
      str[i + sizeof(head) + 2] = 0xff;

    create_file(&file, str, sizeof(str));

    // It should read type 1
    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 0);
    ck_assert(memused() != 0);
    ck_assert(node.n.val.ary != NULL);
    ck_assert(node.n.val.ary->len == 1);
    wznode * child = node.n.val.ary->nodes;
    ck_assert((child->n.info & WZ_TYPE) == WZ_NIL);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.val.ary == NULL);
    wz_free_lv0(&node);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t u8[] = {'f', 'i', 'a', 'n', 'c', 0xc3, 0xa9, 'e'};
    static const uint8_t dec[] = {'f', 'i', 'a', 'n', 'c', 0xe9, 'e'};
    uint8_t key[sizeof(dec)];
    keygen(key, sizeof(dec));
    uint8_t enc[sizeof(dec)];
    uint8_t mask = 0xaa;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      enc[i] = dec[i] ^ mask++ ^ key[i];
    uint8_t str[sizeof(head) + 1 + 1 + 4 + 1 + 1 + 4 + 1 + 1 + sizeof(dec)];
    uint8_t offset = (uint8_t) (sizeof(str) - sizeof(dec) - 1 - 1 - start);
    addr_pos = sizeof(str) - sizeof(dec) - 1 - 1 - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[i] = head[i];
    str[sizeof(head) + 0]  = 0x01; // len
    str[sizeof(head) + 1]  = 0x02; // type
    str[sizeof(head) + 2]  = offset; // offset
    str[sizeof(head) + 3]  = 0;
    str[sizeof(head) + 4]  = 0;
    str[sizeof(head) + 5]  = 0;
    str[sizeof(head) + 6]  = 0x01; // size
    str[sizeof(head) + 7]  = 0x23; // check
    str[sizeof(head) + 8]  = (addr_enc      ) & 0xff; // addr
    str[sizeof(head) + 9]  = (addr_enc >>  8) & 0xff;
    str[sizeof(head) + 10] = (addr_enc >> 16) & 0xff;
    str[sizeof(head) + 11] = (uint8_t) (addr_enc >> 24);
    str[sizeof(head) + 12] = 0x04; // second type
    str[sizeof(head) + 13] = (~sizeof(dec) + 1) & 0xff;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      str[i + sizeof(head) + 14] = enc[i];

    create_file(&file, str, sizeof(str));

    // It should read type 2
    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 0);
    ck_assert(memused() != 0);
    ck_assert(node.n.val.ary != NULL);
    ck_assert(node.n.val.ary->len == 1);
    wznode * child = node.n.val.ary->nodes;
    ck_assert((child->n.info & WZ_TYPE) == WZ_UNK);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8));
    uint32_t child_addr;
    uint8_t child_key;
    uint8_t * child_name;
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8, sizeof(u8)) == 0);
    ck_assert(child_name[sizeof(u8)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    wz_free_lv0(&node);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t u8[] = {0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84};
    static const uint8_t dec[] = {0x42, 0x30, 0x44, 0x30}; // love in japanese
    uint8_t key[sizeof(dec)];
    keygen(key, sizeof(dec));
    uint8_t enc[sizeof(dec)];
    uint16_t mask = 0xaaaa;
    for (uint8_t i = 0; i < sizeof(dec); i = (uint8_t) (i + 2)) {
      enc[i + 1] = (uint8_t) (dec[i + 1] ^ (mask >> 8)   ^ key[i + 1]);
      enc[i]     = (uint8_t) (dec[i]     ^ (mask & 0xff) ^ key[i]);
      mask++;
    }
    uint8_t str[sizeof(head) + 1 + 1 + 1 + sizeof(dec) + 1 + 1 + 4];
    addr_pos = sizeof(str) - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[i] = head[i];
    str[sizeof(head) + 0] = 0x01; // len
    str[sizeof(head) + 1] = 0x03; // type
    str[sizeof(head) + 2] = sizeof(dec) >> 1;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      str[i + sizeof(head) + 3] = enc[i];
    str[sizeof(head) + sizeof(enc) + 3] = 0x01; // size
    str[sizeof(head) + sizeof(enc) + 4] = 0x23; // check
    str[sizeof(head) + sizeof(enc) + 5] = (addr_enc      ) & 0xff; // addr
    str[sizeof(head) + sizeof(enc) + 6] = (addr_enc >>  8) & 0xff;
    str[sizeof(head) + sizeof(enc) + 7] = (addr_enc >> 16) & 0xff;
    str[sizeof(head) + sizeof(enc) + 8] = (uint8_t) (addr_enc >> 24);

    create_file(&file, str, sizeof(str));

    // It should read type 3
    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 0);
    ck_assert(memused() != 0);
    ck_assert(node.n.val.ary != NULL);
    ck_assert(node.n.val.ary->len == 1);
    wznode * child = node.n.val.ary->nodes;
    ck_assert((child->n.info & WZ_TYPE) == WZ_ARY);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8));
    uint32_t child_addr;
    uint8_t child_key;
    uint8_t * child_name;
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8, sizeof(u8)) == 0);
    ck_assert(child_name[sizeof(u8)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    wz_free_lv0(&node);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t u8[] = {0xe6, 0x84, 0x9b, 0xe6, 0x83, 0x85};
    static const uint8_t dec[] = {0x1b, 0x61, 0xc5, 0x60}; // love in japanese
    uint8_t key[sizeof(dec)];
    keygen(key, sizeof(dec));
    uint8_t enc[sizeof(dec)];
    uint16_t mask = 0xaaaa;
    for (uint8_t i = 0; i < sizeof(dec); i = (uint8_t) (i + 2)) {
      enc[i + 1] = (uint8_t) (dec[i + 1] ^ (mask >> 8)   ^ key[i + 1]);
      enc[i]     = (uint8_t) (dec[i]     ^ (mask & 0xff) ^ key[i]);
      mask++;
    }
    uint8_t str[sizeof(head) + 1 + 1 + 1 + sizeof(dec) + 1 + 1 + 4];
    addr_pos = sizeof(str) - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[i] = head[i];
    str[sizeof(head) + 0] = 0x01; // len
    str[sizeof(head) + 1] = 0x04; // type
    str[sizeof(head) + 2] = sizeof(dec) >> 1;
    for (uint8_t i = 0; i < sizeof(dec); i++)
      str[i + sizeof(head) + 3] = enc[i];
    str[sizeof(head) + sizeof(dec) + 3] = 0x01; // size
    str[sizeof(head) + sizeof(dec) + 4] = 0x23; // check
    str[sizeof(head) + sizeof(dec) + 5] = (addr_enc      ) & 0xff; // addr
    str[sizeof(head) + sizeof(dec) + 6] = (addr_enc >>  8) & 0xff;
    str[sizeof(head) + sizeof(dec) + 7] = (addr_enc >> 16) & 0xff;
    str[sizeof(head) + sizeof(dec) + 8] = (uint8_t) (addr_enc >> 24);

    create_file(&file, str, sizeof(str));

    // It should read type 4
    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 0);
    ck_assert(memused() != 0);
    ck_assert(node.n.val.ary != NULL);
    ck_assert(node.n.val.ary->len == 1);
    wznode * child = node.n.val.ary->nodes;
    ck_assert((child->n.info & WZ_TYPE) == WZ_UNK);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8));
    uint32_t child_addr;
    uint8_t child_key;
    uint8_t * child_name;
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8, sizeof(u8)) == 0);
    ck_assert(child_name[sizeof(u8)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    wz_free_lv0(&node);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
  {
    static const uint8_t u8_3[] = {0xe3, 0x81, 0x82, 0xe3, 0x81, 0x84};
    static const uint8_t dec3[] = {0x42, 0x30, 0x44, 0x30}; // love in japanese
    static const uint8_t u8_4[] = {'f', 'i', 'a', 'n', 'c', 0xc3, 0xa9, 'e'};
    static const uint8_t dec4[] = {'f', 'i', 'a', 'n', 'c', 0xe9, 'e'};

    uint32_t key_len = 1;
    if (sizeof(dec3) > key_len) key_len = sizeof(dec3);
    if (sizeof(dec4) > key_len) key_len = sizeof(dec4);
    uint8_t * key;
    ck_assert((key = malloc(key_len)) != NULL);
    keygen(key, key_len);
    uint8_t * enc;
    ck_assert((enc = malloc(key_len)) != NULL);
    uint8_t mask_8;
    uint16_t mask_16;
    uint8_t offset;
    uint8_t str1[1 + 10];
    uint8_t str2[1 + 4 + 1 + 1 + 4];
    uint8_t str3[1 + 1 + sizeof(dec3) + 1 + 1 + 4];
    uint8_t str4[1 + 1 + sizeof(dec4) + 1 + 1 + 4];
    uint32_t str_len = sizeof(head) + 1;

    str_len += (uint32_t) sizeof(str1);
    str1[0] = 0x01; // type
    for (uint8_t i = 0; i < 10; i++)
      str1[i + 1] = 0xff;

    str_len += (uint32_t) sizeof(str2);
    offset = (uint8_t) ((root_addr - start) + 1 +
                        sizeof(str1) + sizeof(str2) + sizeof(str3));
    addr_pos = str_len - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    str2[0]  = 0x02; // type
    str2[1]  = offset; // offset
    str2[2]  = 0;
    str2[3]  = 0;
    str2[4]  = 0;
    str2[5]  = 0x01; // size
    str2[6]  = 0x23; // check
    str2[7]  = (addr_enc      ) & 0xff; // addr
    str2[8]  = (addr_enc >>  8) & 0xff;
    str2[9]  = (addr_enc >> 16) & 0xff;
    str2[10] = (uint8_t) (addr_enc >> 24);

    mask_16 = 0xaaaa;
    for (uint8_t i = 0; i < sizeof(dec3); i = (uint8_t) (i + 2)) {
      enc[i + 1] = (uint8_t) (dec3[i + 1] ^ (mask_16 >> 8)   ^ key[i + 1]);
      enc[i]     = (uint8_t) (dec3[i]     ^ (mask_16 & 0xff) ^ key[i]);
      mask_16++;
    }
    str_len += (uint32_t) sizeof(str3);
    addr_pos = str_len - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    str3[0] = 0x03; // type
    str3[1] = sizeof(dec3) >> 1;
    for (uint8_t i = 0; i < sizeof(dec3); i++)
      str3[i + 2] = enc[i];
    str3[sizeof(dec3) + 2] = 0x01; // size
    str3[sizeof(dec3) + 3] = 0x23; // check
    str3[sizeof(dec3) + 4] = (addr_enc      ) & 0xff; // addr
    str3[sizeof(dec3) + 5] = (addr_enc >>  8) & 0xff;
    str3[sizeof(dec3) + 6] = (addr_enc >> 16) & 0xff;
    str3[sizeof(dec3) + 7] = (uint8_t) (addr_enc >> 24);

    mask_8 = 0xaa;
    for (uint8_t i = 0; i < sizeof(dec4); i++)
      enc[i] = dec4[i] ^ mask_8++ ^ key[i];
    str_len += (uint32_t) sizeof(str4);
    addr_pos = str_len - 4;
    wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
    str4[0] = 0x04; // type
    str4[1] = (~sizeof(dec4) + 1) & 0xff;
    for (uint8_t i = 0; i < sizeof(dec4); i++)
      str4[i + 2] = enc[i];
    str4[sizeof(dec4) + 2] = 0x01; // size
    str4[sizeof(dec4) + 3] = 0x23; // check
    str4[sizeof(dec4) + 4] = (addr_enc      ) & 0xff; // addr
    str4[sizeof(dec4) + 5] = (addr_enc >>  8) & 0xff;
    str4[sizeof(dec4) + 6] = (addr_enc >> 16) & 0xff;
    str4[sizeof(dec4) + 7] = (uint8_t) (addr_enc >> 24);

    free(enc);

    uint8_t * str;
    ck_assert((str = malloc(str_len)) != NULL);
    uint32_t str_i = 0;
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[str_i++] = head[i];
    str[str_i++] = 4; // len
    for (uint8_t i = 0; i < sizeof(str1); i++)
      str[str_i++] = str1[i];
    for (uint8_t i = 0; i < sizeof(str2); i++)
      str[str_i++] = str2[i];
    for (uint8_t i = 0; i < sizeof(str3); i++)
      str[str_i++] = str3[i];
    for (uint8_t i = 0; i < sizeof(str4); i++)
      str[str_i++] = str4[i];

    create_file(&file, str, str_len);

    free(str);

    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 0);
    ck_assert(memused() != 0);
    ck_assert(node.n.val.ary != NULL);
    ck_assert(node.n.val.ary->len == 4);
    wznode * child = node.n.val.ary->nodes;
    uint32_t child_addr;
    uint8_t child_key;
    uint8_t * child_name;

    // It should read type 1
    ck_assert((child->n.info & WZ_TYPE) == WZ_NIL);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.val.ary == NULL);
    child++;

    // It should read type 2
    ck_assert((child->n.info & WZ_TYPE) == WZ_UNK);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8_4));
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8_4, sizeof(u8_4)) == 0);
    ck_assert(child_name[sizeof(u8_4)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    child++;

    // It should read type 3
    ck_assert((child->n.info & WZ_TYPE) == WZ_ARY);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8_3));
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8_3, sizeof(u8_3)) == 0);
    ck_assert(child_name[sizeof(u8_3)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    child++;

    // It should read type 4
    ck_assert((child->n.info & WZ_TYPE) == WZ_UNK);
    ck_assert(child->n.parent == &node);
    ck_assert(child->n.root.file == &file);
    ck_assert(child->n.name_len == sizeof(u8_4));
    if (child->n.info & WZ_EMBED) {
      child_addr = child->na_e.addr;
      child_key = child->na_e.key;
      child_name = child->n.name_e;
    } else {
      child_addr = child->na.addr;
      child_key = child->na.key;
      child_name = child->n.name;
    }
    ck_assert(child_addr == addr_dec);
    ck_assert(child_key == 0xff);
    ck_assert(memcmp(child_name, u8_4, sizeof(u8_4)) == 0);
    ck_assert(child_name[sizeof(u8_4)] == '\0');
    ck_assert(child->n.val.ary == NULL);
    child++;

    wz_free_lv0(&node);
    ck_assert(memused() == 0);

    delete_file(&file);

    free(key);
  }

  // It should not be ok
  {
    uint8_t key[1];
    uint8_t str[sizeof(head) + 1 + 1];
    for (uint8_t i = 0; i < sizeof(head); i++)
      str[i] = head[i];
    str[sizeof(head) + 0]  = 0x01; // len
    str[sizeof(head) + 1]  = 0x05; // type

    create_file(&file, str, sizeof(str));

    // It should not read type 5
    ck_assert(memused() == 0);
    ck_assert(wz_read_lv0(&node, &file, key) == 1);
    ck_assert(memused() == 0);

    delete_file(&file);
  }
} END_TEST

START_TEST(test_encode_ver) {
  uint16_t dec = 0x0123;

  // It should be ok
  uint16_t enc;
  uint32_t hash;
  wz_encode_ver(&enc, &hash, dec);
  ck_assert(enc == 0x005e);
  ck_assert(hash == 0xd372);
} END_TEST

START_TEST(test_deduce_ver) {
  static const uint8_t str_dec[] = {'a', 'b'};
  uint8_t str_enc[sizeof(str_dec)];
  uint8_t key[sizeof(str_dec)];
  keygen(key, sizeof(str_dec));
  uint8_t mask = 0xaa;
  for (uint8_t i = 0; i < sizeof(str_dec); i++)
    str_enc[i] = str_dec[i] ^ mask++ ^ key[i];

  uint8_t head[5];
  for (uint8_t i = 0; i < sizeof(head); i++)
    head[i] = i;
  uint8_t str1[1 + 1 + 1 + sizeof(str_dec) + 1 + 1 + 4];
  uint32_t str_len = sizeof(head) + sizeof(str1);
  const uint16_t dec = 0x00ce;
  uint32_t hash;
  uint16_t enc;
  wz_encode_ver(&enc, &hash, dec);
  const uint32_t root_addr = sizeof(head);
  const uint32_t start = root_addr - 3;
  const uint32_t addr_pos = str_len - 4;
  const uint32_t addr_dec = root_addr;
  uint32_t addr_enc;
  wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
  ck_assert(addr_enc != 0);
  str1[0] = 1; // len
  str1[1] = 0x03; // type
  str1[2] = (~sizeof(str_dec) + 1) & 0xff;
  for (uint8_t i = 0; i < sizeof(str_dec); i++)
    str1[i + 3] = str_enc[i];
  str1[sizeof(str_dec) + 3] = 0x01; // size
  str1[sizeof(str_dec) + 4] = 0x23; // check
  str1[sizeof(str_dec) + 5] = (addr_enc      ) & 0xff; // addr
  str1[sizeof(str_dec) + 6] = (addr_enc >>  8) & 0xff;
  str1[sizeof(str_dec) + 7] = (addr_enc >> 16) & 0xff;
  str1[sizeof(str_dec) + 8] = (uint8_t) (addr_enc >> 24);

  uint8_t * str;
  ck_assert((str = malloc(str_len)) != NULL);
  uint32_t str_i = 0;
  for (uint8_t i = 0; i < sizeof(head); i++)
    str[str_i++] = head[i];
  for (uint8_t i = 0; i < sizeof(str1); i++)
    str[str_i++] = str1[i];

  wzfile file;
  create_file(&file, str, str_len);

  free(str);

  // It should be ok
  uint16_t ret_dec;
  uint32_t ret_hash;
  uint8_t ret_key = 1;
  ck_assert(wz_deduce_ver(&ret_dec, &ret_hash, &ret_key, enc,
                          root_addr, start, str_len, file.raw, key) == 0);
  ck_assert(ret_dec == dec);
  ck_assert(ret_hash == hash);
  ck_assert(ret_key == 0);

  delete_file(&file);
} END_TEST

START_TEST(test_encode_aes) {
  static const uint8_t iv[16] = {
    0x4d, 0x23, 0xc7, 0x2b, 0x4d, 0x23, 0xc7, 0x2b,
    0x4d, 0x23, 0xc7, 0x2b, 0x4d, 0x23, 0xc7, 0x2b
  };
  static uint8_t key[32] = {
    0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00
  };

  // It shoule be ok
  uint8_t cipher[32];
  wz_encode_aes(cipher, sizeof(cipher), key, iv);
  static const uint8_t expected[sizeof(cipher)] = {
    0x96, 0xae, 0x3f, 0xa4, 0x48, 0xfa, 0xdd, 0x90,
    0x46, 0x76, 0x05, 0x61, 0x97, 0xce, 0x78, 0x68,
    0x2b, 0xa0, 0x44, 0x8f, 0xc1, 0x56, 0x7e, 0x32,
    0xfc, 0xe1, 0xf5, 0xb3, 0x14, 0x14, 0xc5, 0x22
  };
  ck_assert(memcmp(cipher, expected, sizeof(cipher)) == 0);
} END_TEST

START_TEST(test_open_file) {
  static const uint8_t copy[] = {'a', 'b'};
  uint8_t head[4 + 4 + 4 + 4 + sizeof(copy) + 2];
  const uint16_t dec = 0x00ce;
  uint32_t hash;
  uint16_t enc;
  wz_encode_ver(&enc, &hash, dec);
  const uint32_t root_addr = sizeof(head);
  const uint8_t start = sizeof(head) - 2;
  head[0]  = 0x01; // ident
  head[1]  = 0x23;
  head[2]  = 0x45;
  head[3]  = 0x67;
  head[4]  = 0x01; // size
  head[5]  = 0x00;
  head[6]  = 0x00;
  head[7]  = 0x00;
  head[8]  = 0x00;
  head[9]  = 0x00;
  head[10] = 0x00;
  head[11] = 0x00;
  head[12] = start;
  head[13] = 0x00;
  head[14] = 0x00;
  head[15] = 0x00;
  for (uint8_t i = 0; i < sizeof(copy); i++)
    head[i + 16] = copy[i];
  head[sizeof(copy) + 16] = (uint8_t) (enc & 0xff);
  head[sizeof(copy) + 17] = (uint8_t) (enc >> 8);
  static const uint8_t str_dec[] = {'c', 'd'};

  wzctx * ctx;
  ck_assert(memused() == 0);
  ck_assert((ctx = wz_init_ctx()) != NULL);
  ck_assert(memused() != 0);
  size_t mem_size = memused();
  uint8_t * key = ctx->keys;

  uint8_t str_enc[sizeof(str_dec)];
  uint8_t mask = 0xaa;
  for (uint8_t i = 0; i < sizeof(str_dec); i++)
    str_enc[i] = str_dec[i] ^ mask++ ^ key[i];
  uint8_t str1[1 + 1 + 1 + sizeof(str_dec) + 1 + 1 + 4];
  uint32_t str_len = sizeof(head) + sizeof(str1);
  const uint32_t addr_pos = str_len - 4;
  const uint32_t addr_dec = root_addr;
  uint32_t addr_enc;
  wz_encode_addr(&addr_enc, addr_dec, addr_pos, start, hash);
  str1[0] = 0x01; // len
  str1[1] = 0x03; // type
  str1[2] = (~sizeof(str_dec) + 1) & 0xff;
  for (uint8_t i = 0; i < sizeof(str_dec); i++)
    str1[i + 3] = str_enc[i];
  str1[sizeof(str_dec) + 3] = 0x01; // size
  str1[sizeof(str_dec) + 4] = 0x23; // check
  str1[sizeof(str_dec) + 5] = (addr_enc      ) & 0xff;
  str1[sizeof(str_dec) + 6] = (addr_enc >>  8) & 0xff;
  str1[sizeof(str_dec) + 7] = (addr_enc >> 16) & 0xff;
  str1[sizeof(str_dec) + 8] = (uint8_t) (addr_enc >> 24);

  uint8_t * str;
  ck_assert((str = malloc(str_len)) != NULL);
  uint32_t str_i = 0;
  for (uint8_t i = 0; i < sizeof(head); i++)
    str[str_i++] = head[i];
  for (uint8_t i = 0; i < sizeof(str1); i++)
    str[str_i++] = str1[i];

  wzfile created;
  create_file(&created, str, str_len);
  close_file(&created);

  free(str);

  // It should be ok
  wzfile * file;
  ck_assert(memused() == mem_size);
  ck_assert((file = wz_open_file(tmp_fname, ctx)) != NULL);
  ck_assert(memused() > mem_size);
  ck_assert(file->size == str_len);
  ck_assert(file->start == start);
  ck_assert(file->hash == hash);
  ck_assert(file->key == 0);
  ck_assert(file->root.n.parent == NULL);
  ck_assert(file->root.n.root.file == file);
  ck_assert((file->root.n.info & WZ_TYPE) == WZ_ARY);
  ck_assert(file->root.na_e.addr == root_addr);
  ck_assert(file->root.n.val.ary == NULL);

  ck_assert(wz_close_file(file) == 0);

  ck_assert(memused() == mem_size);
  wz_free_ctx(ctx);
  ck_assert(memused() == 0);
} END_TEST

TCase *
create_tcase_file(void) {
  TCase * tcase = tcase_create("file");
  tcase_add_test(tcase, test_node);
  tcase_add_test(tcase, test_read_bytes);
  tcase_add_test(tcase, test_read_byte);
  tcase_add_test(tcase, test_read_le16);
  tcase_add_test(tcase, test_read_le32);
  tcase_add_test(tcase, test_read_le64);
  tcase_add_test(tcase, test_read_int32);
  tcase_add_test(tcase, test_read_int64);
  tcase_add_test(tcase, test_decode_chars);
  tcase_add_test(tcase, test_read_chars);
  tcase_add_test(tcase, test_decode_addr);
  tcase_add_test(tcase, test_seek);
  tcase_add_test(tcase, test_read_lv0);
  tcase_add_test(tcase, test_encode_ver);
  tcase_add_test(tcase, test_deduce_ver);
  tcase_add_test(tcase, test_encode_aes);
  tcase_add_test(tcase, test_open_file);
  return tcase;
}
