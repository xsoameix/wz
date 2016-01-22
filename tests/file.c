#include <stdio.h>
#include <string.h>
#include <check.h>
#include <file.h>
#include "mem.h"

void
create_file(wzfile * file, char * buffer, size_t len) {
  FILE * raw = fmemopen(buffer, len, "rb");
  ck_assert(raw != NULL);
  file->raw = raw;
  file->pos = 0;
  file->size = len;
  file->ver.hash = 0;
  file->strk.ascii = NULL;
  file->strk.unicode = NULL;
  file->strk.len = 0;
}

void
delete_file(wzfile * file) {
  ck_assert(memerr() == 0);
  fclose(file->raw);
}

START_TEST(test_read_data) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  char buffer[] = "cd";
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(strncmp(buffer, normal, strlen(normal)), 0);

  // It should not change position if error occured.
  file.pos = 0;
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 1);
  ck_assert(file.pos == 0);
  delete_file(&file);

  // It should not change data if position + len > size
  create_file(&file, normal, strlen(normal));
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 1);
  ck_assert_int_eq(strncmp(buffer, normal, strlen(normal)), 0);
  delete_file(&file);
} END_TEST

START_TEST(test_read_byte) {
  // It should be ok
  char normal[] = "a";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint8_t buffer;
  ck_assert_int_eq(wz_read_byte(&buffer, &file), 0);
  ck_assert(buffer == normal[0]);

  // It should not change data if position + len > size
  uint8_t copy = buffer;
  ck_assert_int_eq(wz_read_byte(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_le16) {
  // It should be ok
  char normal[] = "\x01\x23";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint16_t buffer;
  ck_assert_int_eq(wz_read_le16(&buffer, &file), 0);
  ck_assert(buffer == 0x2301);

  // It should not change data if position + len > size
  uint16_t copy = buffer;
  ck_assert_int_eq(wz_read_le16(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_le32) {
  // It should be ok
  char normal[] = "\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint32_t buffer;
  ck_assert_int_eq(wz_read_le32(&buffer, &file), 0);
  ck_assert(buffer == 0x67452301);

  // It should not change data if position + len > size
  uint32_t copy = buffer;
  ck_assert_int_eq(wz_read_le32(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_le64) {
  // It should be ok
  char normal[] = "\x01\x23\x45\x67\x89\xab\xcd\xef";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint64_t buffer;
  ck_assert_int_eq(wz_read_le64(&buffer, &file), 0);
  ck_assert(buffer == 0xefcdab8967452301);

  // It should not change data if position + len > size
  uint64_t copy = buffer;
  ck_assert_int_eq(wz_read_le64(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_int) {
  // It should read positive int8
  char normal[] = "\x01\xfe\x80\x23\x45\x67\x89";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint32_t buffer;
  ck_assert_int_eq(wz_read_int(&buffer, &file), 0);
  ck_assert(buffer == 1);

  // It should read negative int8
  ck_assert_int_eq(wz_read_int(&buffer, &file), 0);
  ck_assert(buffer == 0xfffffffe);

  // It should read postive int32
  ck_assert_int_eq(wz_read_int(&buffer, &file), 0);
  ck_assert(buffer == 0x89674523);

  // It should not change data if position + len > size
  uint32_t copy = buffer;
  ck_assert_int_eq(wz_read_int(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_bytes) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  char buffer[] = "cd";
  ck_assert_int_eq(wz_read_bytes(buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(strncmp(buffer, normal, strlen(normal)), 0);

  // It should not change data if position + len > size
  ck_assert_int_eq(wz_read_bytes(buffer, strlen(buffer), &file), 1);
  ck_assert_int_eq(strncmp(buffer, normal, strlen(normal)), 0);
  delete_file(&file);
} END_TEST

START_TEST(test_init_str) {
  // It should be ok
  wzstr buffer;
  wz_init_str(&buffer);
  ck_assert(buffer.bytes == NULL);
} END_TEST

START_TEST(test_read_str) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wzstr buffer;
  wz_init_str(&buffer);
  ck_assert_int_eq(wz_read_str(&buffer, strlen(normal), &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, normal, strlen(normal)), 0);
  ck_assert(buffer.len == strlen(normal));
  ck_assert(memused() == strlen(normal));

  // It should not change data if position + len > size
  wzstr copy = buffer;
  ck_assert_int_eq(wz_read_str(&buffer, strlen(normal), &file), 1);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);

  // It should not allocate memory if position + len > size
  ck_assert(memused() == strlen(normal));
  wz_free_str(&buffer);
  delete_file(&file);
} END_TEST

START_TEST(test_free_str) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wzstr buffer;
  wz_init_str(&buffer);
  ck_assert_int_eq(wz_read_str(&buffer, strlen(normal), &file), 0);
  ck_assert(memused() == strlen(normal));
  wz_free_str(&buffer);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_decode_chars) {
  // It should decode ascii
  char ascii[] = "\x01\x23";
  wzfile file = {.strk = {.ascii = "\x89\xab\xcd\xef", .len = 4}};
  wzchr buffer;
  buffer.bytes = ascii;
  buffer.len = strlen(ascii);
  buffer.enc = WZ_ENC_ASCII;
  ck_assert_int_eq(wz_decode_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x88\x88", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 0);

  // It should decode unicode
  char unicode[] = "\x45\x67";
  file.strk.unicode = "\x89\xab\xcd\xef";
  file.strk.len = 4;
  buffer.bytes = unicode;
  buffer.len = strlen(unicode);
  buffer.enc = WZ_ENC_UNICODE;
  ck_assert_int_eq(wz_decode_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\xcc\xcc", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 0);

  // It should not decode if hash == 0
  file.strk.ascii = NULL;
  wzchr copy = buffer;
  ck_assert_int_eq(wz_decode_chars(&buffer, &file), 0);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);

  // It should not decode if string key is too short
  file.strk.ascii = "\xcd";
  file.strk.len = 1;
  ck_assert_int_eq(wz_decode_chars(&buffer, &file), 1);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);
} END_TEST

START_TEST(test_read_chars) {
  // It should be ok
  char normal[] =
    "\xfe\x01\x23"
    "\x80\x02\x00\x00\x00\x45\x67"
    "\x01\x89\xab"
    "\x7f\x03\x00\x00\x00\xcd\xef\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzchr buffer;
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x01\x23", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x45\x67", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x89\xab", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\xcd\xef\x01\x23\x45\x67", 6), 0);
  ck_assert(buffer.len == 6 && memused() == 6);
  wz_free_chars(&buffer);
  delete_file(&file);

  // It should decode if string key is set
  create_file(&file, normal, sizeof(normal) - 1);
  file.strk.ascii   = "\x01\x23\x45\x67\x89\xab";
  file.strk.unicode = "\xcd\xef\x01\x23\x45\x67";
  file.strk.len = 6;
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x00\x00", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x44\x44", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x44\x44", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert_int_eq(strncmp(buffer.bytes, "\x00\x00\x00\x00\x00\x00", 6), 0);
  ck_assert(buffer.len == 6 && memused() == 6);
  wz_free_chars(&buffer);
  delete_file(&file);
} END_TEST

START_TEST(test_free_chars) {
  // It should be ok
  char normal[] = "\xfe\x01\x23";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzchr buffer;
  ck_assert_int_eq(wz_read_chars(&buffer, &file), 0);
  ck_assert(memused() == 2);
  wz_free_chars(&buffer);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_rotl32) {
  // It should be ok
  ck_assert(wz_rotl32(0xf2345678, 3) == 0x91a2b3c7);
} END_TEST

START_TEST(test_decode_addr) {
  // It should be ok
  wzfile file = {.head = {.start = 0x3c}, .ver = {.hash = 0x713}};
  wzaddr addr = {.pos = 0x51, .val = 0x49e34db3};
  wz_decode_addr(&addr, &file);
  ck_assert(addr.val == 0x2ed);
} END_TEST

START_TEST(test_read_addr) {
  // It should be ok
  char normal[] =
    "\x01\x23\x45\x67""\x89\xab\xcd\xef"
    "\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wzaddr addr;
  ck_assert_int_eq(wz_read_addr(&addr, &file), 0);
  ck_assert(addr.val == 0x67452301 && addr.pos == 0);
  ck_assert_int_eq(wz_read_addr(&addr, &file), 0);
  ck_assert(addr.val == 0xefcdab89 && addr.pos == 4);

  // It should decode address if hash is present
  file.ver.hash = 0x89abcdef;
  ck_assert_int_eq(wz_read_addr(&addr, &file), 0);
  ck_assert(addr.val == 0xff77ee0c && addr.pos == 8);
  delete_file(&file);
} END_TEST

START_TEST(test_read_node) {
  // It should read type 1
  char normal[] =
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x02"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x04""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x05";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wznode node;
  ck_assert_int_eq(wz_read_node(&node, &file), 0);
  ck_assert(memused() == 0);

  // It should read type 2
  ck_assert_int_eq(wz_read_node(&node, &file), 1);

  // It should read type 3
  ck_assert(memused() == 0);
  ck_assert_int_eq(wz_read_node(&node, &file), 0);
  ck_assert(node.type == 3);
  ck_assert_int_eq(strncmp(node.name.bytes, "\x01\x23", 2), 0);
  ck_assert(node.name.len == 2);
  ck_assert(node.size == 1 && node.check == 2 && node.addr.val == 0x67452301);
  ck_assert(memused() == 2);
  wz_free_node(&node);

  // It should read type 4
  ck_assert(memused() == 0);
  ck_assert_int_eq(wz_read_node(&node, &file), 0);
  ck_assert(node.type == 4);
  ck_assert_int_eq(strncmp(node.name.bytes, "\x01\x23", 2), 0);
  ck_assert(node.name.len == 2);
  ck_assert(node.size == 1 && node.check == 2 && node.addr.val == 0x67452301);
  ck_assert(memused() == 2);
  wz_free_node(&node);

  // It should not read type 5
  ck_assert_int_eq(wz_read_node(&node, &file), 1);
  ck_assert(node.type == 5);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_free_node) {
  // It should be ok
  char normal[] = "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wznode node;
  ck_assert_int_eq(wz_read_node(&node, &file), 0);
  ck_assert(memused() == 2);
  wz_free_node(&node);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_decode_node) {
  // It should be ok
  char ascii[] = "\x01\x23";
  wzfile file = {
    .head = {.start = 0x3c},
    .ver = {.hash = 0x713},
    .strk = {.ascii = "\x89\xab\xcd\xef", .len = 4}
  };
  wznode node = {
    .type = 3,
    .name = {
      .bytes = ascii,
      .len = strlen(ascii),
      .enc = WZ_ENC_ASCII
    },
    .addr = {.pos = 0x51, .val = 0x49e34db3}
  };
  ck_assert_int_eq(wz_decode_node(&node, &file), 0);
  ck_assert_int_eq(strncmp(node.name.bytes, "\x88\x88", 2), 0);
  ck_assert(node.addr.val == 0x2ed);
  ck_assert(node.name.len == 2 && memused() == 0);
} END_TEST

START_TEST(test_read_dir) {
  // It should be ok
  char normal[] = "\x03"
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x04""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wzdir dir;
  ck_assert_int_eq(wz_read_dir(&dir, &file), 0);
  ck_assert(dir.len == 3);
  ck_assert(dir.nodes[0].type == 1);
  ck_assert(dir.nodes[1].type == 3);
  ck_assert(dir.nodes[2].type == 4);
  ck_assert(memused() == sizeof(* dir.nodes) * 3 + 2 * 2);
  wz_free_dir(&dir);
  delete_file(&file);

  // It should not read invalid data
  char error[] = "\x03"
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x02";
  create_file(&file, error, strlen(error));
  ck_assert_int_eq(wz_read_dir(&dir, &file), 1);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_free_dir) {
  // It should be ok
  char normal[] = "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wzdir dir;
  ck_assert_int_eq(wz_read_dir(&dir, &file), 0);
  ck_assert(memused() == sizeof(* dir.nodes) + 2);
  wz_free_dir(&dir);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_decode_dir) {
  // It should be ok
  char ascii[] = "\x01\x23";
  wzfile file = {.strk = {.ascii = "\x89\xab\xcd\xef", .len = 4}};
  wznode node = {.type = 3};
  node.name.bytes = ascii;
  node.name.len = strlen(ascii);
  node.name.enc = WZ_ENC_ASCII;
  wzdir dir = {.len = 1, .nodes = &node};
  ck_assert_int_eq(wz_decode_dir(&dir, &file), 0);
  ck_assert_int_eq(strncmp(node.name.bytes, "\x88\x88", 2), 0);
  ck_assert(node.name.len == 2 && memused() == 0);
} END_TEST

START_TEST(test_read_head) {
  // It should be ok
  char normal[] =
    "\x01\x23\x45\x67"
    "\x12\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzhead head;
  ck_assert_int_eq(wz_read_head(&head, &file), 0);
  ck_assert_int_eq(strncmp(head.ident, "\x01\x23\x45\x67", 4), 0);
  ck_assert(head.size == 18 && head.start == 18);
  ck_assert_int_eq(strncmp(head.copy.bytes, "ab", 2), 0);
  ck_assert(head.copy.len == 2);
  ck_assert(memused() == 2);
  wz_free_head(&head);
  delete_file(&file);

  // It should not read invalid data
  char error[] =
    "\x01\x23\x45\x67"
    "\x12\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "a";
  create_file(&file, error, sizeof(error) - 1);
  ck_assert_int_eq(wz_read_head(&head, &file), 1);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_free_head) {
  // It should be ok
  char normal[] =
    "\x01\x23\x45\x67"
    "\x12\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzhead head;
  ck_assert_int_eq(wz_read_head(&head, &file), 0);
  ck_assert(memused() == 2);
  wz_free_head(&head);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_encode_ver) {
  // It should be ok
  wzver ver = {.dec = 0x0123};
  ck_assert_int_eq(wz_encode_ver(&ver), 0);
  ck_assert(ver.enc == 0x005e && ver.hash == 0xd372);
} END_TEST

START_TEST(test_valid_ver) {
  // It should be ok
  wzfile file = {
    .size = 0x8a95328,
    .head = {.start = 0x3c},
    .root = {
      .len = 1,
      .nodes = (wznode[]) {{
        .type = 3,
        .addr = {.pos = 0x51, .val = 0x49e34db3}
      }}
    },
    .ver = {.hash = 0x99}
  };
  wzver ver = {.hash = 0x713};
  ck_assert_int_eq(wz_valid_ver(&ver, &file), 0);
  ck_assert(file.ver.hash == 0x99);

  // It should not change version hash if failed
  ver.hash = 0x712;
  ck_assert_int_eq(wz_valid_ver(&ver, &file), 1);
  ck_assert(file.ver.hash == 0x99);
} END_TEST

START_TEST(test_decode_ver) {
  // It should be ok
  wzfile file = {
    .size = 0x712e04f2,
    .head = {.start = 0x3c},
    .root = {
      .len = 1,
      .nodes = (wznode[]) {{
        .type = 3,
        .addr = {.pos = 0x56, .val = 0x5eb2cd05}
      }}
    },
    .ver = {.hash = 0x99}
  };
  wzver ver = {.enc = 0x93};
  ck_assert_int_eq(wz_decode_ver(&ver, &file), 0);
  ck_assert(ver.enc == 0x93);
  ck_assert(ver.dec == 0x153);
  ck_assert(ver.hash == 0xd6ba);
} END_TEST

START_TEST(test_read_file) {
  // It should be ok
  char normal[] =
    "\x01\x23\x45\x67"                 // ident
    "\x1F\x00\x00\x00\x00\x00\x00\x00" // size
    "\x12\x00\x00\x00"                 // start
    "ab"                               // copy
    "\x01\x23"                         // ver
    "\x01"                             // nodes len
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  FILE * raw = fmemopen(normal, sizeof(normal) - 1, "rb");
  ck_assert(raw != NULL);
  ck_assert_int_eq(wz_read_file(&file, raw), 0);
  ck_assert_int_eq(strncmp(file.head.copy.bytes, "ab", 2), 0);
  ck_assert(file.head.copy.len == 2);
  ck_assert(file.root.nodes[0].name.len == 2);
  ck_assert(memused() == sizeof(* file.root.nodes) + file.strk.len * 2 + 4);
  wz_free_file(&file);
  fclose(raw);

  // It should not read invalid data
  char error[] =
    "\x01\x23\x45\x67"
    "\x1F\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab"
    "\x01\x23"
    "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45";
  raw = fmemopen(error, sizeof(error) - 1, "rb");
  ck_assert(raw != NULL);
  ck_assert_int_eq(wz_read_file(&file, raw), 1);
  ck_assert(memused() == 0);
  fclose(raw);
} END_TEST

START_TEST(test_free_file) {
  // It should be ok
  char normal[] =
    "\x01\x23\x45\x67"
    "\x1F\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab"
    "\x01\x23"
    "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  FILE * raw = fmemopen(normal, sizeof(normal) - 1, "rb");
  ck_assert(raw != NULL);
  ck_assert_int_eq(wz_read_file(&file, raw), 0);
  ck_assert(memused() == sizeof(* file.root.nodes) + file.strk.len * 2 + 4);
  wz_free_file(&file);
  ck_assert(memused() == 0);
  fclose(raw);
} END_TEST

START_TEST(test_open_file) {
  // It should be ok
  char * filename = "test_open_file.wz";
  FILE * raw = fopen(filename, "wb");
  ck_assert(raw != NULL);
  wzfile file;
  char normal[] =
    "\x01\x23\x45\x67"
    "\x1F\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab"
    "\x01\x23"
    "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  ck_assert(fwrite(normal, 1, sizeof(normal) - 1, raw) == sizeof(normal) - 1);
  ck_assert_int_eq(fclose(raw), 0);
  ck_assert_int_eq(wz_open_file(&file, filename), 0);
  ck_assert(memused() == sizeof(* file.root.nodes) + file.strk.len * 2 + 4);
  ck_assert_int_eq(wz_close_file(&file), 0);
  ck_assert_int_eq(remove(filename), 0);

  // It should not read the file which does not exist
  ck_assert_int_eq(wz_open_file(&file, "not-exist-file"), 1);
} END_TEST

START_TEST(test_close_file) {
  // It should be ok
  char * filename = "test_close_file.wz";
  FILE * raw = fopen(filename, "wb");
  ck_assert(raw != NULL);
  wzfile file;
  char normal[] =
    "\x01\x23\x45\x67"
    "\x1F\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab"
    "\x01\x23"
    "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  ck_assert(fwrite(normal, 1, sizeof(normal) - 1, raw) == sizeof(normal) - 1);
  ck_assert_int_eq(fclose(raw), 0);
  ck_assert_int_eq(wz_open_file(&file, filename), 0);
  ck_assert(memused() == sizeof(* file.root.nodes) + file.strk.len * 2 + 4);
  ck_assert_int_eq(wz_close_file(&file), 0);
  ck_assert_int_eq(remove(filename), 0);
  ck_assert(memused() == 0);
} END_TEST

Suite *
make_file_suite(void) {
  Suite * suite = suite_create("wzfile");
  TCase * tcase = tcase_create("parse_file");
  tcase_add_test(tcase, test_read_data);
  tcase_add_test(tcase, test_read_byte);
  tcase_add_test(tcase, test_read_le16);
  tcase_add_test(tcase, test_read_le32);
  tcase_add_test(tcase, test_read_le64);
  tcase_add_test(tcase, test_read_int);
  tcase_add_test(tcase, test_read_bytes);
  tcase_add_test(tcase, test_init_str);
  tcase_add_test(tcase, test_read_str);
  tcase_add_test(tcase, test_free_str);
  tcase_add_test(tcase, test_decode_chars);
  tcase_add_test(tcase, test_read_chars);
  tcase_add_test(tcase, test_free_chars);
  tcase_add_test(tcase, test_rotl32);
  tcase_add_test(tcase, test_decode_addr);
  tcase_add_test(tcase, test_read_addr);
  tcase_add_test(tcase, test_read_node);
  tcase_add_test(tcase, test_free_node);
  tcase_add_test(tcase, test_decode_node);
  tcase_add_test(tcase, test_read_dir);
  tcase_add_test(tcase, test_free_dir);
  tcase_add_test(tcase, test_decode_dir);
  tcase_add_test(tcase, test_read_head);
  tcase_add_test(tcase, test_free_head);
  tcase_add_test(tcase, test_encode_ver);
  tcase_add_test(tcase, test_valid_ver);
  tcase_add_test(tcase, test_decode_ver);
  tcase_add_test(tcase, test_read_file);
  tcase_add_test(tcase, test_free_file);
  tcase_add_test(tcase, test_open_file);
  tcase_add_test(tcase, test_close_file);
  suite_add_tcase(suite, tcase);
  return suite;
}
