#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <byteorder.h>
#include <file.h>
#include "check.h"
#include "mem.h"

FILE *
create_tmpfile(char * buffer, size_t len) {
  FILE * raw = fopen("tmpfile", "w+b");
  ck_assert(raw != NULL);
  ck_assert(fwrite(buffer, 1, len, raw) == len);
  rewind(raw);
  return raw;
}

void
delete_tmpfile(FILE * raw) {
  ck_assert_int_eq(fclose(raw), 0);
  ck_assert_int_eq(remove("tmpfile"), 0);
}

void
create_file(wzfile * file, char * buffer, size_t len) {
  file->raw = create_tmpfile(buffer, len);
  file->pos = 0;
  file->size = len;
  file->ver.hash = 0;
  file->key = NULL;
}

void
delete_file(wzfile * file) {
  ck_assert(memerr() == 0);
  delete_tmpfile(file->raw);
}

void
create_ctx(wzctx * ctx) {
  size_t len = 1;
  wzkey * keys = malloc(sizeof(* keys) * len);
  ck_assert(keys != NULL);
  // decoded == encoded    ^ mask       ^ key
  // 'ab'    == "\x01\x23" ^ "\xaa\xab" ^ "\xca\xea"
  keys[0] = (wzkey) {.bytes = (uint8_t *) "\xca\xea", .len = 2};
  ctx->keys = keys, ctx->klen = len;
}

void
delete_ctx(wzctx * ctx) {
  free(ctx->keys);
}

START_TEST(test_read_data) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  char buffer[] = "cd";
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(memcmp(buffer, normal, strlen(normal)), 0);

  // It should not change position if error occured.
  file.pos = 0;
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 1);
  ck_assert(file.pos == 0);
  delete_file(&file);

  // It should not change data if position + len > size
  create_file(&file, normal, strlen(normal));
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(wz_read_data(buffer, strlen(buffer), &file), 1);
  ck_assert_int_eq(memcmp(buffer, normal, strlen(normal)), 0);
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

START_TEST(test_read_long) {
  // It should read positive int8
  char normal[] = "\x01\xfe\x80\x23\x45\x67\x89\xab\xcd\xef\01";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  uint64_t buffer;
  ck_assert_int_eq(wz_read_long(&buffer, &file), 0);
  ck_assert(buffer == 1);

  // It should read negative int8
  ck_assert_int_eq(wz_read_long(&buffer, &file), 0);
  ck_assert(buffer == 0xfffffffffffffffe);

  // It should read postive int64
  ck_assert_int_eq(wz_read_long(&buffer, &file), 0);
  ck_assert(buffer == 0x01efcdab89674523);

  // It should not change data if position + len > size
  uint64_t copy = buffer;
  ck_assert_int_eq(wz_read_long(&buffer, &file), 1);
  ck_assert(buffer == copy);
  delete_file(&file);
} END_TEST

START_TEST(test_read_bytes) {
  // It should be ok
  char normal[] = "ab";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  char buffer[] = "cd";
  ck_assert_int_eq(wz_read_bytes((uint8_t *) buffer, strlen(buffer), &file), 0);
  ck_assert_int_eq(memcmp(buffer, normal, strlen(normal)), 0);

  // It should not change data if position + len > size
  ck_assert_int_eq(wz_read_bytes((uint8_t *) buffer, strlen(buffer), &file), 1);
  ck_assert_int_eq(memcmp(buffer, normal, strlen(normal)), 0);
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
  ck_assert_int_eq(memcmp(buffer.bytes, normal, strlen(normal)), 0);
  ck_assert(buffer.len == strlen(normal));
  ck_assert(memused() == sizeof(normal));

  // It should not change data if position + len > size
  wzstr copy = buffer;
  ck_assert_int_eq(wz_read_str(&buffer, strlen(normal), &file), 1);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);

  // It should not allocate memory if position + len > size
  ck_assert(memused() == sizeof(normal));
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
  ck_assert(memused() == sizeof(normal));
  wz_free_str(&buffer);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_decode_chars) {
  // It should decode ascii
  char ascii[] = "\x01\x23";
  wzkey key = {.bytes = (uint8_t *) "\x89\xab\xcd\xef", .len = 4};
  wzfile file = {.key = &key};
  wzstr buffer;
  buffer.bytes = (uint8_t *) ascii;
  buffer.len = strlen(ascii);
  ck_assert_int_eq(wz_decode_chars(&buffer, 1, file.key), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\x22\x23", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 0);

  // It should decode utf16le
  char utf16le[] = "\x45\x67"; // decode => \x66\x66  utf8 => \xe6\x99\xa6
  buffer.bytes = (uint8_t *) utf16le;
  buffer.len = strlen(utf16le);
  ck_assert_int_eq(wz_decode_chars(&buffer, 0, file.key), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\xe6\x99\xa6", 3), 0);
  ck_assert(buffer.len == 3 && memused() == 3 + 1);
  wz_free_chars(&buffer);
  ck_assert(memused() == 0);

  // It should not decode if key == NULL
  wzstr copy = buffer;
  ck_assert_int_eq(wz_decode_chars(&buffer, 1, NULL), 0);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);

  // It should not decode if string key is too short
  file.key->bytes = (uint8_t *) "\xcd";
  file.key->len = 1;
  ck_assert_int_eq(wz_decode_chars(&buffer, 1, file.key), 1);
  ck_assert(buffer.bytes == copy.bytes);
  ck_assert(buffer.len == copy.len);
} END_TEST

START_TEST(test_read_chars) {
  // It should be ok
  char normal[] =
    "\xfe""\x01\x23"
    "\x80""\x02\x00\x00\x00""\x45\x67"
    "\x01""\x89\xab"
    "\x7f""\x03\x00\x00\x00""\xcd\xef\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzstr buffer;
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\x01\x23", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\x45\x67", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\x89\xab", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  char * expected = "\xcd\xef\x01\x23\x45\x67";
  ck_assert_int_eq(memcmp(buffer.bytes, expected, 6), 0);
  ck_assert(buffer.len == 6 && memused() == 6 + 1);
  wz_free_chars(&buffer);
  delete_file(&file);

  // It should decode if string key is set
  create_file(&file, normal, sizeof(normal) - 1);
  wzctx ctx;
  create_ctx(&ctx);
  file.key = &ctx.keys[0];
  file.key->bytes = (uint8_t *) "\x01\x23\x45\x67\x89\xab";
  file.key->len = 6;
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\xaa\xab", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\xee\xef", 2), 0);
  ck_assert(buffer.len == 2 && memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert_int_eq(memcmp(buffer.bytes, "\xe2\x88\xa2", 2), 0);
  ck_assert(buffer.len == 3 && memused() == 3 + 1);
  wz_free_chars(&buffer);
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  expected = "\xe6\x99\xa6\xee\xbb\xaf\xe6\x99\xa0";
  ck_assert_int_eq(memcmp(buffer.bytes, expected, 9), 0);
  ck_assert(buffer.len == 9 && memused() == 9 + 1);
  wz_free_chars(&buffer);
  delete_ctx(&ctx);
  delete_file(&file);
} END_TEST

START_TEST(test_free_chars) {
  // It should be ok
  char normal[] = "\xfe\x01\x23";
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wzstr buffer;
  ck_assert_int_eq(wz_read_chars(&buffer, file.key, &file), 0);
  ck_assert(memused() == 2 + 1);
  wz_free_chars(&buffer);
  ck_assert(memused() == 0);
  delete_file(&file);
} END_TEST

START_TEST(test_rotl32) {
  // It should be ok
  ck_assert(wz_rotl32(0xf2345678, 3) == 0x91a2b3c7);
} END_TEST

void
wz_encode_addr(wzaddr * addr, wzfile * file) {
  uint32_t key = 0x581c3f6d;
  uint32_t decoded = ~(addr->pos - file->head.start);
  decoded = decoded * file->ver.hash - key;
  decoded = wz_rotl32(decoded, decoded & 0x1f);
  addr->val = decoded ^ (addr->val - file->head.start * 2);
}

START_TEST(test_decode_addr) {
  // It should be ok
  wzfile file = {.head = {.start = 0x3c}, .ver = {.hash = 0x713}};
  wzaddr addr = {.pos = 0x51, .val = 0x2ed};
  wz_encode_addr(&addr, &file);
  ck_assert(addr.val == 0x49e34db3);
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
  file.head.start = 0x12;
  file.ver.hash = 0x89abcdef;
  ck_assert_int_eq(wz_read_addr(&addr, &file), 0);
  ck_assert(addr.val == 0x8ebe951a && addr.pos == 8);
  delete_file(&file);
} END_TEST

START_TEST(test_seek) {
  // It should seek absolute address
  char normal[] =
    "\x01\x23\x45\x67\x89";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  ck_assert_int_eq(wz_seek(2, SEEK_SET, &file), 0);
  ck_assert(file.pos == 2);
  ck_assert(ftell(file.raw) == 2);

  // It should seek relative address
  ck_assert_int_eq(wz_seek(3, SEEK_CUR, &file), 0);
  ck_assert(file.pos == 5);
  ck_assert(ftell(file.raw) == 5);
  delete_file(&file);
} END_TEST

START_TEST(test_read_node) {
  // It should read type 1
  wzctx ctx;
  create_ctx(&ctx);
  char normal[] =
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x02""\x29\x00\x00\x00""\x01""\x02""\x01\x23\x45\x67"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x04""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x05"
    "\x04""\xfe\x01\x23"; // type 2 string
  wzfile file;
  create_file(&file, normal, sizeof(normal) - 1);
  wznode node;
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 0);
  ck_assert(memused() == 0);

  // It should read type 2
  file.head.start = 0x2;
  ck_assert(memused() == 0);
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 0);
  ck_assert(node.type == WZ_NODE_FILE);
  ck_assert_int_eq(memcmp(node.name.bytes, "ab", 2), 0);
  ck_assert(node.name.len == 2);
  ck_assert(node.size == 1 && node.check == 2 && node.addr.val == 0x67452301);
  ck_assert(memused() ==
            sizeof(* node.data.var) + sizeof(* node.data.var->val.obj) + 2 + 1);
  wz_free_node(&node);

  // It should read type 3
  ck_assert(memused() == 0);
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 0);
  ck_assert(node.type == WZ_NODE_DIR);
  ck_assert_int_eq(memcmp(node.name.bytes, "ab", 2), 0);
  ck_assert(node.name.len == 2);
  ck_assert(node.size == 1 && node.check == 2 && node.addr.val == 0x67452301);
  ck_assert(memused() == 2 + 1);
  wz_free_node(&node);

  // It should read type 4
  ck_assert(memused() == 0);
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 0);
  ck_assert(node.type == WZ_NODE_FILE);
  ck_assert_int_eq(memcmp(node.name.bytes, "ab", 2), 0);
  ck_assert(node.name.len == 2);
  ck_assert(node.size == 1 && node.check == 2 && node.addr.val == 0x67452301);
  ck_assert(memused() ==
            sizeof(* node.data.var) + sizeof(* node.data.var->val.obj) + 2 + 1);
  wz_free_node(&node);

  // It should not read type 5
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 1);
  ck_assert(memused() == 0);
  delete_file(&file);
  delete_ctx(&ctx);
} END_TEST

START_TEST(test_free_node) {
  // It should be ok
  wzctx ctx;
  create_ctx(&ctx);
  char normal[] = "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wznode node;
  ck_assert_int_eq(wz_read_node(&node, &file, &ctx), 0);
  ck_assert(memused() == 2 + 1);
  wz_free_node(&node);
  ck_assert(memused() == 0);
  delete_file(&file);
  delete_ctx(&ctx);
} END_TEST

START_TEST(test_read_grp) {
  // It should be ok
  wzctx ctx;
  create_ctx(&ctx);
  char normal[] = "\x03"
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x04""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wznode node = {.addr = {.val = 0}};
  wzgrp * grp = NULL;
  ck_assert_int_eq(wz_read_grp(&grp, &node, &file, &ctx), 0);
  ck_assert(grp->len == 3);
  ck_assert(grp->nodes[0].type == WZ_NODE_NIL);
  ck_assert(grp->nodes[1].type == WZ_NODE_DIR);
  ck_assert(grp->nodes[2].type == WZ_NODE_FILE);
  ck_assert(memused() ==
            sizeof(* grp) +
            sizeof(* grp->nodes) * 3 +
            sizeof(* grp->nodes[0].data.var) +
            sizeof(* grp->nodes[0].data.var->val.obj) +
            2 * (2 + 1));
  wz_free_grp(&grp);
  delete_file(&file);

  // It should not read invalid data
  char error[] = "\x03"
    "\x01""\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67"
    "\x02";
  create_file(&file, error, strlen(error));
  ck_assert_int_eq(wz_read_grp(&grp, &node, &file, &ctx), 1);
  ck_assert(memused() == 0);
  delete_file(&file);
  delete_ctx(&ctx);
} END_TEST

START_TEST(test_free_grp) {
  // It should be ok
  wzctx ctx;
  create_ctx(&ctx);
  char normal[] = "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45\x67";
  wzfile file;
  create_file(&file, normal, strlen(normal));
  wznode node = {.addr = {.val = 0}};
  wzgrp * grp = NULL;
  ck_assert_int_eq(wz_read_grp(&grp, &node, &file, &ctx), 0);
  ck_assert(memused() == sizeof(* grp) + sizeof(* grp->nodes) + 2 + 1);
  wz_free_grp(&grp);
  ck_assert(memused() == 0);
  delete_file(&file);
  delete_ctx(&ctx);
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
  ck_assert_int_eq(memcmp(head.ident, "\x01\x23\x45\x67", 4), 0);
  ck_assert(head.size == 18 && head.start == 18);
  ck_assert_int_eq(memcmp(head.copy.bytes, "ab", 2), 0);
  ck_assert(head.copy.len == 2);
  ck_assert(memused() == 2 + 1);
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
  ck_assert(memused() == 2 + 1);
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
      .data = {
        .grp = (wzgrp[]) {{
          .len = 1,
          .nodes = (wznode[]) {{
            .type = WZ_NODE_DIR,
            .addr = {.pos = 0x51, .val = 0x49e34db3}
          }}
        }}
      }
    },
    .ver = {.hash = 0x99}
  };
  wzver ver = {.hash = 0x713};
  ck_assert_int_eq(wz_valid_ver(&ver, &file.root, &file), 0);
  ck_assert(file.ver.hash == 0x99);

  // It should not change version hash if failed
  ver.hash = 0x712;
  ck_assert_int_eq(wz_valid_ver(&ver, &file.root, &file), 1);
  ck_assert(file.ver.hash == 0x99);
} END_TEST

START_TEST(test_deduce_ver) {
  // It should be ok
  wzver ver = {.dec = 0x00ce};
  ck_assert_int_eq(wz_encode_ver(&ver), 0);
  wzfile file = {.head = {.start = 0}, .ver = ver};
  wzaddr addr = {.pos = 0x7, .val = 0x00000000};
  wz_encode_addr(&addr, &file);
  char normal[] =
    "\x01"                             // nodes len
    "\x03""\xfe\x01\x23""\x01""\x00""\x00\x00\x00\x00";
  * (uint32_t *) (normal + addr.pos) = wz_htole32(addr.val);
  wzctx ctx;
  create_ctx(&ctx);
  wzfile testfile = {.root = {.addr = {.val = 0x00000000}}};
  create_file(&testfile, normal, sizeof(normal) - 1);
  wzver test = {.enc = 0x007a};
  ck_assert_int_eq(wz_deduce_ver(&test, &testfile, &ctx), 0);
  ck_assert(test.dec == 0x00ce);
  ck_assert(test.enc == 0x007a);
  ck_assert(test.hash == 0xd257);
  delete_file(&testfile);
  delete_ctx(&ctx);
} END_TEST

START_TEST(test_decode_aes) {
  // It shoule be ok
  uint8_t key[32] =
    "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
    "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00";
  uint8_t iv[16] =
    "\x4d\x23\xc7\x2b\x4d\x23\xc7\x2b""\x4d\x23\xc7\x2b\x4d\x23\xc7\x2b";
  uint8_t cipher[16] =
    "\x96\xae\x3f\xa4\x48\xfa\xdd\x90""\x46\x76\x05\x61\x97\xce\x78\x68";
  uint8_t plain[16];
  memset(plain, 0x11, sizeof(plain));
  wz_decode_aes(plain, cipher, 16, key, iv);
  uint8_t expected[16] = {0};
  ck_assert_int_eq(memcmp(plain, expected, 16), 0);
} END_TEST

START_TEST(test_encode_aes) {
  // It shoule be ok
  uint8_t plain[32] =
    "\x00\x00\x00\x00\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00""\x00\x00\x00\x00\x00\x00\x00\x00";
  uint8_t cipher[32] = {0};
  wzaes aes = {
    .key =
      "\x13\x00\x00\x00\x08\x00\x00\x00""\x06\x00\x00\x00\xb4\x00\x00\x00"
      "\x1b\x00\x00\x00\x0f\x00\x00\x00""\x33\x00\x00\x00\x52\x00\x00\x00",
    .iv =
      "\x4d\x23\xc7\x2b\x4d\x23\xc7\x2b""\x4d\x23\xc7\x2b\x4d\x23\xc7\x2b",
    .plain = plain, .cipher = cipher, .len = 32
  };
  wz_encode_aes(&aes);
  uint8_t expected[32] =
    "\x96\xae\x3f\xa4\x48\xfa\xdd\x90""\x46\x76\x05\x61\x97\xce\x78\x68"
    "\x2b\xa0\x44\x8f\xc1\x56\x7e\x32""\xfc\xe1\xf5\xb3\x14\x14\xc5\x22";
  ck_assert_int_eq(memcmp(cipher, expected, 32), 0);
} END_TEST

START_TEST(test_init_aes) {
  // It should be ok
  wzaes aes;
  memset(&aes, 0, sizeof(aes));
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  ck_assert(aes.key[0] != 0);
  ck_assert(aes.len != 0);
  ck_assert(memused() == aes.len * 2);
  ck_assert(aes.plain != NULL);
  ck_assert(aes.cipher != NULL);
  wz_free_aes(&aes);
} END_TEST

START_TEST(test_free_aes) {
  // It should be ok
  wzaes aes;
  memset(&aes, 0, sizeof(aes));
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  ck_assert(memused() == aes.len * 2);
  wz_free_aes(&aes);
  ck_assert(memused() == 0);
} END_TEST

START_TEST(test_init_key) {
  // It should be ok
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wzkey key;
  ck_assert_int_eq(wz_init_key(&key, &aes), 0);
  ck_assert(memused() == aes.len * 3);
  ck_assert(key.bytes != NULL);
  wz_free_key(&key);
  wz_free_aes(&aes);
} END_TEST

//START_TEST(test_valid_nodekey) {
//  // It should be ok
//  wzfile file = {
//    .root = {
//      .data = {
//        .dir = (wzdir[]) {{
//          .len = 2,
//          .nodes = (wznode[]) {{
//            .type = 0x03,
//            .name = {.len = 3, .bytes = "a0C", .enc = WZ_ENC_ASCII}
//          }, {
//            .type = 0x04,
//            .name = {.len = 3, .bytes = "<?@", .enc = WZ_ENC_ASCII}
//          }}
//        }}
//      }
//    }
//  };
//  wzstrk strk = {.ascii = NULL};
//  ck_assert_int_eq(wz_valid_nodekey(&strk, &file), 0);
//
//  // It should fail if any character cannot be decoded
//  file.root.data.dir->nodes[1].name.bytes = "<?\x80";
//  ck_assert_int_eq(wz_valid_nodekey(&strk, &file), 1);
//} END_TEST

START_TEST(test_set_key) {
  // It should be ok
  wzaes aes = {
    .cipher = (uint8_t *)
      "\x96\xae\x3f\xa4\x48\xfa\xdd\x90""\x46\x76\x05\x61\x97\xce\x78\x68"
      "\x2b\xa0\x44\x8f\xc1\x56\x7e\x32""\xfc\xe1\xf5\xb3\x14\x14\xc5\x22",
    .len = 32
  };
  wzkey key;
  ck_assert_int_eq(wz_init_key(&key, &aes), 0);
  wz_set_key(&key, &aes);
  ck_assert_int_eq(memcmp(key.bytes, aes.cipher, 32), 0);
  ck_assert(key.len == aes.len);
  wz_free_key(&key);
} END_TEST

START_TEST(test_free_key) {
  // It should be ok
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wzkey key;
  ck_assert_int_eq(wz_init_key(&key, &aes), 0);
  ck_assert(memused() == aes.len * 3);
  ck_assert(memused() > 0);
  wz_free_key(&key);
  ck_assert(memused() == aes.len * 2);
  ck_assert(memused() > 0);
  wz_free_aes(&aes);
} END_TEST

//START_TEST(test_decode_strk) {
//  // It should decode GMS
//  uint8_t gms[] = "\x6f\x6d\xfa\x6c\x8a\x31";
//  wzfile file = {
//    .root = {
//      .data = {
//        .dir = (wzdir[]) {{
//          .len = 1,
//          .nodes = (wznode[]) {{
//            .type = 0x03,
//            .name = {.len = strlen(gms), .bytes = gms, .enc = WZ_ENC_ASCII}
//          }}
//        }}
//      }
//    }
//  };
//  wzstrk strk;
//  ck_assert_int_eq(wz_decode_strk(&strk, wz_valid_nodekey, &file), 0);
//  ck_assert(memused() == strk.len * 2);
//  ck_assert(memused() > 0);
//  wz_free_strk(&strk);
//
//  // It should decode TMS
//  uint8_t tms[] = "\x31\xfe\xd5\x99\xfb\x52";
//  file.root.data.dir->nodes[0].name.bytes = tms;
//  ck_assert_int_eq(wz_decode_strk(&strk, wz_valid_nodekey, &file), 0);
//  ck_assert(memused() == strk.len * 2);
//  ck_assert(memused() > 0);
//  wz_free_strk(&strk);
//
//  // It should decode JMS
//  uint8_t jms[] = "\x9a\x9b\x9c\x9d\x9c\x9f";
//  file.root.data.dir->nodes[0].name.bytes = jms;
//  ck_assert_int_eq(wz_decode_strk(&strk, wz_valid_nodekey, &file), 0);
//  ck_assert(memused() == strk.len * 2);
//  ck_assert(memused() > 0);
//  wz_free_strk(&strk);
//} END_TEST

void
create_content(char ** buffer, size_t * len, wzctx * ctx) {
  wzver ver = {.dec = 0x00ce};
  ck_assert_int_eq(wz_encode_ver(&ver), 0);
  wzfile file = {.head = {.start = 18}, .ver = ver};
  wzaddr addr = {.pos = 27, .val = 0x00000000};
  wz_encode_addr(&addr, &file);
  char normal[] =
    "\x01\x23\x45\x67"                 // ident
    "\x1F\x00\x00\x00\x00\x00\x00\x00" // size
    "\x12\x00\x00\x00"                 // start
    "ab"                               // copy
    "\x7a\x00"                         // ver
    "\x01"                             // nodes len
    "\x03""\xfe\x5d\x67""\x01""\x02""\x00\x00\x00\x00";
  // node name: "\x5d\x67" == "\x96\xae" ^ "\xaa\xab" ^ "ab"
  * (uint32_t *) (normal + addr.pos) = wz_htole32(addr.val);
  char * content = malloc(sizeof(normal) - 1);
  ck_assert(content != NULL);
  memcpy(content, normal, sizeof(normal) - 1);
  * buffer = content, * len = sizeof(normal) - 1;
  wzkey * key = malloc(sizeof(* key));
  ck_assert(key != NULL);
  key->bytes = (uint8_t *) "\x96\xae", key->len = 2;
  ctx->keys = key, ctx->klen = 1;
}

void
delete_content(char * content, wzctx * ctx) {
  free(ctx->keys);
  free(content);
}

START_TEST(test_read_file) {
  // It should be ok
  char * normal;
  size_t len;
  wzctx ctx;
  create_content(&normal, &len, &ctx);
  wzfile file;
  FILE * raw = create_tmpfile(normal, len);
  ck_assert_int_eq(wz_read_file(&file, raw, &ctx), 0);
  ck_assert_int_eq(memcmp(file.head.copy.bytes, "ab", 2), 0);
  ck_assert(file.head.copy.len == 2);
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wz_free_aes(&aes);
  ck_assert(memused() == 2 + 1);
  wz_free_file(&file);
  delete_tmpfile(raw);

  // It should not read invalid data
  char error[] =
    "\x01\x23\x45\x67"
    "\x1F\x00\x00\x00\x00\x00\x00\x00"
    "\x12\x00\x00\x00"
    "ab"
    "\x01\x23"
    "\x01"
    "\x03""\xfe\x01\x23""\x01""\x02""\x01\x23\x45";
  raw = create_tmpfile(error, sizeof(error) - 1);
  ck_assert(raw != NULL);
  ck_assert_int_eq(wz_read_file(&file, raw, &ctx), 1);
  ck_assert(memused() == 0);
  delete_tmpfile(raw);
  delete_content(normal, &ctx);
} END_TEST

START_TEST(test_free_file) {
  // It should be ok
  char * normal;
  size_t len;
  wzctx ctx;
  create_content(&normal, &len, &ctx);
  wzfile file;
  FILE * raw = create_tmpfile(normal, len);
  ck_assert_int_eq(wz_read_file(&file, raw, &ctx), 0);
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wz_free_aes(&aes);
  ck_assert(memused() == 2 + 1);
  wz_free_file(&file);
  ck_assert(memused() == 0);
  delete_tmpfile(raw);
  delete_content(normal, &ctx);
} END_TEST

START_TEST(test_open_file) {
  // It should be ok
  char * filename = "test_open_file.wz";
  FILE * raw = fopen(filename, "wb");
  ck_assert(raw != NULL);
  wzfile file;
  char * normal;
  size_t len;
  wzctx ctx;
  create_content(&normal, &len, &ctx);
  ck_assert(fwrite(normal, 1, len, raw) == len);
  ck_assert_int_eq(fclose(raw), 0);
  ck_assert_int_eq(wz_open_file(&file, filename, &ctx), 0);
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wz_free_aes(&aes);
  ck_assert(memused() == 2 + 1);
  ck_assert_int_eq(wz_close_file(&file), 0);
  ck_assert_int_eq(remove(filename), 0);

  // It should not read the file which does not exist
  ck_assert_int_eq(wz_open_file(&file, "not-exist-file", &ctx), 1);
  delete_content(normal, &ctx);
} END_TEST

START_TEST(test_close_file) {
  // It should be ok
  char * filename = "test_close_file.wz";
  FILE * raw = fopen(filename, "wb");
  ck_assert(raw != NULL);
  wzfile file;
  char * normal;
  size_t len;
  wzctx ctx;
  create_content(&normal, &len, &ctx);
  ck_assert(fwrite(normal, 1, len, raw) == len);
  ck_assert_int_eq(fclose(raw), 0);
  ck_assert_int_eq(wz_open_file(&file, filename, &ctx), 0);
  wzaes aes;
  ck_assert_int_eq(wz_init_aes(&aes), 0);
  wz_free_aes(&aes);
  ck_assert(memused() == 2 + 1);
  ck_assert_int_eq(wz_close_file(&file), 0);
  ck_assert_int_eq(remove(filename), 0);
  ck_assert(memused() == 0);
  delete_content(normal, &ctx);
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
  tcase_add_test(tcase, test_read_long);
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
  tcase_add_test(tcase, test_seek);
  tcase_add_test(tcase, test_read_node);
  tcase_add_test(tcase, test_free_node);
  tcase_add_test(tcase, test_read_grp);
  tcase_add_test(tcase, test_free_grp);
  tcase_add_test(tcase, test_read_head);
  tcase_add_test(tcase, test_free_head);
  tcase_add_test(tcase, test_encode_ver);
  tcase_add_test(tcase, test_valid_ver);
  tcase_add_test(tcase, test_deduce_ver);
  tcase_add_test(tcase, test_decode_aes);
  tcase_add_test(tcase, test_encode_aes);
  tcase_add_test(tcase, test_init_aes);
  tcase_add_test(tcase, test_free_aes);
  tcase_add_test(tcase, test_init_key);
  //tcase_add_test(tcase, test_valid_nodekey);
  tcase_add_test(tcase, test_set_key);
  tcase_add_test(tcase, test_free_key);
  //tcase_add_test(tcase, test_decode_strk);
  tcase_add_test(tcase, test_read_file);
  tcase_add_test(tcase, test_free_file);
  tcase_add_test(tcase, test_open_file);
  tcase_add_test(tcase, test_close_file);
  suite_add_tcase(suite, tcase);
  return suite;
}
