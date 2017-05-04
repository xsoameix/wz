#define _POSIX_C_SOURCE 200112L
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "file.h"

#ifdef _WIN32
#define SEP '\\'
#else
#define SEP '/'
#endif

char *
path_join(const char * a, const char * b) {
  if (a == NULL) a = "";
  if (b == NULL) b = "";
  size_t al = strlen(a);
  size_t bl = strlen(b);
  if (al == 0 && bl == 0) {
    char * c;
    if ((c = malloc(1)) == NULL) return NULL;
    c[0] = '\0';
    return c;
  } else if (al == 0) {
    char * c;
    if ((c = malloc(bl + 1)) == NULL) return NULL;
    memcpy(c, b, bl);
    c[bl] = '\0';
    return c;
  } else if (bl == 0) {
    while (al > 0 && a[al-1] == SEP) al--;
    char * c;
    if ((c = malloc(al + 1)) == NULL) return NULL;
    memcpy(c, a, al);
    c[al] = '\0';
    return c;
  } else {
    while (al > 0 && a[al-1] == SEP) al--;
    while (bl > 0 && b[0] == SEP) bl--, b++;
    char * c;
    if ((c = malloc(al + 1 + bl + 1)) == NULL) return NULL;
    memcpy(c, a, al);
    c[al] = SEP;
    memcpy(c + al + 1, b, bl);
    c[al + 1 + bl] = '\0';
    return c;
  }
}

char *
path_of_file(const char * filename) {
  const char * dir;
  char * path;
  if ((dir = getenv("WZ_DIR")) == NULL) return NULL;
  if ((path = path_join(dir, filename)) == NULL) return NULL;
  return path;
}

int
cmd_help(int argc, char ** argv) {
  // wz help
  (void) argc; (void) argv;
  printf("wz version 1.0.0\n"
         "Copyright (C) 2016 Lien Chiang\n"
         "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
         "This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n"
         "\n"
         "Written by Lien Chiang.\n");
  wznode n;
#define offsetof(a, b) (size_t) ((char *) (&(a)->b) - (char *) (a))
  printf("\n");
  printf("sizeof n16_e           %2zu\n", sizeof(n.n16_e));
  printf("offset n16_e.name_buf  %2zu\n", offsetof(&n, n16_e.name_buf));
  printf("sizeof n16_e.name_buf  %2zu\n", sizeof(n.n16_e.name_buf));
  printf("\n");
  printf("sizeof n32_e           %2zu\n", sizeof(n.n32_e));
  printf("offset n32_e.name_buf  %2zu\n", offsetof(&n, n32_e.name_buf));
  printf("sizeof n32_e.name_buf  %2zu\n", sizeof(n.n32_e.name_buf));
  printf("\n");
  printf("sizeof n64_e           %2zu\n", sizeof(n.n64_e));
  printf("offset n64_e.name_buf  %2zu\n", offsetof(&n, n64_e.name_buf));
  printf("sizeof n64_e.name_buf  %2zu\n", sizeof(n.n64_e.name_buf));
  printf("\n");
  printf("sizeof n16             %2zu\n", sizeof(n.n16));
  printf("offset n16.val         %2zu\n", offsetof(&n, n16.val));
  printf("\n");
  printf("sizeof n32             %2zu\n", sizeof(n.n32));
  printf("offset n32.val         %2zu\n", offsetof(&n, n32.val));
  printf("\n");
  printf("sizeof n64             %2zu\n", sizeof(n.n64));
  printf("offset n64.val         %2zu\n", offsetof(&n, n64.val));
  printf("\n");
  printf("sizeof np_e            %2zu\n", sizeof(n.np_e));
  printf("offset np_e.name_buf   %2zu\n", offsetof(&n, np_e.name_buf));
  printf("sizeof np_e.name_buf   %2zu\n", sizeof(n.np_e.name_buf));
  printf("\n");
  printf("sizeof na_e            %2zu\n", sizeof(n.na_e));
  printf("offset na_e.name_buf   %2zu\n", offsetof(&n, na_e.name_buf));
  printf("sizeof na_e.name_buf   %2zu\n", sizeof(n.na_e.name_buf));
  printf("offset na_e.key        %2zu\n", offsetof(&n, na_e.key));
  printf("offset na_e.addr       %2zu\n", offsetof(&n, na_e.addr));
  printf("\n");
  printf("sizeof na              %2zu\n", sizeof(n.na));
  printf("offset na.key          %2zu\n", offsetof(&n, na.key));
  printf("offset na.addr         %2zu\n", offsetof(&n, na.addr));
  printf("\n");
  printf("sizeof n               %2zu\n", sizeof(n.n));
  printf("offset n.root          %2zu\n", offsetof(&n, n.root));
  printf("offset n.parent        %2zu\n", offsetof(&n, n.parent));
  printf("offset n.name_len      %2zu\n", offsetof(&n, n.name_len));
  printf("offset n.name_e        %2zu\n", offsetof(&n, n.name_e));
  printf("offset n.name          %2zu\n", offsetof(&n, n.name));
  printf("offset n.val           %2zu\n", offsetof(&n, n.val));
  return 0;
}

int
cmd_all(int argc, char ** argv) {
  // wz all <FILE>...
  // read all nodes
  int ret = 1;
  if (argc < 3) return ret;
  char * done;
  if ((done = malloc((size_t) (argc - 2))) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_done;
  struct timespec start;
  struct timespec end;
  int err;
  if ((err = clock_gettime(CLOCK_MONOTONIC, &start)) != 0) goto cleanup_ctx;
  for (int i = 2; i < argc; i++) {
    int read_err = 1;
    done[i - 2] = 0;
    if (strstr(argv[i], "List.wz") == NULL &&
        strstr(argv[i], "Data.wz") == NULL) {
      printf("file: %s\n", argv[i]);
      wzfile file;
      if (wz_open_file(&file, argv[i], &ctx)) goto cleanup_ctx;
      if (wz_read_node_thrd_r(&file.root, &file, &ctx, 8)) goto cleanup_file;
      //if (wz_read_node_r(&file.root, &file, &ctx)) goto cleanup_file;
      read_err = 0;
cleanup_file: wz_close_file(&file);
    } else {
      printf("file: %s ignored\n", argv[i]);
      read_err = 0;
    }
    if (!read_err)
      done[i - 2] = 1;
  }
  if ((err = clock_gettime(CLOCK_MONOTONIC, &end)) != 0) goto cleanup_ctx;
  long time_use =
      (end.tv_sec - start.tv_sec) * 1000000000 +
      (end.tv_nsec - start.tv_nsec);
  for (int i = 2; i < argc; i++)
    printf("%c: %s\n", done[i - 2] ? 'o' : 'x', argv[i]);
  printf("took %3ld.%09ld\n",
         time_use / 1000000000,
         time_use % 1000000000);
  ret = 0;
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_done: free(done);
  return ret;
}

//int
//cmd_map(int argc, char ** argv) {
//  // wz map
//  // read 2 levels nodes of Map.wz
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename;
//  if ((filename = path_of_file("Map.wz")) == NULL) return ret;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename;
//  wzfile file;
//  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
//  wznode * root = wz_open_root_node(&file);
//  uint32_t len = wz_get_nodes_len(root);
//  for (uint32_t i = 0; i < len; i++) {
//    wznode * node = wz_open_node_at(root, i);
//    printf(" %s\n", wz_get_node_name(node));
//    if (node->type != WZ_NODE_DIR) continue;
//    uint32_t node_len = wz_get_nodes_len(node);
//    for (uint32_t j = 0; j < node_len; j++) {
//      wznode * child = wz_open_node_at(node, j);
//      printf("  %s\n", wz_get_node_name(child));
//    }
//  }
//  ret = 0;
//  wz_close_node(root);
//  wz_close_file(&file);
//cleanup_ctx: wz_free_ctx(&ctx);
//cleanup_filename: free(filename);
//  return ret;
//}
//
//int
//cmd_map_helper(int argc, char ** argv) {
//  // wz map-helper <DIR>
//  // read 2 levels nodes in MapHelper.img of Map.wz
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename;
//  if ((filename = path_of_file("Map.wz")) == NULL) return ret;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename;
//  wzfile file;
//  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
//  wznode * root_node = wz_open_root_node(&file);
//  wznode * node = wz_open_node(root_node, "MapHelper.img");
//  wzvar * root_var = wz_open_root_var(node);
//  uint32_t len = wz_get_vars_len(root_var);
//  for (uint32_t i = 0; i < len; i++) {
//    wzvar * var = wz_open_var_at(root_var, i);
//    printf(" %s\n", wz_get_var_name(var));
//    uint32_t var_len = wz_get_vars_len(var);
//    for (uint32_t j = 0; j < var_len; j++) {
//      wzvar * child = wz_open_var_at(var, j);
//      printf("  %s\n", wz_get_var_name(child));
//    }
//  }
//  ret = 0;
//  wz_close_var(root_var);
//  wz_close_node(root_node);
//  wz_close_file(&file);
//cleanup_ctx: wz_free_ctx(&ctx);
//cleanup_filename: free(filename);
//  return ret;
//}
//
//int
//cmd_char(int argc, char ** argv) {
//  // wz char <DIR>
//  // read character's action
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename;
//  if ((filename = path_of_file("Character.wz")) == NULL) return ret;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename;
//  wzfile file;
//  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
//  wznode * root_node = wz_open_root_node(&file);
//  wznode * node = wz_open_node(root_node, "00002001.img");
//  wzvar * root_var = wz_open_root_var(node);
//  wzvar * var_prone = wz_open_var(root_var, "prone/0");
//  wzvar * var_face = wz_open_var(var_prone, "face");
//  wzvar * var_delay = wz_open_var(var_prone, "delay");
//  wzvar * var_arm = wz_open_var(var_prone, "arm");
//  int64_t face = wz_get_int(var_face);
//  int64_t delay = wz_get_int(var_delay);
//  wzimg * arm = wz_get_img(var_arm);
//  printf("face: %"PRId64"\n"
//         "delay: %"PRId64"\n"
//         "arm: %"PRIu32" %"PRIu32"\n",
//         face, delay, arm->w, arm->h);
//  ret = 0;
//  wz_close_file(&file);
//cleanup_ctx: wz_free_ctx(&ctx);
//cleanup_filename: free(filename);
//  return ret;
//}
//
//int
//cmd_char_imgs(int argc, char ** argv) {
//  // wz char-imgs <DIR>
//  // read character's imgs
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename;
//  if ((filename = path_of_file("Character.wz")) == NULL) return ret;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename;
//  wzfile file;
//  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
//  wznode * root_node = wz_open_root_node(&file);
//  wznode * node = wz_open_node(root_node, "Hair/00030020.img");
//  wzvar * root_var = wz_open_root_var(node);
//  uint32_t len = wz_get_vars_len(root_var);
//  for (uint32_t i = 0; i < len; i++) {
//    int show = 0;
//    wzvar * var = wz_open_var_at(root_var, i);
//    uint32_t var_len = wz_get_vars_len(var);
//    for (uint32_t j = 0; j < var_len; j++) {
//      wzvar * child = wz_open_var_at(var, j);
//      uint32_t var_len2 = wz_get_vars_len(child);
//      for (uint32_t k = 0; k < var_len2; k++) {
//        wzvar * child2 = wz_open_var_at(child, k);
//        if (strcmp(wz_get_var_name(child2), "hair") &&
//            strcmp(wz_get_var_name(child2), "hairOverHead") &&
//            strcmp(wz_get_var_name(child2), "hairBelowBody") &&
//            strcmp(wz_get_var_name(child2), "hairShade") &&
//            strcmp(wz_get_var_name(child2), "backHair") &&
//            strcmp(wz_get_var_name(child2), "backHairBelowCap")) {
//          show = 1;
//        }
//      }
//    }
//    if (show) printf("%s\n", wz_get_var_name(var));
//    for (uint32_t j = 0; j < var_len; j++) {
//      int show2 = 0;
//      wzvar * child = wz_open_var_at(var, j);
//      uint32_t var_len2 = wz_get_vars_len(child);
//      for (uint32_t k = 0; k < var_len2; k++) {
//        wzvar * child2 = wz_open_var_at(child, k);
//        if (strcmp(wz_get_var_name(child2), "hair") &&
//            strcmp(wz_get_var_name(child2), "hairOverHead") &&
//            strcmp(wz_get_var_name(child2), "hairBelowBody") &&
//            strcmp(wz_get_var_name(child2), "hairShade") &&
//            strcmp(wz_get_var_name(child2), "backHair") &&
//            strcmp(wz_get_var_name(child2), "backHairBelowCap")) {
//          show2 = 1;
//        }
//      }
//      if (show2) printf(" %s\n", wz_get_var_name(child));
//      for (uint32_t k = 0; k < var_len2; k++) {
//        wzvar * child2 = wz_open_var_at(child, k);
//        if (show2) printf("  %s\n", wz_get_var_name(child2));
//      }
//    }
//  }
//  ret = 0;
//  wz_close_file(&file);
//cleanup_ctx: wz_free_ctx(&ctx);
//cleanup_filename: free(filename);
//  return ret;
//}
//
//int
//cmd_skill_img(int argc, char ** argv) {
//  // wz skill-img <DIR>
//  // read skill's effect image
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename;
//  if ((filename = path_of_file("Skill.wz")) == NULL) return ret;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename;
//  wzfile file;
//  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
//  wznode * node_root = wz_open_root_node(&file);
//  wznode * node = wz_open_node(node_root, "422.img");
//  wzvar * var_root = wz_open_root_var(node);
//  wzvar * var = wz_open_var(var_root, "skill/4221010/effect/0");
//  wzimg * img = wz_get_img(var);
//  static int id = 0;
//  char data_filename[100];
//  snprintf(data_filename, sizeof(data_filename),
//           "out/%d-%"PRIu32"-%"PRIu32".data", id++, img->w, img->h);
//  FILE * data_file = fopen(data_filename, "wb");
//  fwrite(img->data, 1, img->w * img->h * 4, data_file);
//  fclose(data_file);
//  ret = 0;
//  wz_close_file(&file);
//cleanup_ctx: wz_free_ctx(&ctx);
//cleanup_filename: free(filename);
//  return ret;
//}
//
//int
//cmd_scrolls(int argc, char ** argv) {
//  // wz scrolls <DIR>
//  // read all scrolls
//  (void) argc; (void) argv;
//  int ret = 1;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) return ret;
//  char * filename_string;
//  char * filename_item;
//  if ((filename_string = path_of_file("String.wz")) == NULL) goto cleanup_ctx;
//  if ((filename_item = path_of_file("Item.wz")) == NULL)
//    goto cleanup_filename_string;
//  wzfile file_string;
//  wzfile file_item;
//  if (wz_open_file(&file_string, filename_string, &ctx))
//    goto cleanup_filename_item;
//  if (wz_open_file(&file_item, filename_item, &ctx))
//    goto cleanup_file_string;
//  wznode * node_string_root = wz_open_root_node(&file_string);
//  wznode * node_string_consume = wz_open_node(node_string_root, "Consume.img");
//  wzvar * var_string_consume_root = wz_open_root_var(node_string_consume);
//  wznode * node_item_root = wz_open_root_node(&file_item);
//  wznode * node_item_consume = wz_open_node(node_item_root, "Consume");
//  wznode * node_item_scroll = wz_open_node(node_item_consume, "0204.img");
//  wzvar * var_item_scroll_root = wz_open_root_var(node_item_scroll);
//  uint32_t len = wz_get_vars_len(var_string_consume_root);
//  for (uint32_t i = 0; i < len; i++) {
//    wzvar * var_string_consume = wz_open_var_at(var_string_consume_root, i);
//    const char * id = wz_get_var_name(var_string_consume);
//    if (strncmp(id, "204", 3)) continue;
//    char index[8 + 1];
//    int ret_snprintf;
//    if ((ret_snprintf = snprintf(index, sizeof(index), "%8s",
//                                 id)) >= (int) sizeof(index) ||
//        ret_snprintf < 0) goto cleanup_file_item;
//    for (size_t j = 0; index[j] == ' '; j++) index[j] = '0';
//    wzvar * var_item_scroll = wz_open_var(var_item_scroll_root, index);
//    wzvar * var_item_info = wz_open_var(var_item_scroll, "info");
//    wzvar * var_name = wz_open_var(var_string_consume, "name");
//    const char * name = wz_get_str(var_name);
//    wzvar * var_success = wz_open_var(var_item_info, "success");
//    int32_t success;
//    if (var_success->type == WZ_VAR_STR) {
//      if (sscanf(wz_get_str(var_success), "%"PRId32, &success) != 1)
//        goto cleanup_file_item;
//    } else {
//      success = (int32_t) wz_get_int(var_success);
//    }
//    printf("%s  %-50s  %3"PRId32"%%\n", id, name, success);
//  }
//  ret = 0;
//cleanup_file_item:       wz_close_file(&file_item);
//cleanup_file_string:     wz_close_file(&file_string);
//cleanup_filename_item:   free(filename_item);
//cleanup_filename_string: free(filename_string);
//cleanup_ctx:             wz_free_ctx(&ctx);
//  return ret;
//}
//
//int
//cmd_mobs(int argc, char ** argv) {
//  // wz mobs <DIR>
//  // read mob info
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename_mob;
//  char * filename_string;
//  if ((filename_mob = path_of_file("Mob.wz")) == NULL) return ret;
//  if ((filename_string = path_of_file("String.wz")) == NULL)
//    goto cleanup_filename_mob;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename_string;
//  wzfile file_mob;
//  wzfile file_string;
//  if (wz_open_file(&file_mob, filename_mob, &ctx)) goto cleanup_ctx;
//  if (wz_open_file(&file_string, filename_string, &ctx)) goto cleanup_file_mob;
//  wznode * node_mob_root = wz_open_root_node(&file_mob);
//  wznode * node_string_root = wz_open_root_node(&file_string);
//  wznode * node_string_mob = wz_open_node(node_string_root, "Mob.img");
//  wzvar * var_string_mob_root = wz_open_root_var(node_string_mob);
//  char db_id[5 + 1];
//  char mob_id[7 + 1];
//  char item_id[7 + 1];
//  char drop_rate[6 + 1];
//  int times = 0;
//  while (scanf("%[^,],%[^,],%[^,],%[^\x0d]\n",
//               db_id, mob_id, item_id, drop_rate) == 4) {
//    if (!times) {
//      printf("%7s %-23s %3s %10s %7s %6s\n",
//             "id", "name", "lv", "hp", "mp", "drop");
//      times = 1;
//    }
//    char mob_img[7 + 4 + 1];
//    int ret_snprintf;
//    if ((ret_snprintf = snprintf(mob_img, sizeof(mob_img), "%7s.img",
//                                 mob_id)) >= (int) sizeof(mob_img) ||
//        ret_snprintf < 0) goto cleanup_file_string;
//    for (size_t i = 0; mob_img[i] == ' '; i++) mob_img[i] = '0';
//    wznode * node_mob = wz_open_node(node_mob_root, mob_img);
//    wzvar * var_mob_root = wz_open_root_var(node_mob);
//    wzvar * var_mob_info = wz_open_var(var_mob_root, "info");
//    wzvar * var_mob_level = wz_open_var(var_mob_info, "level");
//    wzvar * var_mob_hp = wz_open_var(var_mob_info, "maxHP");
//    wzvar * var_mob_mp = wz_open_var(var_mob_info, "maxMP");
//    wzvar * var_mob_boss = wz_open_var(var_mob_info, "boss");
//    uint32_t mob_level = (uint32_t) wz_get_int(var_mob_level);
//    uint32_t mob_hp = (uint32_t) wz_get_int(var_mob_hp);
//    uint32_t mob_mp = (uint32_t) wz_get_int(var_mob_mp);
//    wzvar * var_string_mob = wz_open_var(var_string_mob_root, mob_id);
//    wzvar * var_string_mob_name = wz_open_var(var_string_mob, "name");
//    const char * mob_name = wz_get_str(var_string_mob_name);
//    printf("%7s %-23s %3"PRIu32" %10"PRIu32" %7"PRIu32" %6s",
//           mob_id, mob_name, mob_level, mob_hp, mob_mp, drop_rate);
//    if (var_mob_boss != NULL && wz_get_int(var_mob_boss) > 0)
//      printf(" boss");
//    printf("\n");
//  }
//  ret = 0;
//cleanup_file_string:     wz_close_file(&file_string);
//cleanup_file_mob:        wz_close_file(&file_mob);
//cleanup_ctx:             wz_free_ctx(&ctx);
//cleanup_filename_string: free(filename_string);
//cleanup_filename_mob:    free(filename_mob);
//  return ret;
//}
//
//int
//cmd_thief_shields(int argc, char ** argv) {
//  // wz thief-shields <DIR>
//  // read common and thief shields
//  (void) argc; (void) argv;
//  int ret = 1;
//  char * filename_string;
//  char * filename_char;
//  if ((filename_string = path_of_file("String.wz")) == NULL) return ret;
//  if ((filename_char = path_of_file("Character.wz")) == NULL)
//    goto cleanup_filename_string;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename_char;
//  wzfile file_string;
//  wzfile file_char;
//  if (wz_open_file(&file_string, filename_string, &ctx))
//    goto cleanup_ctx;
//  if (wz_open_file(&file_char, filename_char, &ctx))
//    goto cleanup_file_string;
//  wznode * node_char_root = wz_open_root_node(&file_char);
//  wznode * node_char_shields = wz_open_node(node_char_root, "Shield");
//  wznode * node_string_root = wz_open_root_node(&file_string);
//  wznode * node_string_eqp = wz_open_node(node_string_root, "Eqp.img");
//  wzvar * var_eqp_root = wz_open_root_var(node_string_eqp);
//  wzvar * var_eqp_shields = wz_open_var(var_eqp_root, "Eqp/Shield");
//  for (uint32_t i = 0, len = wz_get_vars_len(var_eqp_shields); i < len; i++) {
//    wzvar * var_eqp_shield = wz_open_var_at(var_eqp_shields, i);
//    wzvar * var_eqp_shield_name = wz_open_var(var_eqp_shield, "name");
//    const char * eqp_shield_name = wz_get_str(var_eqp_shield_name);
//    const char * shield_id = wz_get_var_name(var_eqp_shield);
//    char shield_img[8 + 4 + 1];
//    int ret_snprintf;
//    if ((ret_snprintf = snprintf(shield_img, sizeof(shield_img), "%8s.img",
//                                 shield_id)) >= (int) sizeof(shield_img) ||
//        ret_snprintf < 0)
//      goto cleanup_file_char;
//    for (size_t j = 0; shield_img[j] == ' '; j++) shield_img[j] = '0';
//    wznode * node_char_shield = wz_open_node(node_char_shields, shield_img);
//    wzvar * var_shield_root = wz_open_root_var(node_char_shield);
//    wzvar * var_shield_info = wz_open_var(var_shield_root, "info");
//    wzvar * var_shield_req_level = wz_open_var(var_shield_info, "reqLevel");
//    wzvar * var_shield_req_job = wz_open_var(var_shield_info, "reqJob");
//    if (wz_get_int(var_shield_req_job) &&
//        wz_get_int(var_shield_req_job) != 8) continue;
//    uint32_t req_level = (uint32_t) wz_get_int(var_shield_req_level);
//    printf("%s %24s %3"PRIu32,
//           shield_id, eqp_shield_name, req_level);
//    uint32_t attrs_len = wz_get_vars_len(var_shield_info);
//    for (uint32_t j = 0; j < attrs_len; j++) {
//      wzvar * var_shield_attr = wz_open_var_at(var_shield_info, j);
//      const char * shield_attr_name = wz_get_var_name(var_shield_attr);
//      if (strcmp(shield_attr_name, "incPDD")) continue;
//      uint32_t shield_attr_value = (uint32_t) wz_get_int(var_shield_attr);
//      printf(" %s %3"PRIu32, shield_attr_name + 3, shield_attr_value);
//    }
//    for (uint32_t j = 0; j < attrs_len; j++) {
//      wzvar * var_shield_attr = wz_open_var_at(var_shield_info, j);
//      const char * shield_attr_name = wz_get_var_name(var_shield_attr);
//      if (strncmp(shield_attr_name, "inc", 3)) continue;
//      if (!strcmp(shield_attr_name, "incPDD")) continue;
//      uint32_t shield_attr_value = (uint32_t) wz_get_int(var_shield_attr);
//      printf(" %s %2"PRIu32, shield_attr_name + 3, shield_attr_value);
//    }
//    printf("\n");
//  }
//  ret = 0;
//cleanup_file_char:       wz_close_file(&file_char);
//cleanup_file_string:     wz_close_file(&file_string);
//cleanup_ctx:             wz_free_ctx(&ctx);
//cleanup_filename_char:   free(filename_char);
//cleanup_filename_string: free(filename_string);
//  return ret;
//}
//
//int
//cmd_life_maps(int argc, char ** argv) {
//  // wz life-maps <DIR>
//  // read life located maps
//  int ret = 1;
//  if (argc != 3) return ret;
//  const char * life_id = argv[2];
//  char * filename_map;
//  char * filename_string;
//  if ((filename_map = path_of_file("Map.wz")) == NULL) return ret;
//  if ((filename_string = path_of_file("String.wz")) == NULL)
//    goto cleanup_filename_map;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename_string;
//  wzfile file_map;
//  wzfile file_string;
//  if (wz_open_file(&file_map, filename_map, &ctx))
//    goto cleanup_ctx;
//  if (wz_open_file(&file_string, filename_string, &ctx))
//    goto cleanup_file_map;
//  wznode * node_string_root = wz_open_root_node(&file_string);
//  wznode * node_string_map = wz_open_node(node_string_root, "Map.img");
//  wzvar * var_string_map_root = wz_open_root_var(node_string_map);
//  wznode * node_map_root = wz_open_root_node(&file_map);
//  wznode * node_map_grps = wz_open_node(node_map_root, "Map");
//  for (uint32_t i = 0, il = wz_get_nodes_len(node_map_grps); i < il; i++) {
//    wznode * node_maps = wz_open_node_at(node_map_grps, i);
//    for (uint32_t j = 0, jl = wz_get_nodes_len(node_maps); j < jl; j++) {
//      wznode * node_map = wz_open_node_at(node_maps, j);
//      wzvar * var_map_root = wz_open_root_var(node_map);
//      wzvar * var_map_lifes = wz_open_var(var_map_root, "life");
//      if (var_map_lifes == NULL) continue;
//      const char * only = "*";
//      for (uint32_t k = 0, kl = wz_get_vars_len(var_map_lifes); k < kl; k++) {
//        wzvar * var_map_life = wz_open_var_at(var_map_lifes, k);
//        wzvar * var_map_life_type = wz_open_var(var_map_life, "type");
//        const char * map_life_type = wz_get_str(var_map_life_type);
//        if (strcmp(map_life_type, "m")) continue;
//        wzvar * var_map_life_id = wz_open_var(var_map_life, "id");
//        const char * map_life_id = wz_get_str(var_map_life_id);
//        if (strcmp(map_life_id, life_id)) { only = ""; break; }
//      }
//      wzvar * found_var_map_life = NULL;
//      for (uint32_t k = 0, kl = wz_get_vars_len(var_map_lifes); k < kl; k++) {
//        wzvar * var_map_life = wz_open_var_at(var_map_lifes, k);
//        wzvar * var_map_life_id = wz_open_var(var_map_life, "id");
//        const char * map_life_id = wz_get_str(var_map_life_id);
//        if (strcmp(map_life_id, life_id)) continue;
//        found_var_map_life = var_map_life;
//        break;
//      }
//      if (found_var_map_life == NULL) continue;
//      const char * node_map_name = wz_get_node_name(node_map);
//      char map_id[9 + 1];
//      if (sscanf(node_map_name, "%[^.]", map_id) != 1)
//        goto cleanup_file_string;
//      wzvar * var_map_life = found_var_map_life;
//      wzvar * var_map_life_type = wz_open_var(var_map_life, "type");
//      const char * map_life_type = wz_get_str(var_map_life_type);
//      const char * life_type;
//      if (!strcmp(map_life_type, "n"))      life_type = "npc";
//      else if (!strcmp(map_life_type, "m")) life_type = "mob";
//      else                                  life_type = "???";
//      wzvar * found_var_string_map = NULL;
//      uint32_t ll = wz_get_vars_len(var_string_map_root);
//      for (uint32_t l = 0; l < ll; l++) {
//        wzvar * var_string_maps = wz_open_var_at(var_string_map_root, l);
//        wzvar * var_string_map = wz_open_var(var_string_maps, map_id);
//        if (var_string_map == NULL) continue;
//        found_var_string_map = var_string_map;
//        break;
//      }
//      const char * map_name;
//      const char * street_name;
//      if (found_var_string_map == NULL) {
//        map_name = "(nil)";
//        street_name = "(nil)";
//      } else {
//        wzvar * var_string_map = found_var_string_map;
//        wzvar * var_map_name = wz_open_var(var_string_map, "mapName");
//        wzvar * var_street_name = wz_open_var(var_string_map, "streetName");
//        map_name = wz_get_str(var_map_name);
//        street_name = wz_get_str(var_street_name);
//      }
//      printf("%s  %s  %s: %s%s\n",
//             life_type, map_id, street_name, map_name, only);
//    }
//  }
//  ret = 0;
//cleanup_file_string:     wz_close_file(&file_string);
//cleanup_file_map:        wz_close_file(&file_map);
//cleanup_ctx:             wz_free_ctx(&ctx);
//cleanup_filename_string: free(filename_string);
//cleanup_filename_map:    free(filename_map);
//  return ret;
//}
//
//int
//cmd_mob_exp(int argc, char ** argv) {
//  // wz mob-exp <DIR>
//  // read highest exp's mob
//  int ret = 1;
//  if (argc != 3) return ret;
//  int32_t minhp;
//  if (sscanf(argv[2], "%"PRId32, &minhp) != 1) return ret;
//  char * filename_mob;
//  char * filename_string;
//  if ((filename_mob = path_of_file("Mob.wz")) == NULL) return ret;
//  if ((filename_string = path_of_file("String.wz")) == NULL)
//    goto cleanup_filename_mob;
//  wzctx ctx;
//  if (wz_init_ctx(&ctx)) goto cleanup_filename_string;
//  wzfile file_mob;
//  wzfile file_string;
//  if (wz_open_file(&file_mob, filename_mob, &ctx))
//    goto cleanup_ctx;
//  if (wz_open_file(&file_string, filename_string, &ctx))
//    goto cleanup_file_mob;
//  wznode * node_string_root = wz_open_root_node(&file_string);
//  wznode * node_string_mob = wz_open_node(node_string_root, "Mob.img");
//  wzvar * var_string_mob_root = wz_open_root_var(node_string_mob);
//  wznode * node_mob_root = wz_open_root_node(&file_mob);
//  for (uint32_t i = 0, il = wz_get_nodes_len(node_mob_root); i < il; i++) {
//    wznode * node_mob = wz_open_node_at(node_mob_root, i);
//    wzvar * var_mob_root = wz_open_root_var(node_mob);
//    wzvar * var_mob_info = wz_open_var(var_mob_root, "info");
//    wzvar * var_mob_maxhp = wz_open_var(var_mob_info, "maxHP");
//    wzvar * var_mob_exp = wz_open_var(var_mob_info, "exp");
//    if (var_mob_exp == NULL) continue;
//    int32_t maxhp = (int32_t) wz_get_int(var_mob_maxhp);
//    int32_t exp = (int32_t) wz_get_int(var_mob_exp);
//    if (maxhp < minhp) continue;
//    if (!exp) continue;
//    const char * mob_img = wz_get_node_name(node_mob);
//    char mob_id[7 + 1];
//    if (sscanf(mob_img, "%[^.]", mob_id) != 1)
//      goto cleanup_file_string;
//    wzvar * var_string_mob = wz_open_var(var_string_mob_root, mob_id);
//    const char * mob_name = "(nil)";
//    if (var_string_mob != NULL) {
//      wzvar * var_string_mob_name = wz_open_var(var_string_mob, "name");
//      mob_name = wz_get_str(var_string_mob_name);
//    }
//    printf("%s  %7d  %10d  %-s\n", mob_id, maxhp / exp, maxhp, mob_name);
//  }
//  ret = 0;
//cleanup_file_string:     wz_close_file(&file_string);
//cleanup_file_mob:        wz_close_file(&file_mob);
//cleanup_ctx:             wz_free_ctx(&ctx);
//cleanup_filename_string: free(filename_string);
//cleanup_filename_mob:    free(filename_mob);
//  return ret;
//}

int
cmd_ls(int argc, char ** argv) {
  int ret = 1;
  if (argc < 3)
    return ret;
  const char * filename = argv[2];
  const char * nodepath = argc >= 4 ? argv[3] : "";
  const char * savename = argc >= 5 ? argv[4] : NULL;
  wzctx ctx;
  if (wz_init_ctx(&ctx))
    return ret;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx))
    goto free_ctx;
  wznode * node_root;
  if ((node_root = wz_open_root(&file)) == NULL) {
    fprintf(stderr, "Error: Unable to open the root node\n");
    goto close_file;
  }
  wznode * node;
  if ((node = wz_open_node(node_root, nodepath)) == NULL) {
    fprintf(stderr, "Error: Unable to open the node: %s\n", nodepath);
    goto close_file;
  }
  if ((node->n.info & WZ_TYPE) == WZ_ARY) {
    wzary * ary = node->n.val.ary;
    for (uint32_t i = 0; i < ary->len; i++) {
      printf("%s\n", wz_get_name(ary->nodes + i));
    }
  } else if ((node->n.info & WZ_TYPE) == WZ_IMG) {
    wzimg * img = node->n.val.img;
    if (savename == NULL) {
      const char * depth;
      switch (img->depth) {
      case WZ_COLOR_8888: depth = "8888"; break;
      case WZ_COLOR_4444: depth = "4444"; break;
      case WZ_COLOR_565:  depth = "565";  break;
      case WZ_COLOR_DXT3: depth = "dxt3"; break;
      case WZ_COLOR_DXT5: depth = "dxt5"; break;
      default:            depth = "unk";  break;
      }
      uint8_t scale;
      switch (img->scale) {
      case 0:  scale =  1; break; // pow(2, 0) == 1
      case 4:  scale = 16; break; // pow(2, 4) == 16
      default: scale =  0; break;
      }
      printf("(image: %u %u %s/%hhu)\n", img->w, img->h, depth, scale);
      for (uint32_t i = 0; i < img->len; i++) {
        printf("%s\n", wz_get_name(img->nodes + i));
      }
    } else {
      int err = 1;
      FILE * savefile;
      if ((savefile = fopen(savename, "w")) == NULL) {
        perror(savename);
        goto close_file;
      }
      if (fwrite(img->data, img->w * img->h * 4, 1, savefile) != 1) {
        perror(savename);
        goto close_savefile;
      }
      err = 0;
close_savefile:
      fclose(savefile);
      if (err)
        goto close_file;
    }
  } else if ((node->n.info & WZ_TYPE) == WZ_AO) {
    wzao * ao = node->n.val.ao;
    if (savename == NULL) {
      const char * format;
      switch (ao->format) {
      case WZ_AUDIO_PCM: format = "pcm"; break;
      case WZ_AUDIO_MP3: format = "mp3"; break;
      default:           format = "unk"; break;
      }
      printf("(audio: %02u:%02u.%03u %uB %s)\n",
             ao->ms / 60000,
             ao->ms / 1000 % 60,
             ao->ms % 1000,
             ao->size, format);
    } else {
      int err = 1;
      FILE * savefile;
      if ((savefile = fopen(savename, "w")) == NULL) {
        perror(savename);
        goto close_file;
      }
      if (fwrite(ao->data, ao->size, 1, savefile) != 1) {
        perror(savename);
        goto close_savefile_;
      }
      err = 0;
close_savefile_:
      fclose(savefile);
      if (err)
        goto close_file;
    }
  } else if ((node->n.info & WZ_TYPE) == WZ_VEX) {
    printf("(vex)\n");
  } else if ((node->n.info & WZ_TYPE) == WZ_VEC) {
    printf("(vec)\n");
  } else if ((node->n.info & WZ_TYPE) == WZ_UOL) {
    printf("(uol)\n");
  } else if ((node->n.info & WZ_TYPE) == WZ_STR) {
    printf("(str: %s)\n", node->n.val.str->bytes);
  } else if ((node->n.info & WZ_TYPE) == WZ_I16 ||
             (node->n.info & WZ_TYPE) == WZ_I32 ||
             (node->n.info & WZ_TYPE) == WZ_I64 ||
             (node->n.info & WZ_TYPE) == WZ_F32 ||
             (node->n.info & WZ_TYPE) == WZ_F64) {
    printf("(number)\n");
  } else if ((node->n.info & WZ_TYPE) == WZ_NIL) {
    printf("(nil)\n");
  }
  ret = 0;
close_file:
  wz_close_file(&file);
free_ctx:
  wz_free_ctx(&ctx);
  return ret;
}

int
main(int argc, char ** argv) {
  const char * cmd;
  if (argc >= 2) cmd = argv[1];
  else           cmd = "";
  typedef struct {
    const char * name;
    int (* call)(int, char **);
  } cmd_func;
  cmd_func funcs[] = {
    {"help",          cmd_help},
    {"all",           cmd_all},
    //{"map",           cmd_map},
    //{"map-helper",    cmd_map_helper},
    //{"char",          cmd_char},
    //{"char-imgs",     cmd_char_imgs},
    //{"skill-img",     cmd_skill_img},
    //{"scrolls",       cmd_scrolls},
    //{"mobs",          cmd_mobs},
    //{"thief-shields", cmd_thief_shields},
    //{"life-maps",     cmd_life_maps},
    //{"mob-exp",       cmd_mob_exp},
    {"ls",            cmd_ls}
  };
  for (size_t i = 0, len = sizeof(funcs) / sizeof(funcs[0]); i < len; i++)
    if (!strcmp(funcs[i].name, cmd)) return funcs[i].call(argc, argv);
  return 1;
}
