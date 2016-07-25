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
  return 0;
}

int
cmd_all(int argc, char ** argv) {
  // wz all <FILE>
  // read all nodes
  int ret = 1;
  if (argc != 3) return ret;
  const char * filename;
  if ((filename = path_of_file(argv[2])) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) return ret;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  if (wz_read_node_r(&file.root, &file, &ctx)) goto cleanup_file;
  printf("all read !\n");
  ret = 0;
cleanup_file: wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
  return ret;
}

int
cmd_map(int argc, char ** argv) {
  // wz map
  // read 2 levels nodes of Map.wz
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("Map.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * root = wz_open_root_node(&file);
  uint32_t len = wz_get_nodes_len(root);
  for (uint32_t i = 0; i < len; i++) {
    wznode * node = wz_open_node_at(root, i);
    printf(" %s\n", wz_get_node_name(node));
    if (node->type != WZ_NODE_DIR) continue;
    uint32_t node_len = wz_get_nodes_len(node);
    for (uint32_t j = 0; j < node_len; j++) {
      wznode * child = wz_open_node_at(node, j);
      printf("  %s\n", wz_get_node_name(child));
    }
  }
  ret = 0;
  wz_close_node(root);
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_map_helper(int argc, char ** argv) {
  // wz map-helper <DIR>
  // read 2 levels nodes in MapHelper.img of Map.wz
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("Map.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * root_node = wz_open_root_node(&file);
  wznode * node = wz_open_node(root_node, "MapHelper.img");
  wzvar * root_var = wz_open_root_var(node);
  uint32_t len = wz_get_vars_len(root_var);
  for (uint32_t i = 0; i < len; i++) {
    wzvar * var = wz_open_var_at(root_var, i);
    printf(" %s\n", wz_get_var_name(var));
    uint32_t var_len = wz_get_vars_len(var);
    for (uint32_t j = 0; j < var_len; j++) {
      wzvar * child = wz_open_var_at(var, j);
      printf("  %s\n", wz_get_var_name(child));
    }
  }
  ret = 0;
  wz_close_var(root_var);
  wz_close_node(root_node);
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_char(int argc, char ** argv) {
  // wz char <DIR>
  // read character's action
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("Character.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * root_node = wz_open_root_node(&file);
  wznode * node = wz_open_node(root_node, "00002001.img");
  wzvar * root_var = wz_open_root_var(node);
  wzvar * var_prone = wz_open_var(root_var, "prone/0");
  wzvar * var_face = wz_open_var(var_prone, "face");
  wzvar * var_delay = wz_open_var(var_prone, "delay");
  wzvar * var_arm = wz_open_var(var_prone, "arm");
  int64_t face = wz_get_int(var_face);
  int64_t delay = wz_get_int(var_delay);
  wzimg * arm = wz_get_img(var_arm);
  printf("face: %"PRId64"\n"
         "delay: %"PRId64"\n"
         "arm: %"PRIu32" %"PRIu32"\n",
         face, delay, arm->w, arm->h);
  ret = 0;
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_char_imgs(int argc, char ** argv) {
  // wz char-imgs <DIR>
  // read character's imgs
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("Character.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * root_node = wz_open_root_node(&file);
  wznode * node = wz_open_node(root_node, "Hair/00030020.img");
  wzvar * root_var = wz_open_root_var(node);
  uint32_t len = wz_get_vars_len(root_var);
  for (uint32_t i = 0; i < len; i++) {
    int show = 0;
    wzvar * var = wz_open_var_at(root_var, i);
    uint32_t var_len = wz_get_vars_len(var);
    for (uint32_t j = 0; j < var_len; j++) {
      wzvar * child = wz_open_var_at(var, j);
      uint32_t var_len2 = wz_get_vars_len(child);
      for (uint32_t k = 0; k < var_len2; k++) {
        wzvar * child2 = wz_open_var_at(child, k);
        if (strcmp(wz_get_var_name(child2), "hair") &&
            strcmp(wz_get_var_name(child2), "hairOverHead") &&
            strcmp(wz_get_var_name(child2), "hairBelowBody") &&
            strcmp(wz_get_var_name(child2), "hairShade") &&
            strcmp(wz_get_var_name(child2), "backHair") &&
            strcmp(wz_get_var_name(child2), "backHairBelowCap")) {
          show = 1;
        }
      }
    }
    if (show) printf("%s\n", wz_get_var_name(var));
    for (uint32_t j = 0; j < var_len; j++) {
      int show2 = 0;
      wzvar * child = wz_open_var_at(var, j);
      uint32_t var_len2 = wz_get_vars_len(child);
      for (uint32_t k = 0; k < var_len2; k++) {
        wzvar * child2 = wz_open_var_at(child, k);
        if (strcmp(wz_get_var_name(child2), "hair") &&
            strcmp(wz_get_var_name(child2), "hairOverHead") &&
            strcmp(wz_get_var_name(child2), "hairBelowBody") &&
            strcmp(wz_get_var_name(child2), "hairShade") &&
            strcmp(wz_get_var_name(child2), "backHair") &&
            strcmp(wz_get_var_name(child2), "backHairBelowCap")) {
          show2 = 1;
        }
      }
      if (show2) printf(" %s\n", wz_get_var_name(child));
      for (uint32_t k = 0; k < var_len2; k++) {
        wzvar * child2 = wz_open_var_at(child, k);
        if (show2) printf("  %s\n", wz_get_var_name(child2));
      }
    }
  }
  ret = 0;
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_skill_img(int argc, char ** argv) {
  // wz skill-img <DIR>
  // read skill's effect image
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("Skill.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * node_root = wz_open_root_node(&file);
  wznode * node = wz_open_node(node_root, "422.img");
  wzvar * var_root = wz_open_root_var(node);
  wzvar * var = wz_open_var(var_root, "skill/4221010/effect/0");
  wzimg * img = wz_get_img(var);
  static int id = 0;
  char data_filename[100];
  snprintf(data_filename, sizeof(data_filename),
           "out/%d-%"PRIu32"-%"PRIu32".data", id++, img->w, img->h);
  FILE * data_file = fopen(data_filename, "wb");
  fwrite(img->data, 1, img->w * img->h * 4, data_file);
  fclose(data_file);
  ret = 0;
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_scrolls(int argc, char ** argv) {
  // wz scrolls <DIR>
  // read all scrolls
  (void) argc; (void) argv;
  int ret = 1;
  char * filename;
  if ((filename = path_of_file("String.wz")) == NULL) return ret;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename;
  wzfile file;
  if (wz_open_file(&file, filename, &ctx)) goto cleanup_ctx;
  wznode * node_root = wz_open_root_node(&file);
  wznode * node = wz_open_node(node_root, "Consume.img");
  wzvar * var_root = wz_open_root_var(node);
  for (uint32_t i = 0, len = wz_get_vars_len(var_root); i < len; i++) {
    wzvar * var = wz_open_var_at(var_root, i);
    const char * id = wz_get_var_name(var);
    if (strncmp(id, "204", 3)) continue;
    wzvar * var_name = wz_open_var(var, "name");
    const char * name = wz_get_str(var_name);
    printf("%s %s\n", id, name);
  }
  ret = 0;
  wz_close_file(&file);
cleanup_ctx: wz_free_ctx(&ctx);
cleanup_filename: free(filename);
  return ret;
}

int
cmd_mobs(int argc, char ** argv) {
  // wz mobs <DIR>
  // read mob info
  (void) argc; (void) argv;
  int ret = 1;
  char * filename_mob;
  char * filename_string;
  if ((filename_mob = path_of_file("Mob.wz")) == NULL) return ret;
  if ((filename_string = path_of_file("String.wz")) == NULL)
    goto cleanup_filename_mob;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename_string;
  wzfile file_mob;
  wzfile file_string;
  if (wz_open_file(&file_mob, filename_mob, &ctx)) goto cleanup_ctx;
  if (wz_open_file(&file_string, filename_string, &ctx)) goto cleanup_file_mob;
  wznode * node_mob_root = wz_open_root_node(&file_mob);
  wznode * node_string_root = wz_open_root_node(&file_string);
  wznode * node_string_mob = wz_open_node(node_string_root, "Mob.img");
  wzvar * var_string_mob_root = wz_open_root_var(node_string_mob);
  char db_id[5 + 1];
  char mob_id[7 + 1];
  char item_id[7 + 1];
  char drop_rate[6 + 1];
  int times = 0;
  while (scanf("%[^,],%[^,],%[^,],%[^\x0d]\n",
               db_id, mob_id, item_id, drop_rate) == 4) {
    if (!times) {
      printf("%7s %-23s %3s %10s %7s %6s\n",
             "id", "name", "lv", "hp", "mp", "drop");
      times = 1;
    }
    char mob_img[7 + 4 + 1];
    int ret_snprintf;
    if ((ret_snprintf = snprintf(mob_img, sizeof(mob_img), "%7s.img",
                                 mob_id)) >= (int) sizeof(mob_img) ||
        ret_snprintf < 0) goto cleanup_file_string;
    for (size_t i = 0; mob_img[i] == ' '; i++) mob_img[i] = '0';
    wznode * node_mob = wz_open_node(node_mob_root, mob_img);
    wzvar * var_mob_root = wz_open_root_var(node_mob);
    wzvar * var_mob_info = wz_open_var(var_mob_root, "info");
    wzvar * var_mob_level = wz_open_var(var_mob_info, "level");
    wzvar * var_mob_hp = wz_open_var(var_mob_info, "maxHP");
    wzvar * var_mob_mp = wz_open_var(var_mob_info, "maxMP");
    wzvar * var_mob_boss = wz_open_var(var_mob_info, "boss");
    uint32_t mob_level = (uint32_t) wz_get_int(var_mob_level);
    uint32_t mob_hp = (uint32_t) wz_get_int(var_mob_hp);
    uint32_t mob_mp = (uint32_t) wz_get_int(var_mob_mp);
    wzvar * var_string_mob = wz_open_var(var_string_mob_root, mob_id);
    wzvar * var_string_mob_name = wz_open_var(var_string_mob, "name");
    const char * mob_name = wz_get_str(var_string_mob_name);
    printf("%7s %-23s %3"PRIu32" %10"PRIu32" %7"PRIu32" %6s",
           mob_id, mob_name, mob_level, mob_hp, mob_mp, drop_rate);
    if (var_mob_boss != NULL && wz_get_int(var_mob_boss) > 0)
      printf(" boss");
    printf("\n");
  }
  ret = 0;
cleanup_file_string:     wz_close_file(&file_string);
cleanup_file_mob:        wz_close_file(&file_mob);
cleanup_ctx:             wz_free_ctx(&ctx);
cleanup_filename_string: free(filename_string);
cleanup_filename_mob:    free(filename_mob);
  return ret;
}

int
cmd_thief_shields(int argc, char ** argv) {
  // wz thief-shields <DIR>
  // read common and thief shields
  (void) argc; (void) argv;
  int ret = 1;
  char * filename_string;
  char * filename_char;
  if ((filename_string = path_of_file("String.wz")) == NULL) return ret;
  if ((filename_char = path_of_file("Character.wz")) == NULL)
    goto cleanup_filename_string;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename_char;
  wzfile file_string;
  wzfile file_char;
  if (wz_open_file(&file_string, filename_string, &ctx))
    goto cleanup_ctx;
  if (wz_open_file(&file_char, filename_char, &ctx))
    goto cleanup_file_string;
  wznode * node_char_root = wz_open_root_node(&file_char);
  wznode * node_char_shields = wz_open_node(node_char_root, "Shield");
  wznode * node_string_root = wz_open_root_node(&file_string);
  wznode * node_string_eqp = wz_open_node(node_string_root, "Eqp.img");
  wzvar * var_eqp_root = wz_open_root_var(node_string_eqp);
  wzvar * var_eqp_shields = wz_open_var(var_eqp_root, "Eqp/Shield");
  for (uint32_t i = 0, len = wz_get_vars_len(var_eqp_shields); i < len; i++) {
    wzvar * var_eqp_shield = wz_open_var_at(var_eqp_shields, i);
    wzvar * var_eqp_shield_name = wz_open_var(var_eqp_shield, "name");
    const char * eqp_shield_name = wz_get_str(var_eqp_shield_name);
    const char * shield_id = wz_get_var_name(var_eqp_shield);
    char shield_img[8 + 4 + 1];
    int ret_snprintf;
    if ((ret_snprintf = snprintf(shield_img, sizeof(shield_img), "%8s.img",
                                 shield_id)) >= (int) sizeof(shield_img) ||
        ret_snprintf < 0)
      goto cleanup_file_char;
    for (size_t j = 0; shield_img[j] == ' '; j++) shield_img[j] = '0';
    wznode * node_char_shield = wz_open_node(node_char_shields, shield_img);
    wzvar * var_shield_root = wz_open_root_var(node_char_shield);
    wzvar * var_shield_info = wz_open_var(var_shield_root, "info");
    wzvar * var_shield_req_level = wz_open_var(var_shield_info, "reqLevel");
    wzvar * var_shield_req_job = wz_open_var(var_shield_info, "reqJob");
    if (wz_get_int(var_shield_req_job) &&
        wz_get_int(var_shield_req_job) != 8) continue;
    uint32_t req_level = (uint32_t) wz_get_int(var_shield_req_level);
    printf("%s %24s %3"PRIu32,
           shield_id, eqp_shield_name, req_level);
    uint32_t attrs_len = wz_get_vars_len(var_shield_info);
    for (uint32_t j = 0; j < attrs_len; j++) {
      wzvar * var_shield_attr = wz_open_var_at(var_shield_info, j);
      const char * shield_attr_name = wz_get_var_name(var_shield_attr);
      if (strcmp(shield_attr_name, "incPDD")) continue;
      uint32_t shield_attr_value = (uint32_t) wz_get_int(var_shield_attr);
      printf(" %s %3"PRIu32, shield_attr_name + 3, shield_attr_value);
    }
    for (uint32_t j = 0; j < attrs_len; j++) {
      wzvar * var_shield_attr = wz_open_var_at(var_shield_info, j);
      const char * shield_attr_name = wz_get_var_name(var_shield_attr);
      if (strncmp(shield_attr_name, "inc", 3)) continue;
      if (!strcmp(shield_attr_name, "incPDD")) continue;
      uint32_t shield_attr_value = (uint32_t) wz_get_int(var_shield_attr);
      printf(" %s %2"PRIu32, shield_attr_name + 3, shield_attr_value);
    }
    printf("\n");
  }
  ret = 0;
cleanup_file_char:       wz_close_file(&file_char);
cleanup_file_string:     wz_close_file(&file_string);
cleanup_ctx:             wz_free_ctx(&ctx);
cleanup_filename_char:   free(filename_char);
cleanup_filename_string: free(filename_string);
  return ret;
}

int
cmd_life_maps(int argc, char ** argv) {
  // wz life-maps <DIR>
  // read life located maps
  int ret = 1;
  if (argc != 3) return ret;
  const char * life_id = argv[2];
  char * filename_map;
  char * filename_string;
  if ((filename_map = path_of_file("Map.wz")) == NULL) return ret;
  if ((filename_string = path_of_file("String.wz")) == NULL)
    goto cleanup_filename_map;
  wzctx ctx;
  if (wz_init_ctx(&ctx)) goto cleanup_filename_string;
  wzfile file_map;
  wzfile file_string;
  if (wz_open_file(&file_map, filename_map, &ctx))
    goto cleanup_ctx;
  if (wz_open_file(&file_string, filename_string, &ctx))
    goto cleanup_file_map;
  wznode * node_string_root = wz_open_root_node(&file_string);
  wznode * node_string_map = wz_open_node(node_string_root, "Map.img");
  wzvar * var_string_map_root = wz_open_root_var(node_string_map);
  wznode * node_map_root = wz_open_root_node(&file_map);
  wznode * node_map_grps = wz_open_node(node_map_root, "Map");
  for (uint32_t i = 0, il = wz_get_nodes_len(node_map_grps); i < il; i++) {
    wznode * node_maps = wz_open_node_at(node_map_grps, i);
    for (uint32_t j = 0, jl = wz_get_nodes_len(node_maps); j < jl; j++) {
      wznode * node_map = wz_open_node_at(node_maps, j);
      wzvar * var_map_root = wz_open_root_var(node_map);
      wzvar * var_map_lifes = wz_open_var(var_map_root, "life");
      if (var_map_lifes == NULL) continue;
      const char * only = "*";
      for (uint32_t k = 0, kl = wz_get_vars_len(var_map_lifes); k < kl; k++) {
        wzvar * var_map_life = wz_open_var_at(var_map_lifes, k);
        wzvar * var_map_life_type = wz_open_var(var_map_life, "type");
        const char * map_life_type = wz_get_str(var_map_life_type);
        if (strcmp(map_life_type, "m")) continue;
        wzvar * var_map_life_id = wz_open_var(var_map_life, "id");
        const char * map_life_id = wz_get_str(var_map_life_id);
        if (strcmp(map_life_id, life_id)) { only = ""; break; }
      }
      for (uint32_t k = 0, kl = wz_get_vars_len(var_map_lifes); k < kl; k++) {
        wzvar * var_map_life = wz_open_var_at(var_map_lifes, k);
        wzvar * var_map_life_id = wz_open_var(var_map_life, "id");
        const char * map_life_id = wz_get_str(var_map_life_id);
        if (strcmp(map_life_id, life_id)) continue;
        const char * node_map_name = wz_get_node_name(node_map);
        char map_id[9 + 1];
        if (sscanf(node_map_name, "%[^.]", map_id) != 1)
          goto cleanup_file_string;
        int brk;
        uint32_t ll = wz_get_vars_len(var_string_map_root);
        for (uint32_t l = 0; l < ll; l++) {
          wzvar * var_string_maps = wz_open_var_at(var_string_map_root, l);
          wzvar * var_string_map = wz_open_var(var_string_maps, map_id);
          if (var_string_map == NULL) continue;
          wzvar * var_map_name = wz_open_var(var_string_map, "mapName");
          wzvar * var_street_name = wz_open_var(var_string_map, "streetName");
          const char * map_name = wz_get_str(var_map_name);
          const char * street_name = wz_get_str(var_street_name);
          wzvar * var_map_life_type = wz_open_var(var_map_life, "type");
          const char * map_life_type = wz_get_str(var_map_life_type);
          const char * life_type;
          if (!strcmp(map_life_type, "n")) life_type = "npc";
          else if (!strcmp(map_life_type, "m")) life_type = "mob";
          else life_type = "???";
          printf("%s  %s  %s: %s%s\n",
                 life_type, map_id, street_name, map_name, only);
          brk = 1;
        }
        if (brk) break;
      }
    }
  }
  ret = 0;
cleanup_file_string:     wz_close_file(&file_string);
cleanup_file_map:        wz_close_file(&file_map);
cleanup_ctx:             wz_free_ctx(&ctx);
cleanup_filename_string: free(filename_string);
cleanup_filename_map:    free(filename_map);
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
    {"map",           cmd_map},
    {"map-helper",    cmd_map_helper},
    {"char",          cmd_char},
    {"char-imgs",     cmd_char_imgs},
    {"skill-img",     cmd_skill_img},
    {"scrolls",       cmd_scrolls},
    {"mobs",          cmd_mobs},
    {"thief-shields", cmd_thief_shields},
    {"life-maps",     cmd_life_maps}
  };
  for (size_t i = 0, len = sizeof(funcs) / sizeof(funcs[0]); i < len; i++)
    if (!strcmp(funcs[i].name, cmd)) return funcs[i].call(argc, argv);
  return 1;
}
