#include <inttypes.h>
#include "file.h"

int
main(int argc, char ** argv) {
  if (argc == 1) {
    printf("wz version 0.0.1\n"
           "Copyright (C) 2016 Lien Chiang\n"
           "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
           "This is free software: you are free to change and redistribute it.\n"
           "There is NO WARRANTY, to the extent permitted by law.\n"
           "\n"
           "Written by Lien Chiang.\n");
  } else if (argc == 2) {
    wzctx ctx;
    if (wz_init_ctx(&ctx)) return 1;
    wzfile file;
    if (wz_open_file(&file, argv[1], &ctx))
      return wz_free_ctx(&ctx), 1;
    if (!wz_read_node_r(&file.root, &file, &ctx))
      printf("all read !\n");
    wz_close_file(&file);
    wz_free_ctx(&ctx);
  } else if (argc == 3) {
    wzctx ctx;
    if (wz_init_ctx(&ctx)) return 1;
    wzfile file;
    if (wz_open_file(&file, "../Map.wz", &ctx))
      return wz_free_ctx(&ctx), 1;
    wznode * root = wz_open_root_node(&file);
    uint32_t len = wz_get_nodes_len(root);
    for (uint32_t i = 0; i < len; i++) {
      wznode * node = wz_open_node_at(root, i);
      printf(" %s\n", wz_get_node_name(node));
      if (WZ_IS_NODE_FILE(node->type)) continue;
      uint32_t node_len = wz_get_nodes_len(node);
      for (uint32_t j = 0; j < node_len; j++) {
        wznode * child = wz_open_node_at(node, j);
        printf("  %s\n", wz_get_node_name(child));
      }
    }
    wz_close_node(root);
    wz_close_file(&file);
    wz_free_ctx(&ctx);
  } else if (argc == 4) {
    wzctx ctx;
    if (wz_init_ctx(&ctx)) return 1;
    wzfile file;
    if (wz_open_file(&file, "../Map.wz", &ctx))
      return wz_free_ctx(&ctx), 1;
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
    wz_close_var(root_var);
    wz_close_node(root_node);
    wz_close_file(&file);
    wz_free_ctx(&ctx);
  } else if (argc == 5) {
    wzctx ctx;
    if (wz_init_ctx(&ctx)) return 1;
    wzfile file;
    if (wz_open_file(&file, "../Character.wz", &ctx))
      return wz_free_ctx(&ctx), 1;
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
    wz_close_file(&file);
    wz_free_ctx(&ctx);
  }
  return 0;
}
