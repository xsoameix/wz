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
    wzfile file;
    if (wz_open_file(&file, argv[1]) ||
        wz_close_file(&file)) return 1;
  }
  return 0;
}
