#include "predef.h"

#ifdef WZ_MSVC
#  pragma warning(push, 3)
#endif

#if defined(WZ_WINDOWS)
#  include <Windows.h>
#elif defined(WZ_MACOS)
#  include <mach/mach_time.h>
#else
#  include <time.h>
#endif
#include <stdio.h>
#include <string.h>

#ifdef WZ_MSVC
#  pragma warning(pop)
#endif

#include "wz.h"
#include "type.h"

static int cmd_version(int argc, char ** argv);
static int cmd_help(int argc, char ** argv);
static int cmd_ls(int argc, char ** argv);
static int cmd_time(int argc, char ** argv);

typedef struct {
  const char * name;
  int (* func)(int, char **);
} wzcmd;

static const wzcmd wz_cmds[] = {
  {"-v",        cmd_version},
  {"--version", cmd_version},
  {"-h",        cmd_help},
  {"--help",    cmd_help},
  {"help",      cmd_help},
  {"ls",        cmd_ls},
  {"time",      cmd_time}
};

static int
cmd_version(int argc, char ** argv) {
  /* wz -v */
  /* wz --version */
  (void) argc;
  (void) argv;
  printf("wz version 1.0.0\n"
         "Copyright (C) 2016 Lien Chiang\n"
         "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
         "This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n"
         "\n"
         "Written by Lien Chiang.\n");
  return 0;
}

static int
cmd_help(int argc, char ** argv) {
  /* wz -h     [<command>] */
  /* wz --help [<command>] */
  /* wz help   [<command>] */
  int (* func)(int, char **) = NULL;
  if (argc > 2) {
    const char * cmd = argv[2];
    size_t len = sizeof(wz_cmds) / sizeof(* wz_cmds);
    size_t i;
    for (i = 0; i < len; i++)
      if (!strcmp(wz_cmds[i].name, cmd)) {
        func = wz_cmds[i].func;
        break;
      }
    if (func == NULL ||
        func == cmd_version ||
        func == cmd_help) {
      fprintf(stderr,
              "wz: '%s' is not a wz command.\n"
              "See 'wz --help'.\n", cmd);
      return 1;
    }
  }
  if (func == NULL)
    printf("usage: wz <command> [<args>]\n"
           "       wz [-v | --version | -h | --help]\n"
           "\n"
           "The available command are:\n"
           "    ls     Show the contents in wz file with given path\n"
           "    time   Parse the wz file and timing it\n"
           "\n"
           "See 'wz help <command>' to read about a specific subcommand.\n");
  else if (func == cmd_ls)
    printf("usage: wz ls <file> [<path>]\n"
           "\n"
           "Show the contents of given path in the wz file.\n");
  else if (func == cmd_time)
    printf("usage: wz time <file> [<file>...]\n"
           "\n"
           "Timing of parsing wz file(s).\n");
  return 0;
}

static int
cmd_ls(int argc, char ** argv) {
  /* wz ls <file> [<path>] */
  /* show the contents of given path in the wz file */
  int ret = 1;
  const char * filename;
  const char * nodepath;
  const char * savename;
  wzctx * ctx;
  wzfile * file;
  wznode * node_root;
  wznode * node;
  if (argc < 3) {
    fprintf(stderr,
            "wz: missing file operand.\n"
            "See 'wz help ls'.\n");
    return ret;
  }
  filename = argv[2];
  nodepath = argc >= 4 ? argv[3] : "";
  savename = argc >= 5 ? argv[4] : NULL;
  if ((ctx = wz_init_ctx()) == NULL)
    return ret;
  if ((file = wz_open_file(filename, ctx)) == NULL)
    goto free_ctx;
  if ((node_root = wz_open_root(file)) == NULL) {
    fprintf(stderr, "Error: Unable to open the root node\n");
    goto close_file;
  }
  if ((node = wz_open_node(node_root, nodepath)) == NULL) {
    fprintf(stderr, "Error: Unable to open the node: %s\n", nodepath);
    goto close_file;
  }
  switch (wz_get_type(node)) {
  case WZ_ARY: {
    wz_uint32_t len;
    wz_uint32_t i;
    (void) wz_get_len(&len, node);
    for (i = 0; i < len; i++) {
      printf("%s\n", wz_get_name(wz_open_node_at(node, i)));
    }
    break;
  }
  case WZ_IMG: {
    wz_uint32_t w;
    wz_uint32_t h;
    wz_uint16_t depth;
    wz_uint8_t scale;
    wz_uint8_t * data = wz_get_img(&w, &h, &depth, &scale, node);
    if (savename == NULL) {
      wz_uint32_t len;
      wz_uint32_t i;
      const char * depth_name;
      switch (depth) {
      case WZ_COLOR_8888: depth_name = "8888"; break;
      case WZ_COLOR_4444: depth_name = "4444"; break;
      case WZ_COLOR_565:  depth_name = "565";  break;
      case WZ_COLOR_DXT3: depth_name = "dxt3"; break;
      case WZ_COLOR_DXT5: depth_name = "dxt5"; break;
      default:            depth_name = "unk";  break;
      }
      switch (scale) {
      case 0:  scale =  1; break; /* pow(2, 0) == 1 */
      case 4:  scale = 16; break; /* pow(2, 4) == 16 */
      default: scale =  0; break;
      }
      printf("(image: %"WZ_PRIu32" %"WZ_PRIu32" %s/%"WZ_PRIu32")\n",
             w, h, depth_name, (wz_uint32_t) scale);
      (void) wz_get_len(&len, node);
      for (i = 0; i < len; i++) {
        printf("%s\n", wz_get_name(wz_open_node_at(node, i)));
      }
    } else {
      int err = 1;
      FILE * savefile;
      if ((savefile = fopen(savename, "w")) == NULL) {
        perror(savename);
        goto close_file;
      }
      if (fwrite(data, w * h * 4, 1, savefile) != 1) {
        perror(savename);
        goto close_savefile;
      }
      err = 0;
close_savefile:
      fclose(savefile);
      if (err)
        goto close_file;
    }
    break;
  }
  case WZ_AO: {
    wz_uint32_t size;
    wz_uint32_t ms;
    wz_uint16_t format;
    wz_uint8_t * data = wz_get_ao(&size, &ms, &format, node);
    if (savename == NULL) {
      const char * format_name;
      switch (format) {
      case WZ_AUDIO_PCM: format_name = "pcm"; break;
      case WZ_AUDIO_MP3: format_name = "mp3"; break;
      default:           format_name = "unk"; break;
      }
      printf("(audio: %02"WZ_PRIu32":%02"WZ_PRIu32".%03"WZ_PRIu32" "
             "%"WZ_PRIu32"B %s)\n",
             ms / 60000,
             ms / 1000 % 60,
             ms % 1000,
             size, format_name);
    } else {
      int err = 1;
      FILE * savefile;
      if ((savefile = fopen(savename, "w")) == NULL) {
        perror(savename);
        goto close_file;
      }
      if (fwrite(data, size, 1, savefile) != 1) {
        perror(savename);
        goto close_savefile_;
      }
      err = 0;
close_savefile_:
      fclose(savefile);
      if (err)
        goto close_file;
    }
    break;
  }
  case WZ_VEX: {
    wz_uint32_t len;
    wz_uint32_t i;
    (void) wz_get_vex_len(&len, node);
    printf("(vex: ");
    for (i = 0; i < len; i++) {
      wz_int32_t x;
      wz_int32_t y;
      (void) wz_get_vex_at(&x, &y, i, node);
      printf("%"WZ_PRId32" %"WZ_PRId32, x, y);
      if (i < len - 1)
        printf(", ");
    }
    printf(")\n");
    break;
  }
  case WZ_VEC: {
    wz_int32_t x;
    wz_int32_t y;
    (void) wz_get_vec(&x, &y, node);
    printf("(vec: %"WZ_PRId32" %"WZ_PRId32")\n", x, y);
    break;
  }
  case WZ_STR:
    printf("(str: %s)\n", wz_get_str(node));
    break;
  case WZ_I16: {
    wz_int32_t val;
    (void) wz_get_int(&val, node);
    printf("(i16: %"WZ_PRId32")\n", (wz_int32_t) val);
    break;
  }
  case WZ_I32: {
    wz_int32_t val;
    (void) wz_get_int(&val, node);
    printf("(i32: %"WZ_PRId32")\n", val);
    break;
  }
  case WZ_I64: {
    wz_int64_t val;
    (void) wz_get_i64(&val, node);
    printf("(i64: %"WZ_PRId64")\n", val);
    break;
  }
  case WZ_F32: {
    float val;
    (void) wz_get_f32(&val, node);
    printf("(f32: %f)\n", val);
    break;
  }
  case WZ_F64: {
    double val;
    (void) wz_get_f64(&val, node);
    printf("(f64: %f)\n", val);
    break;
  }
  case WZ_NIL:
    printf("(nil)\n");
    break;
  default:
    goto close_file;
  }
  ret = 0;
close_file:
  wz_close_file(file);
free_ctx:
  wz_free_ctx(ctx);
  return ret;
}

static int
cmd_time(int argc, char ** argv) {
  /* wz time <file> [<file>...] */
  /* timing of parsing wz file(s) */
  int ret = 1;
  wz_uint8_t err = 0;
  wzctx * ctx;
#if defined(WZ_WINDOWS)
  LARGE_INTEGER freq;
  LARGE_INTEGER start;
  LARGE_INTEGER end;
#elif defined(WZ_MACOS)
  mach_timebase_info_data_t info;
  wz_uint64_t start;
#else
  struct timespec start;
  struct timespec end;
#endif
  wz_uint64_t duration;
  int i;
  if (argc < 3) {
    fprintf(stderr,
            "wz: missing file operand.\n"
            "See 'wz help time'.\n");
    return ret;
  }
  if ((ctx = wz_init_ctx()) == NULL)
    return ret;
#if defined(WZ_WINDOWS)
  if (QueryPerformanceFrequency(&freq) == FALSE)
    goto free_ctx;
  if (QueryPerformanceCounter(&start) == FALSE)
    goto free_ctx;
#elif defined(WZ_MACOS)
  if (mach_timebase_info(&info) != KERN_SUCCESS)
    goto free_ctx;
  start = mach_absolute_time();
#else
  if (clock_gettime(CLOCK_MONOTONIC, &start))
    goto free_ctx;
#endif
  for (i = 2; i < argc; i++) {
    if (strstr(argv[i], "List.wz") == NULL &&
        strstr(argv[i], "Data.wz") == NULL) {
      wzfile * file;
      printf("parsing: %s\n", argv[i]);
      if ((file = wz_open_file(argv[i], ctx)) == NULL) {
        err = 1;
        continue;
      }
      if (wz_parse_file(file)) {
        err = 1;
        goto close_file;
      }
close_file:
      wz_close_file(file);
    } else {
      printf("ignored: %s\n", argv[i]);
    }
  }
#if defined(WZ_WINDOWS)
  if (QueryPerformanceCounter(&end) == FALSE)
    goto free_ctx;
  duration = (wz_uint64_t) ((end.QuadPart - start.QuadPart) *
                            1000000000 / freq.QuadPart);
#elif defined(WZ_MACOS)
  duration = (mach_absolute_time() - start) * info.numer / info.denom;
#else
  if (clock_gettime(CLOCK_MONOTONIC, &end))
    goto free_ctx;
  duration = (wz_uint64_t) ((end.tv_sec - start.tv_sec) * 1000000000 +
                            (end.tv_nsec - start.tv_nsec));
#endif
  printf("took %3"WZ_PRIu64".%09"WZ_PRIu64" seconds, %s occurred\n",
         duration / 1000000000,
         duration % 1000000000,
         err ? "error" : "no error");
  ret = 0;
free_ctx:
  wz_free_ctx(ctx);
  return ret;
}

int
main(int argc, char ** argv) {
  if (argc > 1) {
    const char * cmd = argv[1];
    size_t len = sizeof(wz_cmds) / sizeof(* wz_cmds);
    size_t i;
    for (i = 0; i < len; i++)
      if (!strcmp(wz_cmds[i].name, cmd))
        return wz_cmds[i].func(argc, argv);
    if (cmd[0] == '-')
      fprintf(stderr, "Unknown option: %s\n", cmd);
    else
      fprintf(stderr, "wz: '%s' is not a wz command.\n", cmd);
    fprintf(stderr, "See 'wz --help'.\n");
    return 1;
  }
  cmd_help(1, argv);
  return 1;
}
