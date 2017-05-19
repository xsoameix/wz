#include "predef.h"

#ifdef WZ_MSVC
#  pragma warning(push, 3)
#endif

#include <stdlib.h>

#ifdef WZ_MSVC
#  pragma warning(pop)
#endif

#include "wrap_alloc.h"

typedef struct {
  size_t size;
  void * ptr;
  char   freed;
  char   _[sizeof(void *) - 1]; /* padding */
} musage;

static musage * mused = NULL;
static size_t mused_len = 0;
static size_t mused_capa = 0;
static size_t mused_size = 0;
static size_t mused_err = 0;

void *
wrap_malloc(size_t size) {
  size_t req = mused_len + 1;
  void * ptr;
  if (mused_capa < req) {
    musage * mem;
    size_t l = mused_capa;
    do { l = l < 4 ? 4 : l + l / 4; } while (l < req);
    if ((mem = realloc(mused, l * sizeof(* mused))) == NULL)
      return NULL;
    mused = mem;
    mused_capa = l;
  }
  if ((ptr = malloc(size)) == NULL)
    return NULL;
  mused[mused_len].size = size;
  mused[mused_len].ptr = ptr;
  mused[mused_len].freed = 0;
  mused_len++;
  mused_size += size;
  return ptr;
}

void
wrap_free(void * ptr) {
  musage * usage;
  size_t i;
  if (ptr == NULL)
    return;
  usage = NULL;
  for (i = 0; i < mused_len; i++) {
    usage = &mused[mused_len - i - 1];
    if (usage->ptr == ptr && !usage->freed)
      break;
  }
  if (i == mused_len) {
    mused_err++;
    return;
  }
  usage->freed = 1;
  mused_size -= usage->size;
  free(ptr);
  if (mused_size == 0) {
    free(mused);
    mused = NULL;
    mused_len = 0;
    mused_capa = 0;
  }
}

size_t memused(void) { return mused_size; }
size_t memerr(void)  { return mused_err;  }
