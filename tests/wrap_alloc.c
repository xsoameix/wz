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
  size_t i;
  if (ptr == NULL)
    return;
  for (i = mused_len;;) {
    if (!i) {
      mused_err++;
      return;
    }
    i--;
    if (mused[i].ptr == ptr && !mused[i].freed)
      break;
  }
  mused[i].freed = 1;
  mused_size -= mused[i].size;
  free(ptr);
  if (mused_size == 0) {
    free(mused);
    mused = NULL;
    mused_len = 0;
    mused_capa = 0;
  }
}

void *
wrap_realloc(void * ptr, size_t size) {
  void * mem;
  size_t i;
  if (ptr == NULL)
    return wrap_malloc(size);
  for (i = mused_len;;) {
    if (!i) {
      mused_err++;
      return NULL;
    }
    i--;
    if (mused[i].ptr == ptr && !mused[i].freed)
      break;
  }
  if ((mem = realloc(ptr, size)) == NULL)
    return NULL;
  mused_size = mused_size - mused[i].size + size;
  mused[i].size = size;
  mused[i].ptr = mem;
  return mem;
}

size_t memused(void) { return mused_size; }
size_t memerr(void)  { return mused_err;  }
