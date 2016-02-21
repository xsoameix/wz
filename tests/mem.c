#include <stdlib.h>

typedef struct {
  size_t size;
  void * ptr;
  char   freed;
} musage;

musage mused[100000];
size_t mused_len = 0;
size_t mused_size = 0;
size_t mused_err = 0;

void *
__wrap_malloc(size_t size) {
  void * ptr = malloc(size);
  if (ptr == NULL) return NULL;
  mused[mused_len].size = size;
  mused[mused_len].ptr = ptr;
  mused[mused_len].freed = 0;
  return mused_len++, mused_size += size, ptr;
}

void
__wrap_free(void * ptr) {
  musage * usage;
  size_t i;
  if (ptr == NULL) return;
  usage = NULL;
  for (i = 0; i < mused_len; i++) {
    usage = &mused[mused_len - i - 1];
    if (usage->ptr == ptr && !usage->freed) break;
  }
  if (i == mused_len) { mused_err++; return; }
  usage->freed = 1, mused_size -= usage->size;
  free(ptr);
}

size_t memused(void) { return mused_size; }
size_t memerr(void)  { return mused_err;  }
