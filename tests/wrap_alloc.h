#ifndef WZ_WRAP_ALLOC_H
#define WZ_WRAP_ALLOC_H

void * wrap_malloc(size_t size);
void   wrap_free(void * ptr);
void * wrap_realloc(void * ptr, size_t size);
size_t memused(void);
size_t memerr(void);

#endif
