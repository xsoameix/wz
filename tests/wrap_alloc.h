#ifndef WZ_WRAP_ALLOC_H
#define WZ_WRAP_ALLOC_H

void * wrap_malloc(size_t size);
void   wrap_free(void * ptr);
size_t memused(void);
size_t memerr(void);

#endif
