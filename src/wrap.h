#ifndef WZ_WRAP_H
#define WZ_WRAP_H

#ifdef WZ_WRAP
#define malloc __wrap_malloc
#define free __wrap_free
void * __wrap_malloc(size_t size);
void   __wrap_free(void * ptr);
#endif

#endif
