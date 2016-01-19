#ifndef _WZLIB_MEM_H
#define _WZLIB_MEM_H

#define malloc memalloc
#define free memfree

void * memalloc(size_t size);
void   memfree(void * ptr);
size_t memused(void);
size_t memerr(void);

#endif
