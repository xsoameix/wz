#ifndef _WZLIB_MEM_H
#define _WZLIB_MEM_H

#ifdef _WZLIB_TEST
  #define malloc memalloc
  #define free memfree

  void * memalloc(size_t size);
  void   memfree(void * ptr);
  size_t memused(void);
  size_t memerr(void);
#endif

#endif
