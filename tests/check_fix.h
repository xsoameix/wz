#ifndef WZ_CHECK_FIX_H
#define WZ_CHECK_FIX_H

#include "predef.h"

#ifdef WZ_MSVC
typedef int pid_t;
#endif

#include <check.h>

#undef START_TEST
#define START_TEST(__testname) \
  static void __testname (int _i) { \
    (void) _i; \
    tcase_fn_start (""# __testname, __FILE__, __LINE__);

#endif
