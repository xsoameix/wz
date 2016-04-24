#ifndef WZ_TEST_CHECK_H
#define WZ_TEST_CHECK_H

#ifdef _WIN32
typedef int pid_t;
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#include <check.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif
