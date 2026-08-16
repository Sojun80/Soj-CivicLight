#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <limits.h>

#define _ALIGN(x) __attribute__((aligned(x)))

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#define MAX_PATH PATH_MAX

#endif /* __COMPAT_H__ */
