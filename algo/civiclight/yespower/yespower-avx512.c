/* Build a second yespower implementation for AVX-512VL capable CPUs.
 * Public symbols are renamed so this translation unit can coexist with the
 * AVX2/Rome baseline.  Startup dispatch guarantees these functions are never
 * entered on unsupported hardware. */
#if defined(__x86_64__)

#ifndef __AVX512F__
#define __AVX512F__ 1
#endif
#ifndef __AVX512VL__
#define __AVX512VL__ 1
#endif

#if defined(__clang__)
#pragma clang attribute push(__attribute__((target("avx512f,avx512vl"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC push_options
#pragma GCC target("avx512f,avx512vl")
#endif

#define civic_yespower_init_local civic_yespower_init_local_avx512
#define civic_yespower_free_local civic_yespower_free_local_avx512
#define civic_yespower civic_yespower_avx512
#define civic_yespower_tls civic_yespower_tls_avx512
#define civic_yespower2_tls civic_yespower2_tls_avx512
#include "yespower-opt.c"
#undef civic_yespower2_tls
#undef civic_yespower_tls
#undef civic_yespower
#undef civic_yespower_free_local
#undef civic_yespower_init_local

#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif

#endif
