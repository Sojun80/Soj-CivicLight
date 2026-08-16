/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012-2025 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * This is a proof-of-work focused fork of yescrypt, including optimized and
 * cut-down implementation of the obsolete yescrypt 0.5 (based off its first
 * submission to PHC back in 2014) and a new proof-of-work specific variation
 * known as yespower 1.0.  The former is intended as an upgrade for
 * cryptocurrencies that already use yescrypt 0.5 and the latter may be used
 * as a further upgrade (hard fork) by those and other cryptocurrencies.  The
 * version of algorithm to use is requested through parameters, allowing for
 * both algorithms to co-exist in client and miner implementations (such as in
 * preparation for a hard-fork).
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * AVX and especially XOP speed up Salsa20 a lot, but needlessly result in
 * extra instruction prefixes for pwxform (which we make more use of).  While
 * no slowdown from the prefixes is generally observed on AMD CPUs supporting
 * XOP, some slowdown is sometimes observed on Intel CPUs with AVX.
 */
#ifdef __GNUC__
#ifdef __XOP__
#warning "Note: XOP is enabled.  That's great."
#elif defined(__AVX512VL__)
#warning "Note: AVX512VL is enabled.  That's great."
#elif defined(__AVX__)
#warning "Note: AVX is enabled.  That's OK."
#elif defined(__SSE2__)
#warning "Note: AVX and XOP are not enabled.  That's OK."
#elif defined(__x86_64__) || defined(__i386__)
#warning "SSE2 not enabled.  Expect poor performance."
#else
#warning "Note: building generic code for non-x86.  That's OK."
#endif
#endif

/*
 * The SSE4 code version has fewer instructions than the generic SSE2 version,
 * but all of the instructions are SIMD, thereby wasting the scalar execution
 * units.  Thus, the generic SSE2 version below actually runs faster on some
 * CPUs due to its balanced mix of SIMD and scalar instructions.
 */
#undef USE_SSE4_FOR_32BIT

#ifdef __SSE2__
/*
 * GCC before 4.9 would by default unnecessarily use store/load (without
 * SSE4.1) or (V)PEXTR (with SSE4.1 or AVX) instead of simply (V)MOV.
 * This was tracked as GCC bug 54349.
 * "-mtune=corei7" works around this, but is only supported for GCC 4.6+.
 * We use inline asm for pre-4.6 GCC, further down this file.
 */
#if __GNUC__ == 4 && __GNUC_MINOR__ >= 6 && __GNUC_MINOR__ < 9 && !defined(__clang__) && !defined(__ICC)
#pragma GCC target("tune=corei7")
#endif
#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#elif defined(__AVX2__) || defined(__AVX512VL__)
#include <immintrin.h>
#endif
#elif defined(__SSE__)
#include <xmmintrin.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"
#include "yespower_sha256.h"

#include "yespower.h"

#include "yespower-platform.c"

#if __STDC_VERSION__ >= 199901L
/* Have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

#ifdef __GNUC__
#define unlikely(exp) __builtin_expect(exp, 0)
#else
#define unlikely(exp) (exp)
#endif

#ifdef __SSE__
#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));
#else
#undef PREFETCH
#endif

typedef union
{
    uint32_t w[16];
    uint64_t d[8];
#ifdef __SSE2__
    __m128i q[4];
#endif
} salsa20_blk_t;

static inline void salsa20_simd_shuffle(const salsa20_blk_t *Bin, salsa20_blk_t *Bout)
{
#define COMBINE(out, in1, in2) Bout->d[out] = Bin->w[in1 * 2] | ((uint64_t)Bin->w[in2 * 2 + 1] << 32);
    COMBINE(0, 0, 2)
    COMBINE(1, 5, 7)
    COMBINE(2, 2, 4)
    COMBINE(3, 7, 1)
    COMBINE(4, 4, 6)
    COMBINE(5, 1, 3)
    COMBINE(6, 6, 0)
    COMBINE(7, 3, 5)
#undef COMBINE
}

static inline void salsa20_simd_unshuffle(const salsa20_blk_t *Bin, salsa20_blk_t *Bout)
{
#define UNCOMBINE(out, in1, in2)                                                                                       \
    Bout->w[out * 2]     = Bin->d[in1];                                                                                \
    Bout->w[out * 2 + 1] = Bin->d[in2] >> 32;
    UNCOMBINE(0, 0, 6)
    UNCOMBINE(1, 5, 3)
    UNCOMBINE(2, 2, 0)
    UNCOMBINE(3, 7, 5)
    UNCOMBINE(4, 4, 2)
    UNCOMBINE(5, 1, 7)
    UNCOMBINE(6, 6, 4)
    UNCOMBINE(7, 3, 1)
#undef UNCOMBINE
}

#ifdef __SSE2__
#define DECL_X __m128i X0, X1, X2, X3;
#define DECL_Y __m128i Y0, Y1, Y2, Y3;
#define READ_X(in)                                                                                                     \
    X0 = (in).q[0];                                                                                                    \
    X1 = (in).q[1];                                                                                                    \
    X2 = (in).q[2];                                                                                                    \
    X3 = (in).q[3];
#define WRITE_X(out)                                                                                                   \
    (out).q[0] = X0;                                                                                                   \
    (out).q[1] = X1;                                                                                                   \
    (out).q[2] = X2;                                                                                                   \
    (out).q[3] = X3;

#ifdef __XOP__
#define ARX(out, in1, in2, s) out = _mm_xor_si128(out, _mm_roti_epi32(_mm_add_epi32(in1, in2), s));
#elif defined(__AVX512VL__)
#define ARX(out, in1, in2, s) out = _mm_xor_si128(out, _mm_rol_epi32(_mm_add_epi32(in1, in2), s));
#else
#define ARX(out, in1, in2, s)                                                                                          \
    {                                                                                                                  \
        __m128i tmp = _mm_add_epi32(in1, in2);                                                                         \
        out         = _mm_xor_si128(out, _mm_slli_epi32(tmp, s));                                                      \
        out         = _mm_xor_si128(out, _mm_srli_epi32(tmp, 32 - s));                                                 \
    }
#endif

#define SALSA20_2ROUNDS                                                                                                \
    /* Operate on "columns" */                                                                                         \
    ARX(X1, X0, X3, 7)                                                                                                 \
    ARX(X2, X1, X0, 9)                                                                                                 \
    ARX(X3, X2, X1, 13)                                                                                                \
    ARX(X0, X3, X2, 18)                                                                                                \
    /* Rearrange data */                                                                                               \
    X1 = _mm_shuffle_epi32(X1, 0x93);                                                                                  \
    X2 = _mm_shuffle_epi32(X2, 0x4E);                                                                                  \
    X3 = _mm_shuffle_epi32(X3, 0x39);                                                                                  \
    /* Operate on "rows" */                                                                                            \
    ARX(X3, X0, X1, 7)                                                                                                 \
    ARX(X2, X3, X0, 9)                                                                                                 \
    ARX(X1, X2, X3, 13)                                                                                                \
    ARX(X0, X1, X2, 18)                                                                                                \
    /* Rearrange data */                                                                                               \
    X1 = _mm_shuffle_epi32(X1, 0x39);                                                                                  \
    X2 = _mm_shuffle_epi32(X2, 0x4E);                                                                                  \
    X3 = _mm_shuffle_epi32(X3, 0x93);

/**
 * Apply the Salsa20 core to the block provided in (X0 ... X3).
 */
#define SALSA20_wrapper(out, rounds)                                                                                   \
    {                                                                                                                  \
        __m128i Z0 = X0, Z1 = X1, Z2 = X2, Z3 = X3;                                                                    \
        rounds(out).q[0] = X0 = _mm_add_epi32(X0, Z0);                                                                 \
        (out).q[1] = X1 = _mm_add_epi32(X1, Z1);                                                                       \
        (out).q[2] = X2 = _mm_add_epi32(X2, Z2);                                                                       \
        (out).q[3] = X3 = _mm_add_epi32(X3, Z3);                                                                       \
    }

/**
 * Apply the Salsa20/2 core to the block provided in X.
 */
#define SALSA20_2(out) SALSA20_wrapper(out, SALSA20_2ROUNDS)

#define SALSA20_8ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS

/**
 * Apply the Salsa20/8 core to the block provided in X.
 */
#define SALSA20_8(out) SALSA20_wrapper(out, SALSA20_8ROUNDS)

#define XOR_X(in)                                                                                                      \
    X0 = _mm_xor_si128(X0, (in).q[0]);                                                                                 \
    X1 = _mm_xor_si128(X1, (in).q[1]);                                                                                 \
    X2 = _mm_xor_si128(X2, (in).q[2]);                                                                                 \
    X3 = _mm_xor_si128(X3, (in).q[3]);

#define XOR_X_2(in1, in2)                                                                                              \
    X0 = _mm_xor_si128((in1).q[0], (in2).q[0]);                                                                        \
    X1 = _mm_xor_si128((in1).q[1], (in2).q[1]);                                                                        \
    X2 = _mm_xor_si128((in1).q[2], (in2).q[2]);                                                                        \
    X3 = _mm_xor_si128((in1).q[3], (in2).q[3]);

#define XOR_X_WRITE_XOR_Y_2(out, in)                                                                                   \
    (out).q[0] = Y0 = _mm_xor_si128((out).q[0], (in).q[0]);                                                            \
    (out).q[1] = Y1 = _mm_xor_si128((out).q[1], (in).q[1]);                                                            \
    (out).q[2] = Y2 = _mm_xor_si128((out).q[2], (in).q[2]);                                                            \
    (out).q[3] = Y3 = _mm_xor_si128((out).q[3], (in).q[3]);                                                            \
    X0              = _mm_xor_si128(X0, Y0);                                                                           \
    X1              = _mm_xor_si128(X1, Y1);                                                                           \
    X2              = _mm_xor_si128(X2, Y2);                                                                           \
    X3              = _mm_xor_si128(X3, Y3);

#define INTEGERIFY _mm_cvtsi128_si32(X0)

#else /* !defined(__SSE2__) */

#define DECL_X salsa20_blk_t X;
#define DECL_Y salsa20_blk_t Y;

#define COPY(out, in)                                                                                                  \
    (out).d[0] = (in).d[0];                                                                                            \
    (out).d[1] = (in).d[1];                                                                                            \
    (out).d[2] = (in).d[2];                                                                                            \
    (out).d[3] = (in).d[3];                                                                                            \
    (out).d[4] = (in).d[4];                                                                                            \
    (out).d[5] = (in).d[5];                                                                                            \
    (out).d[6] = (in).d[6];                                                                                            \
    (out).d[7] = (in).d[7];

#define READ_X(in) COPY(X, in)
#define WRITE_X(out) COPY(out, X)

/**
 * salsa20(B):
 * Apply the Salsa20 core to the provided block.
 */
static inline void salsa20(salsa20_blk_t *restrict B, salsa20_blk_t *restrict Bout, uint32_t doublerounds)
{
    salsa20_blk_t X;
#define x X.w

    salsa20_simd_unshuffle(B, &X);

    do
    {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns */
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);

        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);

        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);

        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);

        /* Operate on rows */
        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);

        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);

        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);

        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
#undef R
    } while (--doublerounds);
#undef x

    {
        uint32_t i;
        salsa20_simd_shuffle(&X, Bout);
        for (i = 0; i < 16; i += 4)
        {
            B->w[i]     = Bout->w[i] += B->w[i];
            B->w[i + 1] = Bout->w[i + 1] += B->w[i + 1];
            B->w[i + 2] = Bout->w[i + 2] += B->w[i + 2];
            B->w[i + 3] = Bout->w[i + 3] += B->w[i + 3];
        }
    }
}

/**
 * Apply the Salsa20/2 core to the block provided in X.
 */
#define SALSA20_2(out) salsa20(&X, &out, 1);

/**
 * Apply the Salsa20/8 core to the block provided in X.
 */
#define SALSA20_8(out) salsa20(&X, &out, 4);

#define XOR(out, in1, in2)                                                                                             \
    (out).d[0] = (in1).d[0] ^ (in2).d[0];                                                                              \
    (out).d[1] = (in1).d[1] ^ (in2).d[1];                                                                              \
    (out).d[2] = (in1).d[2] ^ (in2).d[2];                                                                              \
    (out).d[3] = (in1).d[3] ^ (in2).d[3];                                                                              \
    (out).d[4] = (in1).d[4] ^ (in2).d[4];                                                                              \
    (out).d[5] = (in1).d[5] ^ (in2).d[5];                                                                              \
    (out).d[6] = (in1).d[6] ^ (in2).d[6];                                                                              \
    (out).d[7] = (in1).d[7] ^ (in2).d[7];

#define XOR_X(in) XOR(X, X, in)
#define XOR_X_2(in1, in2) XOR(X, in1, in2)
#define XOR_X_WRITE_XOR_Y_2(out, in)                                                                                   \
    XOR(Y, out, in)                                                                                                    \
    COPY(out, Y)                                                                                                       \
    XOR(X, X, Y)

#define INTEGERIFY (uint32_t)X.d[0]
#endif

/**
 * Apply the Salsa20 core to the block provided in X ^ in.
 */
#define SALSA20_XOR_MEM(in, out)                                                                                       \
    XOR_X(in)                                                                                                          \
    SALSA20(out)

#define SALSA20 SALSA20_8
#else /* pass 2 */
#undef SALSA20
#define SALSA20 SALSA20_2
#endif

/**
 * blockmix_salsa(Bin, Bout):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin).  The input Bin must be 128
 * bytes in length; the output Bout must also be the same size.
 */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin, salsa20_blk_t *restrict Bout)
{
    DECL_X

    READ_X(Bin[1])
    SALSA20_XOR_MEM(Bin[0], Bout[0])
    SALSA20_XOR_MEM(Bin[1], Bout[1])
}

static inline uint32_t
blockmix_salsa_xor(const salsa20_blk_t *restrict Bin1, const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout)
{
    DECL_X

    XOR_X_2(Bin1[1], Bin2[1])
    XOR_X(Bin1[0])
    SALSA20_XOR_MEM(Bin2[0], Bout[0])
    XOR_X(Bin1[1])
    SALSA20_XOR_MEM(Bin2[1], Bout[1])

    return INTEGERIFY;
}

#if _YESPOWER_OPT_C_PASS_ == 1
/* This is tunable, but it is part of what defines a yespower version */
/* Version 0.5 */
#define Swidth_0_5 8
/* Version 1.0 */
#define Swidth_1_0 11

/* Not tunable in this implementation, hard-coded in a few places */
#define PWXsimple 2
#define PWXgather 4

/* Derived value.  Not tunable on its own. */
#define PWXbytes (PWXgather * PWXsimple * 8)

/* (Maybe-)runtime derived values.  Not tunable on their own. */
#define Swidth_to_Sbytes1(Swidth) ((1 << (Swidth)) * PWXsimple * 8)
#define Swidth_to_Smask(Swidth) (((1 << (Swidth)) - 1) * PWXsimple * 8)
#define Smask_to_Smask2(Smask) (((uint64_t)(Smask) << 32) | (Smask))

/* These should be compile-time derived */
#define Smask2_0_5 Smask_to_Smask2(Swidth_to_Smask(Swidth_0_5))
#define Smask2_1_0 Smask_to_Smask2(Swidth_to_Smask(Swidth_1_0))

typedef struct
{
    uint8_t *S0, *S1, *S2;
    size_t   w;
    uint32_t Sbytes;
} pwxform_ctx_t;

#define DECL_SMASK2REG       /* empty */
#define MAYBE_MEMORY_BARRIER /* empty */

#ifdef __SSE2__
/*
 * (V)PSRLDQ and (V)PSHUFD have higher throughput than (V)PSRLQ on some CPUs
 * starting with Sandy Bridge.  Additionally, PSHUFD uses separate source and
 * destination registers, whereas the shifts would require an extra move
 * instruction for our code when building without AVX.  Unfortunately, PSHUFD
 * is much slower on Conroe (4 cycles latency vs. 1 cycle latency for PSRLQ)
 * and somewhat slower on some non-Intel CPUs (luckily not including AMD
 * Bulldozer and Piledriver).
 */
#ifdef __AVX__
#define HI32(X) _mm_srli_si128((X), 4)
#elif 1 /* As an option, check for __SSE4_1__ here not to hurt Conroe */
#define HI32(X) _mm_shuffle_epi32((X), _MM_SHUFFLE(2, 3, 0, 1))
#else
#define HI32(X) _mm_srli_epi64((X), 32)
#endif

#if defined(__x86_64__) && __GNUC__ == 4 && __GNUC_MINOR__ < 6 && !defined(__ICC)
#ifdef __AVX__
#define MOVQ "vmovq"
#else
/* "movq" would be more correct, but "movd" is supported by older binutils
 * due to an error in AMD's spec for x86-64. */
#define MOVQ "movd"
#endif
#define EXTRACT64(X)                                                                                                   \
    ({                                                                                                                 \
        uint64_t result;                                                                                               \
        __asm__(MOVQ " %1, %0" : "=r"(result) : "x"(X));                                                               \
        result;                                                                                                        \
    })
#elif defined(__x86_64__) && !defined(_MSC_VER) && !defined(__OPEN64__)
/* MSVC and Open64 had bugs */
#define EXTRACT64(X) _mm_cvtsi128_si64(X)
#elif defined(__x86_64__) && defined(__SSE4_1__)
/* No known bugs for this intrinsic */
#include <smmintrin.h>
#define EXTRACT64(X) _mm_extract_epi64((X), 0)
#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit */
#include <smmintrin.h>
#if 0
/* This is currently unused by the code below, which instead uses these two
 * intrinsics explicitly when (!defined(__x86_64__) && defined(__SSE4_1__)) */
#define EXTRACT64(X) ((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | ((uint64_t)(uint32_t)_mm_extract_epi32((X), 1) << 32))
#endif
#else
/* 32-bit or compilers with known past bugs in _mm_cvtsi128_si64() */
#define EXTRACT64(X) ((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | ((uint64_t)(uint32_t)_mm_cvtsi128_si32(HI32(X)) << 32))
#endif

#if defined(__x86_64__) && (defined(__AVX__) || !defined(__GNUC__))
/* 64-bit with AVX */
/* Force use of 64-bit AND instead of two 32-bit ANDs */
#undef DECL_SMASK2REG
#if defined(__GNUC__) && !defined(__ICC)
#define DECL_SMASK2REG uint64_t Smask2reg = Smask2;
/* Force use of lower-numbered registers to reduce number of prefixes, relying
 * on out-of-order execution and register renaming. */
#define FORCE_REGALLOC_1 __asm__("" : "=a"(x), "+d"(Smask2reg), "+S"(S0), "+D"(S1));
#define FORCE_REGALLOC_2 __asm__("" : : "c"(lo));
#else
static volatile uint64_t Smask2var = Smask2;
#define DECL_SMASK2REG uint64_t Smask2reg = Smask2var;
#define FORCE_REGALLOC_1 /* empty */
#define FORCE_REGALLOC_2 /* empty */
#endif
#define PWXFORM_SIMD(X)                                                                                                \
    {                                                                                                                  \
        uint64_t x;                                                                                                    \
        FORCE_REGALLOC_1                                                                                               \
        uint32_t lo = x = EXTRACT64(X) & Smask2reg;                                                                    \
        FORCE_REGALLOC_2                                                                                               \
        uint32_t hi = x >> 32;                                                                                         \
        X           = _mm_mul_epu32(HI32(X), X);                                                                       \
        X           = _mm_add_epi64(X, *(__m128i *)(S0 + lo));                                                         \
        X           = _mm_xor_si128(X, *(__m128i *)(S1 + hi));                                                         \
    }
#elif defined(__x86_64__)
/* 64-bit without AVX.  This relies on out-of-order execution and register
 * renaming.  It may actually be fastest on CPUs with AVX(2) as well - e.g.,
 * it runs great on Haswell. */
#warning "Note: using x86-64 inline assembly for pwxform.  That's great."
#undef MAYBE_MEMORY_BARRIER
#define MAYBE_MEMORY_BARRIER __asm__("" : : : "memory");
#ifdef __ILP32__ /* x32 */
#define REGISTER_PREFIX "e"
#else
#define REGISTER_PREFIX "r"
#endif
#define PWXFORM_SIMD(X)                                                                                                \
    {                                                                                                                  \
        __m128i H;                                                                                                     \
        __asm__("movd %0, %%rax\n\t"                                                                                   \
                "pshufd $0xb1, %0, %1\n\t"                                                                             \
                "andq %2, %%rax\n\t"                                                                                   \
                "pmuludq %1, %0\n\t"                                                                                   \
                "movl %%eax, %%ecx\n\t"                                                                                \
                "shrq $0x20, %%rax\n\t"                                                                                \
                "paddq (%3,%%" REGISTER_PREFIX "cx), %0\n\t"                                                           \
                "pxor (%4,%%" REGISTER_PREFIX "ax), %0\n\t"                                                            \
                : "+x"(X), "=x"(H)                                                                                     \
                : "d"(Smask2), "S"(S0), "D"(S1)                                                                        \
                : "cc", "ax", "cx");                                                                                   \
    }
#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit with SSE4.1 */
#define PWXFORM_SIMD(X)                                                                                                \
    {                                                                                                                  \
        __m128i x  = _mm_and_si128(X, _mm_set1_epi64x(Smask2));                                                        \
        __m128i s0 = *(__m128i *)(S0 + (uint32_t)_mm_cvtsi128_si32(x));                                                \
        __m128i s1 = *(__m128i *)(S1 + (uint32_t)_mm_extract_epi32(x, 1));                                             \
        X          = _mm_mul_epu32(HI32(X), X);                                                                        \
        X          = _mm_add_epi64(X, s0);                                                                             \
        X          = _mm_xor_si128(X, s1);                                                                             \
    }
#else
/* 32-bit without SSE4.1 */
#define PWXFORM_SIMD(X)                                                                                                \
    {                                                                                                                  \
        uint64_t x  = EXTRACT64(X) & Smask2;                                                                           \
        __m128i  s0 = *(__m128i *)(S0 + (uint32_t)x);                                                                  \
        __m128i  s1 = *(__m128i *)(S1 + (x >> 32));                                                                    \
        X           = _mm_mul_epu32(HI32(X), X);                                                                       \
        X           = _mm_add_epi64(X, s0);                                                                            \
        X           = _mm_xor_si128(X, s1);                                                                            \
    }
#endif

#define PWXFORM_SIMD_WRITE(X, Sw)                                                                                      \
    PWXFORM_SIMD(X)                                                                                                    \
    MAYBE_MEMORY_BARRIER                                                                                               \
    *(__m128i *)(Sw + w) = X;                                                                                          \
    MAYBE_MEMORY_BARRIER

#define PWXFORM_ROUND                                                                                                  \
    PWXFORM_SIMD(X0)                                                                                                   \
    PWXFORM_SIMD(X1)                                                                                                   \
    PWXFORM_SIMD(X2)                                                                                                   \
    PWXFORM_SIMD(X3)

#define PWXFORM_ROUND_WRITE4                                                                                           \
    PWXFORM_SIMD_WRITE(X0, S0)                                                                                         \
    PWXFORM_SIMD_WRITE(X1, S1)                                                                                         \
    w += 16;                                                                                                           \
    PWXFORM_SIMD_WRITE(X2, S0)                                                                                         \
    PWXFORM_SIMD_WRITE(X3, S1)                                                                                         \
    w += 16;

#define PWXFORM_ROUND_WRITE2                                                                                           \
    PWXFORM_SIMD_WRITE(X0, S0)                                                                                         \
    PWXFORM_SIMD_WRITE(X1, S1)                                                                                         \
    w += 16;                                                                                                           \
    PWXFORM_SIMD(X2)                                                                                                   \
    PWXFORM_SIMD(X3)

#else /* !defined(__SSE2__) */

#define PWXFORM_SIMD(x0, x1)                                                                                           \
    {                                                                                                                  \
        uint64_t  x  = x0 & Smask2;                                                                                    \
        uint64_t *p0 = (uint64_t *)(S0 + (uint32_t)x);                                                                 \
        uint64_t *p1 = (uint64_t *)(S1 + (x >> 32));                                                                   \
        x0           = ((x0 >> 32) * (uint32_t)x0 + p0[0]) ^ p1[0];                                                    \
        x1           = ((x1 >> 32) * (uint32_t)x1 + p0[1]) ^ p1[1];                                                    \
    }

#define PWXFORM_SIMD_WRITE(x0, x1, Sw)                                                                                 \
    PWXFORM_SIMD(x0, x1)                                                                                               \
    ((uint64_t *)(Sw + w))[0] = x0;                                                                                    \
    ((uint64_t *)(Sw + w))[1] = x1;

#define PWXFORM_ROUND                                                                                                  \
    PWXFORM_SIMD(X.d[0], X.d[1])                                                                                       \
    PWXFORM_SIMD(X.d[2], X.d[3])                                                                                       \
    PWXFORM_SIMD(X.d[4], X.d[5])                                                                                       \
    PWXFORM_SIMD(X.d[6], X.d[7])

#define PWXFORM_ROUND_WRITE4                                                                                           \
    PWXFORM_SIMD_WRITE(X.d[0], X.d[1], S0)                                                                             \
    PWXFORM_SIMD_WRITE(X.d[2], X.d[3], S1)                                                                             \
    w += 16;                                                                                                           \
    PWXFORM_SIMD_WRITE(X.d[4], X.d[5], S0)                                                                             \
    PWXFORM_SIMD_WRITE(X.d[6], X.d[7], S1)                                                                             \
    w += 16;

#define PWXFORM_ROUND_WRITE2                                                                                           \
    PWXFORM_SIMD_WRITE(X.d[0], X.d[1], S0)                                                                             \
    PWXFORM_SIMD_WRITE(X.d[2], X.d[3], S1)                                                                             \
    w += 16;                                                                                                           \
    PWXFORM_SIMD(X.d[4], X.d[5])                                                                                       \
    PWXFORM_SIMD(X.d[6], X.d[7])
#endif

#define PWXFORM PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND

#define Smask2 Smask2_0_5

#else /* pass 2 */

#undef PWXFORM
#define PWXFORM                                                                                                        \
    PWXFORM_ROUND_WRITE4 PWXFORM_ROUND_WRITE2 PWXFORM_ROUND_WRITE2 w &= Smask2;                                        \
    {                                                                                                                  \
        uint8_t *Stmp = S2;                                                                                            \
        S2            = S1;                                                                                            \
        S1            = S0;                                                                                            \
        S0            = Stmp;                                                                                          \
    }

#undef Smask2
#define Smask2 Smask2_1_0

#endif

/**
 * blockmix_pwxform(Bin, Bout, r, S):
 * Compute Bout = BlockMix_pwxform{salsa20, r, S}(Bin).  The input Bin must
 * be 128r bytes in length; the output Bout must also be the same size.
 */
static void
blockmix(const salsa20_blk_t *restrict Bin, salsa20_blk_t *restrict Bout, size_t r, pwxform_ctx_t *restrict ctx)
{
    if (unlikely(!ctx))
    {
        blockmix_salsa(Bin, Bout);
        return;
    }

    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t   w  = ctx->w;
#endif
    size_t i;
    DECL_X

    /* Convert count of 128-byte blocks to max index of 64-byte block */
    r = r * 2 - 1;

    READ_X(Bin[r])

    DECL_SMASK2REG

    i = 0;
    do
    {
        XOR_X(Bin[i])
        PWXFORM
        if (unlikely(i >= r))
            break;
        WRITE_X(Bout[i])
        i++;
    } while (1);

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0;
    ctx->S1 = S1;
    ctx->S2 = S2;
    ctx->w  = w;
#endif

    SALSA20(Bout[i])
}

static uint32_t blockmix_xor(const salsa20_blk_t *restrict Bin1,
                             const salsa20_blk_t *restrict Bin2,
                             salsa20_blk_t *restrict Bout,
                             size_t r,
                             pwxform_ctx_t *restrict ctx)
{
    if (unlikely(!ctx))
        return blockmix_salsa_xor(Bin1, Bin2, Bout);

    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t   w  = ctx->w;
#endif
    size_t i;
    DECL_X

    /* Convert count of 128-byte blocks to max index of 64-byte block */
    r = r * 2 - 1;

#ifdef PREFETCH
    PREFETCH(&Bin2[r], _MM_HINT_T0)
    for (i = 0; i < r; i++)
    {
        PREFETCH(&Bin2[i], _MM_HINT_T0)
    }
#endif

    XOR_X_2(Bin1[r], Bin2[r])

    DECL_SMASK2REG

    i = 0;
    r--;
    do
    {
        XOR_X(Bin1[i])
        XOR_X(Bin2[i])
        PWXFORM
        WRITE_X(Bout[i])

        XOR_X(Bin1[i + 1])
        XOR_X(Bin2[i + 1])
        PWXFORM

        if (unlikely(i >= r))
            break;

        WRITE_X(Bout[i + 1])

        i += 2;
    } while (1);
    i++;

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0;
    ctx->S1 = S1;
    ctx->S2 = S2;
    ctx->w  = w;
#endif

    SALSA20(Bout[i])

    return INTEGERIFY;
}

static uint32_t
blockmix_xor_save(salsa20_blk_t *restrict Bin1out, salsa20_blk_t *restrict Bin2, size_t r, pwxform_ctx_t *restrict ctx)
{
    uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
    uint8_t *S2 = ctx->S2;
    size_t   w  = ctx->w;
#endif
    size_t i;
    DECL_X
    DECL_Y

    /* Convert count of 128-byte blocks to max index of 64-byte block */
    r = r * 2 - 1;

#ifdef PREFETCH
    PREFETCH(&Bin2[r], _MM_HINT_T0)
    for (i = 0; i < r; i++)
    {
        PREFETCH(&Bin2[i], _MM_HINT_T0)
    }
#endif

    XOR_X_2(Bin1out[r], Bin2[r])

    DECL_SMASK2REG

    i = 0;
    r--;
    do
    {
        XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i])
        PWXFORM
        WRITE_X(Bin1out[i])

        XOR_X_WRITE_XOR_Y_2(Bin2[i + 1], Bin1out[i + 1])
        PWXFORM

        if (unlikely(i >= r))
            break;

        WRITE_X(Bin1out[i + 1])

        i += 2;
    } while (1);
    i++;

#if _YESPOWER_OPT_C_PASS_ > 1
    ctx->S0 = S0;
    ctx->S1 = S1;
    ctx->S2 = S2;
    ctx->w  = w;
#endif

    SALSA20(Bin1out[i])

    return INTEGERIFY;
}

#if _YESPOWER_OPT_C_PASS_ == 1
/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static inline uint32_t integerify(const salsa20_blk_t *B, size_t r)
{
    /*
     * Our 64-bit words are in host byte order, which is why we don't just read
     * w[0] here (would be wrong on big-endian).  Also, our 32-bit words are
     * SIMD-shuffled, but we only care about the least significant 32 bits anyway.
     */
    return (uint32_t)B[2 * r - 1].d[0];
}
#endif

/**
 * smix1(B, r, N, V, XY, S):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 128r+64 bytes in length.  N must be even and at least 4.
 * The array V must be aligned to a multiple of 64 bytes, and arrays B and XY
 * to a multiple of at least 16 bytes.
 */
static void smix1(uint8_t *B, size_t r, uint32_t N, salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t         s = 2 * r;
    salsa20_blk_t *X = V, *Y = &V[s], *V_j;
    uint32_t       i, j, n;

#if _YESPOWER_OPT_C_PASS_ == 1
    for (i = 0; i < 2 * r; i++)
    {
#else
    for (i = 0; i < 2; i++)
    {
#endif
        const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
        salsa20_blk_t       *tmp = Y;
        salsa20_blk_t       *dst = &X[i];
        size_t               k;
        for (k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

#if _YESPOWER_OPT_C_PASS_ > 1
    for (i = 1; i < r; i++)
        blockmix(&X[(i - 1) * 2], &X[i * 2], 1, ctx);
#endif

    blockmix(X, Y, r, ctx);
    X = Y + s;
    blockmix(Y, X, r, ctx);
    j = integerify(X, r);

    for (n = 2; n < N; n <<= 1)
    {
        uint32_t m = (n < N / 2) ? n : (N - 1 - n);
        for (i = 1; i < m; i += 2)
        {
            Y = X + s;
            j &= n - 1;
            j += i - 1;
            V_j = &V[j * s];
            j   = blockmix_xor(X, V_j, Y, r, ctx);
            j &= n - 1;
            j += i;
            V_j = &V[j * s];
            X   = Y + s;
            j   = blockmix_xor(Y, V_j, X, r, ctx);
        }
    }
    n >>= 1;

    j &= n - 1;
    j += N - 2 - n;
    V_j = &V[j * s];
    Y   = X + s;
    j   = blockmix_xor(X, V_j, Y, r, ctx);
    j &= n - 1;
    j += N - 1 - n;
    V_j = &V[j * s];
    blockmix_xor(Y, V_j, XY, r, ctx);

    for (i = 0; i < 2 * r; i++)
    {
        const salsa20_blk_t *src = &XY[i];
        salsa20_blk_t       *tmp = &XY[s];
        salsa20_blk_t       *dst = (salsa20_blk_t *)&B[i * 64];
        size_t               k;
        for (k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

/**
 * smix2(B, r, N, Nloop, V, XY, S):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  N must be a power of 2 and at
 * least 2.  Nloop must be even.  The array V must be aligned to a multiple of
 * 64 bytes, and arrays B and XY to a multiple of at least 16 bytes.
 */
static void
smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop, salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
    size_t         s = 2 * r;
    salsa20_blk_t *X = XY, *Y = &XY[s];
    uint32_t       i, j;

    for (i = 0; i < 2 * r; i++)
    {
        const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
        salsa20_blk_t       *tmp = Y;
        salsa20_blk_t       *dst = &X[i];
        size_t               k;
        for (k = 0; k < 16; k++)
            tmp->w[k] = le32dec(&src->w[k]);
        salsa20_simd_shuffle(tmp, dst);
    }

    j = integerify(X, r) & (N - 1);

#if _YESPOWER_OPT_C_PASS_ == 1
    if (Nloop > 2)
    {
#endif
        do
        {
            salsa20_blk_t *V_j = &V[j * s];
            j                  = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
            V_j                = &V[j * s];
            j                  = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
        } while (Nloop -= 2);
#if _YESPOWER_OPT_C_PASS_ == 1
    }
    else
    {
        const salsa20_blk_t *V_j = &V[j * s];
        j                        = blockmix_xor(X, V_j, Y, r, ctx) & (N - 1);
        V_j                      = &V[j * s];
        blockmix_xor(Y, V_j, X, r, ctx);
    }
#endif

    for (i = 0; i < 2 * r; i++)
    {
        const salsa20_blk_t *src = &X[i];
        salsa20_blk_t       *tmp = Y;
        salsa20_blk_t       *dst = (salsa20_blk_t *)&B[i * 64];
        size_t               k;
        for (k = 0; k < 16; k++)
            le32enc(&tmp->w[k], src->w[k]);
        salsa20_simd_unshuffle(tmp, dst);
    }
}

/**
 * smix(B, r, N, V, XY, S):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  N must be a power of 2 and at least 16.
 * The array V must be aligned to a multiple of 64 bytes, and arrays B and XY
 * to a multiple of at least 16 bytes (aligning them to 64 bytes as well saves
 * cache lines, but it might also result in cache bank conflicts).
 */
static void smix(uint8_t *B, size_t r, uint32_t N, salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
#if _YESPOWER_OPT_C_PASS_ == 1
    uint32_t Nloop_all = (N + 2) / 3; /* 1/3, round up */
    uint32_t Nloop_rw  = Nloop_all;

    Nloop_all++;
    Nloop_all &= ~(uint32_t)1; /* round up to even */
    Nloop_rw &= ~(uint32_t)1;  /* round down to even */
#else
    uint32_t Nloop_rw = (N + 2) / 3; /* 1/3, round up */
    Nloop_rw++;
    Nloop_rw &= ~(uint32_t)1; /* round up to even */
#endif

    smix1(B, 1, ctx->Sbytes / 128, (salsa20_blk_t *)ctx->S0, XY, NULL);
    smix1(B, r, N, V, XY, ctx);
    smix2(B, r, N, Nloop_rw /* must be > 2 */, V, XY, ctx);
#if _YESPOWER_OPT_C_PASS_ == 1
    if (Nloop_all > Nloop_rw)
        smix2(B, r, N, 2, V, XY, ctx);
#endif
}

#if _YESPOWER_OPT_C_PASS_ == 1
#undef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 2
#define blockmix_salsa blockmix_salsa_1_0
#define blockmix_salsa_xor blockmix_salsa_xor_1_0
#define blockmix blockmix_1_0
#define blockmix_xor blockmix_xor_1_0
#define blockmix_xor_save blockmix_xor_save_1_0
#define smix1 smix1_1_0
#define smix2 smix2_1_0
#define smix smix_1_0
#include "yespower-opt.c"
#undef smix

#ifdef __SSE2__
/* CivicLight fixed-parameter two-lane kernel.  PWX has data-dependent loads
 * and writes, so operations remain ordered within each lane.  Alternating the
 * lanes gives the CPU independent work while one lane's loads are pending. */
typedef struct
{
    __m128i x[4];
    uint8_t *S0, *S1, *S2;
    size_t w;
} civic_yp2_state_t;

static inline __attribute__((always_inline)) __m128i
civic_pwx_1_0(__m128i X, const uint8_t *S0, const uint8_t *S1)
{
    uint64_t x = EXTRACT64(X) & Smask2_1_0;
    uint32_t lo = (uint32_t)x;
    uint32_t hi = (uint32_t)(x >> 32);
    X = _mm_mul_epu32(HI32(X), X);
    X = _mm_add_epi64(X, *(__m128i *)(S0 + lo));
    return _mm_xor_si128(X, *(__m128i *)(S1 + hi));
}

static inline __attribute__((always_inline)) void
civic_pwx_1_0_2way(__m128i *Xa,
                   __m128i *Xb,
                   const uint8_t *S0a,
                   const uint8_t *S1a,
                   const uint8_t *S0b,
                   const uint8_t *S1b)
{
#ifdef __AVX2__
    uint64_t xa = EXTRACT64(*Xa) & Smask2_1_0;
    uint64_t xb = EXTRACT64(*Xb) & Smask2_1_0;
    __m256i X = _mm256_set_m128i(*Xb, *Xa);
    __m256i H = _mm256_srli_si256(X, 4);
    __m256i add = _mm256_set_m128i(*(__m128i *)(S0b + (uint32_t)xb),
                                    *(__m128i *)(S0a + (uint32_t)xa));
    __m256i xorv = _mm256_set_m128i(*(__m128i *)(S1b + (uint32_t)(xb >> 32)),
                                     *(__m128i *)(S1a + (uint32_t)(xa >> 32)));
    X = _mm256_mul_epu32(H, X);
    X = _mm256_add_epi64(X, add);
    X = _mm256_xor_si256(X, xorv);
    *Xa = _mm256_castsi256_si128(X);
    *Xb = _mm256_extracti128_si256(X, 1);
#else
    *Xa = civic_pwx_1_0(*Xa, S0a, S1a);
    *Xb = civic_pwx_1_0(*Xb, S0b, S1b);
#endif
}

#define CIVIC_YP2_STEP(I)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        civic_pwx_1_0_2way(&a->x[I], &b->x[I], a->S0, a->S1, b->S0, b->S1);                                         \
    } while (0)

#define CIVIC_YP2_STEP_WRITE(I, MEMBER)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        civic_pwx_1_0_2way(&a->x[I], &b->x[I], a->S0, a->S1, b->S0, b->S1);                                         \
        *(__m128i *)(a->MEMBER + a->w) = a->x[I];                                                                     \
        *(__m128i *)(b->MEMBER + b->w) = b->x[I];                                                                     \
    } while (0)

static inline __attribute__((always_inline)) void
civic_pwxform_2way(civic_yp2_state_t *a, civic_yp2_state_t *b)
{
    CIVIC_YP2_STEP_WRITE(0, S0);
    CIVIC_YP2_STEP_WRITE(1, S1);
    a->w += 16;
    b->w += 16;
    CIVIC_YP2_STEP_WRITE(2, S0);
    CIVIC_YP2_STEP_WRITE(3, S1);
    a->w += 16;
    b->w += 16;

    CIVIC_YP2_STEP_WRITE(0, S0);
    CIVIC_YP2_STEP_WRITE(1, S1);
    a->w += 16;
    b->w += 16;
    CIVIC_YP2_STEP(2);
    CIVIC_YP2_STEP(3);

    CIVIC_YP2_STEP_WRITE(0, S0);
    CIVIC_YP2_STEP_WRITE(1, S1);
    a->w += 16;
    b->w += 16;
    CIVIC_YP2_STEP(2);
    CIVIC_YP2_STEP(3);

    a->w &= Smask2_1_0;
    b->w &= Smask2_1_0;
    uint8_t *tmp = a->S2;
    a->S2 = a->S1;
    a->S1 = a->S0;
    a->S0 = tmp;
    tmp = b->S2;
    b->S2 = b->S1;
    b->S1 = b->S0;
    b->S0 = tmp;
}

#undef CIVIC_YP2_STEP_WRITE
#undef CIVIC_YP2_STEP

static inline void civic_yp2_read(civic_yp2_state_t *st, const salsa20_blk_t *in)
{
    st->x[0] = in->q[0];
    st->x[1] = in->q[1];
    st->x[2] = in->q[2];
    st->x[3] = in->q[3];
}

static inline void civic_yp2_xor(civic_yp2_state_t *st, const salsa20_blk_t *in)
{
    st->x[0] = _mm_xor_si128(st->x[0], in->q[0]);
    st->x[1] = _mm_xor_si128(st->x[1], in->q[1]);
    st->x[2] = _mm_xor_si128(st->x[2], in->q[2]);
    st->x[3] = _mm_xor_si128(st->x[3], in->q[3]);
}

static inline void civic_yp2_write(salsa20_blk_t *out, const civic_yp2_state_t *st)
{
    out->q[0] = st->x[0];
    out->q[1] = st->x[1];
    out->q[2] = st->x[2];
    out->q[3] = st->x[3];
}

static inline void civic_yp2_finish_salsa(civic_yp2_state_t *st, salsa20_blk_t *out)
{
    __m128i X0 = st->x[0], X1 = st->x[1], X2 = st->x[2], X3 = st->x[3];
    SALSA20((*out));
}

static inline void civic_yp2_ctx_load(civic_yp2_state_t *st, const pwxform_ctx_t *ctx)
{
    st->S0 = ctx->S0;
    st->S1 = ctx->S1;
    st->S2 = ctx->S2;
    st->w = ctx->w;
}

static inline void civic_yp2_ctx_store(pwxform_ctx_t *ctx, const civic_yp2_state_t *st)
{
    ctx->S0 = st->S0;
    ctx->S1 = st->S1;
    ctx->S2 = st->S2;
    ctx->w = st->w;
}

#ifdef __AVX2__
/* Run the two independent Salsa20/2 states in the 128-bit halves of YMM
 * registers.  VPSHUFD is lane-local, so this is exactly the scalar SIMD
 * layout duplicated across the low and high halves. */
#ifdef __AVX512VL__
#define CIVIC_SALSA_ARX(OUT, IN1, IN2, SHIFT)                                                                         \
    (OUT) = _mm256_xor_si256((OUT), _mm256_rol_epi32(_mm256_add_epi32((IN1), (IN2)), (SHIFT)))
#else
#define CIVIC_SALSA_ARX(OUT, IN1, IN2, SHIFT)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        __m256i civic_salsa_tmp = _mm256_add_epi32((IN1), (IN2));                                                     \
        (OUT) = _mm256_xor_si256((OUT), _mm256_slli_epi32(civic_salsa_tmp, (SHIFT)));                                \
        (OUT) = _mm256_xor_si256((OUT), _mm256_srli_epi32(civic_salsa_tmp, 32 - (SHIFT)));                           \
    } while (0)
#endif

static inline __attribute__((always_inline)) __m256i
civic_salsa_pack(__m128i low, __m128i high)
{
    return _mm256_set_m128i(high, low);
}

static inline __attribute__((always_inline)) void
civic_salsa2_2way(__m256i *X0p,
                  __m256i *X1p,
                  __m256i *X2p,
                  __m256i *X3p,
                  salsa20_blk_t *out0,
                  salsa20_blk_t *out1)
{
    __m256i X0 = *X0p, X1 = *X1p, X2 = *X2p, X3 = *X3p;
    __m256i Z0 = X0, Z1 = X1, Z2 = X2, Z3 = X3;

    CIVIC_SALSA_ARX(X1, X0, X3, 7);
    CIVIC_SALSA_ARX(X2, X1, X0, 9);
    CIVIC_SALSA_ARX(X3, X2, X1, 13);
    CIVIC_SALSA_ARX(X0, X3, X2, 18);
    X1 = _mm256_shuffle_epi32(X1, 0x93);
    X2 = _mm256_shuffle_epi32(X2, 0x4e);
    X3 = _mm256_shuffle_epi32(X3, 0x39);
    CIVIC_SALSA_ARX(X3, X0, X1, 7);
    CIVIC_SALSA_ARX(X2, X3, X0, 9);
    CIVIC_SALSA_ARX(X1, X2, X3, 13);
    CIVIC_SALSA_ARX(X0, X1, X2, 18);
    X1 = _mm256_shuffle_epi32(X1, 0x39);
    X2 = _mm256_shuffle_epi32(X2, 0x4e);
    X3 = _mm256_shuffle_epi32(X3, 0x93);

    X0 = _mm256_add_epi32(X0, Z0);
    X1 = _mm256_add_epi32(X1, Z1);
    X2 = _mm256_add_epi32(X2, Z2);
    X3 = _mm256_add_epi32(X3, Z3);
    *X0p = X0;
    *X1p = X1;
    *X2p = X2;
    *X3p = X3;
    out0->q[0] = _mm256_castsi256_si128(X0);
    out0->q[1] = _mm256_castsi256_si128(X1);
    out0->q[2] = _mm256_castsi256_si128(X2);
    out0->q[3] = _mm256_castsi256_si128(X3);
    out1->q[0] = _mm256_extracti128_si256(X0, 1);
    out1->q[1] = _mm256_extracti128_si256(X1, 1);
    out1->q[2] = _mm256_extracti128_si256(X2, 1);
    out1->q[3] = _mm256_extracti128_si256(X3, 1);
}

static inline __attribute__((always_inline)) void
civic_blockmix_salsa_2way(const salsa20_blk_t *Bin0,
                          salsa20_blk_t *Bout0,
                          const salsa20_blk_t *Bin1,
                          salsa20_blk_t *Bout1)
{
    __m256i X0 = civic_salsa_pack(Bin0[1].q[0], Bin1[1].q[0]);
    __m256i X1 = civic_salsa_pack(Bin0[1].q[1], Bin1[1].q[1]);
    __m256i X2 = civic_salsa_pack(Bin0[1].q[2], Bin1[1].q[2]);
    __m256i X3 = civic_salsa_pack(Bin0[1].q[3], Bin1[1].q[3]);

#define CIVIC_SALSA_XOR_PAIR(BLOCK0, BLOCK1)                                                                          \
    X0 = _mm256_xor_si256(X0, civic_salsa_pack((BLOCK0).q[0], (BLOCK1).q[0]));                                       \
    X1 = _mm256_xor_si256(X1, civic_salsa_pack((BLOCK0).q[1], (BLOCK1).q[1]));                                       \
    X2 = _mm256_xor_si256(X2, civic_salsa_pack((BLOCK0).q[2], (BLOCK1).q[2]));                                       \
    X3 = _mm256_xor_si256(X3, civic_salsa_pack((BLOCK0).q[3], (BLOCK1).q[3]))

    CIVIC_SALSA_XOR_PAIR(Bin0[0], Bin1[0]);
    civic_salsa2_2way(&X0, &X1, &X2, &X3, &Bout0[0], &Bout1[0]);
    CIVIC_SALSA_XOR_PAIR(Bin0[1], Bin1[1]);
    civic_salsa2_2way(&X0, &X1, &X2, &X3, &Bout0[1], &Bout1[1]);
#undef CIVIC_SALSA_XOR_PAIR
}

static inline __attribute__((always_inline)) void
civic_blockmix_salsa_xor_2way(const salsa20_blk_t *Bin10,
                              const salsa20_blk_t *Bin20,
                              salsa20_blk_t *Bout0,
                              const salsa20_blk_t *Bin11,
                              const salsa20_blk_t *Bin21,
                              salsa20_blk_t *Bout1,
                              uint32_t result[2])
{
    __m256i X0 = civic_salsa_pack(_mm_xor_si128(Bin10[1].q[0], Bin20[1].q[0]),
                                  _mm_xor_si128(Bin11[1].q[0], Bin21[1].q[0]));
    __m256i X1 = civic_salsa_pack(_mm_xor_si128(Bin10[1].q[1], Bin20[1].q[1]),
                                  _mm_xor_si128(Bin11[1].q[1], Bin21[1].q[1]));
    __m256i X2 = civic_salsa_pack(_mm_xor_si128(Bin10[1].q[2], Bin20[1].q[2]),
                                  _mm_xor_si128(Bin11[1].q[2], Bin21[1].q[2]));
    __m256i X3 = civic_salsa_pack(_mm_xor_si128(Bin10[1].q[3], Bin20[1].q[3]),
                                  _mm_xor_si128(Bin11[1].q[3], Bin21[1].q[3]));

#define CIVIC_SALSA_XOR_FOUR(A0, B0, A1, B1)                                                                          \
    X0 = _mm256_xor_si256(X0, civic_salsa_pack(_mm_xor_si128((A0).q[0], (B0).q[0]),                                 \
                                                _mm_xor_si128((A1).q[0], (B1).q[0])));                                \
    X1 = _mm256_xor_si256(X1, civic_salsa_pack(_mm_xor_si128((A0).q[1], (B0).q[1]),                                 \
                                                _mm_xor_si128((A1).q[1], (B1).q[1])));                                \
    X2 = _mm256_xor_si256(X2, civic_salsa_pack(_mm_xor_si128((A0).q[2], (B0).q[2]),                                 \
                                                _mm_xor_si128((A1).q[2], (B1).q[2])));                                \
    X3 = _mm256_xor_si256(X3, civic_salsa_pack(_mm_xor_si128((A0).q[3], (B0).q[3]),                                 \
                                                _mm_xor_si128((A1).q[3], (B1).q[3])))

    CIVIC_SALSA_XOR_FOUR(Bin10[0], Bin20[0], Bin11[0], Bin21[0]);
    civic_salsa2_2way(&X0, &X1, &X2, &X3, &Bout0[0], &Bout1[0]);
    CIVIC_SALSA_XOR_FOUR(Bin10[1], Bin20[1], Bin11[1], Bin21[1]);
    civic_salsa2_2way(&X0, &X1, &X2, &X3, &Bout0[1], &Bout1[1]);
#undef CIVIC_SALSA_XOR_FOUR
    result[0] = (uint32_t)Bout0[1].d[0];
    result[1] = (uint32_t)Bout1[1].d[0];
}

#undef CIVIC_SALSA_ARX
#endif

static void civic_blockmix_2way(const salsa20_blk_t *Bin0,
                                salsa20_blk_t *Bout0,
                                pwxform_ctx_t *ctx0,
                                const salsa20_blk_t *Bin1,
                                salsa20_blk_t *Bout1,
                                pwxform_ctx_t *ctx1,
                                size_t r)
{
    size_t last = r * 2 - 1;
    civic_yp2_state_t a, b;
    civic_yp2_read(&a, &Bin0[last]);
    civic_yp2_read(&b, &Bin1[last]);
    civic_yp2_ctx_load(&a, ctx0);
    civic_yp2_ctx_load(&b, ctx1);

    for (size_t i = 0; i <= last; ++i)
    {
        civic_yp2_xor(&a, &Bin0[i]);
        civic_yp2_xor(&b, &Bin1[i]);
        civic_pwxform_2way(&a, &b);
        if (i != last)
        {
            civic_yp2_write(&Bout0[i], &a);
            civic_yp2_write(&Bout1[i], &b);
        }
    }
    civic_yp2_ctx_store(ctx0, &a);
    civic_yp2_ctx_store(ctx1, &b);
    civic_yp2_finish_salsa(&a, &Bout0[last]);
    civic_yp2_finish_salsa(&b, &Bout1[last]);
}

static void civic_blockmix_xor_2way(const salsa20_blk_t *Bin10,
                                    const salsa20_blk_t *Bin20,
                                    salsa20_blk_t *Bout0,
                                    pwxform_ctx_t *ctx0,
                                    const salsa20_blk_t *Bin11,
                                    const salsa20_blk_t *Bin21,
                                    salsa20_blk_t *Bout1,
                                    pwxform_ctx_t *ctx1,
                                    size_t r,
                                    uint32_t result[2])
{
    size_t last = r * 2 - 1;
    civic_yp2_state_t a, b;
#ifdef PREFETCH
    PREFETCH(&Bin20[last], _MM_HINT_T0)
    PREFETCH(&Bin21[last], _MM_HINT_T0)
    for (size_t p = 0; p < last; ++p)
    {
        PREFETCH(&Bin20[p], _MM_HINT_T0)
        PREFETCH(&Bin21[p], _MM_HINT_T0)
    }
#endif
    civic_yp2_read(&a, &Bin10[last]);
    civic_yp2_xor(&a, &Bin20[last]);
    civic_yp2_read(&b, &Bin11[last]);
    civic_yp2_xor(&b, &Bin21[last]);
    civic_yp2_ctx_load(&a, ctx0);
    civic_yp2_ctx_load(&b, ctx1);

    for (size_t i = 0; i <= last; ++i)
    {
        civic_yp2_xor(&a, &Bin10[i]);
        civic_yp2_xor(&a, &Bin20[i]);
        civic_yp2_xor(&b, &Bin11[i]);
        civic_yp2_xor(&b, &Bin21[i]);
        civic_pwxform_2way(&a, &b);
        if (i != last)
        {
            civic_yp2_write(&Bout0[i], &a);
            civic_yp2_write(&Bout1[i], &b);
        }
    }
    civic_yp2_ctx_store(ctx0, &a);
    civic_yp2_ctx_store(ctx1, &b);
    civic_yp2_finish_salsa(&a, &Bout0[last]);
    civic_yp2_finish_salsa(&b, &Bout1[last]);
    result[0] = (uint32_t)Bout0[last].d[0];
    result[1] = (uint32_t)Bout1[last].d[0];
}

static void civic_blockmix_xor_save_2way(salsa20_blk_t *Bin1out0,
                                         salsa20_blk_t *Bin20,
                                         pwxform_ctx_t *ctx0,
                                         salsa20_blk_t *Bin1out1,
                                         salsa20_blk_t *Bin21,
                                         pwxform_ctx_t *ctx1,
                                         size_t r,
                                         uint32_t result[2])
{
    size_t last = r * 2 - 1;
    civic_yp2_state_t a, b;
#ifdef PREFETCH
    __builtin_prefetch(&Bin20[last], 1, 3);
    __builtin_prefetch(&Bin21[last], 1, 3);
    for (size_t p = 0; p < last; ++p)
    {
        __builtin_prefetch(&Bin20[p], 1, 3);
        __builtin_prefetch(&Bin21[p], 1, 3);
    }
#endif
    civic_yp2_read(&a, &Bin1out0[last]);
    civic_yp2_xor(&a, &Bin20[last]);
    civic_yp2_read(&b, &Bin1out1[last]);
    civic_yp2_xor(&b, &Bin21[last]);
    civic_yp2_ctx_load(&a, ctx0);
    civic_yp2_ctx_load(&b, ctx1);

    for (size_t i = 0; i <= last; ++i)
    {
        for (unsigned q = 0; q < 4; ++q)
        {
            __m128i ya = _mm_xor_si128(Bin20[i].q[q], Bin1out0[i].q[q]);
            __m128i yb = _mm_xor_si128(Bin21[i].q[q], Bin1out1[i].q[q]);
            Bin20[i].q[q] = ya;
            Bin21[i].q[q] = yb;
            a.x[q] = _mm_xor_si128(a.x[q], ya);
            b.x[q] = _mm_xor_si128(b.x[q], yb);
        }
        civic_pwxform_2way(&a, &b);
        if (i != last)
        {
            civic_yp2_write(&Bin1out0[i], &a);
            civic_yp2_write(&Bin1out1[i], &b);
        }
    }
    civic_yp2_ctx_store(ctx0, &a);
    civic_yp2_ctx_store(ctx1, &b);
    civic_yp2_finish_salsa(&a, &Bin1out0[last]);
    civic_yp2_finish_salsa(&b, &Bin1out1[last]);
    result[0] = (uint32_t)Bin1out0[last].d[0];
    result[1] = (uint32_t)Bin1out1[last].d[0];
}

#ifdef __AVX2__
static void civic_smix1_salsa_2way(uint8_t *B0,
                                   uint8_t *B1,
                                   salsa20_blk_t *V0,
                                   salsa20_blk_t *V1,
                                   salsa20_blk_t *XY0,
                                   salsa20_blk_t *XY1)
{
    enum { civic_salsa_N = 768, civic_salsa_s = 2 };
    salsa20_blk_t *X[2] = {V0, V1};
    salsa20_blk_t *Y[2] = {&V0[civic_salsa_s], &V1[civic_salsa_s]};
    salsa20_blk_t *V[2] = {V0, V1};
    uint8_t *B[2] = {B0, B1};
    uint32_t j[2], result[2];

    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2; ++i)
        {
            salsa20_blk_t *tmp = Y[lane];
            salsa20_blk_t *dst = &X[lane][i];
            const salsa20_blk_t *src = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                tmp->w[k] = le32dec(&src->w[k]);
            salsa20_simd_shuffle(tmp, dst);
        }

    civic_blockmix_salsa_2way(X[0], Y[0], X[1], Y[1]);
    X[0] = Y[0] + civic_salsa_s;
    X[1] = Y[1] + civic_salsa_s;
    civic_blockmix_salsa_2way(Y[0], X[0], Y[1], X[1]);
    j[0] = integerify(X[0], 1);
    j[1] = integerify(X[1], 1);

    uint32_t n;
    for (n = 2; n < civic_salsa_N; n <<= 1)
    {
        uint32_t m = (n < civic_salsa_N / 2) ? n : (civic_salsa_N - 1 - n);
        for (uint32_t i = 1; i < m; i += 2)
        {
            Y[0] = X[0] + civic_salsa_s;
            Y[1] = X[1] + civic_salsa_s;
            salsa20_blk_t *Vj0 = &V[0][((j[0] & (n - 1)) + i - 1) * civic_salsa_s];
            salsa20_blk_t *Vj1 = &V[1][((j[1] & (n - 1)) + i - 1) * civic_salsa_s];
            civic_blockmix_salsa_xor_2way(X[0], Vj0, Y[0], X[1], Vj1, Y[1], result);
            j[0] = result[0];
            j[1] = result[1];
            Vj0 = &V[0][((j[0] & (n - 1)) + i) * civic_salsa_s];
            Vj1 = &V[1][((j[1] & (n - 1)) + i) * civic_salsa_s];
            X[0] = Y[0] + civic_salsa_s;
            X[1] = Y[1] + civic_salsa_s;
            civic_blockmix_salsa_xor_2way(Y[0], Vj0, X[0], Y[1], Vj1, X[1], result);
            j[0] = result[0];
            j[1] = result[1];
        }
    }
    n >>= 1;

    Y[0] = X[0] + civic_salsa_s;
    Y[1] = X[1] + civic_salsa_s;
    salsa20_blk_t *Vj0 = &V[0][((j[0] & (n - 1)) + civic_salsa_N - 2 - n) * civic_salsa_s];
    salsa20_blk_t *Vj1 = &V[1][((j[1] & (n - 1)) + civic_salsa_N - 2 - n) * civic_salsa_s];
    civic_blockmix_salsa_xor_2way(X[0], Vj0, Y[0], X[1], Vj1, Y[1], result);
    j[0] = result[0];
    j[1] = result[1];
    Vj0 = &V[0][((j[0] & (n - 1)) + civic_salsa_N - 1 - n) * civic_salsa_s];
    Vj1 = &V[1][((j[1] & (n - 1)) + civic_salsa_N - 1 - n) * civic_salsa_s];
    civic_blockmix_salsa_xor_2way(Y[0], Vj0, XY0, Y[1], Vj1, XY1, result);

    salsa20_blk_t *XY[2] = {XY0, XY1};
    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2; ++i)
        {
            salsa20_blk_t *tmp = &XY[lane][civic_salsa_s];
            salsa20_blk_t *dst = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                le32enc(&tmp->w[k], XY[lane][i].w[k]);
            salsa20_simd_unshuffle(tmp, dst);
        }
}

#ifdef CIVIC_YESPOWER_SALSA_BENCH
void civic_yespower_salsa_init_serial_bench(uint8_t *B0,
                                            uint8_t *B1,
                                            void *V0,
                                            void *V1,
                                            void *XY0,
                                            void *XY1)
{
    smix1_1_0(B0, 1, 768, (salsa20_blk_t *)V0, (salsa20_blk_t *)XY0, NULL);
    smix1_1_0(B1, 1, 768, (salsa20_blk_t *)V1, (salsa20_blk_t *)XY1, NULL);
}

void civic_yespower_salsa_init_paired_bench(uint8_t *B0,
                                            uint8_t *B1,
                                            void *V0,
                                            void *V1,
                                            void *XY0,
                                            void *XY1)
{
    civic_smix1_salsa_2way(B0, B1,
                            (salsa20_blk_t *)V0, (salsa20_blk_t *)V1,
                            (salsa20_blk_t *)XY0, (salsa20_blk_t *)XY1);
}
#endif
#endif

static void civic_smix1_1_0_2way(uint8_t *B0,
                                 uint8_t *B1,
                                 size_t r,
                                 uint32_t N,
                                 salsa20_blk_t *V0,
                                 salsa20_blk_t *V1,
                                 salsa20_blk_t *XY0,
                                 salsa20_blk_t *XY1,
                                 pwxform_ctx_t *ctx0,
                                 pwxform_ctx_t *ctx1)
{
    size_t s = 2 * r;
    salsa20_blk_t *X[2] = {V0, V1};
    salsa20_blk_t *Y[2] = {&V0[s], &V1[s]};
    uint8_t *B[2] = {B0, B1};
    uint32_t j[2], result[2];

    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2; ++i)
        {
            salsa20_blk_t *tmp = Y[lane];
            salsa20_blk_t *dst = &X[lane][i];
            const salsa20_blk_t *src = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                tmp->w[k] = le32dec(&src->w[k]);
            salsa20_simd_shuffle(tmp, dst);
        }

    for (size_t i = 1; i < r; ++i)
        civic_blockmix_2way(&X[0][(i - 1) * 2], &X[0][i * 2], ctx0,
                            &X[1][(i - 1) * 2], &X[1][i * 2], ctx1, 1);

    civic_blockmix_2way(X[0], Y[0], ctx0, X[1], Y[1], ctx1, r);
    X[0] = Y[0] + s;
    X[1] = Y[1] + s;
    civic_blockmix_2way(Y[0], X[0], ctx0, Y[1], X[1], ctx1, r);
    j[0] = integerify(X[0], r);
    j[1] = integerify(X[1], r);

    uint32_t n;
    for (n = 2; n < N; n <<= 1)
    {
        uint32_t m = (n < N / 2) ? n : (N - 1 - n);
        for (uint32_t i = 1; i < m; i += 2)
        {
            Y[0] = X[0] + s;
            Y[1] = X[1] + s;
            salsa20_blk_t *Vj0 = &V0[((j[0] & (n - 1)) + i - 1) * s];
            salsa20_blk_t *Vj1 = &V1[((j[1] & (n - 1)) + i - 1) * s];
            civic_blockmix_xor_2way(X[0], Vj0, Y[0], ctx0, X[1], Vj1, Y[1], ctx1, r, result);
            j[0] = result[0];
            j[1] = result[1];
            Vj0 = &V0[((j[0] & (n - 1)) + i) * s];
            Vj1 = &V1[((j[1] & (n - 1)) + i) * s];
            X[0] = Y[0] + s;
            X[1] = Y[1] + s;
            civic_blockmix_xor_2way(Y[0], Vj0, X[0], ctx0, Y[1], Vj1, X[1], ctx1, r, result);
            j[0] = result[0];
            j[1] = result[1];
        }
    }
    n >>= 1;

    Y[0] = X[0] + s;
    Y[1] = X[1] + s;
    salsa20_blk_t *Vj0 = &V0[((j[0] & (n - 1)) + N - 2 - n) * s];
    salsa20_blk_t *Vj1 = &V1[((j[1] & (n - 1)) + N - 2 - n) * s];
    civic_blockmix_xor_2way(X[0], Vj0, Y[0], ctx0, X[1], Vj1, Y[1], ctx1, r, result);
    j[0] = result[0];
    j[1] = result[1];
    Vj0 = &V0[((j[0] & (n - 1)) + N - 1 - n) * s];
    Vj1 = &V1[((j[1] & (n - 1)) + N - 1 - n) * s];
    civic_blockmix_xor_2way(Y[0], Vj0, XY0, ctx0, Y[1], Vj1, XY1, ctx1, r, result);

    salsa20_blk_t *XY[2] = {XY0, XY1};
    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2 * r; ++i)
        {
            salsa20_blk_t *tmp = &XY[lane][s];
            salsa20_blk_t *dst = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                le32enc(&tmp->w[k], XY[lane][i].w[k]);
            salsa20_simd_unshuffle(tmp, dst);
        }
}

static void civic_smix2_1_0_2way(uint8_t *B0,
                                 uint8_t *B1,
                                 size_t r,
                                 uint32_t N,
                                 uint32_t Nloop,
                                 salsa20_blk_t *V0,
                                 salsa20_blk_t *V1,
                                 salsa20_blk_t *XY0,
                                 salsa20_blk_t *XY1,
                                 pwxform_ctx_t *ctx0,
                                 pwxform_ctx_t *ctx1)
{
    size_t s = 2 * r;
    uint8_t *B[2] = {B0, B1};
    salsa20_blk_t *V[2] = {V0, V1};
    salsa20_blk_t *X[2] = {XY0, XY1};
    salsa20_blk_t *Y[2] = {&XY0[s], &XY1[s]};
    uint32_t j[2], result[2];

    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2 * r; ++i)
        {
            salsa20_blk_t *tmp = Y[lane];
            salsa20_blk_t *dst = &X[lane][i];
            const salsa20_blk_t *src = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                tmp->w[k] = le32dec(&src->w[k]);
            salsa20_simd_shuffle(tmp, dst);
        }
    j[0] = integerify(X[0], r) & (N - 1);
    j[1] = integerify(X[1], r) & (N - 1);

    do
    {
        salsa20_blk_t *Vj0 = &V[0][j[0] * s];
        salsa20_blk_t *Vj1 = &V[1][j[1] * s];
        civic_blockmix_xor_save_2way(X[0], Vj0, ctx0, X[1], Vj1, ctx1, r, result);
        j[0] = result[0] & (N - 1);
        j[1] = result[1] & (N - 1);
        Vj0 = &V[0][j[0] * s];
        Vj1 = &V[1][j[1] * s];
        civic_blockmix_xor_save_2way(X[0], Vj0, ctx0, X[1], Vj1, ctx1, r, result);
        j[0] = result[0] & (N - 1);
        j[1] = result[1] & (N - 1);
    } while (Nloop -= 2);

    for (unsigned lane = 0; lane < 2; ++lane)
        for (size_t i = 0; i < 2 * r; ++i)
        {
            salsa20_blk_t *tmp = Y[lane];
            salsa20_blk_t *dst = (salsa20_blk_t *)&B[lane][i * 64];
            for (size_t k = 0; k < 16; ++k)
                le32enc(&tmp->w[k], X[lane][i].w[k]);
            salsa20_simd_unshuffle(tmp, dst);
        }
}

static void civic_smix_1_0_2way(uint8_t *B0,
                                uint8_t *B1,
                                uint32_t N,
                                uint32_t r,
                                salsa20_blk_t *V0,
                                salsa20_blk_t *V1,
                                salsa20_blk_t *XY0,
                                salsa20_blk_t *XY1,
                                pwxform_ctx_t *ctx0,
                                pwxform_ctx_t *ctx1)
{
    uint32_t Nloop_rw = (N + 2) / 3;
    Nloop_rw = (Nloop_rw + 1) & ~(uint32_t)1;
#ifdef __AVX2__
    civic_smix1_salsa_2way(B0, B1,
                            (salsa20_blk_t *)ctx0->S0,
                            (salsa20_blk_t *)ctx1->S0,
                            XY0, XY1);
#else
    smix1_1_0(B0, 1, ctx0->Sbytes / 128, (salsa20_blk_t *)ctx0->S0, XY0, NULL);
    smix1_1_0(B1, 1, ctx1->Sbytes / 128, (salsa20_blk_t *)ctx1->S0, XY1, NULL);
#endif
    civic_smix1_1_0_2way(B0, B1, r, N, V0, V1, XY0, XY1, ctx0, ctx1);
    civic_smix2_1_0_2way(B0, B1, r, N, Nloop_rw, V0, V1, XY0, XY1, ctx0, ctx1);
}
#endif

/**
 * civic_yespower(local, src, srclen, params, dst):
 * Compute civic_yespower(src[0 .. srclen - 1], N, r), to be checked for "< target".
 * local is the thread-local data structure, allowing to preserve and reuse a
 * memory allocation across calls, thereby reducing its overhead.
 *
 * Return 0 on success; or -1 on error.
 */
int civic_yespower(civic_yespower_local_t        *local,
                   const uint8_t                 *src,
                   size_t                         srclen,
                   const civic_yespower_params_t *params,
                   civic_yespower_binary_t       *dst)
{
    civic_yespower_version_t version = params->version;
    uint32_t                 N       = params->N;
    uint32_t                 r       = params->r;
    const uint8_t           *pers    = params->pers;
    size_t                   perslen = params->perslen;
    uint32_t                 Swidth;
    size_t                   B_size, V_size, XY_size, need;
    uint8_t                 *B, *S;
    salsa20_blk_t           *V, *XY;
    pwxform_ctx_t            ctx;
    uint8_t                  sha256[32];

    /* Sanity-check parameters */
    if ((version != YESPOWER_0_5 && version != YESPOWER_1_0) || N < 1024 || N > 512 * 1024 || r < 8 || r > 32 ||
        (N & (N - 1)) != 0 || (!pers && perslen))
    {
        errno = EINVAL;
        goto fail;
    }

    /* Allocate memory */
    B_size = (size_t)128 * r;
    V_size = B_size * N;
    if (version == YESPOWER_0_5)
    {
        XY_size    = B_size * 2;
        Swidth     = Swidth_0_5;
        ctx.Sbytes = 2 * Swidth_to_Sbytes1(Swidth);
    }
    else
    {
        XY_size    = B_size + 64;
        Swidth     = Swidth_1_0;
        ctx.Sbytes = 3 * Swidth_to_Sbytes1(Swidth);
    }
    need = B_size + V_size + XY_size + ctx.Sbytes;
    if (local->aligned_size < need)
    {
        if (free_region(local))
            goto fail;
        if (!alloc_region(local, need))
            goto fail;
    }
    B      = (uint8_t *)local->aligned;
    V      = (salsa20_blk_t *)((uint8_t *)B + B_size);
    XY     = (salsa20_blk_t *)((uint8_t *)V + V_size);
    S      = (uint8_t *)XY + XY_size;
    ctx.S0 = S;
    ctx.S1 = S + Swidth_to_Sbytes1(Swidth);

    YP_SHA256_Buf(src, srclen, sha256);

    if (version == YESPOWER_0_5)
    {
        YP_PBKDF2_SHA256(sha256, sizeof(sha256), src, srclen, 1, B, B_size);
        memcpy(sha256, B, sizeof(sha256));
        smix(B, r, N, V, XY, &ctx);
        YP_PBKDF2_SHA256(sha256, sizeof(sha256), B, B_size, 1, (uint8_t *)dst, sizeof(*dst));

        if (pers)
        {
            YP_HMAC_SHA256_Buf(dst, sizeof(*dst), pers, perslen, sha256);
            YP_SHA256_Buf(sha256, sizeof(sha256), (uint8_t *)dst);
        }
    }
    else
    {
        ctx.S2 = S + 2 * Swidth_to_Sbytes1(Swidth);
        ctx.w  = 0;

        if (pers)
        {
            src    = pers;
            srclen = perslen;
        }
        else
        {
            srclen = 0;
        }

        YP_PBKDF2_SHA256(sha256, sizeof(sha256), src, srclen, 1, B, 128);
        memcpy(sha256, B, sizeof(sha256));
        smix_1_0(B, r, N, V, XY, &ctx);
        YP_HMAC_SHA256_Buf(B + B_size - 64, 64, sha256, sizeof(sha256), (uint8_t *)dst);
    }

    /* Success! */
    return 0;

fail:
    memset(dst, 0xff, sizeof(*dst));
    return -1;
}

static int civic_yespower2_fixed(civic_yespower_local_t *local0,
                                 civic_yespower_local_t *local1,
                                 const uint8_t *src0,
                                 const uint8_t *src1,
                                 civic_yespower_binary_t *dst0,
                                 civic_yespower_binary_t *dst1)
{
#ifdef __SSE2__
    enum { civic_N = 2048, civic_r = 8 };
    const size_t B_size = 128u * civic_r;
    const size_t V_size = B_size * civic_N;
    const size_t XY_size = B_size + 64u;
    const size_t S_part = Swidth_to_Sbytes1(Swidth_1_0);
    const size_t S_size = 3u * S_part;
    const size_t need = B_size + V_size + XY_size + S_size;
    civic_yespower_local_t *locals[2] = {local0, local1};
    const uint8_t *src[2] = {src0, src1};
    civic_yespower_binary_t *dst[2] = {dst0, dst1};
    uint8_t *B[2], *S[2];
    salsa20_blk_t *V[2], *XY[2];
    pwxform_ctx_t ctx[2];
    uint8_t sha256[2][32];

    for (unsigned lane = 0; lane < 2; ++lane)
    {
        if (locals[lane]->aligned_size < need)
        {
            if (free_region(locals[lane]) || !alloc_region(locals[lane], need))
                goto fail2;
        }
        B[lane] = (uint8_t *)locals[lane]->aligned;
        V[lane] = (salsa20_blk_t *)(B[lane] + B_size);
        XY[lane] = (salsa20_blk_t *)((uint8_t *)V[lane] + V_size);
        S[lane] = (uint8_t *)XY[lane] + XY_size;
        ctx[lane].S0 = S[lane];
        ctx[lane].S1 = S[lane] + S_part;
        ctx[lane].S2 = S[lane] + 2 * S_part;
        ctx[lane].Sbytes = S_size;
        ctx[lane].w = 0;
        YP_SHA256_Buf(src[lane], 32, sha256[lane]);
        YP_PBKDF2_SHA256(sha256[lane], 32, src[lane], 0, 1, B[lane], 128);
        memcpy(sha256[lane], B[lane], 32);
    }

    civic_smix_1_0_2way(B[0], B[1], civic_N, civic_r,
                         V[0], V[1], XY[0], XY[1], &ctx[0], &ctx[1]);
    for (unsigned lane = 0; lane < 2; ++lane)
        YP_HMAC_SHA256_Buf(B[lane] + B_size - 64, 64,
                           sha256[lane], sizeof(sha256[lane]),
                           (uint8_t *)dst[lane]);
    return 0;

fail2:
    memset(dst0, 0xff, sizeof(*dst0));
    memset(dst1, 0xff, sizeof(*dst1));
    return -1;
#else
    (void)local0; (void)local1; (void)src0; (void)src1; (void)dst0; (void)dst1;
    errno = ENOSYS;
    return -1;
#endif
}

int civic_yespower2_tls(const uint8_t *src0,
                        const uint8_t *src1,
                        size_t srclen,
                        const civic_yespower_params_t *params,
                        civic_yespower_binary_t *dst0,
                        civic_yespower_binary_t *dst1)
{
#ifdef _MSC_VER
    static __declspec(thread) int initialized;
    static __declspec(thread) civic_yespower_local_t local[2];
#else
    static __thread int initialized;
    static __thread civic_yespower_local_t local[2];
#endif
    if (!initialized)
    {
        init_region(&local[0]);
        init_region(&local[1]);
        initialized = 1;
    }
#ifdef __SSE2__
    if (srclen == 32 && params->version == YESPOWER_1_0 && params->N == 2048 &&
        params->r == 8 && !params->pers && params->perslen == 0)
        return civic_yespower2_fixed(&local[0], &local[1], src0, src1, dst0, dst1);
#endif

    int rc0 = civic_yespower(&local[0], src0, srclen, params, dst0);
    int rc1 = civic_yespower(&local[1], src1, srclen, params, dst1);
    return rc0 | rc1;
}

/**
 * civic_yespower_tls(src, srclen, params, dst):
 * Compute civic_yespower(src[0 .. srclen - 1], N, r), to be checked for "< target".
 * The memory allocation is maintained internally using thread-local storage.
 *
 * Return 0 on success; or -1 on error.
 */
int civic_yespower_tls(const uint8_t                 *src,
                       size_t                         srclen,
                       const civic_yespower_params_t *params,
                       civic_yespower_binary_t       *dst)
{
#ifdef _MSC_VER
    static __declspec(thread) int                    initialized = 0;
    static __declspec(thread) civic_yespower_local_t local;
#else
    static __thread int                    initialized = 0;
    static __thread civic_yespower_local_t local;
#endif

    if (!initialized)
    {
        init_region(&local);
        initialized = 1;
    }

    return civic_yespower(&local, src, srclen, params, dst);
}

int civic_yespower_init_local(civic_yespower_local_t *local)
{
    init_region(local);
    return 0;
}

int civic_yespower_free_local(civic_yespower_local_t *local)
{
    return free_region(local);
}
#endif
