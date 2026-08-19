#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

enum
{
    B_SIZE = 128,
    V_SIZE = 128 * 8 * 2048, /* 128*r*N, r=8, N=2048 -> 2MB */
    XY_SIZE = 128 * 8 * 2, /* 2 * (2r blocks), r=8: X[16] + Y[16] -> 2KB */
    S_SIZE = (1 << 11) * 2 * 8, /* Swidth_to_Sbytes1(11) = 32KB per S part */
    S_TOTAL = 3 * S_SIZE
};

extern void civic_yespower_smix2_bench(uint8_t *, uint8_t *, void *, void *, void *, void *,
                                       void *, void *, int);
extern void civic_yespower_smix2_bench_noxor(uint8_t *, uint8_t *, void *, void *,
                                             void *, void *, void *, void *, int);
extern void civic_yespower_smix2_bench_wide(uint8_t *, uint8_t *, void *, void *,
                                              void *, void *, void *, void *, int);
extern void civic_yespower_smix2_bench_pipe(uint8_t *, uint8_t *, void *, void *,
                                            void *, void *, void *, void *, int);
extern void civic_yespower_smix2_bench_pipewide(uint8_t *, uint8_t *, void *, void *,
                                                void *, void *, void *, void *, int);
extern void civic_yespower_smix2_bench_pwxreg(uint8_t *, uint8_t *, void *, void *,
                                              void *, void *, void *, void *, int);
extern void civic_yespower_smix1_bench(uint8_t *, uint8_t *, void *, void *,
                                       void *, void *, void *, void *, int);
extern void civic_yespower_smix2_bench4(uint8_t *, uint8_t *, uint8_t *, uint8_t *,
                                        void *, void *, void *, void *,
                                        void *, void *, void *, void *,
                                        void *, void *, void *, void *,
                                        int);

static int alloc_aligned(void **ptr, size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
    {
        errno = ENOMEM;
        return 1;
    }
    if (size >= (2u << 20))
        madvise(p, size, MADV_HUGEPAGE);
    *ptr = p;
    return 0;
}

static void free_aligned(void *p, size_t size)
{
    munmap(p, size);
}

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end)
{
    return (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000ull +
           (uint64_t)(end->tv_nsec - start->tv_nsec);
}

static void fill_pattern(uint8_t *p, size_t n, unsigned seed)
{
    for (size_t i = 0; i < n; ++i)
        p[i] = (uint8_t)((i * 31u + seed * 7u) >> 3);
}

static uint64_t run_chunk2(int mode, unsigned iterations, uint8_t *B[2], void *V[2],
                           void *XY[2], void *S[2])
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    for (unsigned i = 0; i < iterations; ++i)
        civic_yespower_smix2_bench(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], mode);
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    return elapsed_ns(&start, &end);
}

static uint64_t run_chunk4(int mode, unsigned iterations, uint8_t *B[4], void *V[4],
                           void *XY[4], void *S[4])
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    for (unsigned i = 0; i < iterations; ++i)
        civic_yespower_smix2_bench4(B[0], B[1], B[2], B[3], V[0], V[1], V[2], V[3],
                                    XY[0], XY[1], XY[2], XY[3], S[0], S[1], S[2], S[3], mode);
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    return elapsed_ns(&start, &end);
}

int main(int argc, char **argv)
{
    unsigned chunks = 8;
    unsigned iterations = 30;
    if (argc > 1)
        chunks = (unsigned)strtoul(argv[1], NULL, 10);
    if (argc > 2)
        iterations = (unsigned)strtoul(argv[2], NULL, 10);
    if (!chunks || !iterations)
        return 2;

    uint8_t *B[4];
    void *V[4], *XY[4], *S[4];
    for (unsigned lane = 0; lane < 4; ++lane)
    {
        if (alloc_aligned((void **)&B[lane], B_SIZE) ||
            alloc_aligned(&V[lane], V_SIZE) ||
            alloc_aligned(&XY[lane], XY_SIZE) ||
            alloc_aligned(&S[lane], S_TOTAL))
            return 1;
        fill_pattern(B[lane], B_SIZE, lane);
        fill_pattern((uint8_t *)V[lane], V_SIZE, lane + 3);
        memset(XY[lane], 0, XY_SIZE);
        fill_pattern((uint8_t *)S[lane], S_TOTAL, lane + 9);
    }

    static const char *names[4] = {"random+save  ", "sequential    ", "random+nosave", "pwxform-only "};
    static const char *names1[4] = {"smix1 full   ", "smix1 no-pwx  ", "smix1 no-vread", "smix1 pwx-only"};
    uint64_t totals2[4] = {0, 0, 0, 0};
    uint64_t totals4[4] = {0, 0, 0, 0};
    uint64_t totals1[4] = {0, 0, 0, 0};
    uint64_t noxor = 0, pipe = 0, wide = 0, pwxreg = 0, xpref = 0, pipewide = 0;
    const unsigned noxor_chunks = chunks;

    for (int m = 0; m < 4; ++m)
    {
        civic_yespower_smix2_bench(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], m);
        civic_yespower_smix2_bench4(B[0], B[1], B[2], B[3], V[0], V[1], V[2], V[3],
                                    XY[0], XY[1], XY[2], XY[3], S[0], S[1], S[2], S[3], m);
    }

    struct timespec ns, ne;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench_noxor(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    noxor = elapsed_ns(&ns, &ne);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench_pipe(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    pipe = elapsed_ns(&ns, &ne);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench_wide(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    wide = elapsed_ns(&ns, &ne);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench_pipewide(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    pipewide = elapsed_ns(&ns, &ne);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench_pwxreg(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    pwxreg = elapsed_ns(&ns, &ne);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
    for (unsigned chunk = 0; chunk < noxor_chunks; ++chunk)
        for (unsigned i = 0; i < iterations; ++i)
            civic_yespower_smix2_bench(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], 5);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
    xpref = elapsed_ns(&ns, &ne);

    for (unsigned chunk = 0; chunk < chunks; ++chunk)
        for (int m = 0; m < 4; ++m)
        {
            totals2[m] += run_chunk2(m, iterations, B, V, XY, S);
            totals4[m] += run_chunk4(m, iterations, B, V, XY, S);
        }

    for (unsigned chunk = 0; chunk < chunks; ++chunk)
        for (int m = 0; m < 4; ++m)
        {
            clock_gettime(CLOCK_MONOTONIC_RAW, &ns);
            for (unsigned i = 0; i < iterations; ++i)
                civic_yespower_smix1_bench(B[0], B[1], V[0], V[1], XY[0], XY[1], S[0], S[1], m);
            clock_gettime(CLOCK_MONOTONIC_RAW, &ne);
            totals1[m] += elapsed_ns(&ns, &ne);
        }

    uint64_t calls = (uint64_t)chunks * iterations;
    printf("smix2 random loop (N=2048 r=8), %llu calls/mode, 2-way = 2 hashes/call, 4-way = 4 hashes/call\n",
           (unsigned long long)calls);
    printf("  mode         |   2-way ns/call |  4-way ns/call |  ns/hash 2w | ns/hash 4w |  4w speedup\n");
    for (int m = 0; m < 4; ++m)
    {
        double p2 = (double)totals2[m] / calls;
        double p4 = (double)totals4[m] / calls;
        printf("  %s | %15.1f | %15.1f | %12.1f | %11.1f | %7.2fx\n",
               names[m], p2, p4, p2 / 2, p4 / 4, (p2 / 2) / (p4 / 4));
    }
    double pn = (double)noxor / ((uint64_t)noxor_chunks * iterations);
    printf("  noxor-state   | %15.1f | %15s | %12.1f | %11s | %7s\n",
           pn, "-", pn / 2, "-", "-");
    double pp = (double)pipe / ((uint64_t)noxor_chunks * iterations);
    printf("  pipelined     | %15.1f | %15s | %12.1f | %11s | %7s\n",
           pp, "-", pp / 2, "-", "-");
    double pw = (double)wide / ((uint64_t)noxor_chunks * iterations);
    printf("  256-bit XOR   | %15.1f | %15s | %12.1f | %11s | %7s\n",
           pw, "-", pw / 2, "-", "-");
    double ppw = (double)pipewide / ((uint64_t)noxor_chunks * iterations);
    printf("  pipe+wide     | %15.1f | %15s | %12.1f | %11s | %7s\n",
           ppw, "-", ppw / 2, "-", "-");
    double pr = (double)pwxreg / ((uint64_t)noxor_chunks * iterations);
    printf("  pwx-reg (2w)  | %15.1f | %15s | %12.1f | %11s | %7s\n",
           pr, "-", pr / 2, "-", "-");
    double px = (double)xpref / ((uint64_t)noxor_chunks * iterations);
    printf("  xpref (2w)    | %15.1f | %15s | %12.1f | %11s | %7s\n",
           px, "-", px / 2, "-", "-");
    printf("smix1 V-fill (N=2048 r=8), %llu calls/mode, 2-way = 2 hashes/call\n",
           (unsigned long long)calls);
    for (int m = 0; m < 4; ++m)
    {
        double p1 = (double)totals1[m] / calls;
        printf("  %s | %15.1f | %15s | %12.1f | %11s | %7s\n",
               names1[m], p1, "-", p1 / 2, "-", "-");
    }

    for (unsigned lane = 0; lane < 4; ++lane)
    {
        free_aligned(B[lane], B_SIZE);
        free_aligned(V[lane], V_SIZE);
        free_aligned(XY[lane], XY_SIZE);
        free_aligned(S[lane], S_TOTAL);
    }
    return 0;
}
