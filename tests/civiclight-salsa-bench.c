#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum
{
    B_SIZE = 128,
    V_SIZE = 128 * 768,
    XY_SIZE = 192
};

typedef void (*salsa_init_fn)(uint8_t *, uint8_t *, void *, void *, void *, void *);

extern void civic_yespower_salsa_init_serial_bench(uint8_t *, uint8_t *, void *, void *, void *, void *);
extern void civic_yespower_salsa_init_paired_bench(uint8_t *, uint8_t *, void *, void *, void *, void *);

typedef struct
{
    uint8_t *B[2];
    void *V[2];
    void *XY[2];
} bench_state_t;

static int alloc_aligned(void **ptr, size_t size)
{
    int rc = posix_memalign(ptr, 64, size);
    if (rc != 0)
        errno = rc;
    return rc;
}

static int bench_state_init(bench_state_t *st)
{
    memset(st, 0, sizeof(*st));
    for (unsigned lane = 0; lane < 2; ++lane)
    {
        if (alloc_aligned((void **)&st->B[lane], B_SIZE) ||
            alloc_aligned(&st->V[lane], V_SIZE) ||
            alloc_aligned(&st->XY[lane], XY_SIZE))
            return -1;
        for (unsigned i = 0; i < B_SIZE; ++i)
            st->B[lane][i] = (uint8_t)(i * (lane ? 5 : 3) + lane * 17 + 1);
        memset(st->V[lane], 0, V_SIZE);
        memset(st->XY[lane], 0, XY_SIZE);
    }
    return 0;
}

static void bench_state_free(bench_state_t *st)
{
    for (unsigned lane = 0; lane < 2; ++lane)
    {
        free(st->B[lane]);
        free(st->V[lane]);
        free(st->XY[lane]);
    }
}

static uint64_t elapsed_ns(const struct timespec *start, const struct timespec *end)
{
    return (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000ull +
           (uint64_t)(end->tv_nsec - start->tv_nsec);
}

static uint64_t run_chunk(salsa_init_fn fn, bench_state_t *st, unsigned iterations)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    for (unsigned i = 0; i < iterations; ++i)
        fn(st->B[0], st->B[1], st->V[0], st->V[1], st->XY[0], st->XY[1]);
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    return elapsed_ns(&start, &end);
}

int main(int argc, char **argv)
{
    unsigned chunks = 12;
    unsigned iterations = 1000;
    if (argc > 1)
        chunks = (unsigned)strtoul(argv[1], NULL, 10);
    if (argc > 2)
        iterations = (unsigned)strtoul(argv[2], NULL, 10);
    if (!chunks || !iterations)
        return 2;

    bench_state_t serial, paired;
    if (bench_state_init(&serial) || bench_state_init(&paired))
    {
        perror("benchmark allocation");
        return 1;
    }

    civic_yespower_salsa_init_serial_bench(serial.B[0], serial.B[1],
                                            serial.V[0], serial.V[1], serial.XY[0], serial.XY[1]);
    civic_yespower_salsa_init_paired_bench(paired.B[0], paired.B[1],
                                            paired.V[0], paired.V[1], paired.XY[0], paired.XY[1]);
    if (memcmp(serial.B[0], paired.B[0], B_SIZE) || memcmp(serial.B[1], paired.B[1], B_SIZE))
    {
        fprintf(stderr, "serial/paired warmup mismatch\n");
        return 1;
    }

    uint64_t serial_ns = 0, paired_ns = 0;
    for (unsigned chunk = 0; chunk < chunks; ++chunk)
    {
        if (chunk & 1)
        {
            paired_ns += run_chunk(civic_yespower_salsa_init_paired_bench, &paired, iterations);
            serial_ns += run_chunk(civic_yespower_salsa_init_serial_bench, &serial, iterations);
        }
        else
        {
            serial_ns += run_chunk(civic_yespower_salsa_init_serial_bench, &serial, iterations);
            paired_ns += run_chunk(civic_yespower_salsa_init_paired_bench, &paired, iterations);
        }
        if (memcmp(serial.B[0], paired.B[0], B_SIZE) || memcmp(serial.B[1], paired.B[1], B_SIZE))
        {
            fprintf(stderr, "serial/paired mismatch after chunk %u\n", chunk);
            return 1;
        }
    }

    uint64_t pairs = (uint64_t)chunks * iterations;
    double serial_per_pair = (double)serial_ns / pairs;
    double paired_per_pair = (double)paired_ns / pairs;
    printf("Salsa initialization: 768 BlockMix calls/hash, 1536 Salsa/2 cores/hash\n");
    printf("pairs=%llu serial=%.1f ns/pair paired=%.1f ns/pair speedup=%.3fx saved=%.2f%%\n",
           (unsigned long long)pairs,
           serial_per_pair,
           paired_per_pair,
           serial_per_pair / paired_per_pair,
           (serial_per_pair - paired_per_pair) * 100.0 / serial_per_pair);
    printf("checksum=%02x%02x\n", paired.B[0][0], paired.B[1][0]);

    bench_state_free(&serial);
    bench_state_free(&paired);
    return 0;
}
