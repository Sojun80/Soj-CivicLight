#include "civiclight.h"
#include "../sha/sha256-hash.h"
#include "civiclight_stats.h"
#include "yespower/yespower.h"
#include <stdint.h>
#include <string.h>

// Fork activation: block headers with nTime before this use the original
// algorithm; at/after this, they use civiclight v2 (yespower-based).
static const uint32_t CIVICLIGHT_V2_ACTIVATION_TIME = 1784797200;

typedef int (*civic_yespower_impl_fn)(const uint8_t *,
                                      size_t,
                                      const civic_yespower_params_t *,
                                      civic_yespower_binary_t *);

typedef int (*civic_yespower2_impl_fn)(const uint8_t *,
                                       const uint8_t *,
                                       size_t,
                                       const civic_yespower_params_t *,
                                       civic_yespower_binary_t *,
                                       civic_yespower_binary_t *);

static civic_yespower_impl_fn civic_yespower_impl = civic_yespower_tls;
static civic_yespower2_impl_fn civic_yespower2_impl = civic_yespower2_tls;
static const char            *civic_yespower_mode = "yespower AVX2";

void civiclight_select_yespower_impl(bool allow_avx512)
{
    civic_yespower_impl = civic_yespower_tls;
    civic_yespower2_impl = civic_yespower2_tls;
    civic_yespower_mode = "yespower AVX2";

#if defined(__x86_64__)
    __builtin_cpu_init();
    if (allow_avx512 && __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl"))
    {
        civic_yespower_impl = civic_yespower_tls_avx512;
        civic_yespower2_impl = civic_yespower2_tls_avx512;
        civic_yespower_mode = "yespower AVX-512VL";
    }
#else
    (void)allow_avx512;
#endif
}

const char *civiclight_yespower_impl_name(void)
{
    return civic_yespower_mode;
}

static void sha256d_local(void *output, const void *input, size_t len)
{
    uint8_t h[32];
    sha256_full(h, input, len);
    sha256_full(output, h, 32);
}

static void sha256d_80_midstate(void *output, const void *header80, const sha256_context *midstate)
{
    uint8_t h[32];
    sha256_context ctx = *midstate;
    sha256_update(&ctx, (const uint8_t *)header80 + 64, 16);
    sha256_final(&ctx, h);
    sha256_full(output, h, 32);
}

// ---- v1: original algorithm ----
static void civiclight_core_v1(void *output, const void *input, size_t len)
{
    uint8_t hash1[32];
    sha256_full(hash1, input, len);
    for (int i = 0; i < 32; i++)
        hash1[i] ^= 0x5A;
    sha256_full(output, hash1, 32);
}

// ---- v2: ASIC-resistant algorithm (SHA256 -> yespower -> XOR -> SHA256) ----
static void civiclight_core_v2(void *output, const void *input, size_t len)
{
    uint8_t hash1[32];
    uint8_t xor_buf[32];
    sha256_full(hash1, input, len);

    civic_yespower_params_t params;
    params.version = YESPOWER_1_0;
    params.N       = 2048;
    params.r       = 8;
    params.pers    = NULL;
    params.perslen = 0;

    civic_yespower_binary_t yp_out;
    civic_yespower_impl(hash1, 32, &params, &yp_out);

    for (int i = 0; i < 32; i++)
        xor_buf[i] = yp_out.uc[i] ^ hash1[i];

    sha256_full(output, xor_buf, 32);
}

static void civiclight_core_v2_2way(void *output0,
                                    void *output1,
                                    const void *input0,
                                    const void *input1,
                                    size_t len)
{
    uint8_t hash1[2][32];
    uint8_t xor_buf[2][32];
    civic_yespower_binary_t yp_out[2];
    const civic_yespower_params_t params = {YESPOWER_1_0, 2048, 8, NULL, 0};

    sha256_full(hash1[0], input0, len);
    sha256_full(hash1[1], input1, len);
    civic_yespower2_impl(hash1[0], hash1[1], 32, &params, &yp_out[0], &yp_out[1]);

    for (int i = 0; i < 32; i++)
    {
        xor_buf[0][i] = yp_out[0].uc[i] ^ hash1[0][i];
        xor_buf[1][i] = yp_out[1].uc[i] ^ hash1[1][i];
    }
    sha256_full(output0, xor_buf[0], 32);
    sha256_full(output1, xor_buf[1], 32);
}

// Extract nTime from raw 80-byte block header (bytes 68-71, little-endian)
static uint32_t extract_ntime(const void *header80)
{
    const uint8_t *b = (const uint8_t *)header80;
    return (uint32_t)b[68] | ((uint32_t)b[69] << 8) | ((uint32_t)b[70] << 16) | ((uint32_t)b[71] << 24);
}

static void civiclight_powhash(void *output, const void *header80)
{
    uint8_t intermediate[32];
    sha256d_local(intermediate, header80, 80);

    uint32_t ntime = extract_ntime(header80);
    if (ntime >= CIVICLIGHT_V2_ACTIVATION_TIME)
        civiclight_core_v2(output, intermediate, 32);
    else
        civiclight_core_v1(output, intermediate, 32);
}

static void civiclight_powhash_from_midstate(void *output,
                                            const void *header80,
                                            const sha256_context *midstate)
{
    uint8_t intermediate[32];
    sha256d_80_midstate(intermediate, header80, midstate);
    if (extract_ntime(header80) >= CIVICLIGHT_V2_ACTIVATION_TIME)
        civiclight_core_v2(output, intermediate, 32);
    else
        civiclight_core_v1(output, intermediate, 32);
}

static void civiclight_powhash_2way_midstate(void *output0,
                                             void *output1,
                                             const void *header0,
                                             const void *header1,
                                             const sha256_context *midstate)
{
    uint8_t intermediate[2][32];
    sha256d_80_midstate(intermediate[0], header0, midstate);
    sha256d_80_midstate(intermediate[1], header1, midstate);

    if (extract_ntime(header0) >= CIVICLIGHT_V2_ACTIVATION_TIME &&
        extract_ntime(header1) >= CIVICLIGHT_V2_ACTIVATION_TIME)
    {
        civiclight_core_v2_2way(output0, output1, intermediate[0], intermediate[1], 32);
    }
    else
    {
        if (extract_ntime(header0) >= CIVICLIGHT_V2_ACTIVATION_TIME)
            civiclight_core_v2(output0, intermediate[0], 32);
        else
            civiclight_core_v1(output0, intermediate[0], 32);
        if (extract_ntime(header1) >= CIVICLIGHT_V2_ACTIVATION_TIME)
            civiclight_core_v2(output1, intermediate[1], 32);
        else
            civiclight_core_v1(output1, intermediate[1], 32);
    }
}

int civiclight_hash(void *output, const void *input, int thr_id)
{
    civiclight_powhash(output, input);
    return 1;
}

int civiclight_hash_2way(void *output0, void *output1, const void *input0, const void *input1)
{
    if (memcmp(input0, input1, 64) != 0)
    {
        civiclight_powhash(output0, input0);
        civiclight_powhash(output1, input1);
        return 1;
    }
    sha256_context midstate __attribute__((aligned(64)));
    sha256_ctx_init(&midstate);
    sha256_update(&midstate, input0, 64);
    civiclight_powhash_2way_midstate(output0, output1, input0, input1, &midstate);
    return 1;
}

int scanhash_civiclight(struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t       edata[20] __attribute__((aligned(64)));
    uint32_t       hash[8] __attribute__((aligned(64)));
    uint32_t       hash_pair[2][8] __attribute__((aligned(64)));
    uint32_t       edata_pair[2][20] __attribute__((aligned(64)));
    sha256_context header_midstate __attribute__((aligned(64)));
    uint32_t      *pdata       = work->data;
    uint32_t      *ptarget     = work->target;
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce  = max_nonce - 1;
    uint32_t       n           = first_nonce;
    const int      thr_id      = mythr->id;
    const bool     bench       = opt_benchmark;
    uint32_t       stats_batch = 0;
    v128_bswap32_80(edata, pdata);
    // Benchmark work is all zeroes. Give it a post-fork timestamp so
    // --benchmark measures the current memory-hard v2 algorithm, not v1.
    if (bench)
        edata[17] = CIVICLIGHT_V2_ACTIVATION_TIME;
    memcpy(edata_pair[0], edata, sizeof(edata));
    memcpy(edata_pair[1], edata, sizeof(edata));
    sha256_ctx_init(&header_midstate);
    sha256_update(&header_midstate, edata, 64);
    while (n + 1 < last_nonce && !work_restart[thr_id].restart)
    {
        edata_pair[0][19] = n;
        edata_pair[1][19] = n + 1;
        civiclight_powhash_2way_midstate(hash_pair[0],
                                         hash_pair[1],
                                         edata_pair[0],
                                         edata_pair[1],
                                         &header_midstate);
        if (!bench && (stats_batch += 2) >= 256)
        {
            civiclight_stats_add_hashes(stats_batch);
            stats_batch = 0;
        }
        if (unlikely(valid_hash(hash_pair[0], ptarget) && !bench))
        {
            pdata[19] = bswap_32(n);
            submit_solution(work, hash_pair[0], mythr);
        }
        if (unlikely(valid_hash(hash_pair[1], ptarget) && !bench))
        {
            pdata[19] = bswap_32(n + 1);
            submit_solution(work, hash_pair[1], mythr);
        }
        n += 2;
    }
    if (n < last_nonce && !work_restart[thr_id].restart)
    {
        edata[19] = n;
        civiclight_powhash_from_midstate(hash, edata, &header_midstate);
        if (!bench)
            stats_batch++;
        if (unlikely(valid_hash(hash, ptarget) && !bench))
        {
            pdata[19] = bswap_32(n);
            submit_solution(work, hash, mythr);
        }
        n++;
    }
    if (!bench && stats_batch)
        civiclight_stats_add_hashes(stats_batch);
    *hashes_done = n - first_nonce;
    pdata[19]    = n;
    return 0;
}

bool register_civiclight_algo(algo_gate_t *gate)
{
    civiclight_select_yespower_impl(true);
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
    gate->scanhash      = (void *)&scanhash_civiclight;
    gate->hash          = (void *)&civiclight_hash;
    return true;
};
