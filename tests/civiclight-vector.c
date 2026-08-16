#include "algo/civiclight/civiclight.h"
#include "algo/civiclight/yespower/yespower.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_vector(const char *path)
{
    static const char expected[] = "b9272e5ef8030b985689704c5aae1f2ccd871702de375f50d849c657a85df327";
    uint8_t           header[80];
    uint8_t           pow_hash[32];
    char              actual[65];

    for (unsigned int i = 0; i < sizeof(header); ++i)
        header[i] = (uint8_t)i;

    /* 0x6a643910 little-endian: safely after the v2 activation time. */
    header[68] = 0x10;
    header[69] = 0x39;
    header[70] = 0x64;
    header[71] = 0x6a;

    civiclight_hash(pow_hash, header, 0);
    for (unsigned int i = 0; i < sizeof(pow_hash); ++i)
        snprintf(actual + i * 2, 3, "%02x", pow_hash[i]);
    actual[64] = '\0';

    if (strcmp(actual, expected) != 0)
    {
        fprintf(stderr, "CivicLight v2 vector mismatch\nexpected: %s\nactual:   %s\n", expected, actual);
        return 1;
    }

    printf("CivicLight v2 %s vector OK: %s\n", path, actual);
    return 0;
}

static int check_pair(int avx512)
{
    uint8_t src[2][32];
    civic_yespower_binary_t scalar[2], paired[2];
    const civic_yespower_params_t params = {YESPOWER_1_0, 2048, 8, NULL, 0};

    for (unsigned round = 0; round < 4; ++round)
    {
        for (unsigned i = 0; i < 32; ++i)
        {
            src[0][i] = (uint8_t)(i * 3 + round * 17 + 1);
            src[1][i] = (uint8_t)(i * 5 + round * 29 + 7);
        }
        if (avx512)
        {
            if (civic_yespower_tls_avx512(src[0], 32, &params, &scalar[0]) ||
                civic_yespower_tls_avx512(src[1], 32, &params, &scalar[1]) ||
                civic_yespower2_tls_avx512(src[0], src[1], 32, &params, &paired[0], &paired[1]))
                return 1;
        }
        else
        {
            if (civic_yespower_tls(src[0], 32, &params, &scalar[0]) ||
                civic_yespower_tls(src[1], 32, &params, &scalar[1]) ||
                civic_yespower2_tls(src[0], src[1], 32, &params, &paired[0], &paired[1]))
                return 1;
        }
        if (memcmp(scalar, paired, sizeof(scalar)) != 0)
        {
            fprintf(stderr, "CivicLight %s two-lane yespower mismatch in round %u\n",
                    avx512 ? "AVX-512VL" : "AVX2", round);
            return 1;
        }
    }
    printf("CivicLight %s two-lane yespower OK\n", avx512 ? "AVX-512VL" : "AVX2");
    return 0;
}

static int check_pow_pair(void)
{
    uint8_t header[2][80];
    uint8_t scalar[2][32];
    uint8_t paired[2][32];

    for (unsigned round = 0; round < 4; ++round)
    {
        for (unsigned i = 0; i < 80; ++i)
            header[0][i] = header[1][i] = (uint8_t)(i * 7 + round * 11);
        uint32_t ntime = round ? 1784797200u + round : 1784797199u;
        memcpy(&header[0][68], &ntime, sizeof(ntime));
        memcpy(&header[1][68], &ntime, sizeof(ntime));
        uint32_t nonce0 = 0x10203040u + round * 2;
        uint32_t nonce1 = nonce0 + 1;
        memcpy(&header[0][76], &nonce0, sizeof(nonce0));
        memcpy(&header[1][76], &nonce1, sizeof(nonce1));

        civiclight_hash(scalar[0], header[0], 0);
        civiclight_hash(scalar[1], header[1], 0);
        civiclight_hash_2way(paired[0], paired[1], header[0], header[1]);
        if (memcmp(scalar, paired, sizeof(scalar)) != 0)
        {
            fprintf(stderr, "CivicLight two-way full hash mismatch in round %u\n", round);
            return 1;
        }
    }
    printf("CivicLight two-way full hash and header midstate OK\n");
    return 0;
}

int main(void)
{
    civiclight_select_yespower_impl(false);
    if (check_vector(civiclight_yespower_impl_name()) != 0)
        return 1;

    civiclight_select_yespower_impl(true);
    if (check_vector(civiclight_yespower_impl_name()) != 0)
        return 1;

    if (check_pair(0) != 0 || check_pair(1) != 0 || check_pow_pair() != 0)
        return 1;

    return 0;
}
