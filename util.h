#ifndef SOJ_UTIL_H__
#define SOJ_UTIL_H__

#include <soj-config.h>
#include <stdint.h>

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) + ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) + ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[3]       = x & 0xff;
    p[2]       = (x >> 8) & 0xff;
    p[1]       = (x >> 16) & 0xff;
    p[0]       = (x >> 24) & 0xff;
}
#endif

// This is a poorman's SIMD instruction, use 64 bit instruction to encode 2
// uint32_t. This function flips endian on two adjacent 32 bit quantities
// aligned to 64 bits. If source is LE output is BE, and vice versa.
static inline void swab32_x2(uint64_t *dst, uint64_t src)
{
    *dst = ((src & 0xff000000ff000000) >> 24) | ((src & 0x00ff000000ff0000) >> 8) | ((src & 0x0000ff000000ff00) << 8) |
           ((src & 0x000000ff000000ff) << 24);
}

static inline void swab32_array(uint32_t *dst_p, uint32_t *src_p, int n)
{
    for (int i = 0; i < n / 2; i++)
        swab32_x2(&((uint64_t *)dst_p)[i], ((uint64_t *)src_p)[i]);
}

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0]       = x & 0xff;
    p[1]       = (x >> 8) & 0xff;
    p[2]       = (x >> 16) & 0xff;
    p[3]       = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE16DEC
static inline uint16_t le16dec(const void *pp)
{
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}
#endif

#if !HAVE_DECL_LE16ENC
static inline void le16enc(void *pp, uint16_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0]       = x & 0xff;
    p[1]       = (x >> 8) & 0xff;
}
#endif

#endif
