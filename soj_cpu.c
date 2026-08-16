#if !defined(SOJ_CPU_C__)
#define SOJ_CPU_C__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "soj.h"
#include "soj_cpu.h"

#if defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#endif

#if defined(__x86_64__)
#define EAX_Reg 0
#define EBX_Reg 1
#define ECX_Reg 2
#define EDX_Reg 3

#define CPU_INFO 1
#define EXTENDED_FEATURES 7
#define AVX10_FEATURES 0x24
#define EXTENDED_CPU_INFO 0x80000001
#define CPU_BRAND_1 0x80000002
#define CPU_BRAND_2 0x80000003
#define CPU_BRAND_3 0x80000004

#define SSSE3_Flag (1 << 9)
#define SSE41_Flag (1 << 19)
#define SSE42_Flag (1 << 20)
#define AES_NI_Flag (1 << 25)
#define XSAVE_Flag (1 << 26)
#define OSXSAVE_Flag (1 << 27)
#define AVX_Flag (1 << 28)

#define SSE2_Flag (1 << 26)

#define AVX2_Flag (1 << 5)
#define AVX512_F_Flag (1 << 16)
#define AVX512_DQ_Flag (1 << 17)
#define SHA_Flag (1 << 29)
#define AVX512_BW_Flag (1U << 30)
#define AVX512_VL_Flag (1U << 31)

#define VAES_Flag (1 << 9)

#define SHA512_Flag 1
#define AVX10_Flag (1 << 19)

#define AVX10_VERSION_mask 0xff

#define AVX_mask (AVX_Flag | XSAVE_Flag | OSXSAVE_Flag)
#define AVX512_mask (AVX512_VL_Flag | AVX512_BW_Flag | AVX512_DQ_Flag | AVX512_F_Flag)

static void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int output[4])
{
#if defined(__GNUC__) || defined(__clang__)
    unsigned int a, b, c, d;
    asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(subleaf));
    output[EAX_Reg] = a;
    output[EBX_Reg] = b;
    output[ECX_Reg] = c;
    output[EDX_Reg] = d;
#else
    output[0] = output[1] = output[2] = output[3] = 0;
#endif
}

#elif defined(__aarch64__)
static void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int output[4])
{
    (void)leaf;
    (void)subleaf;
    output[0] = (unsigned int)getauxval(AT_HWCAP);
    output[1] = (unsigned int)getauxval(AT_HWCAP2);
    output[2] = 0;
    output[3] = 0;
}
#else
static void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int output[4])
{
    (void)leaf;
    (void)subleaf;
    output[0] = output[1] = output[2] = output[3] = 0;
}
#endif

void cpu_getname(char *outbuf, size_t maxsz)
{
    memset(outbuf, 0, maxsz);
#if defined(_WIN32)
    snprintf(outbuf, maxsz, "Windows x86_64");
    return;
#else
    FILE  *fd   = fopen("/proc/cpuinfo", "rb");
    char  *buf  = NULL, *p, *eol;
    size_t size = 0;

    if (!fd)
        return;

    while (getdelim(&buf, &size, 0, fd) != -1)
    {
        if (buf && (p = strstr(buf, "model name\t")) && strstr(p, ":"))
        {
            p = strstr(p, ":");
            if (p)
            {
                p += 2;
                eol = strstr(p, "\n");
                if (eol)
                    *eol = '\0';
                snprintf(outbuf, maxsz, "%s", p);
            }
            break;
        }
    }

    free(buf);
    fclose(fd);
#endif
}

void cpu_getmodelid(char *outbuf, size_t maxsz)
{
    memset(outbuf, 0, maxsz);
#if defined(_WIN32)
    snprintf(outbuf, maxsz, "windows:%d", num_cpus);
    return;
#else

    FILE  *fd     = fopen("/proc/cpuinfo", "rb");
    char  *buf    = NULL, *p;
    int    cpufam = 0, model = 0, stepping = 0;
    size_t size = 0;

    if (!fd)
        return;

    while (getdelim(&buf, &size, 0, fd) != -1)
    {
        if (buf && (p = strstr(buf, "cpu family\t")) && strstr(p, ":"))
        {
            p = strstr(p, ":");
            if (p)
                cpufam = atoi(p + 2);
        }
        if (buf && (p = strstr(buf, "model\t")) && strstr(p, ":"))
        {
            p = strstr(p, ":");
            if (p)
                model = atoi(p + 2);
        }
        if (buf && (p = strstr(buf, "stepping\t")) && strstr(p, ":"))
        {
            p = strstr(p, ":");
            if (p)
                stepping = atoi(p + 2);
        }
        if (cpufam && model && stepping)
        {
            snprintf(outbuf, maxsz, "%x:%02x%02x:%d", cpufam, model, stepping, num_cpus);
            outbuf[maxsz - 1] = '\0';
            break;
        }
    }

    free(buf);
    fclose(fd);
#endif
}

bool cpu_arch_x86_64()
{
#if defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

bool cpu_arch_aarch64()
{
#if defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

bool has_sse2()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[EDX_Reg] & SSE2_Flag) != 0;
#else
    return false;
#endif
}

bool has_ssse3()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[ECX_Reg] & SSSE3_Flag) != 0;
#else
    return false;
#endif
}

bool has_sse41()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[ECX_Reg] & SSE41_Flag) != 0;
#else
    return false;
#endif
}

bool has_sse42()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[ECX_Reg] & SSE42_Flag) != 0;
#else
    return false;
#endif
}

bool has_neon()
{
#if defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

bool has_avx()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[ECX_Reg] & AVX_mask) == AVX_mask;
#else
    return false;
#endif
}

bool has_avx2()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 0, cpu_info);
    return (cpu_info[EBX_Reg] & AVX2_Flag) != 0;
#else
    return false;
#endif
}

bool has_sve()
{
#if defined(__aarch64__) && defined(HWCAP_SVE)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[0] & HWCAP_SVE) != 0;
#else
    return false;
#endif
}

bool has_sve2()
{
#if defined(__aarch64__) && defined(HWCAP2_SVE2)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[1] & HWCAP2_SVE2) != 0;
#else
    return false;
#endif
}

bool has_sme()
{
#if defined(__aarch64__) && defined(HWCAP2_SME)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[1] & HWCAP2_SME) != 0;
#else
    return false;
#endif
}

bool has_sme2()
{
#if defined(__aarch64__) && defined(HWCAP2_SME2)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[1] & HWCAP2_SME2) != 0;
#else
    return false;
#endif
}

bool has_avx512()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 0, cpu_info);
    return (cpu_info[EBX_Reg] & AVX512_mask) == AVX512_mask;
#else
    return false;
#endif
}

bool has_aes()
{
#if defined(__x86_64__)
    if (!has_sse2())
        return false;
    unsigned int cpu_info[4] = {0};
    cpuid(CPU_INFO, 0, cpu_info);
    return (cpu_info[ECX_Reg] & AES_NI_Flag) != 0;
#elif defined(__aarch64__) && defined(HWCAP_AES)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[0] & HWCAP_AES) != 0;
#else
    return false;
#endif
}

bool has_vaes()
{
#if defined(__x86_64__)
    if (!has_avx2())
        return false;
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 0, cpu_info);
    return (cpu_info[ECX_Reg] & VAES_Flag) != 0;
#else
    return false;
#endif
}

bool has_sha256()
{
#if defined(__x86_64__)
    if (!has_avx())
        return false;
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 0, cpu_info);
    return (cpu_info[EBX_Reg] & SHA_Flag) != 0;
#elif defined(__aarch64__) && defined(HWCAP_SHA2)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[0] & HWCAP_SHA2) != 0;
#else
    return false;
#endif
}

bool has_sha512()
{
#if defined(__x86_64__)
    if (!has_avx2())
        return false;
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 1, cpu_info);
    return (cpu_info[EAX_Reg] & SHA512_Flag) != 0;
#elif defined(__aarch64__) && defined(HWCAP_SHA512)
    unsigned int cpu_info[4] = {0};
    cpuid(0, 0, cpu_info);
    return (cpu_info[0] & HWCAP_SHA512) != 0;
#else
    return false;
#endif
}

bool has_avx10()
{
#if defined(__x86_64__)
    unsigned int cpu_info[4] = {0};
    cpuid(EXTENDED_FEATURES, 1, cpu_info);
    return (cpu_info[EDX_Reg] & AVX10_Flag) != 0;
#else
    return false;
#endif
}

unsigned int avx10_version()
{
#if defined(__x86_64__)
    if (has_avx10())
    {
        unsigned int cpu_info[4] = {0};
        cpuid(AVX10_FEATURES, 0, cpu_info);
        return cpu_info[EBX_Reg] & AVX10_VERSION_mask;
    }
#endif
    return 0;
}

int sve_vector_length()
{
#if defined(__aarch64__) && defined(PR_SVE_GET_VL) && defined(PR_SVE_VL_LEN_MASK)
    if (has_sve())
    {
        int vl = prctl(PR_SVE_GET_VL);
        if (vl >= 0)
            return (vl & PR_SVE_VL_LEN_MASK) * 8;
    }
#endif
    return 0;
}

void cpu_bestfeature(char *outbuf, size_t maxsz)
{
    if (!outbuf || maxsz == 0)
        return;

#if defined(__aarch64__)
    snprintf(outbuf, maxsz, "ARM");
#else
    if (has_avx10())
        snprintf(outbuf, maxsz, "AVX10");
    else if (has_avx512())
        snprintf(outbuf, maxsz, "AVX512");
    else if (has_avx2())
        snprintf(outbuf, maxsz, "AVX2");
    else if (has_avx())
        snprintf(outbuf, maxsz, "AVX");
    else if (has_sse42())
        snprintf(outbuf, maxsz, "SSE42");
    else if (has_sse2())
        snprintf(outbuf, maxsz, "SSE2");
    else
        *outbuf = '\0';
#endif
}

void cpu_brand_string(char *s)
{
#if defined(__x86_64__)
    int cpu_info[4] = {0};

    cpuid(CPU_BRAND_1, 0, (unsigned int *)cpu_info);
    memcpy(s, cpu_info, sizeof(cpu_info));
    cpuid(CPU_BRAND_2, 0, (unsigned int *)cpu_info);
    memcpy(s + 16, cpu_info, sizeof(cpu_info));
    cpuid(CPU_BRAND_3, 0, (unsigned int *)cpu_info);
    memcpy(s + 32, cpu_info, sizeof(cpu_info));
#elif defined(__aarch64__)
    sprintf(s, "ARM 64 bit CPU");
#else
    sprintf(s, "unknown/unsupported CPU architecture");
#endif
}

struct cpu_cap_snapshot
{
    bool cpu_has_sse2;
    bool cpu_has_ssse3;
    bool cpu_has_sse41;
    bool cpu_has_sse42;
    bool cpu_has_avx;
    bool cpu_has_neon;
    bool cpu_has_sve;
    bool cpu_has_sve2;
    bool cpu_has_sme;
    bool cpu_has_sme2;
    bool cpu_has_avx2;
    bool cpu_has_avx512;
    bool cpu_has_avx10;
    bool cpu_has_aes;
    bool cpu_has_vaes;
    bool cpu_has_sha256;
    bool cpu_has_sha512;

    bool sw_has_x86_64;
    bool sw_has_aarch64;
    int  sw_arm_arch;
    bool sw_has_neon;
    bool sw_has_sve;
    bool sw_has_sve2;
    bool sw_has_sme;
    bool sw_has_sme2;
    bool sw_has_sse2;
    bool sw_has_ssse3;
    bool sw_has_sse41;
    bool sw_has_sse42;
    bool sw_has_avx;
    bool sw_has_avx2;
    bool sw_has_avx512;
    bool sw_has_avx10;
    bool sw_has_aes;
    bool sw_has_vaes;
    bool sw_has_sha256;
    bool sw_has_sha512;
};

static void cpu_cap_collect(struct cpu_cap_snapshot *caps)
{
    memset(caps, 0, sizeof(*caps));

    caps->cpu_has_sse2   = has_sse2();
    caps->cpu_has_ssse3  = has_ssse3();
    caps->cpu_has_sse41  = has_sse41();
    caps->cpu_has_sse42  = has_sse42();
    caps->cpu_has_avx    = has_avx();
    caps->cpu_has_neon   = has_neon();
    caps->cpu_has_sve    = has_sve();
    caps->cpu_has_sve2   = has_sve2();
    caps->cpu_has_sme    = has_sme();
    caps->cpu_has_sme2   = has_sme2();
    caps->cpu_has_avx2   = has_avx2();
    caps->cpu_has_avx512 = has_avx512();
    caps->cpu_has_avx10  = has_avx10();
    caps->cpu_has_aes    = has_aes();
    caps->cpu_has_vaes   = has_vaes();
    caps->cpu_has_sha256 = has_sha256();
    caps->cpu_has_sha512 = has_sha512();

#if defined(__x86_64__)
    caps->sw_has_x86_64 = true;
#elif defined(__aarch64__)
    caps->sw_has_aarch64 = true;
#ifdef __ARM_NEON
    caps->sw_has_neon = true;
#endif
#ifdef __ARM_ARCH
    caps->sw_arm_arch = __ARM_ARCH;
#endif
#endif

#if defined(__SSE2__)
    caps->sw_has_sse2 = true;
#endif
#if defined(__SSSE3__)
    caps->sw_has_ssse3 = true;
#endif
#if defined(__SSE41__)
    caps->sw_has_sse41 = true;
#endif
#ifdef __SSE4_2__
    caps->sw_has_sse42 = true;
#endif
#ifdef __AVX__
    caps->sw_has_avx = true;
#endif
#ifdef __AVX2__
    caps->sw_has_avx2 = true;
#endif
#if (defined(__AVX512F__) && defined(__AVX512DQ__) && defined(__AVX512BW__) && defined(__AVX512VL__))
    caps->sw_has_avx512 = true;
#endif
#if defined(__AVX10_1__)
    caps->sw_has_avx10 = true;
#endif

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    caps->sw_has_aes = true;
#endif
#ifdef __VAES__
    caps->sw_has_vaes = true;
#endif
#if defined(__SHA__) || defined(__ARM_FEATURE_SHA2)
    caps->sw_has_sha256 = true;
#endif
#if defined(__SHA512__) || defined(__ARM_FEATURE_SHA512)
    caps->sw_has_sha512 = true;
#endif

#if defined(__ARM_NEON)
    caps->sw_has_neon = true;
#endif
#if defined(__ARM_FEATURE_SVE)
    caps->sw_has_sve = true;
#endif
#if defined(__ARM_FEATURE_SVE2)
    caps->sw_has_sve2 = true;
#endif
#if defined(__ARM_FEATURE_SME)
    caps->sw_has_sme = true;
#endif
#if defined(__ARM_FEATURE_SME2)
    caps->sw_has_sme2 = true;
#endif
}

static void cpu_cap_print(const struct cpu_cap_snapshot *caps)
{
    char cpu_brand[0x40];

    cpu_brand_string(cpu_brand);
    printf("CPU: %s\n", cpu_brand);

    printf("SW built on " __DATE__
#if defined(__clang__)
           " with CLANG-%d.%d.%d",
           __clang_major__,
           __clang_minor__,
           __clang_patchlevel__);
#elif defined(__GNUC__)
           " with GCC-%d.%d.%d",
           __GNUC__,
           __GNUC_MINOR__,
           __GNUC_PATCHLEVEL__);
#endif

#if defined(__linux)
    printf(" Linux\n");
#elif defined(__APPLE__)
    printf(" MacOS\n");
#elif defined(__bsd__) || defined(__unix__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    printf(" BSD/Unix\n");
#else
    printf("\n");
#endif

    printf("CPU features: ");
    if (cpu_arch_x86_64())
    {
        if (caps->cpu_has_avx10)
            printf(" AVX10.%d", avx10_version());
        if (caps->cpu_has_avx512)
            printf(" AVX512");
        else if (caps->cpu_has_avx2)
            printf(" AVX2  ");
        else if (caps->cpu_has_avx)
            printf(" AVX   ");
        else if (caps->cpu_has_sse42)
            printf(" SSE4.2");
        else if (caps->cpu_has_sse41)
            printf(" SSE4.1");
        else if (caps->cpu_has_ssse3)
            printf(" SSSE3 ");
        else if (caps->cpu_has_sse2)
            printf(" SSE2  ");
    }
    else if (cpu_arch_aarch64())
    {
        if (caps->cpu_has_neon)
            printf("       NEON");
        if (caps->cpu_has_sve2)
            printf(" SVE2-%d", sve_vector_length());
        else if (caps->cpu_has_sve)
            printf(" SVE");
        if (caps->cpu_has_sme2)
            printf(" SME2");
        else if (caps->cpu_has_sme)
            printf(" SME");
    }
    if (caps->cpu_has_vaes)
        printf(" VAES");
    else if (caps->cpu_has_aes)
        printf("  AES");
    if (caps->cpu_has_sha512)
        printf(" SHA512");
    else if (caps->cpu_has_sha256)
        printf(" SHA256");

    printf("\nSW features:  ");
    if (caps->sw_has_x86_64)
    {
        if (caps->sw_has_avx10)
            printf(" AVX10 ");
        else if (caps->sw_has_avx512)
            printf(" AVX512");
        else if (caps->sw_has_avx2)
            printf(" AVX2  ");
        else if (caps->sw_has_avx)
            printf(" AVX   ");
        else if (caps->sw_has_sse42)
            printf(" SSE4.2");
        else if (caps->sw_has_sse41)
            printf(" SSE4.1");
        else if (caps->sw_has_ssse3)
            printf(" SSSE3 ");
        else if (caps->sw_has_sse2)
            printf(" SSE2  ");
    }
    else if (caps->sw_has_aarch64)
    {
        if (caps->sw_arm_arch)
            printf(" armv%d", caps->sw_arm_arch);
        if (caps->sw_has_neon)
            printf(" NEON");
        if (caps->sw_has_sve2)
            printf(" SVE2");
        else if (caps->sw_has_sve)
            printf(" SVE");
        if (caps->sw_has_sme2)
            printf(" SME2");
        else if (caps->sw_has_sme)
            printf(" SME");
    }
    if (caps->sw_has_vaes)
        printf(" VAES");
    else if (caps->sw_has_aes)
        printf("  AES");
    if (caps->sw_has_sha512)
        printf(" SHA512");
    else if (caps->sw_has_sha256)
        printf(" SHA256");
    printf("\n");
}

bool cpu_capability(bool display_only)
{
    struct cpu_cap_snapshot caps;
    cpu_cap_collect(&caps);
    if (display_only)
        cpu_cap_print(&caps);
    return true;
}

#endif
