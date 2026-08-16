#ifndef SOJ_CPU_H__
#define SOJ_CPU_H__

#include <stdbool.h>
#include <stddef.h>

void cpu_getname(char *outbuf, size_t maxsz);
void cpu_getmodelid(char *outbuf, size_t maxsz);
void cpu_brand_string(char *s);
void cpu_bestfeature(char *outbuf, size_t maxsz);

bool cpu_arch_x86_64(void);
bool cpu_arch_aarch64(void);

bool has_sse2(void);
bool has_ssse3(void);
bool has_sse41(void);
bool has_sse42(void);
bool has_avx(void);
bool has_avx2(void);
bool has_avx512(void);
bool has_avx10(void);

bool has_neon(void);
bool has_sve(void);
bool has_sve2(void);
bool has_sme(void);
bool has_sme2(void);

bool has_aes(void);
bool has_vaes(void);
bool has_sha256(void);
bool has_sha512(void);

unsigned int avx10_version(void);
int          sve_vector_length(void);
bool         cpu_capability(bool display_only);

#endif
