#ifndef __CIVICLIGHT_H__
#define __CIVICLIGHT_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

int         civiclight_hash(void *output, const void *input, int thr_id);
int         civiclight_hash_2way(void *output0, void *output1, const void *input0, const void *input1);
bool        register_civiclight_algo(algo_gate_t *gate);
void        civiclight_select_yespower_impl(bool allow_avx512);
const char *civiclight_yespower_impl_name(void);

#endif
