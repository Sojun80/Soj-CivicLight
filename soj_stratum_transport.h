#ifndef SOJ_STRATUM_TRANSPORT_H__
#define SOJ_STRATUM_TRANSPORT_H__

#include "soj.h"

bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx);

#endif
