#ifndef SOJ_PROTOCOL_H__
#define SOJ_PROTOCOL_H__

#include "soj.h"

void std_le_build_stratum_request(char *req, struct work *work);
void std_be_build_stratum_request(char *req, struct work *work);
void sha256d_gen_merkle_root(char *merkle_root, struct stratum_ctx *sctx);
void sha256_gen_merkle_root(char *merkle_root, struct stratum_ctx *sctx);

#endif
