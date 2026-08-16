#include "soj_protocol.h"

#include "algo-gate-api.h"
#include "algo/sha/sha256-hash.h"
#include "algo/sha/sha256d.h"

void std_le_build_stratum_request(char *req, struct work *work)
{
    unsigned char *xnonce2str;
    uint32_t       ntime, nonce;
    char           ntimestr[9], noncestr[9];
    le32enc(&ntime, work->data[algo_gate.ntime_index]);
    le32enc(&nonce, work->data[algo_gate.nonce_index]);
    bin2hex(ntimestr, (char *)(&ntime), sizeof(uint32_t));
    bin2hex(noncestr, (char *)(&nonce), sizeof(uint32_t));
    xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
    snprintf(req,
             JSON_BUF_LEN,
             "{\"method\":\"%s.%s\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],\"id\":4}",
             "mining",
             "submit",
             rpc_user,
             work->job_id,
             xnonce2str,
             ntimestr,
             noncestr);
    free(xnonce2str);
}

void std_be_build_stratum_request(char *req, struct work *work)
{
    unsigned char *xnonce2str;
    uint32_t       ntime, nonce;
    char           ntimestr[9], noncestr[9];
    be32enc(&ntime, work->data[algo_gate.ntime_index]);
    be32enc(&nonce, work->data[algo_gate.nonce_index]);
    bin2hex(ntimestr, (char *)(&ntime), sizeof(uint32_t));
    bin2hex(noncestr, (char *)(&nonce), sizeof(uint32_t));
    xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
    snprintf(req,
             JSON_BUF_LEN,
             "{\"method\":\"%s.%s\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],\"id\":4}",
             "mining",
             "submit",
             rpc_user,
             work->job_id,
             xnonce2str,
             ntimestr,
             noncestr);
    free(xnonce2str);
}

void sha256d_gen_merkle_root(char *merkle_root, struct stratum_ctx *sctx)
{
    sha256d(merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size);
    for (int i = 0; i < sctx->job.merkle_count; i++)
    {
        memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
        sha256d(merkle_root, merkle_root, 64);
    }
}

void sha256_gen_merkle_root(char *merkle_root, struct stratum_ctx *sctx)
{
    sha256_full(merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size);
    for (int i = 0; i < sctx->job.merkle_count; i++)
    {
        memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
        sha256d(merkle_root, merkle_root, 64);
    }
}
double nbits_to_diff_clean(uint32_t nbits)
{
    // Extract shift and mantissa
    uint32_t shift    = nbits >> 24;
    uint32_t mantissa = nbits & 0x00ffffff;

    if (mantissa == 0)
        return 0.0; // Avoid division by zero

    // Bitcoin's difficulty calculation:
    // difficulty = max_target / current_target
    // where max_target is the target at difficulty 1

    // For Bitcoin, difficulty 1 corresponds to nBits = 0x1d00ffff
    // This gives us the reference point
    uint32_t max_target_nbits = 0x1d00ffff;
    uint32_t max_shift        = max_target_nbits >> 24;        // 0x1d = 29
    uint32_t max_mantissa     = max_target_nbits & 0x00ffffff; // 0x00ffff

    // Calculate the ratio of targets
    // current_target = mantissa * 256^(shift-3)
    // max_target = max_mantissa * 256^(max_shift-3)
    // difficulty = max_target / current_target

    long double difficulty = (long double)max_mantissa / (long double)mantissa;

    // Apply the shift difference
    int shift_diff = max_shift - shift; // 29 - shift

    if (shift_diff > 0)
    {
        // max_target is larger, multiply difficulty
        for (int i = 0; i < shift_diff; i++)
        {
            difficulty *= 256.0;
        }
    }
    else if (shift_diff < 0)
    {
        // max_target is smaller, divide difficulty
        for (int i = 0; i < -shift_diff; i++)
        {
            difficulty /= 256.0;
        }
    }

    return (double)difficulty;
}

