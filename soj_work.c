#include "soj_work.h"

#include "algo-gate-api.h"

void work_free(struct work *w)
{
    if (w->txs)
        free(w->txs);
    if (w->workid)
        free(w->workid);
    if (w->job_id)
        free(w->job_id);
    if (w->xnonce2)
        free(w->xnonce2);

}

void work_copy(struct work *dest, const struct work *src)
{
    memcpy(dest, src, sizeof(struct work));
    if (src->txs)
        dest->txs = strdup(src->txs);
    if (src->workid)
        dest->workid = strdup(src->workid);
    if (src->job_id)
        dest->job_id = strdup(src->job_id);
    if (src->xnonce2)
    {
        dest->xnonce2 = (uchar *)malloc(src->xnonce2_len);
        memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
    }

    strcpy(dest->ntime, src->ntime);
}

int std_get_work_data_size(void)
{
    return STD_WORK_DATA_SIZE;
}

bool std_le_work_decode(struct work *work)
{
    const int adata_sz = algo_gate.get_work_data_size() / 4;
    for (int i = 0; i < adata_sz; i++)
        work->data[i] = le32dec(work->data + i);
    for (int i = 0; i < 8; i++)
        work->target[i] = le32dec(work->target + i);
    return true;
}

bool std_be_work_decode(struct work *work)
{
    const int adata_sz = algo_gate.get_work_data_size() / 4;
    for (int i = 0; i < adata_sz; i++)
        work->data[i] = be32dec(work->data + i);
    for (int i = 0; i < 8; i++)
        work->target[i] = le32dec(work->target + i);
    return true;
}

void set_work_data_big_endian(struct work *work)
{
    const int nonce_index = algo_gate.nonce_index;
    for (int i = 0; i < nonce_index; i++)
        be32enc(work->data + i, work->data[i]);
}

void std_get_new_work(struct work *work, struct work *g_work, int thr_id, uint32_t *end_nonce_ptr)
{
    uint32_t *nonceptr       = work->data + algo_gate.nonce_index;
    bool      force_new_work = false;

    if (have_stratum)
        force_new_work = (work->job_id && g_work->job_id)
                             ? strtoul(work->job_id, NULL, 16) != strtoul(g_work->job_id, NULL, 16)
                             : true;

    if (force_new_work || (*nonceptr >= *end_nonce_ptr) || memcmp(work->data, g_work->data, algo_gate.work_cmp_size))
    {
        work_free(work);
        work_copy(work, g_work);
        *nonceptr      = 0xffffffffU / opt_n_threads * thr_id;
        *end_nonce_ptr = (0xffffffffU / opt_n_threads) * (thr_id + 1) - 0x20;
    }
    else
        ++(*nonceptr);
}
