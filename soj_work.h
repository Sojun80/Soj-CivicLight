#ifndef SOJ_WORK_H__
#define SOJ_WORK_H__

#include "soj.h"

void work_free(struct work *w);
void work_copy(struct work *dest, const struct work *src);
int  std_get_work_data_size(void);
bool std_le_work_decode(struct work *work);
bool std_be_work_decode(struct work *work);
void set_work_data_big_endian(struct work *work);
void std_get_new_work(struct work *work, struct work *g_work, int thr_id, uint32_t *end_nonce_ptr);

#endif
