#ifndef SOJ_QUEUE_H__
#define SOJ_QUEUE_H__

#include <stdbool.h>
#include <time.h>

struct thread_q;

struct thread_q *tq_new(void);
void             tq_free(struct thread_q *tq);
bool             tq_push(struct thread_q *tq, void *data);
void            *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void             tq_freeze(struct thread_q *tq);

#endif
