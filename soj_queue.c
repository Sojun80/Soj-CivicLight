#include "elist.h"
#include "soj.h"
#include <string.h>

struct tq_ent
{
    void            *data;
    struct list_head q_node;
};

struct thread_q
{
    struct list_head q;
    pthread_mutex_t  mutex;
    pthread_cond_t   cond;
    bool             frozen;
    bool             stop;
};

struct thread_q *tq_new(void)
{
    struct thread_q *tq = (struct thread_q *)calloc(1, sizeof(*tq));
    if (!tq)
        return NULL;

    INIT_LIST_HEAD(&tq->q);
    pthread_mutex_init(&tq->mutex, NULL);
    pthread_cond_init(&tq->cond, NULL);
    return tq;
}

void tq_free(struct thread_q *tq)
{
    struct tq_ent *ent, *iter;

    if (!tq)
        return;

    pthread_mutex_lock(&tq->mutex);
    tq->stop = true;
    pthread_cond_broadcast(&tq->cond);
    pthread_mutex_unlock(&tq->mutex);

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&ts, NULL);

    pthread_mutex_lock(&tq->mutex);
    list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent)
    {
        list_del(&ent->q_node);
        free(ent);
    }
    INIT_LIST_HEAD(&tq->q);
    pthread_mutex_unlock(&tq->mutex);

    pthread_cond_destroy(&tq->cond);
    pthread_mutex_destroy(&tq->mutex);
    memset(tq, 0, sizeof(*tq));
    free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
    pthread_mutex_lock(&tq->mutex);
    tq->frozen = frozen;
    pthread_cond_signal(&tq->cond);
    pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
    tq_freezethaw(tq, true);
}

bool tq_push(struct thread_q *tq, void *data)
{
    struct tq_ent *ent;
    bool           rc = true;

    ent = (struct tq_ent *)calloc(1, sizeof(*ent));
    if (!ent)
        return false;

    ent->data = data;
    INIT_LIST_HEAD(&ent->q_node);

    pthread_mutex_lock(&tq->mutex);
    if (!tq->frozen)
    {
        list_add_tail(&ent->q_node, &tq->q);
    }
    else
    {
        free(ent);
        rc = false;
    }
    pthread_cond_signal(&tq->cond);
    pthread_mutex_unlock(&tq->mutex);
    return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
    if (!tq)
        return NULL;

    pthread_mutex_lock(&tq->mutex);
    while (list_empty(&tq->q) && !tq->stop)
    {
        int rc =
            abstime ? pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime) : pthread_cond_wait(&tq->cond, &tq->mutex);
        if (rc != 0)
        {
            pthread_mutex_unlock(&tq->mutex);
            return NULL;
        }
    }

    if (list_empty(&tq->q))
    {
        pthread_mutex_unlock(&tq->mutex);
        return NULL;
    }

    if (!tq->q.next || !tq->q.prev)
    {
        pthread_mutex_unlock(&tq->mutex);
        applog(LOG_ERR, "CRITICAL: tq->q.next=%p or tq->q.prev=%p is NULL (memory corruption)", tq->q.next, tq->q.prev);
        return NULL;
    }

    if (tq->q.next == &tq->q)
    {
        pthread_mutex_unlock(&tq->mutex);
        applog(LOG_ERR, "CRITICAL: List appears empty but list_empty returned false (corruption)");
        return NULL;
    }

    struct tq_ent *ent = list_entry(tq->q.next, struct tq_ent, q_node);
    if (!ent)
    {
        pthread_mutex_unlock(&tq->mutex);
        applog(LOG_ERR, "CRITICAL: list_entry returned NULL (corruption)");
        return NULL;
    }

    list_del(&ent->q_node);
    pthread_mutex_unlock(&tq->mutex);

    void *r = ent->data;
    free(ent);
    return r;
}
