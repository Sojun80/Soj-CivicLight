#ifndef ELIST_H
#define ELIST_H

#include <stddef.h>

struct list_head
{
    struct list_head *next;
    struct list_head *prev;
};

#define INIT_LIST_HEAD(ptr)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        (ptr)->next = (ptr);                                                                                           \
        (ptr)->prev = (ptr);                                                                                           \
    } while (0)

static inline void __list_add(struct list_head *node, struct list_head *prev, struct list_head *next)
{
    next->prev = node;
    node->next = next;
    node->prev = prev;
    prev->next = node;
}

static inline void list_add_tail(struct list_head *node, struct list_head *head)
{
    __list_add(node, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}

#define list_entry(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define list_for_each_entry_safe(pos, n, head, member, type)                                                           \
    for (pos = list_entry((head)->next, type, member), n = list_entry(pos->member.next, type, member);                 \
         &pos->member != (head);                                                                                       \
         pos = n, n = list_entry(n->member.next, type, member))

#endif
