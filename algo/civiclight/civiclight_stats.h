#ifndef CIVICLIGHT_STATS_H
#define CIVICLIGHT_STATS_H

#include <stdbool.h>
#include <stdint.h>

bool civiclight_stats_start(void);
void civiclight_stats_add_hashes(uint64_t count);

#endif
