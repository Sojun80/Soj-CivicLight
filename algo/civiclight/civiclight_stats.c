#include "civiclight_stats.h"
#include "soj.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define CIVICLIGHT_STATS_INTERVAL 10
#define CIVICLIGHT_STATS_SAMPLES 92

typedef struct
{
    struct timeval at;
    double         hashes;
} civiclight_rate_sample_t;

static civiclight_rate_sample_t rate_samples[CIVICLIGHT_STATS_SAMPLES];
static unsigned int             rate_sample_next;
static unsigned int             rate_sample_count;
static pthread_mutex_t          start_lock = PTHREAD_MUTEX_INITIALIZER;
static bool                     stats_started;
static _Atomic uint64_t         civiclight_hashes;

void civiclight_stats_add_hashes(uint64_t count)
{
    atomic_fetch_add_explicit(&civiclight_hashes, count, memory_order_relaxed);
}

static double timeval_seconds(const struct timeval *tv)
{
    return (double)tv->tv_sec + (double)tv->tv_usec * 1e-6;
}

static void format_uptime(double seconds, char *out, size_t out_size)
{
    uint64_t     whole   = seconds > 0.0 ? (uint64_t)seconds : 0;
    uint64_t     hours   = whole / 3600u;
    unsigned int minutes = (unsigned int)((whole / 60u) % 60u);
    unsigned int secs    = (unsigned int)(whole % 60u);
    snprintf(out, out_size, "%02" PRIu64 ":%02u:%02u", hours, minutes, secs);
}

static void format_rate(double rate, char *out, size_t out_size)
{
    static const char *units[] = {"H/s", "kH/s", "MH/s", "GH/s", "TH/s"};
    unsigned int       unit    = 0;
    while (rate >= 1000.0 && unit + 1u < sizeof(units) / sizeof(units[0]))
    {
        rate /= 1000.0;
        unit++;
    }
    snprintf(out, out_size, rate >= 100.0 ? "%.0f %s" : rate >= 10.0 ? "%.1f %s" : "%.2f %s", rate, units[unit]);
}

static void format_work(double hashes, char *out, size_t out_size)
{
    static const char *units[] = {"H", "kH", "MH", "GH", "TH", "PH"};
    unsigned int       unit    = 0;
    while (hashes >= 1000.0 && unit + 1u < sizeof(units) / sizeof(units[0]))
    {
        hashes /= 1000.0;
        unit++;
    }
    snprintf(out, out_size, hashes >= 100.0 ? "%.0f %s" : hashes >= 10.0 ? "%.1f %s" : "%.2f %s", hashes, units[unit]);
}

static void get_memory_gb(double *available_gb, double *total_gb)
{
    FILE *file         = fopen("/proc/meminfo", "r");
    long  total_kb     = 0;
    long  available_kb = 0;
    long  free_kb      = 0;
    char  key[64];
    char  unit[32];
    long  value;

    if (file)
    {
        while (fscanf(file, "%63s %ld %31s", key, &value, unit) == 3)
        {
            if (strcmp(key, "MemTotal:") == 0)
                total_kb = value;
            else if (strcmp(key, "MemAvailable:") == 0)
                available_kb = value;
            else if (strcmp(key, "MemFree:") == 0)
                free_kb = value;
        }
        fclose(file);
    }

    if (available_kb <= 0)
        available_kb = free_kb;
    *available_gb = (double)available_kb / (1024.0 * 1024.0);
    *total_gb     = (double)total_kb / (1024.0 * 1024.0);
}

static double window_rate(const struct timeval *now, double hashes, unsigned int window_seconds)
{
    const double                    now_seconds = timeval_seconds(now);
    const double                    cutoff      = now_seconds - (double)window_seconds;
    const civiclight_rate_sample_t *oldest      = NULL;

    for (unsigned int age = 1; age <= rate_sample_count; age++)
    {
        unsigned int idx = (rate_sample_next + CIVICLIGHT_STATS_SAMPLES - age) % CIVICLIGHT_STATS_SAMPLES;
        const civiclight_rate_sample_t *sample = &rate_samples[idx];
        if (timeval_seconds(&sample->at) < cutoff)
            break;
        oldest = sample;
    }

    if (!oldest)
        return 0.0;
    double elapsed = now_seconds - timeval_seconds(&oldest->at);
    return elapsed > 0.0 ? (hashes - oldest->hashes) / elapsed : 0.0;
}

static void *civiclight_stats_thread(void *unused)
{
    (void)unused;
    struct timeval started;
    gettimeofday(&started, NULL);

    double starting_hashes = (double)atomic_load_explicit(&civiclight_hashes, memory_order_relaxed);

    rate_samples[0].at     = started;
    rate_samples[0].hashes = starting_hashes;
    rate_sample_next       = 1;
    rate_sample_count      = 1;

    for (;;)
    {
        sleep(CIVICLIGHT_STATS_INTERVAL);

        struct timeval now;
        gettimeofday(&now, NULL);

        double hashes = (double)atomic_load_explicit(&civiclight_hashes, memory_order_relaxed);
        pthread_mutex_lock(&stats_lock);
        uint32_t accepted = accepted_share_count;
        uint32_t rejected = rejected_share_count;
        pthread_mutex_unlock(&stats_lock);

        double rate_1m  = window_rate(&now, hashes, 60);
        double rate_5m  = window_rate(&now, hashes, 300);
        double rate_15m = window_rate(&now, hashes, 900);

        rate_samples[rate_sample_next].at     = now;
        rate_samples[rate_sample_next].hashes = hashes;
        rate_sample_next                      = (rate_sample_next + 1u) % CIVICLIGHT_STATS_SAMPLES;
        if (rate_sample_count < CIVICLIGHT_STATS_SAMPLES)
            rate_sample_count++;

        char uptime[32];
        char one_minute[32];
        char five_minutes[32];
        char fifteen_minutes[32];
        char total_work[32];
        format_uptime(timeval_seconds(&now) - timeval_seconds(&started), uptime, sizeof(uptime));
        format_rate(rate_1m, one_minute, sizeof(one_minute));
        format_rate(rate_5m, five_minutes, sizeof(five_minutes));
        format_rate(rate_15m, fifteen_minutes, sizeof(fifteen_minutes));
        format_work(hashes - starting_hashes, total_work, sizeof(total_work));

        double available_gb;
        double total_gb;
        get_memory_gb(&available_gb, &total_gb);

        applog(LOG_BLUE,
               "Stats: %s | 1m: %s | 5m: %s | 15m: %s | Total: %s, %u accepted, %u rejected, free:%.1fgb/%.1fgb",
               uptime,
               one_minute,
               five_minutes,
               fifteen_minutes,
               total_work,
               accepted,
               rejected,
               available_gb,
               total_gb);
    }
    return NULL;
}

bool civiclight_stats_start(void)
{
    pthread_mutex_lock(&start_lock);
    if (!stats_started)
    {
        pthread_t thread;
        if (pthread_create(&thread, NULL, civiclight_stats_thread, NULL) == 0)
        {
            pthread_detach(thread);
            stats_started = true;
        }
        else
        {
            applog(LOG_ERR, "[CIVICLIGHT] Failed to start stats logger thread");
        }
    }
    bool result = stats_started;
    pthread_mutex_unlock(&start_lock);
    return result;
}
