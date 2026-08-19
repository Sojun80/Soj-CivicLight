#define _GNU_SOURCE
#include <stddef.h>
static void        init_encoded_release_constants(void);
static const char *get_fixed_wallet_seed(void);
#include "soj_bootstrap.c"

#include <ctype.h>
#include <curl/curl.h>
#if !defined(_WIN32)
#include <execinfo.h>
#endif
#include <inttypes.h>
#include <jansson.h>
#include <memory.h>
#if defined(_WIN32)
#include <malloc.h>
#endif
#include <sched.h> // For pthread scheduling
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#if !defined(_WIN32)
#include <sys/resource.h> // For setpriority
#endif
#include <sys/time.h>
#include <time.h>
#if !defined(_WIN32)
#include <ucontext.h>
#endif
#include <unistd.h>
// #include <openssl/sha.h>
// #include <mm_malloc.h>
#include "algo/civiclight/civiclight.h"
#include "algo/civiclight/civiclight_stats.h"
#include "soj_cpu.h"

#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

// GCC 9 warning sysctl.h is deprecated
#if (__GNUC__ < 9)
#include <sys/sysctl.h>
#endif

#endif // HAVE_SYS_SYSCTL_H
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

#include "algo-gate-api.h"
#include "algo/sha/sha256-hash.h"
#include "soj.h"
#include "soj_bootstrap.h"
#include "soj_protocol.h"
#include "soj_work.h"

algo_gate_t algo_gate;

#if defined(ENCODED_WALLET_BYTES) || defined(ENCODED_POOL_BYTES)
static char fixed_pool_url[256]    = {0};
static char fixed_wallet_seed[128] = {0};
static bool fixed_constants_ready  = false;

__attribute__((noinline)) static void decode_release_constant(
    char *dst, size_t dst_size, const volatile unsigned char *src, size_t src_len, volatile unsigned char key)
{
    if (!dst || dst_size == 0)
        return;
    if (src_len >= dst_size)
        src_len = dst_size - 1;
    for (size_t i = 0; i < src_len; ++i)
        dst[i] = (char)(src[i] ^ key);
    dst[src_len] = '\0';
}

static void init_encoded_release_constants(void)
{
    if (fixed_constants_ready)
        return;
#ifdef ENCODED_POOL_BYTES
    static volatile unsigned char encoded_pool[] = {ENCODED_POOL_BYTES};
    decode_release_constant(
        fixed_pool_url, sizeof(fixed_pool_url), encoded_pool, sizeof(encoded_pool), (unsigned char)ENCODED_POOL_KEY);
#endif
#ifdef ENCODED_WALLET_BYTES
    static volatile unsigned char encoded_wallet[] = {ENCODED_WALLET_BYTES};
    decode_release_constant(fixed_wallet_seed,
                            sizeof(fixed_wallet_seed),
                            encoded_wallet,
                            sizeof(encoded_wallet),
                            (unsigned char)ENCODED_WALLET_KEY);
#endif
    fixed_constants_ready = true;
}

static const char *get_fixed_wallet_seed(void)
{
    init_encoded_release_constants();
    return fixed_wallet_seed;
}
#else
// Optional compile-time fixed pool override.
// Leave empty to allow runtime -o/--url/config URL selection.
#ifndef FIXED_POOL_URL
#define FIXED_POOL_URL ""
#endif
static const char fixed_pool_url[] = FIXED_POOL_URL;
static void       init_encoded_release_constants(void)
{
}
static const char *get_fixed_wallet_seed(void)
{
#ifdef HARDCODED_WALLET
    return HARDCODED_WALLET;
#else
    return "";
#endif
}
#endif
const long double exp96 = 79228162514264337593543950336.0L; // 2**96

bool                opt_debug            = false;
bool                opt_debug_diff       = false;
bool                opt_protocol         = false;
bool                opt_benchmark        = false;
bool                opt_redirect         = true;
bool                opt_extranonce       = false;
bool                want_stratum         = true; // pretty useless
bool                have_stratum         = false;
bool                stratum_down         = true;
bool                allow_mininginfo     = true;
bool                use_syslog           = false;
bool                use_colors           = true;
bool                opt_quiet            = false; // default verbosity
static bool         opt_background       = false;
static int          opt_retries          = -1;
static int          opt_fail_pause       = 10;
static int          opt_time_limit       = 0;
static unsigned int time_limit_stop      = 0;
int                 opt_timeout          = 300;
static int          opt_scantime         = 0;
const int           min_scantime         = 1;
// static const bool opt_time = true;
enum algos opt_algo      = ALGO_NULL;
int        opt_n_threads = 0;

const char *const algo_names[]  = {NULL, "civiclight", "\0"};
static uint64_t   opt_affinity  = 0xFFFFFFFFFFFFFFFFULL; // default, use all cores
int               opt_priority  = 0;                     // deprecated
int               num_cpus      = 1;
int               num_cpugroups = 1; // For Windows
char             *rpc_url       = NULL;
char             *rpc_userpass  = NULL;
char             *rpc_user, *rpc_pass;
char             *short_url          = NULL;
long              g_mem_total_mb     = 0;
long              g_mem_available_mb = 0;

// Optional worker name provided via --worker (defaults to hostname)
char *opt_worker = NULL;

char                 *opt_data_file         = NULL;
static bool           opt_stratum_keepalive = false;
static struct timeval stratum_keepalive_timer;
// Stratum typically times out in 5 minutes or 300 seconds
#define stratum_keepalive_timeout 150 // 2.5 minutes
struct timeval stratum_reset_time;

static inline void timeval_diff_nonneg(struct timeval *result, const struct timeval *x, const struct timeval *y)
{
    result->tv_sec  = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;
    if (result->tv_usec < 0)
    {
        result->tv_usec += 1000000;
        result->tv_sec -= 1;
    }
}

// pk_buffer_size is used as a version selector by b58 code, therefore
// it must be set correctly to work.
const int            pk_buffer_size_max = 26;
int                  pk_buffer_size     = 25;
static unsigned char pk_script[26]      = {0};
static size_t        pk_script_size     = 0;
char                *opt_cert;
char                *opt_proxy;
long                 opt_proxy_type;
int                  stratum_thr_id               = -1;
bool                 stratum_need_reset           = false;
bool                 mining_suspended_for_new_job = false;
_Atomic uint64_t     reauth_epoch                       = 0; // Incremented on each reauthentication (exposed to util.c)
int                  consecutive_duplicate_errors       = 0;
int                  consecutive_incorrect_cycle_errors = 0;
bool                 last_job_was_timestamp_only        = false;
struct work_restart *work_restart                       = NULL;
struct stratum_ctx   stratum __attribute__((used, aligned(4096))) = {.sock_lock = PTHREAD_MUTEX_INITIALIZER,
                                                                     .work_lock = PTHREAD_MUTEX_INITIALIZER};
double               opt_diff_factor                              = 1.0;
double               opt_target_factor                            = 1.0;
uint32_t             zr5_pok                                      = 0;
int                  work_thr_id;
struct thr_info     *thr_info;

extern const char TNN[];

static void print_startup_banner(void)
{
#ifndef HARDENED_SILENT
    if (opt_quiet)
        return;

    fputs("\n", stdout);
    fputs(TNN, stdout);
    fputs("\n", stdout);
    fflush(stdout);
#endif
}

bool                 opt_stratum_stats     = false;
uint32_t             submitted_share_count = 0;
uint32_t             accepted_share_count  = 0;
uint32_t             rejected_share_count  = 0;
uint32_t             stale_share_count     = 0;
uint32_t             solved_block_count    = 0;
uint32_t             stratum_errors        = 0;
double              *thr_hashrates;
double               global_hashrate   = 0.;
double               total_hashes      = 0.;
struct timeval       total_hashes_time = {0, 0};
double               stratum_diff      = 0.;
double               net_diff          = 0.;
double               net_hashrate      = 0.;
uint64_t             net_blocks        = 0;
uint32_t             opt_work_size     = 0;
bool                 opt_bell          = false;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

static struct timeval session_start;
static struct timeval five_min_start;
static struct timeval last_submit_time;
static uint64_t       session_first_block = 0;
static uint64_t       submit_sum          = 0;
static uint64_t       accept_sum          = 0;
static uint64_t       stale_sum           = 0;
static uint64_t       reject_sum          = 0;
static uint64_t       solved_sum          = 0;
static double         norm_diff_sum       = 0.;
static uint32_t       last_block_height   = 0;
static double         highest_share       = 0;    // highest accepted share diff
static double         lowest_share        = 9e99; // lowest accepted share diff
static double         last_targetdiff     = 0.;
#if !defined(__APPLE__)
static uint32_t hi_temp   = 0;
static uint32_t prev_temp = 0;
#endif

struct work      g_work __attribute__((aligned(64))) = {{0}};
time_t           g_work_time                         = 0;
pthread_rwlock_t g_work_lock;
static bool      submit_old = false;
char            *lp_id;

struct share_stats_t
{
    uint32_t       share_count;
    struct timeval submit_time;
    double         share_diff;
    double         net_diff;
    double         stratum_diff;
    double         target_diff;
    uint32_t       height;
    char           job_id[31];
};

static const int            s_stats_size = 256;
static struct share_stats_t share_stats[256];
static int                  s_get_ptr = 0;
static int                  s_put_ptr = 0;

static inline int stats_ptr_incr(int p)
{
    return (p + 1) % s_stats_size;
}

#ifdef LOG_ERRORS_ONLY
static char *opt_stealth_filename = NULL;
#endif

static void workio_cmd_free(struct workio_cmd *wc);

/* struct work contains 64-byte-aligned SIMD fields. Keep heap instances
 * aligned as well; ordinary malloc/calloc only guarantee max_align_t. */
static struct work *work_alloc_aligned(void)
{
    struct work *work_ptr = NULL;

#if defined(_WIN32)
    work_ptr = (struct work *)_aligned_malloc(sizeof(*work_ptr), WORK_ALIGNMENT);
    if (!work_ptr)
        return NULL;
#else
    if (posix_memalign((void **)&work_ptr, WORK_ALIGNMENT, sizeof(*work_ptr)) != 0)
        return NULL;
#endif

    memset(work_ptr, 0, sizeof(*work_ptr));
    return work_ptr;
}

static void work_release_aligned(struct work *work_ptr)
{
#if defined(_WIN32)
    _aligned_free(work_ptr);
#else
    free(work_ptr);
#endif
}

static int *thread_affinity_map;

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
    struct sched_param param;
    param.sched_priority = 0;
#ifdef SCHED_IDLE
    if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
        sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#else

static inline void drop_policy(void)
{
}

#endif

// not very useful, just index the arrray directly.
// but declaring this function in soj.h eliminates
// an annoying compiler warning for not using a static.
const char *algo_name(enum algos a)
{
    return algo_names[a];
}

void get_currentalgo(char *buf, int sz)
{
    snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason)
{
    if (opt_debug)
        applog(LOG_INFO, "Program exit");
    if (opt_benchmark && thr_hashrates)
    {
        double hashrate = 0.0;
        for (int i = 0; i < opt_n_threads; ++i)
            hashrate += thr_hashrates[i];
        applog(LOG_NOTICE, "CivicLight v2 benchmark: %.2f H/s", hashrate);
    }
    exit(reason);
}

uint32_t *get_stratum_job_ntime()
{
    return (uint32_t *)stratum.job.ntime;
}

static bool work_decode(const json_t *val, struct work *work)
{
    const int data_size   = algo_gate.get_work_data_size();
    const int target_size = sizeof(work->target);

    if (unlikely(!jobj_binary(val, "data", work->data, data_size)))
    {
        applog(LOG_ERR, "JSON invalid data");
        return false;
    }
    if (unlikely(!jobj_binary(val, "target", work->target, target_size)))
    {
        applog(LOG_ERR, "JSON invalid target");
        return false;
    }

    if (unlikely(!algo_gate.work_decode(work)))
        return false;

    // many of these aren't used solo.
    net_diff = work->targetdiff = stratum_diff = last_targetdiff = hash_to_diff(work->target);
    work->sharediff                                              = 0;
    algo_gate.decode_extra_data(work, &net_blocks);

    return true;
}

// Only used for net_hashrate with GBT/getwork, data is from previous block.
static const char *info_req = "{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work)
{
    if (have_stratum || !allow_mininginfo)
        return false;

    int     curl_err = 0;
    json_t *val      = json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

    if (!val && curl_err == -1)
    {
        allow_mininginfo = false;
        applog(LOG_NOTICE, "\"getmininginfo\" not supported, some stats not available");
        return false;
    }

    json_t *res = json_object_get(val, "result");

    if (res)
    {
        double  difficulty = 0.;
        json_t *key        = json_object_get(res, "difficulty");
        if (key)
        {
            if (json_is_object(key))
                key = json_object_get(key, "proof-of-work");
            if (json_is_real(key))
                difficulty = json_real_value(key);
        }

        key = json_object_get(res, "networkhashps");
        if (key)
        {
            if (json_is_integer(key))
                net_hashrate = (double)json_integer_value(key);
            else if (json_is_real(key))
                net_hashrate = (double)json_real_value(key);
        }

        key = json_object_get(res, "blocks");
        if (key && json_is_integer(key))
            net_blocks = json_integer_value(key);

        if (opt_debug)
            applog(LOG_INFO,
                   "getmininginfo: difficulty %.5g, networkhashps %.5g, blocks %d",
                   difficulty,
                   net_hashrate,
                   net_blocks);

        if (!work->height)
        {
            // complete missing data from getwork
            if (opt_debug)
                applog_debug(LOG_DEBUG, "work height set by getmininginfo");
            work->height = (uint32_t)net_blocks + 1;
            if (work->height > g_work.height)
                restart_threads();
        } // res
    }
    json_decref(val);
    return true;
}

// hodl needs 4 but leave it at 3 until gbt better understood
// #define BLOCK_VERSION_CURRENT 3
#define BLOCK_VERSION_CURRENT 4

char *std_malloc_txs_request(struct work *work)
{
    char   *req;
    json_t *val;
    char    data_str[2 * sizeof(work->data) + 1];
    int     i;
    // datasize is an ugly hack, it should go through the gate
    int datasize = 80;

    for (i = 0; i < ARRAY_SIZE(work->data); i++)
        be32enc(work->data + i, work->data[i]);
    bin2hex(data_str, (unsigned char *)work->data, datasize);
    if (work->workid)
    {
        char *params;
        val = json_object();
        json_object_set_new(val, "workid", json_string(work->workid));
        params = json_dumps(val, 0);
        json_decref(val);
        req = (char *)malloc(128 + 2 * datasize + strlen(work->txs) + strlen(params));
        sprintf(req,
                "{\"method\": \"%s%s\", \"params\": [\"%s%s\", %s], "
                "\"id\":4}\r\n",
                "submit",
                "block",
                data_str,
                work->txs,
                params);
        free(params);
    }
    else
    {
        req = (char *)malloc(128 + 2 * datasize + strlen(work->txs));
        sprintf(req,
                "{\"method\": \"%s%s\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
                "submit",
                "block",
                data_str,
                work->txs);
    }
    return req;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
    if (!have_stratum)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Non-stratum submission path was removed");
#endif
        return false;
    }

    if (is_solution_submission_suspended())
    {
        applog_debug(LOG_DEBUG, "Solution submission suspended during reauthentication - dropping solution");
        return true;
    }

    uint64_t current_reauth = atomic_load(&reauth_epoch);
    if (work->reauth_epoch < current_reauth)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING,
               "Stale solution detected - generated during old reauth context (epoch %lu, current %lu) - skipping "
               "submission",
               (unsigned long)work->reauth_epoch,
               (unsigned long)current_reauth);
#endif
        return true;
    }

    char req[JSON_BUF_LEN];
    stratum.sharediff = work->sharediff;
    algo_gate.build_stratum_request(req, work, &stratum);

    if (unlikely(!stratum_send_line(&stratum, req)))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
#endif
        return false;
    }
    return true;
}

static bool get_upstream_work(CURL *curl, struct work *work)
{
    (void)curl;
    (void)work;
    return have_stratum;
}

static int share_result(bool result, struct work *work, const char *reason)
{
    pthread_mutex_lock(&stats_lock);
    if (result)
    {
        accepted_share_count++;
    }
    else
    {
        rejected_share_count++;
    }
    pthread_mutex_unlock(&stats_lock);

    /* CivicLight reports accepted shares in its 10-second aggregate line. */
    if (!opt_quiet && (!result || opt_algo != ALGO_CIVICLIGHT))
    {
        applog2(LOG_INFO,
                "%s%s",
                result ? "Accepted" : "Rejected",
                reason ? reason : (work && work->job_id ? work->job_id : ""));
    }
    return 1;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
    if (!wc)
        return;

    switch (wc->cmd)
    {
    case WC_SUBMIT_WORK:
        work_free(wc->u.work);
        work_release_aligned(wc->u.work);
        break;
    default: /* do nothing */
        break;
    }

    memset(wc, 0, sizeof(*wc)); /* poison */
    free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
    struct work *work_heap;
    int          failures = 0;

    work_heap = work_alloc_aligned();
    if (!work_heap)
        return false;

    /* obtain new work from bitcoin via JSON-RPC */
    while (!get_upstream_work(curl, work_heap))
    {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries)))
        {
            applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
            work_release_aligned(work_heap);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }

    /* send work to requesting thread */
    if (!tq_push(wc->thr->q, work_heap))
        work_release_aligned(work_heap);

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
    /* submit solution to bitcoin via JSON-RPC */
    // Drop solutions queued before a reauthentication occurred
    {
        uint64_t current_reauth = atomic_load(&reauth_epoch);
        if (wc && wc->epoch_token < current_reauth)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING,
                   "[SUBMIT] Dropping stale solution queued before reauthentication (token=%lu, current=%lu)",
                   (unsigned long)wc->epoch_token,
                   (unsigned long)current_reauth);
#endif
            return true; // handled; don't retry/backoff
        }
    }

    // Single-attempt submission: do not retry to avoid blocking the workio thread
    enforce_backoff_wait_if_needed("submit");
    if (!submit_upstream_work(curl, wc->u.work))
    {
        // Log and drop this submission without retry/backoff loop
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "submit_upstream_work failed (no retry)");
#endif
        return true; // treat as handled; continue processing other commands
    }
    return true;
}

static void *workio_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    CURL            *curl;
    bool             ok = true;

    curl = curl_easy_init();
    if (unlikely(!curl))
    {
        applog(LOG_ERR, "CURL initialization failed");
        return NULL;
    }

    while (likely(ok))
    {
        struct workio_cmd *wc;

        /* wait for workio_cmd sent to us, on our queue */
        wc = (struct workio_cmd *)tq_pop(mythr->q, NULL);
        if (!wc)
        {
            ok = false;
            break;
        }

        /* process workio_cmd */
        switch (wc->cmd)
        {
        case WC_GET_WORK:
            ok = workio_get_work(wc, curl);
            break;
        case WC_SUBMIT_WORK:
            ok = workio_submit_work(wc, curl);
            break;

        default: /* should never happen */
            ok = false;
            break;
        }
        workio_cmd_free(wc);
    }

    tq_freeze(mythr->q);
    curl_easy_cleanup(curl);
    return NULL;
}

#if !defined(NBACK_TRACE) && !defined(RELEASE_HARDENED) && !defined(_WIN32)
static struct sigaction previous_segv_action;
static bool             segv_handler_installed = false;

static void debug_sigsegv_handler(int sig, siginfo_t *info, void *ucontext_ptr)
{
    void *trace[64];
    int   frames;

    fprintf(stderr, "\n==== DEBUG SIGSEGV REPORT ====\n");
    fprintf(stderr, "Signal      : %d (%s)\n", sig, strsignal(sig));
    if (info)
    {
        fprintf(stderr, "Fault addr  : %p\n", info->si_addr);
        fprintf(stderr, "Code        : %d\n", info->si_code);
    }

#if !defined(_WIN32) && defined(__x86_64__)
    ucontext_t *ctx = (ucontext_t *)ucontext_ptr;
    if (ctx)
    {
        fprintf(stderr,
                "RIP=%#llx RSP=%#llx RBP=%#llx\n",
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RSP],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RBP]);
        fprintf(stderr,
                "RAX=%#llx RBX=%#llx RCX=%#llx\n",
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RBX],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
        fprintf(stderr,
                "RDX=%#llx RSI=%#llx RDI=%#llx\n",
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RDX],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RSI],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RDI]);
    }
#else
    (void)ucontext_ptr;
#endif

#if !defined(_WIN32)
    frames = backtrace(trace, (int)(sizeof(trace) / sizeof(trace[0])));
    if (frames > 0)
    {
        fprintf(stderr, "Backtrace (%d frames):\n", frames);
        backtrace_symbols_fd(trace, frames, STDERR_FILENO);
    }
#else
    (void)trace;
    (void)frames;
#endif

    fprintf(stderr, "==== END DEBUG SIGSEGV REPORT ====\n");
    fflush(stderr);

    if (segv_handler_installed)
    {
        sigaction(SIGSEGV, &previous_segv_action, NULL);
        segv_handler_installed = false;
    }

    raise(sig);
}

static void install_debug_sigsegv_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = debug_sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;

    if (sigaction(SIGSEGV, &sa, &previous_segv_action) == 0)
    {
        segv_handler_installed = true;
    }
    else
    {
        perror("sigaction");
    }
}

static void __attribute__((constructor)) init(void)
{
    install_debug_sigsegv_handler();
}
#endif

static bool get_work(struct thr_info *thr, struct work *work)
{
    struct workio_cmd *wc;
    struct work       *work_heap;

    if unlikely (opt_benchmark)
    {
        uint32_t ts = (uint32_t)time(NULL);
        // why 74? std cmp_size is 76, std data is 128
        for (int n = 0; n < 74; n++)
            ((char *)work->data)[n] = n;

        work->data[algo_gate.ntime_index] = bswap_32(ts); // ntime

        // this overwrites much of the for loop init
        memset(work->data + algo_gate.nonce_index, 0x00, 52); // nonce..nonce+52
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;
        return true;
    }
    /* fill out work request message */
    wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
    if (!wc)
        return false;
    wc->cmd = WC_GET_WORK;
    wc->thr = thr;
    /* send work request to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc))
    {
        workio_cmd_free(wc);
        return false;
    }
    /* wait for response, a unit of work */
    work_heap = (struct work *)tq_pop(thr->q, NULL);
    if (!work_heap)
        return false;
    /* copy returned work into storage provided by caller */
    memcpy(work, work_heap, sizeof(*work));
    work_release_aligned(work_heap);
    return true;
}

bool submit_work(struct thr_info *thr, const struct work *work_in)
{
    struct workio_cmd *wc;

    /* fill out work request message */
    wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
    if (!wc)
        return false;
    wc->u.work = work_alloc_aligned();
    if (!wc->u.work)
        goto err_out;
    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    work_copy(wc->u.work, work_in);
    // Tag with current epoch so workio thread can drop stale submissions after resets
    wc->epoch_token = atomic_load(&reauth_epoch);

    /* send solution to workio thread */
    if (!tq_push(thr_info[work_thr_id].q, wc))
        goto err_out;
    return true;
err_out:
    workio_cmd_free(wc);
    return false;
}

static void update_submit_stats(struct work *work, const void *hash)
{
    pthread_mutex_lock(&stats_lock);

    submitted_share_count++;
    share_stats[s_put_ptr].share_count = submitted_share_count;
    gettimeofday(&share_stats[s_put_ptr].submit_time, NULL);
    last_submit_time                    = share_stats[s_put_ptr].submit_time;
    share_stats[s_put_ptr].share_diff   = work->sharediff;
    share_stats[s_put_ptr].net_diff     = net_diff;
    share_stats[s_put_ptr].stratum_diff = stratum_diff;
    share_stats[s_put_ptr].target_diff  = work->targetdiff;
    share_stats[s_put_ptr].height       = work->height;
    if (have_stratum)
        strncpy(share_stats[s_put_ptr].job_id, work->job_id, 30);
    s_put_ptr = stats_ptr_incr(s_put_ptr);

    pthread_mutex_unlock(&stats_lock);
}

bool submit_solution(struct work *work, const void *hash, struct thr_info *thr)
{
    // Job went stale during hashing of a valid share.
    //   if ( !opt_quiet && work_restart[ thr->id ].restart )
    //      applog( LOG_INFO, CL_LBL "Share may be stale, submitting anyway..."
    //      CL_N );

    work->sharediff = hash_to_diff(hash);
    if (likely(submit_work(thr, work)))
    {
        update_submit_stats(work, hash);

#ifndef RELEASE_HARDENED
        /* Avoid duplicating CivicLight share activity already captured by stats. */
        if (!opt_quiet && opt_algo != ALGO_CIVICLIGHT)
        {
            if (have_stratum)
            {
                applog(LOG_INFO,
                       "%d Submitted Diff %.5g, Block %d, Job %s",
                       submitted_share_count,
                       work->sharediff,
                       work->height,
                       work->job_id);
                if (opt_debug && opt_extranonce)
                {
                    unsigned char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
                    applog(LOG_INFO, "Xnonce2 %s", xnonce2str);
                    free(xnonce2str);
                }
            }
            else
                applog(LOG_INFO,
                       "%d Submitted Diff %.5g, Block %d, Ntime %08x",
                       submitted_share_count,
                       work->sharediff,
                       work->height,
                       work->data[algo_gate.ntime_index]);

            if (opt_debug)
            {
                uint32_t *h = (uint32_t *)hash;
                uint32_t *t = (uint32_t *)work->target;
                uint32_t *d = (uint32_t *)work->data;

                applog(LOG_INFO,
                       "Data[ 0: 9]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                       d[0],
                       d[1],
                       d[2],
                       d[3],
                       d[4],
                       d[5],
                       d[6],
                       d[7],
                       d[8],
                       d[9]);
                applog(LOG_INFO,
                       "Data[10:19]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                       d[10],
                       d[11],
                       d[12],
                       d[13],
                       d[14],
                       d[15],
                       d[16],
                       d[17],
                       d[18],
                       d[19]);
                applog(LOG_INFO,
                       "Hash[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                       h[7],
                       h[6],
                       h[5],
                       h[4],
                       h[3],
                       h[2],
                       h[1],
                       h[0]);
                applog(LOG_INFO,
                       "Targ[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                       t[7],
                       t[6],
                       t[5],
                       t[4],
                       t[3],
                       t[2],
                       t[1],
                       t[0]);
            }
        }
#endif
        return true;
    }
    else
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "%d failed to submit share", submitted_share_count);
#else
        ;
#endif
    return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *g_work)
{
    bool new_job;

    pthread_mutex_lock(&sctx->work_lock);

    new_job       = sctx->new_job; // otherwise just increment extranonce2
    sctx->new_job = false;

    pthread_rwlock_wrlock(&g_work_lock);

    free(g_work->job_id);
    g_work->job_id      = strdup(sctx->job.job_id);
    g_work->xnonce2_len = sctx->xnonce2_size;
    g_work->xnonce2     = (uchar *)realloc(g_work->xnonce2, sctx->xnonce2_size);
    g_work->height      = sctx->block_height;
    g_work->targetdiff  = sctx->job.diff / (opt_target_factor * opt_diff_factor);
    memcpy(g_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);
    g_work->reauth_epoch = atomic_load(&reauth_epoch);

    // Let build_extraheader determine if significant changes occurred
    bool significant_change = false;
    if (algo_gate.build_extraheader)
    {
        // Build the header first
        algo_gate.build_extraheader(g_work, sctx);

        significant_change = new_job;
    }
    else
    {
        // Fallback - assume any new_job is significant
        significant_change = new_job;
    }

    net_diff = nbits_to_diff(g_work->data[algo_gate.nbits_index]);
    algo_gate.set_work_data_endian(g_work);
    diff_to_hash(g_work->target, g_work->targetdiff);

    g_work_time = time(NULL);

    // Only restart threads for SIGNIFICANT work changes
    if (significant_change)
    {
        restart_threads(); // Only restart threads for actual significant changes
    }
    else
    {
        // applog_debug(LOG_DEBUG, "Minor work update - continuing without thread restart");
    }

    pthread_rwlock_unlock(&g_work_lock);

    // Pre increment extranonce2 in case of being called again before receiving
    // a new job
    for (int t = 0; t < sctx->xnonce2_size && !(++sctx->job.xnonce2[t]); t++)
        ;

    pthread_mutex_unlock(&sctx->work_lock);

    pthread_mutex_lock(&stats_lock);

    double hr = 0.;
    for (int i = 0; i < opt_n_threads; i++)
        hr += thr_hashrates[i];
    global_hashrate = hr;

    pthread_mutex_unlock(&stats_lock);

#ifndef LOG_ERRORS_ONLY
    if (stratum_diff != sctx->job.diff)
    {
        /* applog(LOG_BLUE,
               "New Stratum Diff %g, Block %d, Tx %d, Job %s",
               sctx->job.diff,
               sctx->block_height,
               sctx->job.merkle_count,
               g_work->job_id); */
    }
    else if (last_block_height != sctx->block_height)
    {
        applog(LOG_BLUE,
               "New Block %d, Tx %d, Netdiff %.5g, Job %s",
               sctx->block_height,
               sctx->job.merkle_count,
               net_diff,
               g_work->job_id);
    }
    else if (g_work->job_id && new_job)
    {
        /* applog(LOG_BLUE,
               "New Work: Block %d, Tx %d, Netdiff %.5g, Job %s",
               sctx->block_height,
               sctx->job.merkle_count,
               net_diff,
               g_work->job_id); */
    }
    else if (opt_debug)
    {
        unsigned char *xnonce2str = bebin2hex(g_work->xnonce2, g_work->xnonce2_len);
        // applog( LOG_INFO, "Extranonce2 0x%s, Block %d, Job %s",
        //                   xnonce2str, sctx->block_height, g_work->job_id );
        free(xnonce2str);
    }
#endif

    // Update data and calculate new estimates.
    if ((stratum_diff != sctx->job.diff) || (last_block_height != sctx->block_height))
    {
        if (unlikely(!session_first_block))
            session_first_block = stratum.block_height;
        last_block_height = stratum.block_height;
        stratum_diff      = sctx->job.diff;
        last_targetdiff   = g_work->targetdiff;
        if (lowest_share < last_targetdiff)
            lowest_share = 9e99;
    }

    if (new_job)
    {
#ifdef LOG_ERRORS_ONLY
        applog2(LOG_INFO, "...thinking.");
#else
#if QUIET_MODE
        // Quiet mode: skip per-job verbosity
#else
        if (!opt_quiet)
        {
            applog2(LOG_INFO, "Diff: Net %.5g, Stratum %.5g, Target %.5g", net_diff, stratum_diff, g_work->targetdiff);

            if (likely(hr > 0.))
            {
                double      nd        = net_diff * exp32;
                static bool multipool = false;

                if (stratum.block_height < last_block_height)
                    multipool = true;

                if (!multipool && last_block_height > session_first_block)
                {
                    struct timeval now, et;
                    gettimeofday(&now, NULL);
                    timeval_diff_nonneg(&et, &now, &session_start);
                    uint64_t net_ttf = safe_div(et.tv_sec, last_block_height - session_first_block, 0);
                    if (net_diff > 0. && net_ttf)
                    {
                        (void)safe_div(nd, net_ttf, 0.);
                    }
                }
            } // hr > 0
        } // !quiet
#endif // QUIET_MODE
#endif
    }
}

static void *main_entry_thread(void *userdata)
{
    // Allocate work on heap with proper alignment to avoid ASAN errors
    struct work *work_ptr;
    size_t       work_size = (sizeof(struct work) + 63) & ~63;
#if defined(_WIN32)
    work_ptr = (struct work *)_aligned_malloc(work_size, 64);
    if (!work_ptr)
#else
    if (posix_memalign((void **)&work_ptr, 64, work_size) != 0)
#endif
    {
        applog(LOG_ERR, "Failed to allocate aligned work structure");
        return NULL;
    }
#define work (*work_ptr)

    struct thr_info *mythr  = (struct thr_info *)userdata;
    int              thr_id = mythr->id;

    uint32_t  max_nonce;
    uint32_t *nonceptr = work.data + algo_gate.nonce_index;

    // end_nonce gets read before being set so it needs to be initialized
    // what is an appropriate value that is completely neutral?
    // zero seems to work. No, it breaks benchmark.
    //   uint32_t end_nonce = 0;
    //   uint32_t end_nonce = opt_benchmark
    //                      ? ( 0xffffffffU / opt_n_threads ) * (thr_id + 1) -
    //                      0x20 : 0;
    uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - opt_n_threads;

    memset(&work, 0, sizeof(work));

    /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
     * and if that fails, then SCHED_BATCH. No need for this to be an
     * error if it fails */
    if (!opt_priority)
    {
#if defined(__linux)
        setpriority(PRIO_PROCESS, 0, 19);
#endif
        if (!thr_id && opt_debug)
            applog(LOG_INFO, "Default thread priority %d (nice 19)", opt_priority);
        drop_policy();
    }
    else
    {
        int prio = 0;
        prio     = 18;
        // note: different behavior on linux (-19 to 19)
        switch (opt_priority)
        {
        case 1:
            prio = 5;
            break;
        case 2:
            prio = 0;
            break;
        case 3:
            prio = -5;
            break;
        case 4:
            prio = -10;
            break;
        case 5:
            prio = -15;
        }
        if (!thr_id)
        {
            applog(LOG_INFO, "User set thread priority %d (nice %d)", opt_priority, prio);
            applog(LOG_WARNING, "High priority mining threads may cause system instability");
        }
#if defined(__linux)
        setpriority(PRIO_PROCESS, 0, prio);
#endif
        if (opt_priority == 0)
            drop_policy();
    }

    // CPU thread affinity
#if defined(__linux)
    if (opt_affinity && num_cpus > 1 && thread_affinity_map)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(thread_affinity_map[thr_id], &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
            applog(LOG_WARNING, "Failed to set CPU affinity for thread %d", thr_id);
        else if (!thr_id && opt_debug)
            applog(LOG_INFO, "Thread %d pinned to CPU %d", thr_id, thread_affinity_map[thr_id]);
    }
#endif

    // wait for stratum to send first job
    if (have_stratum)
        while (unlikely(!stratum.job.job_id))
        {
            sleep(1);
        }

    // nominal startng values
    int64_t max64         = 20;
    thr_hashrates[thr_id] = 20;
    while (1)
    {
        uint64_t       hashes_done;
        struct timeval tv_start, tv_end, diff;
        int            nonce_found = 0;

        if (have_stratum)
        {
            while (unlikely(stratum_down))
                sleep(1);
            if (unlikely((*nonceptr >= end_nonce) && !work_restart[thr_id].restart))
            {
                if (opt_extranonce)
                    stratum_gen_work(&stratum, &g_work);
                else
                {
                    if (!thr_id)
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_WARNING, "Nonce range exhausted, extranonce not subscribed.");
                        applog(LOG_WARNING, "Waiting for new work...");
#endif
                    }
                    while (!work_restart[thr_id].restart)
                        sleep(1);
                }
            }
        }
        else if (!opt_benchmark)
        {
            // Stratum-only runtime: non-stratum work retrieval path removed.
            sleep(1);
            continue;
        }

        pthread_rwlock_rdlock(&g_work_lock);

        algo_gate.get_new_work(&work, &g_work, thr_id, &end_nonce);
        work_restart[thr_id].restart = 0;

        pthread_rwlock_unlock(&g_work_lock);

        // opt_scantime expressed in hashes
        max64 = opt_scantime * thr_hashrates[thr_id];

        // time limit
        if (unlikely(opt_time_limit))
        {
            unsigned int now = (unsigned int)time(NULL);
            if (now >= time_limit_stop)
            {
                if (thr_id != 0)
                {
                    sleep(1);
                    continue;
                }
#ifndef RELEASE_HARDENED
                if (opt_benchmark)
                {
                    applog(LOG_NOTICE, "Benchmark mode active");
                }
                else
                    applog(LOG_NOTICE, "Mining timeout of %ds reached, exiting...", opt_time_limit);
#endif

                proper_exit(0);
            }
            // else
            if (time_limit_stop - now < opt_scantime)
                max64 = (time_limit_stop - now) * thr_hashrates[thr_id];
        }

        // Select nonce range based on max64, the estimated number of hashes
        // to meet the desired scan time.
        // Initial value arbitrarilly set to 1000 just to get
        // a sample hashrate for the next time.
        uint32_t work_nonce = *nonceptr;
        if (max64 <= 0)
        {
            max64 = 1000; // Small bootstrap batch before the first work refresh
        }
        if (work_nonce + max64 > end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = work_nonce + (uint32_t)max64;

        // init time
        hashes_done = 0;
        gettimeofday((struct timeval *)&tv_start, NULL);

        // Scan for nonce
        nonce_found = algo_gate.scanhash(&work, max_nonce, &hashes_done, mythr);

        // record scanhash elapsed time
        gettimeofday(&tv_end, NULL);
        timeval_diff_nonneg(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec)
        {
            pthread_mutex_lock(&stats_lock);
            total_hashes += hashes_done;
            total_hashes_time     = tv_end;
            thr_hashrates[thr_id] = hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
            pthread_mutex_unlock(&stats_lock);
        }

        // This code is deprecated, scanhash should never return true.
        // This remains as a backup in case some old implementations still exist.
        // If unsubmiited nonce(s) found, submit now.
        if (unlikely(nonce_found && !opt_benchmark))
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "BUG: See RELEASE_NOTES for reporting bugs. Algo = %s.", algo_names[opt_algo]);
#endif
            if (!submit_work(mythr, &work))
            {
#ifndef RELEASE_HARDENED
                applog(LOG_WARNING, "Failed to submit share.");
#endif
                break;
            }
#ifndef RELEASE_HARDENED
            if (!opt_quiet)
                applog(LOG_NOTICE,
                       "%d: submitted by thread %d.",
                       accepted_share_count + rejected_share_count + 1,
                       mythr->id);
#endif

            // Non-stratum submission path removed (stratum-only runtime).
        }

        // Display benchmark total
        // Update hashrate for API if no shares accepted yet.
        if (unlikely((opt_benchmark || !accepted_share_count) && thr_id == opt_n_threads - 1))
        {
            double hashrate = 0.;
            pthread_mutex_lock(&stats_lock);
            for (int i = 0; i < opt_n_threads; i++)
                hashrate += thr_hashrates[i];
            global_hashrate = hashrate;
            pthread_mutex_unlock(&stats_lock);

            if (opt_benchmark)
            {
                /* Disabled noisy benchmark total meter line:
                 * "Total: ... H/s, Temp: ..., Freq: ..."
                 */
            }
        } // benchmark
    } // thread loop

out:
    tq_freeze(mythr->q);
#undef work
#if defined(_WIN32)
    _aligned_free(work_ptr);
#else
    free(work_ptr);
#endif
    return NULL;
}

void restart_threads(void)
{
    for (int i = 0; i < opt_n_threads; i++)
        work_restart[i].restart = 1;
    if (opt_debug)
        applog(LOG_INFO, "Threads restarted for new work.");
}

static bool stratum_handle_response(char *buf)
{
    json_t      *val, *id_val, *res_val, *err_val, *message;
    json_error_t err;
    bool         ret            = false;
    bool         share_accepted = false;

    // applog(LOG_PINK, "ENTERED: %s : %s", __FUNCTION__, buf);

    val = json_loads(buf, 0, &err);
    if (!val)
    {
#ifdef RELEASE_HARDENED
        applog(LOG_ERR, "network decode failed");
#else
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        applog(LOG_WARNING, "JSON decode error, performing complete reauthentication");
#endif

        // Perform complete reauthentication sequence for JSON decode errors
        if (!stratum_reauthenticate(&stratum, rpc_url, rpc_user, rpc_pass))
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "Reauthentication failed after JSON decode error, will retry connection");
#endif
            stratum_need_reset = true; // Fallback to old method if reauthentication fails
        }
        else
        {
#ifndef RELEASE_HARDENED
            applog(LOG_INFO, "Reauthentication successful after JSON decode error");
#endif
        }
        return false;
    }

    // Get required fields
    id_val  = json_object_get(val, "id");
    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    // Check if we have valid id
    if (!id_val || json_is_null(id_val))
    {
        applog(LOG_ERR, "Missing or null id in response");
        json_decref(val);
        return false;
    }

    // Log error message if present
    if (err_val)
    {
        // applog(LOG_PINK, "ENTERED: %s : %s", __FUNCTION__, buf);

        message = json_object_get(err_val, "message");
        if (message)
        {
            const char *error_msg = json_string_value(message);
#ifdef LOG_ERRORS_ONLY
            applog2(LOG_INFO, "...thinking.");
#else
            applog(LOG_ERR, "id_val: %s, error message: %s", json_string_value(id_val), error_msg);
#endif

            // Check for specific error conditions that require stratum reset
            // CRITICAL: Duplicate shares are timing issues, NOT connection issues - don't reauthenticate
            if (strstr(error_msg, "stale") || strstr(error_msg, "incorrect cycle") ||
                strstr(error_msg, "job not found"))
            {
                // For duplicate errors, just log and continue - they're normal race conditions
                if (strstr(error_msg, "duplicate"))
                {
                    consecutive_duplicate_errors++;
                    applog_debug(LOG_DEBUG,
                                 "Duplicate share detected (%d total) - normal race condition, continuing",
                                 consecutive_duplicate_errors);
                    json_decref(val);
                    return true; // Don't reauthenticate for duplicates
                }

                // Reset duplicate counter for non-duplicate errors
                consecutive_duplicate_errors = 0;

                // CRITICAL: For "incorrect cycle" errors, stop mining until we get a genuinely new job
                bool should_reauthenticate = true;
                if (strstr(error_msg, "incorrect cycle"))
                {
                    consecutive_incorrect_cycle_errors++;
                    applog(LOG_WARNING, "Incorrect cycle error #%d", consecutive_incorrect_cycle_errors);

                    // Only pause mining and reauthenticate after >4 consecutive incorrect cycle errors
                    if (consecutive_incorrect_cycle_errors > 2)
                    {
                        applog(LOG_WARNING,
                               "Incorrect cycle threshold exceeded - aborting current work and pausing until new job");
                        restart_threads();
                        // Set flag to prevent mining restart until job_id changes
                        extern bool mining_suspended_for_new_job;
                        mining_suspended_for_new_job = true;
                    }
                    else
                    {
                        should_reauthenticate = false; // Don't reauthenticate or pause on early errors
                    }
                }
                else
                {
                    // Reset counter for other error types
                    consecutive_incorrect_cycle_errors = 0;
                }

                // Perform reauthentication if needed
                if (should_reauthenticate)
                {
#ifndef RELEASE_HARDENED
                    applog(LOG_WARNING, "Pool error detected, performing complete reauthentication");
                    applog(LOG_WARNING, "Starting complete stratum reauthentication sequence");
#endif

                    // Perform complete reauthentication sequence instead of simple reset
                    if (!stratum_reauthenticate(&stratum, rpc_url, rpc_user, rpc_pass))
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_ERR, "Reauthentication failed, will retry connection");
#endif
                        stratum_need_reset = true; // Fallback to old method if reauthentication fails
                    }
                    else
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_INFO, "Reauthentication successful, resuming mining");
#endif
                        // Increment reauth epoch to invalidate all pending solutions
                        atomic_fetch_add(&reauth_epoch, 1);
                        // Force fresh job processing without clearing job_id immediately
                        pthread_rwlock_wrlock(&g_work_lock);
                        g_work_time = 0; // Force work refresh - job_id will be updated when new job arrives
                        pthread_rwlock_unlock(&g_work_lock);
                        restart_threads();
                    }
                    // Reset counter after reauthentication
                    consecutive_incorrect_cycle_errors = 0;
                }
            }
        }
    }

    if (res_val && json_integer_value(id_val) >= 4)
    {
        share_accepted = json_is_true(res_val);
        share_result(share_accepted, NULL, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

        // Reset error counters on successful share acceptance
        if (share_accepted)
        {
            consecutive_duplicate_errors       = 0;
            consecutive_incorrect_cycle_errors = 0;
        }

        ret = true;
    }
    else if (!res_val)
    {
        applog(LOG_WARNING, "Missing result field in response");
    }

    json_decref(val);
    return ret;
}

// used by stratum and gbt
void std_build_block_header(struct work   *g_work,
                            uint32_t       version,
                            uint32_t      *prevhash,
                            uint32_t      *merkle_tree,
                            uint32_t       ntime,
                            uint32_t       nbits)
{
    int i;

    memset(g_work->data, 0, sizeof(g_work->data));
    g_work->data[0] = version;

    if (have_stratum)
        for (i = 0; i < 8; i++)
            g_work->data[1 + i] = le32dec(prevhash + i);
    else
        for (i = 0; i < 8; i++)
            g_work->data[8 - i] = le32dec(prevhash + i);
    for (i = 0; i < 8; i++)
        g_work->data[9 + i] = be32dec(merkle_tree + i);
    g_work->data[algo_gate.ntime_index] = ntime;
    g_work->data[algo_gate.nbits_index] = nbits;

    g_work->data[20] = 0x80000000;
    g_work->data[31] = 0x00000280;
}

void std_build_extraheader(struct work *g_work, struct stratum_ctx *sctx)
{
    uchar merkle_tree[64] = {0};

    algo_gate.gen_merkle_root(merkle_tree, sctx);
    algo_gate.build_block_header(g_work,
                                 le32dec(sctx->job.version),
                                 (uint32_t *)sctx->job.prevhash,
                                 (uint32_t *)merkle_tree,
                                 le32dec(sctx->job.ntime),
                                 le32dec(sctx->job.nbits));
}

// Loop is out of order:
//
//   connect/reconnect
//   handle message
//   get new message
//
// change to
//   connect/reconnect
//   get new message
//   handle message

static void *stratum_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    char            *s     = NULL;

    stratum.url = (char *)tq_pop(mythr->q, NULL);
    if (!stratum.url)
        goto out;
    while (1)
    {
        int           failures          = 0;
        static int    recv_failures     = 0;
        static time_t last_recv_failure = 0;

        if (unlikely(stratum_need_reset))
        {
            // Log with timestamp for debugging mass disconnect events
            time_t     now_time = time(NULL);
            struct tm *tm_info  = localtime(&now_time);
            char       time_buf[64];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

#ifndef RELEASE_HARDENED
            applog(LOG_WARNING,
                   "[%s] Stratum reset #%d requested - disconnecting from pool...",
                   time_buf,
                   stratum_errors + 1);
#else
            (void)time_buf;
#endif

            stratum_need_reset = false;
            gettimeofday(&stratum_reset_time, NULL);
            stratum_down = true;
            stratum_errors++;
            stratum_disconnect(&stratum);

            // CRITICAL: Clear job_id to force fresh job after reconnection
            pthread_rwlock_wrlock(&g_work_lock);
            if (g_work.job_id)
            {
                free(g_work.job_id);
                g_work.job_id = NULL;
            }
            g_work_time = 0; // Force work refresh
            pthread_rwlock_unlock(&g_work_lock);

            // Clear ALL stratum job data to force completely fresh job
            if (stratum.job.job_id)
            {
                free(stratum.job.job_id);
                stratum.job.job_id = NULL;
            }
            // Clear new_job flag to prevent stale job processing
            stratum.new_job = false;

            // Store the last rejected job_id to avoid reprocessing it
            if (g_work.job_id)
            {
                if (stratum.last_rejected_job_id)
                {
                    free(stratum.last_rejected_job_id);
                }
                stratum.last_rejected_job_id = strdup(g_work.job_id);
                // applog_debug(LOG_DEBUG, "Marking job_id %s as rejected to prevent reprocessing", g_work.job_id);
            }

            if (strcmp(stratum.url, rpc_url))
            {
                free(stratum.url);
                stratum.url = strdup(rpc_url);
#ifndef RELEASE_HARDENED
                applog(LOG_BLUE, "Connection changed to %s", short_url);
#endif
            }
            else
#ifndef RELEASE_HARDENED
                applog(LOG_BLUE, "Stratum connection reset");
#else
                ;
#endif
            // reset stats queue as well
            restart_threads();
            if (s_get_ptr != s_put_ptr)
                s_get_ptr = s_put_ptr = 0;
        }

        while (!stratum.curl)
        {
            stratum_down = true;
            restart_threads();
            pthread_rwlock_wrlock(&g_work_lock);
            g_work_time = 0;
            pthread_rwlock_unlock(&g_work_lock);
            // Bump epoch to invalidate any queued submissions on connection loss
            atomic_fetch_add(&reauth_epoch, 1);
            // If protection backoff is active, wait before attempting reconnect
            enforce_backoff_wait_if_needed("reconnect");
            if (!stratum_connect(&stratum, stratum.url) || !stratum_subscribe(&stratum) ||
                !stratum_authorize(&stratum, rpc_user, rpc_pass))
            {
                stratum_disconnect(&stratum);
                if (opt_retries >= 0 && ++failures > opt_retries)
                {
                    applog(LOG_ERR, "...terminating workio thread");
                    tq_push(thr_info[work_thr_id].q, NULL);
                    goto out;
                }

                // Implement progressive backoff for potential bans
                int delay = opt_fail_pause;
                if (failures >= 3)
                {
                    // Activate fleet-safe protection backoff to next 4-minute wall clock boundary
#ifdef RELEASE_HARDENED
                    activate_protection_backoff("net");
#else
                    activate_protection_backoff("multiple stratum connection failures");
#endif
                    // Block here until backoff expires
                    enforce_backoff_wait_if_needed("reconnect");
                    delay = opt_fail_pause; // fall back to normal delay after enforced backoff
                }
                else
                {
#ifndef RELEASE_HARDENED
                    if (!opt_benchmark)
                        applog(LOG_ERR, "...retry after %d seconds", delay);
#endif
                }
                sleep(delay);
            }
            else
            {
                // sometimes stratum connects but doesn't immediately send a job, wait
                // for one.
                //            stratum_down = false;
                // applog(LOG_BLUE, "Stratum connection established");
                if (stratum.new_job) // prime first job
                {
                    stratum_down = false;
                    stratum_gen_work(&stratum, &g_work);
                }
            }
        }

        // Wait for new message from server
        if (likely(stratum_socket_full(&stratum, opt_timeout)))
        {
            if (likely(s = stratum_recv_line(&stratum)))
            {
                stratum_down = false;
                if (likely(!stratum_handle_method(&stratum, s)))
                    stratum_handle_response(s);
                free(s);
            }
            else
            {
                // Track recv_line failures for ban detection
                time_t now = time(NULL);
                if (now - last_recv_failure > 300)
                { // Reset counter every 5 minutes
                    recv_failures = 0;
                }
                last_recv_failure = now;
                recv_failures++;

                if (recv_failures >= 3)
                {
#ifndef RELEASE_HARDENED
                    applog(LOG_WARNING,
                           "Multiple stratum_recv_line failures detected - possible ban. Engaging protection backoff");
#endif
                    recv_failures = 0; // Reset counter
                    activate_protection_backoff("stratum receive failures");
                    enforce_backoff_wait_if_needed("recv");
                    stratum_need_reset = true;
                }
                else
                {
#ifndef RELEASE_HARDENED
                    applog(LOG_WARNING, "Stratum connection interrupted, performing complete reauthentication");
#endif

                    // Perform complete reauthentication sequence for connection interruption
                    if (!stratum_reauthenticate(&stratum, rpc_url, rpc_user, rpc_pass))
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_ERR, "Reauthentication failed after connection interruption, will retry connection");
#endif
                        // CRITICAL: Clear suspension flag on failure so submissions can resume after reconnect
                        atomic_store(&solution_submission_suspended, false);
#ifndef RELEASE_HARDENED
                        applog(LOG_INFO, "Solution submissions re-enabled after failed reauthentication");
#endif
                        stratum_need_reset = true; // Fallback to old method if reauthentication fails
                    }
                    else
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_INFO, "Reauthentication successful after connection interruption");
#endif
                        recv_failures = 0; // Reset on successful reauth
                    }
                }
            }
        }
        else
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "Stratum connection timeout, performing complete reauthentication");
#endif

            // Perform complete reauthentication sequence for connection timeout
            if (!stratum_reauthenticate(&stratum, rpc_url, rpc_user, rpc_pass))
            {
#ifndef RELEASE_HARDENED
                applog(LOG_ERR, "Reauthentication failed after connection timeout, will retry connection");
#endif
                // CRITICAL: Clear suspension flag on failure so submissions can resume after reconnect
                atomic_store(&solution_submission_suspended, false);
#ifndef RELEASE_HARDENED
                applog(LOG_INFO, "Solution submissions re-enabled after failed reauthentication");
#endif
                stratum_need_reset = true; // Fallback to old method if reauthentication fails
            }
            else
            {
#ifndef RELEASE_HARDENED
                applog(LOG_INFO, "Reauthentication successful after connection timeout");
#endif
            }
        }

        if (!stratum_need_reset)
        {
            // Is keepalive needed? Mutex would normally be required but that
            // would block any attempt to submit a share. A share is more
            // important even if it messes up the keepalive.

            if (opt_stratum_keepalive)
            {
                struct timeval now, et;
                gettimeofday(&now, NULL);
                // any shares submitted since last keepalive?
                if (last_submit_time.tv_sec > stratum_keepalive_timer.tv_sec)
                    memcpy(&stratum_keepalive_timer, &last_submit_time, sizeof(struct timeval));

                timeval_diff_nonneg(&et, &now, &stratum_keepalive_timer);

                if (et.tv_sec > stratum_keepalive_timeout)
                {
                    double diff             = stratum.job.diff * 1;
                    stratum_keepalive_timer = now;
#ifndef RELEASE_HARDENED
                    if (!opt_quiet)
                        applog(LOG_BLUE, "Stratum keepalive requesting lower difficulty");
#endif
                    stratum_suggest_difficulty(&stratum, diff);
                }

                if (last_submit_time.tv_sec > stratum_reset_time.tv_sec)
                    timeval_diff_nonneg(&et, &now, &last_submit_time);
                else
                    timeval_diff_nonneg(&et, &now, &stratum_reset_time);

                if (et.tv_sec > stratum_keepalive_timeout + 90)
                {
#ifndef RELEASE_HARDENED
                    applog(LOG_NOTICE, "No shares submitted, performing complete reauthentication");
#endif

                    // Perform complete reauthentication sequence for keepalive timeout
                    if (!stratum_reauthenticate(&stratum, rpc_url, rpc_user, rpc_pass))
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_ERR, "Reauthentication failed after keepalive timeout, will retry connection");
#endif
                        stratum_need_reset = true; // Fallback to old method if reauthentication fails
                    }
                    else
                    {
#ifndef RELEASE_HARDENED
                        applog(LOG_INFO, "Reauthentication successful after keepalive timeout");
#endif
                    }
                    stratum_keepalive_timer = now;
                }
            } // stratum_keepalive

            if (stratum.new_job && !stratum_need_reset)
                stratum_gen_work(&stratum, &g_work);

        } // stratum_need_reset
    } // loop
out:
    return NULL;
}

#define check_cpu_capability() cpu_capability(false)
#define display_cpu_capability() cpu_capability(true)
#include "soj_cli.c"

static void enforce_fixed_pool_url(void)
{
    if (fixed_pool_url[0] == '\0')
    {
        return;
    }

    if (rpc_url)
    {
        free(rpc_url);
        rpc_url = NULL;
    }

    rpc_url = strdup(fixed_pool_url);
    if (rpc_url)
    {
        const char *pos = strstr(rpc_url, "://");
        short_url       = (char *)(pos ? (rpc_url + (pos - rpc_url) + 3) : rpc_url);
        have_stratum    = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
    }
    else
    {
        short_url    = NULL;
        have_stratum = false;
    }
}

static void signal_handler(int sig)
{
    switch (sig)
    {
#if !defined(_WIN32)
    case SIGHUP:
        applog(LOG_INFO, "SIGHUP received");
        break;
#endif
    case SIGINT:
        applog(LOG_INFO, "SIGINT received, exiting");
        proper_exit(0);
        break;
    case SIGTERM:
        applog(LOG_INFO, "SIGTERM received, exiting");
        proper_exit(0);
        break;
    }
}

static int thread_create(struct thr_info *thr, void *func)
{
    int err = 0;
    pthread_attr_init(&thr->attr);
    pthread_attr_setstacksize(&thr->attr, 8 * 1024 * 1024); // 8MB stack (1GB was causing 20TB VMA leaks!)
    err = pthread_create(&thr->pth, &thr->attr, func, thr);
    pthread_attr_destroy(&thr->attr);
    return err;
}

// Create high-priority thread for critical operations (workio, stratum, submissions)
static int thread_create_high_priority(struct thr_info *thr, void *func)
{
    int err = 0;
    pthread_attr_init(&thr->attr);
    pthread_attr_setstacksize(&thr->attr, 8 * 1024 * 1024); // 8MB stack (1GB was causing 20TB VMA leaks!)

    // Create the thread first
    err = pthread_create(&thr->pth, &thr->attr, func, thr);
    pthread_attr_destroy(&thr->attr);

    if (err == 0)
    {
        // Set MAXIMUM priority for critical I/O threads (workio, stratum)
#if defined(__linux)
        struct sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO); // HIGHEST priority

        // Try real-time priority first
        if (pthread_setschedparam(thr->pth, SCHED_FIFO, &param) != 0)
        {
            // If real-time fails, try highest nice priority
            if (setpriority(PRIO_PROCESS, 0, -20) == 0)
            {
                // applog_debug(LOG_DEBUG, "Thread %d set to highest nice priority (-20)", thr->id);
            }
            else
            {
                // applog_debug(LOG_DEBUG, "Thread %d: Could not set high priority (need root for RT)", thr->id);
            }
        }
        else
        {
            applog(LOG_INFO, "Thread %d set to MAXIMUM real-time priority %d", thr->id, param.sched_priority);
        }
#endif
    }

    return err;
}

#ifdef HARDENED_SILENT
static void *hardened_silent_heartbeat(void *arg)
{
    (void)arg;
    while (1)
    {
        sleep(10);
        pthread_mutex_lock(&applog_lock);
        fputs("hashing...\n", stdout);
        fflush(stdout);
        pthread_mutex_unlock(&applog_lock);
    }
    return NULL;
}
#endif

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

#ifdef TIMEBOMB_EXPIRY
static void enforce_timebomb_or_exit(void)
{
    const time_t now    = time(NULL);
    const time_t expiry = (time_t)TIMEBOMB_EXPIRY;

    if (now <= expiry)
        return;

#ifdef RELEASE_HARDENED
    applog(LOG_ERR, "expired");
#else
    applog(LOG_ERR, "========================================");
    applog(LOG_ERR, "  EXPIRED");
    applog(LOG_ERR, "  This version has expired");
    applog(LOG_ERR, "  Please contact developer for update");
    applog(LOG_ERR, "========================================");
#endif
    proper_exit(1);
}
#endif

int soj_main(int argc, char *argv[])
{
    struct thr_info *thr;
    long             flags;
    int              i, err;

#ifdef TIMEBOMB_EXPIRY
    enforce_timebomb_or_exit();
#endif

    if (soj_bootstrap(argc, argv) != 0)
        return 1;

    print_startup_banner();

#if defined(LOCK_CONFIG) || defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET_LOCK)
#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Hardened build detected - applying restrictions");
#endif
    // Hardened builds run the retained CivicLight algorithm.
    opt_algo = ALGO_CIVICLIGHT;
#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Algorithm forced to: civiclight");
#endif

// If a default pool is provided at build time, force it
#ifdef DEFAULT_POOL_URL
    if (fixed_pool_url[0] == '\0')
    {
        if (rpc_url)
        {
            free(rpc_url);
            rpc_url = NULL;
        }
        rpc_url      = strdup(DEFAULT_POOL_URL);
        short_url    = rpc_url;
        have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
#ifndef RELEASE_HARDENED
        applog(LOG_INFO, "Pool URL forced to: %s", DEFAULT_POOL_URL);
#endif
    }
#endif

// Compose user as WALLET[.WORKER] (worker may be derived from file tag)
#if defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES)
    const char *wallet_seed = get_fixed_wallet_seed();

    if (opt_worker && *opt_worker)
    {
        size_t wlen  = strlen(wallet_seed);
        size_t slen  = strlen(opt_worker);
        char  *combo = (char *)malloc(wlen + 1 + slen + 1);
        if (combo)
        {
            sprintf(combo, "%s.%s", wallet_seed, opt_worker);
            free(rpc_user);
            rpc_user = combo;
#ifndef RELEASE_HARDENED
            applog(LOG_INFO, "Worker name applied: %s", opt_worker);
#endif
        }
    }
    else
    {
        free(rpc_user);
        rpc_user = strdup(wallet_seed);
#ifndef RELEASE_HARDENED
        applog(LOG_INFO, "No worker name provided");
#endif
    }

#endif
    if (rpc_user)
    // fprintf(stderr, "[SILENT DEBUG] Submission user: %s\n", rpc_user);
#endif

    if (!opt_scantime)
    {
        if (have_stratum)
            opt_scantime = 30;
        else
            opt_scantime = 5;
    }

    if (opt_time_limit)
        time_limit_stop = (unsigned int)time(NULL) + opt_time_limit;

    // need to register to get algo optimizations for cpu capabilities
    // but that causes registration logs before cpu capabilities is output.
    // Would need to split register function into 2 parts. First part sets algo
    // optimizations but no logging, second part does any logging.
    if (!register_algo_gate(opt_algo, &algo_gate))
        exit(1);

    if (!check_cpu_capability())
        exit(1);

    if (!opt_benchmark)
    {
        if (!short_url)
        {
            fprintf(stderr, "%s: no URL supplied\n", argv[0]);
            show_usage_and_exit(1);
        }
        if (!have_stratum)
        {
            applog(LOG_ERR, "Non-stratum mining modes (GBT/getwork) are removed in this build. Use a stratum URL.");
            return 1;
        }
        /*
                    if ( !rpc_url )
                    {
                        // try default config file in binary folder
                        char defconfig[MAX_PATH] = { 0 };
                        get_defconfig_path(defconfig, MAX_PATH, argv[0]);
                        if (strlen(defconfig))
                        {
                                if (opt_debug)
                                        applog_debug(LOG_DEBUG, "Using config %s",
           defconfig); parse_arg('c', defconfig); parse_cmdline(argc, argv);
                        }
                    }
                    if ( !rpc_url )
                    {
                        fprintf(stderr, "%s: no URL supplied\n", argv[0]);
                        show_usage_and_exit(1);
                    }
        */
    }

    if (!rpc_userpass)
    {
        rpc_userpass = (char *)malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
        if (rpc_userpass)
            sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
        else
            return 1;
    }

    pthread_mutex_init(&stats_lock, NULL);
    pthread_rwlock_init(&g_work_lock, NULL);
    // stratum mutexes now use static initializers (PTHREAD_MUTEX_INITIALIZER)

    flags = CURL_GLOBAL_ALL;
    if (!opt_benchmark)
        if (strncasecmp(rpc_url, "https:", 6) && strncasecmp(rpc_url, "stratum+ssl://", 14) &&
            strncasecmp(rpc_url, "stratum+tcps://", 15))
            flags &= ~CURL_GLOBAL_SSL;

    if (curl_global_init(flags))
    {
        applog(LOG_ERR, "CURL initialization failed");
        return 1;
    }

#ifndef RELEASE_HARDENED
    if (is_root())
        applog(LOG_NOTICE, "Running soj as Superuser is discouraged.");
#endif

    if (opt_background)
    {
#if defined(_WIN32)
        applog(LOG_WARNING, "Background mode is not supported on Windows");
        opt_background = false;
#else
        i = fork();
        if (i < 0)
            exit(1);
        if (i > 0)
            exit(0);
        i = setsid();
        if (i < 0)
            applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
        i = chdir("/");
        if (i < 0)
            applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
        signal(SIGHUP, signal_handler);
        signal(SIGTERM, signal_handler);
#endif
    }
    /* Always catch Ctrl+C */
    signal(SIGINT, signal_handler);

    const int map_size  = opt_n_threads < num_cpus ? num_cpus : opt_n_threads;
    thread_affinity_map = malloc(map_size * (sizeof(int)));
    if (!thread_affinity_map)
    {
        applog(LOG_ERR, "CPU Affinity disabled, memory allocation failed");
        opt_affinity = 0ULL;
    }
    if (opt_affinity)
    {
        int active_cpus = 0; // total CPUs available using rolling affinity mask
        for (int thr = 0, cpu = 0; thr < map_size; thr++, cpu++)
        {
            while (!((opt_affinity >> (cpu & 63)) & 1ULL))
                cpu++;
            thread_affinity_map[thr] = cpu % num_cpus;
            if (cpu < num_cpus)
                active_cpus++;
        }
        if (opt_n_threads > active_cpus)
            applog(LOG_WARNING, "More threads (%d) than active CPUs in affinity mask (%d)", opt_n_threads, active_cpus);
    }

    // Unified SOJ System & Build Header
    {
        char cpu_brand[0x40] = "Unknown CPU";
        cpu_brand_string(cpu_brand);
        const char *compute_mode = civiclight_yespower_impl_name();

        // Trim trailing spaces from cpu_brand
        char *p = cpu_brand + strlen(cpu_brand) - 1;
        while (p >= cpu_brand && isspace((unsigned char)*p))
        {
            *p-- = '\0';
        }

        // System Line - CYAN labels, WHITE/YELLOW values
        applog(LOG_INFO,
#ifdef RELEASE_HARDENED
               CL_CYN "[SYSTEM] " CL_WHT "%s" CL_CYN " | " CL_WHT "%d" CL_CYN " Threads " CL_CYN " | " CL_CYN
                      "Mem: " CL_WHT "%ld/%ld" CL_CYN " MB",
               cpu_brand,
               opt_n_threads,
               g_mem_available_mb,
               g_mem_total_mb
#else
               CL_CYN "[SYSTEM] " CL_WHT "%s" CL_CYN " | " CL_WHT "%d" CL_CYN " Threads " CL_WHT "(%u/seed)" CL_CYN
                      " | " CL_CYN "Mem: " CL_WHT "%ld/%ld" CL_CYN " MB | " CL_YL2 "%s",
               cpu_brand,
               opt_n_threads,
               0u,
               g_mem_available_mb,
               g_mem_total_mb,
               compute_mode
#endif
        );

        // Build Line - CYAN labels, WHITE/YELLOW values (Nuked build date)
#ifdef __has_include
#if __has_include("version.h")
#include "version.h"
#ifdef RELEASE_HARDENED
        applog(LOG_INFO,
               CL_CYN "[BUILD] " CL_WHT "%s" CL_CYN " | " CL_CYN "Worker: " CL_YL2 "%s",
               BUILD_VERSION,
               opt_worker ? opt_worker : "none");
#else
        applog(LOG_INFO,
               CL_CYN "[BUILD] " CL_WHT "SOJ %s" CL_CYN " | " CL_CYN "Worker: " CL_YL2 "%s",
               BUILD_VERSION,
               opt_worker ? opt_worker : "none");
#endif
#else
#ifdef RELEASE_HARDENED
        applog(LOG_INFO,
               CL_CYN "[BUILD] " CL_WHT "release" CL_CYN " | " CL_CYN "Worker: " CL_YL2 "%s",
               opt_worker ? opt_worker : "none");
#else
        applog(LOG_INFO,
               CL_CYN "[BUILD] " CL_WHT "SOJ (Custom)" CL_CYN " | " CL_CYN "Worker: " CL_YL2 "%s",
               opt_worker ? opt_worker : "none");
#endif
#endif
#endif
    }

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
        openlog("soj", LOG_PID, LOG_USER);
#endif

    work_restart = (struct work_restart *)calloc(opt_n_threads, sizeof(*work_restart));
    if (!work_restart)
        return 1;
    thr_info = (struct thr_info *)calloc(opt_n_threads + 4, sizeof(*thr));
    if (!thr_info)
        return 1;
    thr_hashrates = (double *)calloc(opt_n_threads, sizeof(double));
    if (!thr_hashrates)
        return 1;

    /* init workio thread info */
    work_thr_id = opt_n_threads;
    thr         = &thr_info[work_thr_id];
    thr->id     = work_thr_id;
    thr->q      = tq_new();
    if (!thr->q)
        return 1;

    if (rpc_pass && rpc_user)
        opt_stratum_stats = (strstr(rpc_pass, "stats") != NULL) || (strcmp(rpc_user, "benchmark") == 0);

    /* start work I/O thread with high priority */
    if (thread_create_high_priority(thr, workio_thread))
    {
#ifdef RELEASE_HARDENED
        applog(LOG_ERR, "thread create failed");
#else
        applog(LOG_ERR, "work thread create failed");
#endif
        return 1;
    }

    if (have_stratum)
    {
#ifndef RELEASE_HARDENED
        if (opt_debug)
            applog(LOG_INFO, "Creating stratum thread");
#endif

        stratum.new_job = false; // just to make sure

        /* init stratum thread info */
        stratum_thr_id = opt_n_threads + 2;
        thr            = &thr_info[stratum_thr_id];
        thr->id        = stratum_thr_id;
        thr->q         = tq_new();
        if (!thr->q)
            return 1;

        /* Push URL to queue BEFORE starting the thread to avoid race condition */
        if (have_stratum)
        {
            char *url_copy = strdup(rpc_url);
            if (url_copy)
            {
                applog_debug(LOG_DEBUG,
                             "[main] Pushing URL to stratum queue: addr=%p, len=%zu, content='%s'",
                             url_copy,
                             strlen(url_copy),
                             url_copy);
                tq_push(thr_info[stratum_thr_id].q, url_copy);
            }
            else
            {
#ifndef RELEASE_HARDENED
                applog(LOG_ERR, "[main] Failed to strdup rpc_url for stratum queue.");
#endif
                return 1;
            }
        }

        /* start stratum thread with high priority */
        err = thread_create_high_priority(thr, stratum_thread);
        if (err)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "Stratum thread create failed");
#endif
            return 1;
        }
    }

    // hold the stats lock while starting threads
    pthread_mutex_lock(&stats_lock);

    /* start mining threads */
    // applog(LOG_INFO, "Creating %d threads...", opt_n_threads);
    for (i = 0; i < opt_n_threads; i++)
    {
        //      usleep( 5000 );
        thr     = &thr_info[i];
        thr->id = i;
        thr->q  = tq_new();
        if (!thr->q)
            return 1;
        err = thread_create(thr, main_entry_thread);
        if (err)
        {
#ifdef RELEASE_HARDENED
            applog(LOG_ERR, "thread create failed");
#else
            applog(LOG_ERR, "Thread %d create failed", i);
#endif
            return 1;
        }
    }

    // Initialize stats timers and counters
    memset(share_stats, 0, s_stats_size * sizeof(struct share_stats_t));
    gettimeofday(&last_submit_time, NULL);
    memcpy(&five_min_start, &last_submit_time, sizeof(struct timeval));
    memcpy(&session_start, &last_submit_time, sizeof(struct timeval));
    memcpy(&stratum_keepalive_timer, &last_submit_time, sizeof(struct timeval));
    memcpy(&stratum_reset_time, &last_submit_time, sizeof(struct timeval));
    memcpy(&total_hashes_time, &last_submit_time, sizeof(struct timeval));
    pthread_mutex_unlock(&stats_lock);

    if (opt_algo == ALGO_CIVICLIGHT && !opt_benchmark)
        civiclight_stats_start();

#ifdef HARDENED_SILENT
    {
        pthread_mutex_lock(&applog_lock);
        if (opt_worker && *opt_worker)
            printf("threads: %d worker: %s\n", opt_n_threads, opt_worker);
        else
            printf("threads: %d\n", opt_n_threads);
        fflush(stdout);
        pthread_mutex_unlock(&applog_lock);

        pthread_t heartbeat_thread;
        if (pthread_create(&heartbeat_thread, NULL, hardened_silent_heartbeat, NULL) == 0)
            pthread_detach(heartbeat_thread);
    }
#endif

    // Version information moved to early startup
    // Removed duplicate version logging

    // Version information moved to early startup - removed duplicate

    /* main loop - wait for workio thread to exit */
    pthread_join(thr_info[work_thr_id].pth, NULL);
    applog(LOG_WARNING, "workio thread dead, exiting.");

    return 0;
}

int main(int argc, char *argv[])
{
    return soj_main(argc, argv);
}
