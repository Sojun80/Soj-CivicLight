#ifndef SOJ_H__
#define SOJ_H__

#include "soj_queue.h"
#include <soj-config.h>
#include <sys/types.h>
#include <unistd.h>

// CPU architecture
#if defined(__x86_64__)
#define USER_AGENT_ARCH "x64" // Intel, AMD x86_64
#elif defined(__aarch64__)
#define USER_AGENT_ARCH "arm" // AArch64
#elif defined(__riscv)
#define USER_AGENT_ARCH "rv" // RISC-V
#else
#define USER_AGENT_ARCH
#endif

// Operating system
// __APPLE__ includes MacOS & IOS, no MacOS only macros found.
#if defined(__linux)
#define USER_AGENT_OS "L" // GNU Linux
#elif defined(__APPLE__)
#define USER_AGENT_OS "M" // Apple MacOS
#elif defined(__bsd__) || defined(__unix__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define USER_AGENT_OS "U" // BSD unix
#else
#define USER_AGENT_OS
#endif

#ifdef RELEASE_HARDENED
#define USER_AGENT "miner"
#else
#define USER_AGENT "SOJ"
#endif

#include <curl/curl.h>
#include <inttypes.h>
#include <jansson.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

// no mm_malloc for Neon
#if !defined(__ARM_NEON)

#include <mm_malloc.h>

#define mm_malloc(nbytes, alignment) _mm_malloc(nbytes, alignment)
#define mm_free _mm_free

#else

#define mm_malloc(nbytes, alignment) malloc(nbytes)
#define mm_free free

#endif

// TODO for windows
static inline bool is_root()
{
    return !getuid();
}

#ifndef alloca
#if defined(__GNUC__)
#define alloca __builtin_alloca
#elif defined(_AIX)
#define alloca __alloca
#elif !defined(HAVE_ALLOCA)
#ifdef __cplusplus
extern "C"
#endif
    void *alloca(size_t);
#endif
#endif

// keyboard beep
static const char ASCII_BELL = '\a';

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_BLUE 0x10  /* unique value */
#define LOG_MAJR 0x11  /* unique value */
#define LOG_MINR 0x12  /* unique value */
#define LOG_GREEN 0x13 /* unique value */
#define LOG_PINK 0x14  /* unique value */
#else
enum
{
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    /* custom notices */
    LOG_BLUE  = 0x10,
    LOG_MAJR  = 0x11,
    LOG_MINR  = 0x12,
    LOG_GREEN = 0x13,
    LOG_PINK  = 0x14
};
#endif

#define WORK_ALIGNMENT 64

#include "compat.h"
#include "util.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

typedef unsigned char uchar;

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads(str, 0, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, 0, err_ptr)
#else
#define JSON_LOADS(str, err_ptr) json_loads(str, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, err_ptr)
#endif

json_t *json_load_url(char *cfg_url, json_error_t *err);

struct work;

void work_free(struct work *w);
void work_copy(struct work *dest, const struct work *src);

struct cpu_info
{
    int      thr_id;
    int      accepted;
    int      rejected;
    double   khashes;
    bool     has_monitoring;
    float    cpu_temp;
    int      cpu_fan;
    uint32_t cpu_clock;
};

#define JSON_RPC_LONGPOLL (1 << 0)
#define JSON_RPC_QUIET_404 (1 << 1)
#define JSON_RPC_IGNOREERR (1 << 2)

#define JSON_BUF_LEN 8192

#define CL_N "\x1B[0m"
#define CL_RED "\x1B[31m"
#define CL_GRN "\x1B[32m"
#define CL_YLW "\x1B[33m" // dark yellow
#define CL_BLU "\x1B[34m"
#define CL_MAG "\x1B[35m" // purple
#define CL_CYN "\x1B[36m"

#define CL_BLK "\x1B[22;30m" /* black */
#define CL_RD2 "\x1B[22;31m" /* red */
#define CL_GR2 "\x1B[22;32m" /* green */
#define CL_BRW "\x1B[22;33m" /* brown */
#define CL_BL2 "\x1B[22;34m" /* blue */
#define CL_MA2 "\x1B[22;35m" /* purple */
#define CL_CY2 "\x1B[22;36m" /* cyan */
#define CL_SIL "\x1B[22;37m" /* gray */

#define CL_GRY "\x1B[90m"    /* dark gray selectable in putty */
#define CL_LRD "\x1B[01;31m" /* bright red */
#define CL_LGR "\x1B[01;32m" /* bright green */
#define CL_YL2 "\x1B[01;33m" /* bright yellow */
#define CL_LBL "\x1B[01;34m" /* light blue */
#define CL_LMA "\x1B[01;35m" /* light magenta */
#define CL_LCY "\x1B[01;36m" /* light cyan */

#define CL_WHT "\x1B[01;37m" /* white */

void applog(int prio, const char *fmt, ...);
void applog2(int prio, const char *fmt, ...);
void applog_nl(const char *fmt, ...);

// Let runtime -D (opt_debug) control debug logging even in release builds unless explicitly disabled
#ifndef ALLOW_RUNTIME_DEBUG_LOGS
#define ALLOW_RUNTIME_DEBUG_LOGS 1
#endif

#if defined(NDEBUG) && !ALLOW_RUNTIME_DEBUG_LOGS
#define applog_debug(...) ((void)0)
#else
#define applog_debug(...) applog(__VA_ARGS__)
#endif

void restart_threads(void);
extern json_t       *
json_rpc_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req, int *curl_err, int flags);
void  bin2hex(char *s, const unsigned char *p, size_t len);
char *abin2hex(const unsigned char *p, size_t len);
char *bebin2hex(const unsigned char *p, size_t len);
bool  hex2bin(unsigned char *p, const char *hexstr, const size_t len);
bool  jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen);

// Bitcoin formula for converting difficulty to an equivalent
// number of hashes.
//
//     https://en.bitcoin.it/wiki/Difficulty
//     hash = diff * 2**32

#define EXP16 65536.
#define EXP32 4294967296.
extern const long double exp32;  // 2**32
extern const long double exp48;  // 2**48
extern const long double exp64;  // 2**64
extern const long double exp96;  // 2**96
extern const long double exp128; // 2**128
extern const long double exp160; // 2**160

bool fulltest(const uint32_t *hash, const uint32_t *target);
bool valid_hash(const void *, const void *);

extern double hash_to_diff(const void *);
extern void   diff_to_hash(uint32_t *, const double);
extern double nbits_to_diff(uint32_t);

struct thr_info
{
    int              id;
    pthread_t        pth;
    pthread_attr_t   attr;
    struct thread_q *q;
    struct cpu_info  cpu;
};

// int test_hash_and_submit( struct work *work, const void *hash,
//                            struct thr_info *thr );

bool submit_solution(struct work *work, const void *hash, struct thr_info *thr);

void get_currentalgo(char *buf, int sz);
struct work
{
    uint32_t       target[8] __attribute__((aligned(64)));
    uint32_t       data[48] __attribute__((aligned(64)));
    uint32_t       hash[8] __attribute__((aligned(32)));
    double         targetdiff;
    double         sharediff;
    double         stratum_diff;
    char           ntime[32];
    int            height;
    char          *txs;
    int            tx_count;
    char          *workid;
    char          *job_id;
    size_t         xnonce2_len;
    unsigned char *xnonce2;
    bool           stale;
    uint64_t reauth_epoch; // Reauthentication epoch when this work was generated

} __attribute__((aligned(WORK_ALIGNMENT)));

struct stratum_job
{
    unsigned char   prevhash[32];
    char           *job_id;
    size_t          coinbase_size;
    unsigned char  *coinbase;
    unsigned char  *xnonce2;
    int             merkle_count;
    int             merkle_buf_size;
    unsigned char **merkle;
    unsigned char   version[4];
    unsigned char   nbits[4];
    unsigned char   ntime[4];
    double          diff;
    bool            clean;
} __attribute__((aligned(64)));

struct stratum_ctx
{
    char *url;

    CURL           *curl;
    char           *curl_url;
    char            curl_err_str[CURL_ERROR_SIZE];
    curl_socket_t   sock;
    size_t          sockbuf_size;
    char           *sockbuf;
    pthread_mutex_t sock_lock;

    double next_diff;
    double sharediff;

    char              *session_id;
    size_t             xnonce1_size;
    unsigned char     *xnonce1;
    size_t             xnonce2_size;
    struct stratum_job job;
    struct work        work __attribute__((aligned(64)));
    pthread_mutex_t    work_lock;

    int    block_height;
    bool   new_job;
    char  *last_rejected_job_id; // Track last rejected job_id to avoid reprocessing
    bool   immediate_disconnect;
    time_t next_reconnect_time;
} __attribute__((aligned(64)));

bool  stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool  stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool  stratum_connect(struct stratum_ctx *sctx, const char *url);
void  stratum_disconnect(struct stratum_ctx *sctx);
bool  stratum_subscribe(struct stratum_ctx *sctx);
bool  stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool  stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool  stratum_suggest_difficulty(struct stratum_ctx *sctx, double diff);
bool  stratum_reauthenticate(struct stratum_ctx *sctx, const char *url, const char *user, const char *pass);
bool  is_solution_submission_suspended(void);

extern _Atomic bool solution_submission_suspended; // Global flag for reauthentication suspension

extern bool  aes_ni_supported;
extern char *rpc_user;
extern char *short_url;

// SOJ Unified Logging Globals
extern long     g_mem_total_mb, g_mem_available_mb;

void parse_arg(int key, char *arg);
void parse_config(json_t *config, char *ref);
void proper_exit(int reason);

extern char *opt_worker; // Optional worker name (defaults to hostname if not provided)

struct work_restart
{
    volatile uint8_t restart;
    char             padding[128 - sizeof(uint8_t)];
};

enum workio_commands
{
    WC_GET_WORK,
    WC_SUBMIT_WORK,
};

struct workio_cmd
{
    enum workio_commands cmd;
    struct thr_info     *thr;
    union
    {
        struct work *work;
    } u;
    // Epoch snapshot when this command was enqueued; used to drop stale submits after resets
    uint64_t epoch_token;
};

uint32_t *get_stratum_job_ntime();

enum algos
{
    ALGO_NULL,
    ALGO_CIVICLIGHT,
    ALGO_COUNT
};

// This list must be in exactly the same order as above.
extern const char *const algo_names[];

const char *algo_name(enum algos a);

extern enum algos           opt_algo;
extern bool                 opt_debug;
extern bool                 opt_debug_diff;
extern bool                 opt_benchmark;
extern bool                 opt_protocol;
extern bool                 opt_extranonce;
extern bool                 opt_quiet;
extern bool                 opt_redirect;
extern int                  opt_timeout;
extern char                *lp_id;
extern char                *rpc_userpass;
extern bool                 want_stratum;
extern bool                 have_stratum;
extern char                *opt_cert;
extern char                *opt_proxy;
extern long                 opt_proxy_type;
extern bool                 use_syslog;
extern bool                 use_colors;
extern pthread_mutex_t      applog_lock;
extern struct thr_info     *thr_info;
extern int                  stratum_thr_id;
extern int                  opt_n_threads;
extern struct work_restart *work_restart;
extern uint32_t             opt_work_size;
extern double              *thr_hashrates;
extern double               global_hashrate;
extern double               stratum_diff;
extern double               net_diff;
extern double               net_hashrate;
extern char                *opt_param_key;
extern double               opt_diff_factor;
extern double               opt_target_factor;
extern bool                 allow_mininginfo;
extern struct work          g_work;
extern pthread_rwlock_t     g_work_lock;
extern time_t               g_work_time;
extern struct stratum_ctx   stratum;
extern struct timeval       stratum_reset_time;
extern time_t               pause_until_time; // Protection: pause mining after stratum failures
extern bool                 opt_stratum_stats;
extern int                  num_cpus;
extern int                  num_cpugroups;
extern int                  opt_priority;
extern uint32_t             accepted_share_count;
extern uint32_t             rejected_share_count;
extern uint32_t             solved_block_count;
extern pthread_mutex_t      applog_lock;
extern pthread_mutex_t      stats_lock;
extern const int            pk_buffer_size_max;
extern int                  pk_buffer_size;
extern char                *opt_data_file;
extern bool                 opt_bell; //  keyboard beep
// Backoff helpers
void activate_protection_backoff(const char *reason);
void enforce_backoff_wait_if_needed(const char *context);
#ifdef LOG_ERRORS_ONLY
static char const usage[] = "Usage: soj --file <filename>\n";
#elif defined(RELEASE_HARDENED)
static char const usage[] = "\
Usage: miner [OPTIONS]\n\
Options:\n\
  -o, --url=URL         URL of mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
  -t, --threads=N       number of threads\n\
      --worker=NAME     set worker name\n\
  -T, --timeout=N       network timeout in seconds\n\
  -h, --help            display this help text and exit\n\
";
#else
static char const usage[] = "\
Usage: soj [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          civiclight    CivicNet memory-hard PoW\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of threads (default: number of processors)\n\
      --worker=NAME     set worker name; defaults to system hostname if omitted\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
      --retry-pause=N   time to pause between retries, in seconds (default: 10)\n\
      --time-limit=N    maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       timeout for long poll and stratum (default: 300 seconds)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
  -f, --diff-factor=N   divide req. difficulty by this factor (std is 1.0)\n\
  -m, --diff-multiplier=N Multiply difficulty by this factor (std is 1.0)\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           reduce log verbosity\n\
      --no-color        disable colored output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
                            "\
  -S, --syslog          use system log for output messages\n"
#endif
                            "\
  -B, --background      run in the background\n\
      --benchmark SECS  run CivicLight v2 benchmark for SECS\n\
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1\n\
      --cpu-priority    set process priority (default: 0 idle, 2 normal to 5 highest) (deprecated)\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
		      --data-file=FILE  path and name of data file\n\
		      --stratum-keepalive  prevent disconnects when difficulty is too high\n\
	\n\
		  -V, --version         display version and CPU information and exit\n\
		  -h, --help            display this help text and exit\n\
		";
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option
{
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};
#endif

#ifndef OPT_WORKER_KEY
#define OPT_WORKER_KEY 2001
#endif

#ifndef OPT_BENCHMARK_CIVICLIGHT
#define OPT_BENCHMARK_CIVICLIGHT 1090
#endif

#ifdef LOG_ERRORS_ONLY
#define OPT_STEALTH_FILE 3000
#endif

extern struct option const options[];

#endif /* __SOJ_H__ */
