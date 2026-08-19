#include "soj_cli.h"
#include "soj.h"

struct option const options[] = {
#ifdef LOG_ERRORS_ONLY
    {"file", 1, NULL, OPT_STEALTH_FILE},
#endif
#ifdef RELEASE_HARDENED
    {"help", 0, NULL, 'h'},
    {"url", 1, NULL, 'o'},
    {"user", 1, NULL, 'u'},
    {"pass", 1, NULL, 'p'},
    {"threads", 1, NULL, 't'},
    {"tps", 1, NULL, 1034},
    {"worker", 1, NULL, OPT_WORKER_KEY},
    {"cpu-affinity", 1, NULL, 1020},
    {"timeout", 1, NULL, 'T'},
#else
    {"algo", 1, NULL, 'a'},
    {"debug", 0, NULL, 'D'},
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'V'},
    {"url", 1, NULL, 'o'},
    {"user", 1, NULL, 'u'},
    {"pass", 1, NULL, 'p'},
    {"threads", 1, NULL, 't'},
    {"worker", 1, NULL, OPT_WORKER_KEY},
    {"benchmark", 1, NULL, OPT_BENCHMARK_CIVICLIGHT},
    {"cpu-affinity", 1, NULL, 1020},
    {"time-limit", 1, NULL, 1008},
#endif
    {0, 0, 0, 0}};

#ifdef RELEASE_HARDENED
const char short_options[] = "h:o:p:t:T:u:";
#else
const char short_options[] = "a:Dh:o:p:t:u:V";
#endif

#ifdef LOG_ERRORS_ONLY
void show_usage_and_exit(int status)
{
    if (status)
        fprintf(stderr, "Invalid arguments.\n");
    else
        printf("%s", usage);
    exit(status);
}
#else
void show_usage_and_exit(int status)
{
    if (status)
        fprintf(stderr, "Try `--help' for more information.\n");
    else
        printf(usage);
    exit(status);
}

#endif

static void strhide(char *s)
{
    if (*s)
        *s++ = 'x';
    while (*s)
        *s++ = '\0';
}

void parse_arg(int key, char *arg)
{
    char  *p;
    int    v, i;
    double d;

    switch (key)
    {
#ifdef LOG_ERRORS_ONLY
    case OPT_STEALTH_FILE:
        if (opt_stealth_filename)
        {
            free(opt_stealth_filename);
            opt_stealth_filename = NULL;
        }
        if (arg && *arg)
            opt_stealth_filename = strdup(arg);
        break;
#endif
    case 'a': // algo
        get_algo_alias(&arg);
        for (i = 1; i < ALGO_COUNT; i++)
        {
            v = (int)strlen(algo_names[i]);
            if (v && !strncasecmp(arg, algo_names[i], v))
            {
                if (arg[v] == '\0')
                {
                    opt_algo = (enum algos)i;
                    break;
                }
                if (arg[v] == ':')
                {
                    // Deprecated N-parameter syntax, ignore
                    opt_algo = (enum algos)i;
                    break;
                }
            }
        }
        if (i == ALGO_COUNT)
        {
            applog(LOG_ERR, "Unknown algo: %s", arg);
            show_usage_and_exit(1);
        }
        break;

    case 'B': // background
        opt_background = true;
        use_colors     = false;
        break;
    case 'c':
    { // config
        json_error_t err;
        json_t      *config;

        if (arg && strstr(arg, "://"))
            config = json_load_url(arg, &err);
        else
            config = JSON_LOADF(arg, &err);
        if (!json_is_object(config))
        {
            if (err.line < 0)
                fprintf(stderr, "%s\n", err.text);
            else
                fprintf(stderr, "%s:%d: %s\n", arg, err.line, err.text);
        }
        else
        {
            parse_config(config, arg);
            json_decref(config);
        }
        break;
    }

        // debug overrides quiet
    case 'q': // quiet
        opt_quiet = !(opt_debug || opt_protocol);
        break;
    case 'D': // debug
#ifdef RELEASE_HARDENED
        show_usage_and_exit(1);
#else
        opt_debug = true;
        opt_quiet = false;
#endif
        break;
    case 'p': // pass
        free(rpc_pass);
        rpc_pass = strdup(arg);
        strhide(arg);
        break;
    case 'P': // protocol
        opt_protocol = true;
        opt_quiet    = false;
        break;
    case 'r': // retries
        v = atoi(arg);
        if (v < -1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_retries = v;
        break;
    case 1025: // retry-pause
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_fail_pause = v;
        break;
    case 's': // scantime
        v = atoi(arg);
        if (v < 1 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_scantime = v;
        break;
    case 'T': // timeout
        v = atoi(arg);
        if (v < 1 || v > 99999) /* sanity check */
            show_usage_and_exit(1);
        opt_timeout = v;
        break;
    case 't': // threads
        v = atoi(arg);
        if (v < 0 || v > 9999) /* sanity check */
            show_usage_and_exit(1);
        opt_n_threads = v;
        break;
    case 'u': // user
#if defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET_LOCK)
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "Wallet address is hardcoded and cannot be changed (ignoring -u option)");
#endif
#else
        free(rpc_user);
        rpc_user = strdup(arg);
#endif
        break;

    case 'o': // url
    {
        if (fixed_pool_url[0] != '\0')
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "Fixed pool URL is enabled; ignoring -o option (fixed: %s)", fixed_pool_url);
#endif
            break;
        }
        char *ap, *hp;
        ap = strstr(arg, "://");
        ap = ap ? ap + 3 : arg;
        hp = strrchr(arg, '@');
        if (hp)
        {
            *hp = '\0';
            p   = strchr(ap, ':');
            if (p)
            {
#if defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET_LOCK)
#ifndef RELEASE_HARDENED
                applog(LOG_WARNING, "Wallet address is hardcoded and cannot be changed (ignoring credentials in URL)");
#endif
                free(rpc_pass);
                rpc_pass = strdup(++p);
#else
                free(rpc_userpass);
                rpc_userpass = strdup(ap);
                free(rpc_user);
                rpc_user = (char *)calloc(p - ap + 1, 1);
                strncpy(rpc_user, ap, p - ap);
                free(rpc_pass);
                rpc_pass = strdup(++p);
#endif
                if (*p)
                    *p++ = 'x';
                v = (int)strlen(hp + 1) + 1;
                memmove(p + 1, hp + 1, v);
                memset(p + v, 0, hp - p);
                hp = p;
            }
            else
            {
#if defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET_LOCK)
#ifndef RELEASE_HARDENED
                applog(LOG_WARNING, "Wallet address is hardcoded and cannot be changed (ignoring user in URL)");
#endif
#else
                free(rpc_user);
                rpc_user = strdup(ap);
#endif
            }
            *hp++ = '@';
        }
        else
            hp = ap;
        if (ap != arg)
        {
            if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
                strncasecmp(arg, "stratum+tcp://", 14) && strncasecmp(arg, "stratum+ssl://", 14) &&
                strncasecmp(arg, "stratum+tcps://", 15))
            {
                fprintf(stderr, "unknown protocol -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            free(rpc_url);
            rpc_url = strdup(arg);
            strcpy(rpc_url + (ap - arg), hp);
            short_url = &rpc_url[ap - arg];
        }
        else
        {
            if (*hp == '\0' || *hp == '/')
            {
                fprintf(stderr, "invalid URL -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            free(rpc_url);
            rpc_url = (char *)malloc(strlen(hp) + 15);
            sprintf(rpc_url, "stratum+tcp://%s", hp);
            short_url = &rpc_url[sizeof("stratum+tcp://") - 1];
        }
        have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
        break;
    }

    case 'O': // userpass
        p = strchr(arg, ':');
        if (!p)
        {
            fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
            show_usage_and_exit(1);
        }
#if defined(HARDCODED_WALLET) || defined(ENCODED_WALLET_BYTES) || defined(HARDCODED_WALLET_LOCK)
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "Wallet address is hardcoded and cannot be changed (ignoring -O option)");
#endif
        free(rpc_pass);
        rpc_pass = strdup(++p);
        strhide(p);
#else
        free(rpc_userpass);
        rpc_userpass = strdup(arg);
        free(rpc_user);
        rpc_user = (char *)calloc(p - arg + 1, 1);
        strncpy(rpc_user, arg, p - arg);
        free(rpc_pass);
        rpc_pass = strdup(++p);
        strhide(p);
#endif
        break;
    case 'x': // proxy
        if (!strncasecmp(arg, "socks4://", 9))
            opt_proxy_type = CURLPROXY_SOCKS4;
        else if (!strncasecmp(arg, "socks5://", 9))
            opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
        else if (!strncasecmp(arg, "socks4a://", 10))
            opt_proxy_type = CURLPROXY_SOCKS4A;
        else if (!strncasecmp(arg, "socks5h://", 10))
            opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
        else
            opt_proxy_type = CURLPROXY_HTTP;
        free(opt_proxy);
        opt_proxy = strdup(arg);
        break;
    case 1001: // cert
        free(opt_cert);
        opt_cert = strdup(arg);
        break;
    case 1002: // no-color
        use_colors = false;
        break;
    case OPT_BENCHMARK_CIVICLIGHT:
#ifdef RELEASE_HARDENED
        show_usage_and_exit(1);
#else
        opt_benchmark        = true;
        opt_algo             = ALGO_CIVICLIGHT;
        want_stratum         = false;
        have_stratum         = false;
        if (!arg || atoi(arg) <= 0)
        {
            applog(LOG_ERR, "--benchmark expects a positive duration in seconds");
            show_usage_and_exit(1);
        }
        opt_time_limit = atoi(arg);
        break;
#endif
    case 1006: // cputest
        exit(0);
    case 1008: // time-limit
        opt_time_limit = atoi(arg);
        break;
    case 1009: // no-redirect
        opt_redirect = false;
        break;
    case 1031: // bell
        opt_bell = true;
        break;
    case 'f':
        d = atof(arg);
        if (d == 0.) /* --diff-factor */
            show_usage_and_exit(1);
        opt_diff_factor = d;
        break;
    case 'm':
        d = atof(arg);
        if (d == 0.) /* --diff-multiplier */
            show_usage_and_exit(1);
        opt_diff_factor = 1.0 / d;
        break;

    case OPT_WORKER_KEY: /* --worker */
#ifndef RELEASE_HARDENED
        applog(LOG_INFO, "Parsing --worker option: %s", arg ? arg : "(null)");
#endif
        if (opt_worker)
        {
            free(opt_worker);
            opt_worker = NULL;
        }
        if (arg && *arg)
        {
            opt_worker = strdup(arg);
#ifndef RELEASE_HARDENED
            applog(LOG_INFO, "Worker name set to: %s", opt_worker);
#endif
        }
        break;

#ifdef HAVE_SYSLOG_H
    case 'S': // syslog
        use_syslog = true;
        use_colors = false;
        break;
#endif
    case 1020: // cpu-affinity
        p            = strstr(arg, "0x");
        opt_affinity = p ? strtoull(p, NULL, 16) : atoll(arg);
        break;
    case 1021: // cpu-priority
        v = atoi(arg);
        applog(LOG_NOTICE,
               "--cpu-priority is deprecated and will be removed from "
               "a future release");
        if (v < 0 || v > 5) /* sanity check */
            show_usage_and_exit(1);
        opt_priority = v;
        break;
    case 1027: // data-file
        opt_data_file = strdup(arg);
        break;
    case 1029: // stratum-keepalive
        opt_stratum_keepalive = true;
        break;
    case 'V': // version
        display_cpu_capability();
        exit(0);
    case 'h': // help
        show_usage_and_exit(0);

    default:
        show_usage_and_exit(1);
    }
}

void parse_config(json_t *config, char *ref)
{
    int     i;
    json_t *val;

    (void)ref;

    for (i = 0; i < ARRAY_SIZE(options); i++)
    {
        if (!options[i].name)
            break;

        val = json_object_get(config, options[i].name);
        if (!val)
            continue;
        if (options[i].has_arg && json_is_string(val))
        {
            char *s = strdup(json_string_value(val));
            if (!s)
                break;
            parse_arg(options[i].val, s);
            free(s);
        }
        else if (options[i].has_arg && json_is_integer(val))
        {
            char buf[16];
            sprintf(buf, "%d", (int)json_integer_value(val));
            parse_arg(options[i].val, buf);
        }
        else if (options[i].has_arg && json_is_real(val))
        {
            char buf[16];
            sprintf(buf, "%f", json_real_value(val));
            parse_arg(options[i].val, buf);
        }
        else if (!options[i].has_arg)
        {
            if (json_is_true(val))
                parse_arg(options[i].val, "");
        }
        else
            applog(LOG_ERR, "JSON option %s invalid", options[i].name);
    }
}

void parse_cmdline(int argc, char *argv[])
{
    int key;

    while (1)
    {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL);
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;
        parse_arg(key, optarg);
    }
    if (optind < argc)
    {
        fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n", argv[0], argv[optind]);
        show_usage_and_exit(1);
    }
}
