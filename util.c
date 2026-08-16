/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2014 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include <soj-config.h>

#include "soj_cpu.h"
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <inttypes.h>
#include <jansson.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
// #include <syslog.h>
#if defined(WIN32)
#include "compat/winansi.h"
#include <mstcpip.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#ifndef _MSC_VER
/* dirname() linux/mingw, else in compat.h */
#include <libgen.h>
#endif

#include "algo-gate-api.h"
#include "algo/sha/sha256d.h"
#include "soj_protocol.h"
extern algo_gate_t algo_gate; // <-- actual global array of all algos
// extern int opt_algo;          // index of the selected algo
struct header_info
{
    char  *lp_path;
    char  *reason;
    char  *stratum_url;
    size_t content_length;
};

struct data_buffer
{
    void               *buf;
    size_t              len;
    size_t              allocated;
    struct header_info *headers;
};

static pthread_once_t g_log_tag_once   = PTHREAD_ONCE_INIT;
static char           g_log_tag_letter = 'D';

static void init_log_tag_letter(void)
{
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
#if defined(_WIN32)
    g_log_tag_letter  = (char)('A' + (rand() % 26u));
#else
    g_log_tag_letter  = (char)('A' + (rand_r(&seed) % 26u));
#endif
}

static inline char get_log_tag_letter(void)
{
    pthread_once(&g_log_tag_once, init_log_tag_letter);
    return g_log_tag_letter;
}

// PROTECTION: Track consecutive stratum failures to avoid pool bans
// Make backoff helpers available to other compilation units
extern time_t    pause_until_time;
static const int PAUSE_DURATION_SECONDS = 240;

void activate_protection_backoff(const char *reason)
{
    time_t now = time(NULL);
    // Round to next 4-minute boundary to de-synchronize fleets
    time_t next_boundary = ((now / PAUSE_DURATION_SECONDS) + 1) * PAUSE_DURATION_SECONDS;
    pause_until_time     = next_boundary;

    int wait_s = (int)(next_boundary - now);
#ifdef RELEASE_HARDENED
    applog(LOG_ERR, "backoff active");
    applog(LOG_ERR, "wait: %d seconds", wait_s);
#else
    applog(LOG_ERR, "========== PROTECTION MODE ACTIVATED ==========");
    applog(LOG_ERR, "Reason: %s", reason ? reason : "(unspecified)");
    applog(LOG_ERR, "Pausing until next 4-minute boundary in %d seconds", wait_s);
    applog(LOG_ERR, "This prevents bans and bad submissions while pool recovers");
    applog(LOG_ERR, "==============================================");
#endif

    // Abort current work so threads unwind quickly
    restart_threads();
}

void enforce_backoff_wait_if_needed(const char *context)
{
    // Non-busy wait until wall clock crosses pause_until_time
    for (;;)
    {
        time_t now   = time(NULL);
        time_t until = pause_until_time; // read once
        if (until == 0 || now >= until)
            break;

        int remaining = (int)(until - now);
        // Log sparsely (every ~30s) to avoid log spam on long waits
        if (remaining % 30 == 0 || remaining <= 10)
        {
            applog(LOG_WARNING,
                   "[BACKOFF%s%s] Waiting %d sec until resume",
                   context ? " " : "",
                   context ? context : "",
                   remaining);
        }
        int slice = remaining < 5 ? remaining : 5;
        if (slice > 0)
            sleep(slice);
        else
            break;
    }
}

// TEST MODE: Allow controlled simulation of stratum failures

static size_t stratum_discard_cb(const void *ptr, size_t size, size_t nmemb, void *user_data)
{
    (void)ptr;
    (void)user_data;
    return size * nmemb;
}

// Dsiplay prefix only with no colour & no nl, add more message and nl later
// with printf.
// No atomicity between prefix and message.
void applog_nl(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    int       len = 64 + (int)strlen(fmt) + 2;
    struct tm tm;
    char     *f   = (char *)malloc(len);
    time_t    now = time(NULL);
#if defined(_WIN32)
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif

    sprintf(f,
            "[%d-%02d-%02d %02d:%02d:%02d %c] %s",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            get_log_tag_letter(),
            fmt);
    pthread_mutex_lock(&applog_lock);
    vfprintf(stdout, f, ap); /* atomic write to stdout */
    fflush(stdout);
    free(f);
    pthread_mutex_unlock(&applog_lock);
    va_end(ap);
}

void applog2(int prio, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
    {
        va_list ap2;
        char   *buf;
        int     len;

        /* custom colors to syslog prio */
        if (prio > LOG_DEBUG)
        {
            switch (prio)
            {
            case LOG_BLUE:
                prio = LOG_NOTICE;
                break;
            }
        }

        va_copy(ap2, ap);
        len = vsnprintf(NULL, 0, fmt, ap2) + 1;
        va_end(ap2);
        buf = alloca(len);
        if (vsnprintf(buf, len, fmt, ap) >= 0)
            syslog(prio, "%s", buf);
    }
#else
    if (0)
    {
    }
#endif
    else
    {
        const char *color = "";
        char       *f;
        int         len;
        //    struct tm tm;
        //    time_t now = time(NULL);
        //    localtime_r(&now, &tm);

        switch (prio)
        {
        case LOG_CRIT:
            color = CL_LRD;
            break;
        case LOG_ERR:
            color = CL_RED;
            break;
        case LOG_WARNING:
            color = CL_YL2;
            break;
        case LOG_MAJR:
            color = CL_YL2;
            break;
        case LOG_NOTICE:
            color = CL_WHT;
            break;
        case LOG_INFO:
            color = "";
            break;
        case LOG_DEBUG:
            color = CL_GRY;
            break;
        case LOG_MINR:
            color = CL_YLW;
            break;
        case LOG_GREEN:
            color = CL_GRN;
            prio  = LOG_INFO;
            break;
        case LOG_BLUE:
            color = CL_CYN;
            prio  = LOG_NOTICE;
            break;
        case LOG_PINK:
            color = CL_LMA;
            prio  = LOG_NOTICE;
            break;
        }
        if (!use_colors)
            color = "";

        len = 64 + (int)strlen(fmt) + 2;
        f   = (char *)malloc(len);
        sprintf(f,
                "                     %s %s%s\n",
                //      sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
                //         tm.tm_year + 1900,
                //         tm.tm_mon + 1,
                //         tm.tm_mday,
                //         tm.tm_hour,
                //         tm.tm_min,
                //         tm.tm_sec,
                color,
                fmt,
                use_colors ? CL_N : "");
        pthread_mutex_lock(&applog_lock);
        vfprintf(stdout, f, ap); /* atomic write to stdout */
        fflush(stdout);
        free(f);
        pthread_mutex_unlock(&applog_lock);
    }
    va_end(ap);
}

void applog(int prio, const char *fmt, ...)
{
#ifdef HARDENED_SILENT
    if (!opt_debug)
        return;
#endif
#ifdef LOG_ERRORS_ONLY
    // Only allow LOG_CRIT (0) and LOG_ERR (1), suppress everything else
    if (prio > LOG_ERR)
        return;
#endif
    // Suppress LOG_DEBUG messages unless debug mode is enabled
    if (prio == LOG_DEBUG && !opt_debug)
        return;

    va_list ap;

    va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
    {
        va_list ap2;
        char   *buf;
        int     len;

        /* custom colors to syslog prio */
        if (prio > LOG_DEBUG)
        {
            switch (prio)
            {
            case LOG_BLUE:
                prio = LOG_NOTICE;
                break;
            }
        }

        va_copy(ap2, ap);
        len = vsnprintf(NULL, 0, fmt, ap2) + 1;
        va_end(ap2);
        buf = alloca(len);
        if (vsnprintf(buf, len, fmt, ap) >= 0)
            syslog(prio, "%s", buf);
    }
#else
    if (0)
    {
    }
#endif
    else
    {
        const char *color = "";
        char       *f;
        int         len;
        struct tm   tm;
        time_t      now  = time(NULL);
        char       *bell = "";

#if defined(_WIN32)
        localtime_s(&tm, &now);
#else
        localtime_r(&now, &tm);
#endif

        switch (prio)
        {
        case LOG_CRIT:
            color = CL_LRD;
            break;
        case LOG_ERR:
            color = CL_RED;
            break;
        case LOG_WARNING:
            color = CL_YL2;
            break;
        case LOG_MAJR:
            color = CL_YL2;
            break;
        case LOG_NOTICE:
            color = CL_WHT;
            break;
        case LOG_INFO:
            color = "";
            break;
        case LOG_DEBUG:
            color = CL_GRY;
            break;
        case LOG_MINR:
            color = CL_YLW;
            break;
        case LOG_GREEN:
            color = CL_GRN;
            prio  = LOG_INFO;
            break;
        case LOG_BLUE:
            color = CL_CYN;
            prio  = LOG_NOTICE;
            break;
        case LOG_PINK:
            color = CL_LMA;
            prio  = LOG_NOTICE;
            break;
        }
        if (!use_colors)
            color = "";

        if (opt_bell && (prio == LOG_WARNING || prio == LOG_ERR))
            *bell = ASCII_BELL;

        len = 64 + (int)strlen(fmt) + 2;
        f   = (char *)malloc(len);
        sprintf(f,
                "[%d-%02d-%02d %02d:%02d:%02d %c]%s %s%s\n",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                get_log_tag_letter(),
                color,
                fmt,
                use_colors ? CL_N : "");
        pthread_mutex_lock(&applog_lock);
        vfprintf(stdout, f, ap); /* atomic write to stdout */
        fflush(stdout);
        free(f);
        pthread_mutex_unlock(&applog_lock);
    }
    va_end(ap);
}

void log_sw_err(char *filename, int line_number, char *msg)
{
    applog(LOG_ERR, "SW_ERR: %s:%d, %s", filename, line_number, msg);
}

/* Get default config.json path (will be system specific) */
void get_defconfig_path(char *out, size_t bufsize, char *argv0)
{
    char       *cmd  = strdup(argv0);
    char       *dir  = dirname(cmd);
    const char *sep  = strstr(dir, "\\") ? "\\" : "/";
    struct stat info = {0};
#ifdef WIN32
    snprintf(out, bufsize, "%s\\soj\\soj-conf.json", getenv("APPDATA"));
#else
    snprintf(out, bufsize, "%s\\.soj\\soj-conf.json", getenv("HOME"));
#endif
    if (dir && stat(out, &info) != 0)
    {
        snprintf(out, bufsize, "%s%ssoj-conf.json", dir, sep);
    }
    if (stat(out, &info) != 0)
    {
        out[0] = '\0';
        return;
    }
    out[bufsize - 1] = '\0';
    free(cmd);
}

/* Modify the representation of integer numbers which would cause an overflow
 * so that they are treated as floating-point numbers.
 * This is a hack to overcome the limitations of some versions of Jansson. */
static char *hack_json_numbers(const char *in)
{
    char *out;
    int   i, off, intoff;
    bool  in_str, in_int;

    out = (char *)calloc(2 * strlen(in) + 1, 1);
    if (!out)
        return NULL;
    off = intoff = 0;
    in_str = in_int = false;
    for (i = 0; in[i]; i++)
    {
        char c = in[i];
        if (c == '"')
        {
            in_str = !in_str;
        }
        else if (c == '\\')
        {
            out[off++] = c;
            if (!in[++i])
                break;
        }
        else if (!in_str && !in_int && isdigit(c))
        {
            intoff = off;
            in_int = true;
        }
        else if (in_int && !isdigit(c))
        {
            if (c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-')
            {
                in_int = false;
                if (off - intoff > 4)
                {
                    char *end;
#if JSON_INTEGER_IS_LONG_LONG
                    errno = 0;
                    strtoll(out + intoff, &end, 10);
                    if (!*end && errno == ERANGE)
                    {
#else
                    long l;
                    errno = 0;
                    l     = strtol(out + intoff, &end, 10);
                    if (!*end && (errno == ERANGE || l > INT_MAX))
                    {
#endif
                        out[off++] = '.';
                        out[off++] = '0';
                    }
                }
            }
        }
        out[off++] = in[i];
    }
    return out;
}

static void databuf_free(struct data_buffer *db)
{
    if (!db)
        return;

    free(db->buf);

    memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb, void *user_data)
{
    struct data_buffer        *db  = user_data;
    size_t                     len = size * nmemb;
    size_t                     newalloc, reqalloc;
    void                      *newmem;
    static const unsigned char zero                 = 0;
    static const size_t        max_realloc_increase = 8 * 1024 * 1024;
    static const size_t        initial_alloc        = 16 * 1024;

    /* minimum required allocation size */
    reqalloc = db->len + len + 1;

    if (reqalloc > db->allocated)
    {
        if (db->len > 0)
        {
            newalloc = db->allocated * 2;
        }
        else
        {
            if (db->headers->content_length > 0)
                newalloc = db->headers->content_length + 1;
            else
                newalloc = initial_alloc;
        }

        if (db->headers->content_length == 0)
        {
            /* limit the maximum buffer increase */
            if (newalloc - db->allocated > max_realloc_increase)
                newalloc = db->allocated + max_realloc_increase;
        }

        /* ensure we have a big enough allocation */
        if (reqalloc > newalloc)
            newalloc = reqalloc;

        newmem = realloc(db->buf, newalloc);
        if (!newmem)
            return 0;

        db->buf       = newmem;
        db->allocated = newalloc;
    }

    memcpy(db->buf + db->len, ptr, len);       /* append new data */
    memcpy(db->buf + db->len + len, &zero, 1); /* null terminate */

    db->len += len;

    return len;
}

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
    struct header_info *hi = (struct header_info *)user_data;
    size_t              remlen, slen, ptrlen = size * nmemb;
    char               *rem, *val = NULL, *key = NULL;
    void               *tmp;

    val = (char *)calloc(1, ptrlen);
    key = (char *)calloc(1, ptrlen);
    if (!key || !val)
        goto out;

    tmp = memchr(ptr, ':', ptrlen);
    if (!tmp || (tmp == ptr)) /* skip empty keys / blanks */
        goto out;
    slen = (char *)tmp - (char *)ptr;
    if ((slen + 1) == ptrlen) /* skip key w/ no value */
        goto out;
    memcpy(key, ptr, slen); /* store & nul term key */
    key[slen] = 0;

    rem    = (char *)ptr + slen + 1; /* trim value's leading whitespace */
    remlen = ptrlen - slen - 1;
    while ((remlen > 0) && (isspace(*rem)))
    {
        remlen--;
        rem++;
    }

    memcpy(val, rem, remlen); /* store value, trim trailing ws */
    val[remlen] = 0;
    while ((*val) && (isspace(val[strlen(val) - 1])))
    {
        val[strlen(val) - 1] = 0;
    }

    if (!strcasecmp("X-Long-Polling", key))
    {
        hi->lp_path = val; /* steal memory reference */
        val         = NULL;
    }

    if (!strcasecmp("X-Reject-Reason", key))
    {
        hi->reason = val; /* steal memory reference */
        val        = NULL;
    }

    if (!strcasecmp("X-Stratum", key))
    {
        hi->stratum_url = val; /* steal memory reference */
        val             = NULL;
    }

    if (!strcasecmp("Content-Length", key))
        hi->content_length = strtoul(val, NULL, 10);

out:
    free(key);
    free(val);
    return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd, curlsocktype purpose)
{
#ifdef __linux
    int tcp_keepcnt = 3;
#endif
    int tcp_keepintvl = 50;
    int tcp_keepidle  = 50;
#ifndef WIN32
    int keepalive = 1;
    if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive))))
        return 1;
#ifdef __linux
    if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(tcp_keepcnt))))
        return 1;
    if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle))))
        return 1;
    if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl))))
        return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
    if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &tcp_keepintvl, sizeof(tcp_keepintvl))))
        return 1;
#endif /* __APPLE_CC__ */
#else  /* WIN32 */
    struct tcp_keepalive vals;
    vals.onoff             = 1;
    vals.keepalivetime     = tcp_keepidle * 1000;
    vals.keepaliveinterval = tcp_keepintvl * 1000;
    DWORD outputBytes;
    if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals), NULL, 0, &outputBytes, NULL, NULL)))
        return 1;
#endif /* WIN32 */

    return 0;
}
#endif

json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req, int *curl_err, int flags)
{
    json_t            *val, *err_val, *res_val;
    int                rc;
    long               http_rc;
    struct data_buffer all_data = {0};
    char              *json_buf;
    json_error_t       err;
    struct curl_slist *headers                       = NULL;
    char               curl_err_str[CURL_ERROR_SIZE] = {0};
    long               timeout                       = (flags & JSON_RPC_LONGPOLL) ? opt_timeout : 30;
    struct header_info hi                            = {0};

    all_data.headers = &hi;
    /* it is assumed that 'curl' is freshly [re]initialized at this pt */

    if (opt_protocol)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (opt_cert)
        curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
    if (opt_redirect)
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
    if (opt_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
    }
    if (userpass)
    {
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }
#if LIBCURL_VERSION_NUM >= 0x070f06
    if (flags & JSON_RPC_LONGPOLL)
        curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, rpc_req);

    if (opt_protocol)
        applog_debug(LOG_DEBUG, "JSON protocol request:\n%s\n", rpc_req);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
    headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll reject-reason");
    // headers = curl_slist_append(headers, "Accept:"); // disable Accept hdr
    // headers = curl_slist_append(headers, "Expect:"); // disable Expect hdr

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    rc = curl_easy_perform(curl);
    if (curl_err != NULL)
        *curl_err = rc;
    if (rc)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
        if (!((flags & JSON_RPC_LONGPOLL) && rc == CURLE_OPERATION_TIMEDOUT) &&
            !((flags & JSON_RPC_QUIET_404) && http_rc == 404))
            applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
        if (curl_err && (flags & JSON_RPC_QUIET_404) && http_rc == 404)
            *curl_err = CURLE_OK;
        goto err_out;
    }

    // want_stratum is useless, and so is this code it seems. Nothing in
    // hi appears to be set.
    /* If X-Stratum was found, activate Stratum */
    if (want_stratum && hi.stratum_url && !strncasecmp(hi.stratum_url, "stratum+tcp://", 14))
    {
        have_stratum = true;
        tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
        hi.stratum_url = NULL;
    }

    if (!all_data.buf)
    {
        applog(LOG_ERR, "Empty data received in json_rpc_call.");
        goto err_out;
    }

    json_buf = hack_json_numbers((char *)all_data.buf);
    errno    = 0; /* needed for Jansson < 2.1 */
    val      = JSON_LOADS(json_buf, &err);
    free(json_buf);
    if (!val)
    {
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        goto err_out;
    }

    if (opt_protocol)
    {
        char *s = json_dumps(val, JSON_INDENT(3));
        applog_debug(LOG_DEBUG, "JSON protocol response:\n%s", s);
        free(s);
    }

    /* JSON-RPC valid response returns a 'result' and a null 'error'. */
    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    if (!res_val || (err_val && !json_is_null(err_val) && !(flags & JSON_RPC_IGNOREERR)))
    {

        char *s = NULL;

        if (err_val)
        {
            s                = json_dumps(err_val, 0);
            json_t *msg      = json_object_get(err_val, "message");
            json_t *err_code = json_object_get(err_val, "code");
            if (curl_err && json_integer_value(err_code))
                *curl_err = (int)json_integer_value(err_code);

            if (msg && json_is_string(msg))
            {
                free(s);
                s = strdup(json_string_value(msg));
            }
            json_decref(err_val);
        }
        else
            s = strdup("(unknown reason)");

        if (!curl_err || opt_debug)
            applog(LOG_ERR, "JSON-RPC call failed: %s", s);

        free(s);

        goto err_out;
    }

    if (hi.reason)
        json_object_set_new(val, "reject-reason", json_string(hi.reason));

    databuf_free(&all_data);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return val;

err_out:
    free(hi.lp_path);
    free(hi.reason);
    free(hi.stratum_url);
    databuf_free(&all_data);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return NULL;
}

/* used to load a remote config */
json_t *json_load_url(char *cfg_url, json_error_t *err)
{
    char               err_str[CURL_ERROR_SIZE] = {0};
    struct data_buffer all_data                 = {0};
    int                rc                       = 0;
    json_t            *cfg                      = NULL;
    CURL              *curl                     = curl_easy_init();
    if (unlikely(!curl))
    {
        applog(LOG_ERR, "Remote config init failed!");
        return NULL;
    }
    curl_easy_setopt(curl, CURLOPT_URL, cfg_url);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_str);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
    if (opt_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
    }
    else if (getenv("http_proxy"))
    {
        if (getenv("all_proxy"))
            curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
        else if (getenv("ALL_PROXY"))
            curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
        else
            curl_easy_setopt(curl, CURLOPT_PROXY, "");
    }
    rc = curl_easy_perform(curl);
    if (rc)
    {
        applog(LOG_ERR, "Remote config read failed: %s", err_str);
        goto err_out;
    }
    if (!all_data.buf || !all_data.len)
    {
        applog(LOG_ERR, "Empty data received for config");
        goto err_out;
    }

    cfg = JSON_LOADS((char *)all_data.buf, err);
err_out:
    curl_easy_cleanup(curl);
    return cfg;
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        sprintf(s + (i * 2), "%02x", (unsigned int)p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
    char *s = (char *)malloc((len * 2) + 1);
    if (!s)
        return NULL;
    bin2hex(s, p, len);
    return s;
}

char *bebin2hex(const unsigned char *p, size_t len)
{
    char *s = (char *)malloc((len * 2) + 1);
    if (!s)
        return NULL;
    for (size_t i = 0, j = len - 1; i < len; i++, j--)
        sprintf(s + (i * 2), "%02x", (unsigned int)p[j]);
    return s;
}

static inline unsigned char hex_decode_nibble_branchless(unsigned char c)
{
    return (unsigned char)((c & 0x0f) + (((c >> 6) & 1) * 9));
}

static inline uint64_t hex_swar_invalid_mask(uint64_t chunk)
{
    const uint64_t ONES = UINT64_C(0x0101010101010101);
    const uint64_t HIGH = UINT64_C(0x8080808080808080);

    // digit valid iff byte in ['0','9']
    uint64_t above_39  = (chunk + ONES * (0x7f - 0x39)) & HIGH;
    uint64_t below_30  = ~((chunk | HIGH) - ONES * 0x30) & HIGH;
    uint64_t not_digit = above_39 | below_30;

    // alpha valid iff (byte|0x20) in ['a','f']
    uint64_t norm      = chunk | (ONES * 0x20);
    uint64_t above_66  = (norm + ONES * (0x7f - 0x66)) & HIGH;
    uint64_t below_61  = ~((norm | HIGH) - ONES * 0x61) & HIGH;
    uint64_t not_alpha = above_66 | below_61;

    return not_digit & not_alpha;
}

bool hex2bin(unsigned char *p, const char *hexstr, const size_t len)
{
    if (hexstr == NULL)
        return false;

    size_t hexstr_len = strlen(hexstr);
    if ((hexstr_len % 2) != 0)
    {
        applog(LOG_ERR, "hex2bin string truncated");
        return false;
    }
    size_t bin_len = hexstr_len / 2;
    if (bin_len > len)
    {
        applog(LOG_ERR, "hex2bin buffer too small");
        return false;
    }

    memset(p, 0, len);

    size_t i = 0;
    size_t j = 0;

    for (; i + 8 <= hexstr_len; i += 8, j += 4)
    {
        uint64_t chunk;
        memcpy(&chunk, hexstr + i, 8);

        if (hex_swar_invalid_mask(chunk))
        {
            applog(LOG_ERR, "hex2bin invalid hex");
            return false;
        }

        uint64_t lo4  = chunk & UINT64_C(0x0f0f0f0f0f0f0f0f);
        uint64_t bit6 = (chunk >> 6) & UINT64_C(0x0101010101010101);
        uint64_t vals = lo4 + bit6 * 9;

        uint64_t hi   = (vals & UINT64_C(0x00ff00ff00ff00ff)) << 4;
        uint64_t lo   = (vals >> 8) & UINT64_C(0x00ff00ff00ff00ff);
        uint64_t pack = hi | lo;

        p[j]     = (unsigned char)(pack);
        p[j + 1] = (unsigned char)(pack >> 16);
        p[j + 2] = (unsigned char)(pack >> 32);
        p[j + 3] = (unsigned char)(pack >> 48);
    }

    // scalar tail
    for (; i < hexstr_len; i += 2, j++)
    {
        unsigned char hi_c = (unsigned char)hexstr[i];
        unsigned char lo_c = (unsigned char)hexstr[i + 1];

        bool hi_ok = (hi_c >= '0' && hi_c <= '9') || (hi_c >= 'a' && hi_c <= 'f') || (hi_c >= 'A' && hi_c <= 'F');
        bool lo_ok = (lo_c >= '0' && lo_c <= '9') || (lo_c >= 'a' && lo_c <= 'f') || (lo_c >= 'A' && lo_c <= 'F');
        if (!hi_ok || !lo_ok)
        {
            applog(LOG_ERR, "hex2bin invalid hex");
            return false;
        }

        p[j] = (unsigned char)((hex_decode_nibble_branchless(hi_c) << 4) | hex_decode_nibble_branchless(lo_c));
    }

    return true;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
    unsigned char buf[32];
    int           i;

    sha256d(buf, bin, (int)(binsz - 4));
    if (memcmp(&bin[binsz - 4], buf, 4))
        return -1;

    /* Check number of zeros is correct AFTER verifying checksum
     * (to avoid possibility of accessing the string beyond the end) */
    for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i)
        ;
    if (bin[i] == '\0' || b58[i] == '1')
        return -3;

    return bin[0];
}

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
    const char *hexstr;
    json_t     *tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp))
    {
        applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr))
    {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin((uchar *)buf, hexstr, buflen))
        return false;

    return true;
}

// Mathmatically the difficulty is simply the reciprocal of the hash: d = 1/h.
// Both are real numbers but the hash (target) is represented as a 256 bit
// fixed point number with the upper 32 bits representing the whole integer
// part and the lower 224 bits representing the fractional part:
//   target[ 255:224 ] = trunc( 1/diff )
//   target[ 223:  0 ] = frac( 1/diff )
//
// The 256 bit hash is exact but any floating point representation is not.
// Stratum provides the target difficulty as double precision, inexcact,
// which must be converted to a hash target. The converted hash target will
// likely be less precise due to inexact input and conversion error.
// On the other hand getwork provides a 256 bit hash target which is exact.
//
// How much precision is needed?
//
// 128 bit types are implemented in software by the compiler on 64 bit
// hardware resulting in lower performance and more error than would be
// expected with a hardware 128 bit implementaion.
// Float80 exploits the internals of the FP unit which provide a 64 bit
// mantissa in an 80 bit register with hardware rounding. When the destination
// is double the data is rounded to float64 format. Long double returns all
// 80 bits without rounding and including any accumulated computation error.
// Float80 does not fit efficiently in memory.
//
// Significant digits:
// 256 bit hash: 76
// float:         7     (float32, 80 bits with rounding to 32 bits)
// double:       15     (float64, 80 bits with rounding to 64 bits)
// long double:  19     (float80, 80 bits with no rounding)
// __float128:   33     (128 bits with no rounding)
// uint32_t:      9
// uint64_t:     19
// uint128_t     38
//
// The concept of significant digits doesn't apply to the 256 bit hash
// representation. It's fixed point making leading zeros significant,
// limiting its range and precision due to fewer zon-zero significant digits.
//
// Doing calculations with float128 and uint128 increases precision for
// target_to_diff, but doesn't help with stratum diff being limited to
// double precision. Is the extra precision really worth the extra cost?
// With float128 the error rate is 1/1e33 compared with 1/1e15 for double.
// For double that's 1 error in every petahash with a very low difficulty,
// not a likely situation. With higher difficulty effective precision
// increases.
//
// Unfortunately I can't get float128 to work so long double (float80) is
// as precise as it gets.
// All calculations will be done using long double then converted to double.
// This prevents introducing significant new error while taking advantage
// of HW rounding.

#if defined(GCC_INT128)

void diff_to_hash(uint32_t *target, const double diff)
{
    uint128_t           *targ = (uint128_t *)target;
    register long double m    = 1. / diff;
    //  targ[0] = 0;
    targ[0] = -1;
    targ[1] = (uint128_t)(m * exp96);
}

double hash_to_diff(const void *target)
{
    const uint128_t     *targ = (const uint128_t *)target;
    register long double m    = ((long double)targ[1] / exp96);
    //                        + ( (long double)targ[0] / exp160 );
    return (double)(1. / m);
}

inline bool valid_hash(const void *hash, const void *target)
{
    const uint128_t *h  = (const uint128_t *)hash;
    const uint128_t *t  = (const uint128_t *)target;
    const uint128_t  h1 = h[1];
    const uint128_t  t1 = t[1];
    if (h1 != t1)
        return h1 < t1;
    return h[0] <= t[0];
}

#else

void diff_to_hash(uint32_t *target, const double diff)
{
    uint64_t            *targ = (uint64_t *)target;
    register long double m    = (1. / diff) * exp32;
    //  targ[1] = targ[0] = 0;
    targ[1] = targ[0] = -1;
    targ[3]           = (uint64_t)m;
    targ[2]           = (uint64_t)((m - (long double)targ[3]) * exp64);
}

double hash_to_diff(const void *target)
{
    const uint64_t      *targ = (const uint64_t *)target;
    register long double m    = ((long double)targ[3] / exp32) + ((long double)targ[2] / exp96);
    return (double)(1. / m);
}

inline bool valid_hash(const void *hash, const void *target)
{
    const uint64_t *h  = (const uint64_t *)hash;
    const uint64_t *t  = (const uint64_t *)target;
    const uint64_t  h3 = h[3];
    const uint64_t  t3 = t[3];
    if (h3 != t3)
        return h3 < t3;
    const uint64_t h2 = h[2];
    const uint64_t t2 = t[2];
    if (h2 != t2)
        return h2 < t2;
    const uint64_t h1 = h[1];
    const uint64_t t1 = t[1];
    if (h1 != t1)
        return h1 < t1;
    return h[0] <= t[0];
}

#endif
// inline double nbits_to_diff_clean(uint32_t nbits) {
//   // Extract shift and mantissa
//   uint32_t shift = nbits >> 24;
//   uint32_t mantissa = nbits & 0x00ffffff;
//
//   if (mantissa == 0)
//     return 0.0; // Avoid division by zero
//
//   // Calculate target = mantissa * 256^(shift-3)
//   // Difficulty = max_target / target
//   // Where max_target is approximately 2^224 (for Bitcoin's original
//   difficulty
//   // 1)
//
//   long double target;
//   int exp = shift - 3; // Bitcoin uses shift-3 for the exponent
//
//   if (exp >= 0) {
//     target = (long double)mantissa;
//     for (int i = 0; i < exp; i++) {
//       target *= 256.0;
//     }
//   } else {
//     target = (long double)mantissa;
//     for (int i = 0; i < -exp; i++) {
//       target /= 256.0;
//     }
//   }
//
//   // Bitcoin's difficulty 1 target (approximately)
//   long double max_target =
//       0x00000000FFFF0000000000000000000000000000000000000000000000000000ULL;
//
//   return (double)(max_target / target);
// }
inline double nbits_to_diff(uint32_t nbits)
{
    long double diff;
    uint32_t    shift     = nbits & 0xff;
    uint32_t    bits      = bswap_32(nbits) & 0x00ffffff;
    int         shift_off = (int)shift - 29;

    // diff = ( (2**16 -1) / ( 256**shift_off * bits )
    // With uint128 byte shift is good for 16 <= shift <= 41. As unlikely
    // as this may seem necessary, check just in case.

    if (shift_off >= -13 && shift_off <= 12)
    { // fast
        if (shift_off == 0)
            diff = (long double)0xffff / (long double)bits;
        else if (shift_off < 0) // shift < 29
            diff = (long double)((uint128_t)0xffff << ((-shift_off) * 8)) / (long double)bits;
        else // ( shift_off > 0 )   // shift > 29
            diff = (long double)0xffff / (long double)((uint128_t)bits << (shift_off * 8));
    }
    else
    { // slow
        int m;
        diff = 0.;
        for (m = shift; m < 29; m++)
            diff *= 256.0;
        for (m = 29; m < shift; m++)
            diff /= 256.0;
    }

    // if ( opt_debug )
    //  applog( LOG_INFO, "nbits %08x: shift %u(%d), bits %06x, diff %8g",
    //                     nbits, shift, shift_off, bits, (double)diff );

    return (double)diff;
}
