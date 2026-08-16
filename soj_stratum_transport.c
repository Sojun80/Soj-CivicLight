#include "soj_stratum_transport.h"
#include "algo-gate-api.h"
#include "soj.h"
#include <soj-config.h>

static int       consecutive_stratum_failures = 0;
time_t           pause_until_time             = 0;
static const int MAX_FAILURES_BEFORE_PAUSE    = 3;
static const int PAUSE_DURATION_SECONDS       = 240;

#include <curl/curl.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

extern int              consecutive_duplicate_errors;
extern int              consecutive_incorrect_cycle_errors;
extern bool             last_job_was_timestamp_only;
extern int              stratum_thr_id;
extern int              opt_fail_pause;
extern bool             stratum_down;
extern struct thr_info *thr_info;

extern void activate_protection_backoff(const char *reason);
extern void enforce_backoff_wait_if_needed(const char *scope);

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

static bool send_line(struct stratum_ctx *volatile sctx, char *s)
{
    size_t sent = 0;
    int    len;

    len      = (int)strlen(s);
    s[len++] = '\n';

    while (len > 0)
    {
        struct timeval timeout = {0, 0};
        int            n;
        fd_set         wd;

        FD_ZERO(&wd);
        if (sctx->sock < 0)
            return false;
        FD_SET(sctx->sock, &wd);
        if (select((int)(sctx->sock + 1), NULL, &wd, NULL, &timeout) < 1)
            return false;

#if LIBCURL_VERSION_NUM >= 0x071802
        CURLcode rc = curl_easy_send(sctx->curl, s + sent, len, (size_t *)&n);
        if (rc != CURLE_OK)
        {
            if (rc != CURLE_AGAIN)
#else
        n = send(sctx->sock, s + sent, len, 0);
        if (n < 0)
        {
            if (!socket_blocks())
#endif
                return false;
            n = 0;
        }
        sent += n;
        len -= n;
    }

    return true;
}

static size_t stratum_discard_cb(const void *ptr, size_t size, size_t nmemb, void *user_data)
{
    (void)ptr;
    (void)user_data;
    return size * nmemb;
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
#endif
#ifdef __APPLE_CC__
    if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &tcp_keepintvl, sizeof(tcp_keepintvl))))
        return 1;
#endif
#endif
    (void)userdata;
    (void)purpose;
    return 0;
}
#endif

__attribute__((noinline)) bool stratum_send_line(struct stratum_ctx *volatile sctx, char *s)
{
    bool ret = false;

    if (opt_protocol)
        applog_debug(LOG_DEBUG, "> %s", s);

    // CRITICAL: Validate sctx before dereferencing
    if (!sctx || sctx < (struct stratum_ctx *)0x1000)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_send_line: Invalid sctx pointer: %p", sctx);
#endif
        return false;
    }

    // WORKAROUND: Clang miscompiles &sctx->sock_lock, so use explicit pointer
    pthread_mutex_t *lock = &sctx->sock_lock;
    __asm__ __volatile__("" ::: "memory"); // Memory barrier

    pthread_mutex_lock(lock);
    ret = send_line(sctx, s);
    pthread_mutex_unlock(lock);

    return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
    struct timeval tv;
    fd_set         rd;

    // Validate socket before using it in select()
    if (sock < 0 || sock >= FD_SETSIZE)
    {
        return false;
    }

    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    tv.tv_sec  = timeout;
    tv.tv_usec = 0;
    if (select((int)(sock + 1), &rd, NULL, NULL, &tv) > 0)
        return true;
    return false;
}

__attribute__((noinline)) bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
    return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
    size_t old, n;

    old = strlen(sctx->sockbuf);
    n   = old + strlen(s) + 1;
    if (n >= sctx->sockbuf_size)
    {
        sctx->sockbuf_size = n + (RBUFSIZE - (n % RBUFSIZE));
        sctx->sockbuf      = (char *)realloc(sctx->sockbuf, sctx->sockbuf_size);
    }
    strcpy(sctx->sockbuf + old, s);
}

__attribute__((noinline)) char *stratum_recv_line(struct stratum_ctx *sctx)
{
    ssize_t buflen;
    char   *sret = NULL;

    if (!strstr(sctx->sockbuf, "\n"))
    {
        bool   ret = true;
        time_t rstart;

        time(&rstart);
        if (!socket_full(sctx->sock, 60))
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "stratum_recv_line timed out");
#endif
            goto out;
        }
        do
        {
            char    s[RBUFSIZE];
            ssize_t n;

            memset(s, 0, RBUFSIZE);

#if LIBCURL_VERSION_NUM >= 0x071802

            CURLcode rc = curl_easy_recv(sctx->curl, s, RECVSIZE, (size_t *)&n);
            if (rc == CURLE_OK && !n)
            {
                ret = false;
                break;
            }
            if (rc != CURLE_OK)
            {
                if (rc != CURLE_AGAIN || !socket_full(sctx->sock, 1))
                {
#else

            n = recv(sctx->sock, s, RECVSIZE, 0);
            if (!n)
            {
                ret = false;
                break;
            }
            if (n < 0)
            {
                if (!socket_blocks() || !socket_full(sctx->sock, 1))
                {
#endif
                    ret = false;
                    break;
                }
            }
            else
                stratum_buffer_append(sctx, s);
        } while (time(NULL) - rstart < 60 && !strstr(sctx->sockbuf, "\n"));

        if (!ret)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "stratum_recv_line failed");
#endif

            // Track consecutive failures
            consecutive_stratum_failures++;
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING,
                   "Consecutive stratum failures: %d/%d",
                   consecutive_stratum_failures,
                   MAX_FAILURES_BEFORE_PAUSE);
#endif

            // Force disconnect on repeated failures to ensure clean reconnect
            if (consecutive_stratum_failures >= 2)
            {
#ifndef RELEASE_HARDENED
                applog(LOG_WARNING, "Forcing stratum disconnect to reset connection");
#endif
                stratum_disconnect(sctx);
            }

            // If we hit threshold, enter protection mode
            if (consecutive_stratum_failures >= MAX_FAILURES_BEFORE_PAUSE)
            {
                // FLEET COORDINATION: Round to next wall clock 4-minute boundary
                time_t now           = time(NULL);
                time_t next_boundary = ((now / PAUSE_DURATION_SECONDS) + 1) * PAUSE_DURATION_SECONDS;
                pause_until_time     = next_boundary;
#ifndef RELEASE_HARDENED
                applog(LOG_ERR, "==========PROTECTION MODE ACTIVATED==========");
                applog(LOG_ERR, "Too many stratum failures (%d consecutive)", consecutive_stratum_failures);
                applog(LOG_ERR,
                       "Fleet coordination: Pausing until next 4-minute boundary: %ld seconds",
                       next_boundary - now);
                applog(LOG_ERR, "This prevents sending bad solutions to the pool");
                applog(LOG_ERR, "==============================================");
#endif
                consecutive_stratum_failures = 0; // Reset counter
            }

            goto out;
        }
    }

    buflen   = (ssize_t)strlen(sctx->sockbuf);
    char *nl = strchr(sctx->sockbuf, '\n');
    if (!nl)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
#endif

        // Track consecutive failures
        consecutive_stratum_failures++;
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING,
               "Consecutive stratum failures: %d/%d",
               consecutive_stratum_failures,
               MAX_FAILURES_BEFORE_PAUSE);
#endif

        // Force disconnect on repeated failures to ensure clean reconnect
        if (consecutive_stratum_failures >= 2)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "Forcing stratum disconnect to reset connection");
#endif
            stratum_disconnect(sctx);
        }

        // If we hit threshold, enter protection mode
        if (consecutive_stratum_failures >= MAX_FAILURES_BEFORE_PAUSE)
        {
            // FLEET COORDINATION: Round to next wall clock 4-minute boundary
            time_t now           = time(NULL);
            time_t next_boundary = ((now / PAUSE_DURATION_SECONDS) + 1) * PAUSE_DURATION_SECONDS;
            pause_until_time     = next_boundary;
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "==========PROTECTION MODE ACTIVATED==========");
            applog(LOG_ERR, "Too many stratum failures (%d consecutive)", consecutive_stratum_failures);
            applog(
                LOG_ERR, "Fleet coordination: Pausing until next 4-minute boundary: %ld seconds", next_boundary - now);
            applog(LOG_ERR, "This prevents sending bad solutions to the pool");
            applog(LOG_ERR, "==============================================");
#endif
            consecutive_stratum_failures = 0; // Reset counter
        }

        goto out;
    }

    *nl  = '\0';
    sret = strdup(sctx->sockbuf);

    // Shift remaining bytes (if any) down over the extracted line and trailing '\n'.
    {
        const char   *rem     = nl + 1;
        const ssize_t rem_len = (ssize_t)(buflen - (rem - sctx->sockbuf));
        if (rem_len > 0)
        {
            memmove(sctx->sockbuf, rem, (size_t)rem_len + 1); // include NUL
        }
        else
        {
            sctx->sockbuf[0] = '\0';
        }
    }

out:
    if (sret && opt_protocol)
        applog_debug(LOG_DEBUG, "< %s", sret);

    // Reset failure counter on successful communication
    if (sret)
    {
        if (consecutive_stratum_failures > 0)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_INFO, "Stratum communication recovered, resetting failure counter");
#endif
            consecutive_stratum_failures = 0;
        }
    }

    return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101 && LIBCURL_VERSION_NUM < 0x072d00
// #if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose, struct curl_sockaddr *addr)
{
    curl_socket_t *sock = (curl_socket_t *)clientp;
    *sock               = socket(addr->family, addr->socktype, addr->protocol);
    return *sock;
}
#endif

__attribute__((noinline)) bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
    CURL *curl;
    int   rc;

    // Removed random connection delay - not needed for stale share prevention

    pthread_mutex_lock(&sctx->sock_lock);
    if (sctx->curl)
        curl_easy_cleanup(sctx->curl);
    sctx->curl = curl_easy_init();
    if (!sctx->curl)
    {
        applog(LOG_ERR, "CURL initialization failed");
        pthread_mutex_unlock(&sctx->sock_lock);
        return false;
    }
    curl = sctx->curl;
    if (!sctx->sockbuf)
    {
        sctx->sockbuf      = (char *)calloc(RBUFSIZE, 1);
        sctx->sockbuf_size = RBUFSIZE;
    }
    sctx->sockbuf[0] = '\0';
    pthread_mutex_unlock(&sctx->sock_lock);
    if (url != sctx->url)
    {
        free(sctx->url);
        sctx->url = strdup(url);
    }

    free(sctx->curl_url);
    sctx->curl_url = (char *)malloc(strlen(url));

    // replace the stratum protocol prefix with http, https for ssl
    sprintf(
        sctx->curl_url, "%s%s", (strstr(url, "s://") || strstr(url, "ssl://")) ? "https" : "http", strstr(url, "://"));

    //   sprintf( sctx->curl_url, "http%s", strstr( url, "s://" )
    //                              ? strstr( url, "s://" )
    //                              : strstr (url, "://"  ) );

    if (opt_protocol)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    if (opt_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
#if LIBCURL_VERSION_NUM >= 0x070f06
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101 && LIBCURL_VERSION_NUM < 0x072d00
    // #if LIBCURL_VERSION_NUM >= 0x071101
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

    rc = curl_easy_perform(curl);
    if (rc)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
#endif
        curl_easy_cleanup(curl);
        sctx->curl = NULL;
        return false;
    }

    if (sctx->immediate_disconnect && time(NULL) < sctx->next_reconnect_time)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR,
               "Skipping stratum reconnect attempt for another %ld seconds due to prior immediate disconnect",
               (long)(sctx->next_reconnect_time - time(NULL)));
#endif
        curl_easy_cleanup(curl);
        sctx->curl = NULL;
        return false;
    }

    curl_socket_t last_sock = -1;
    curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &last_sock);
    sctx->sock = last_sock;

    sctx->immediate_disconnect = false;

#ifndef WIN32
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sctx->sock, &readfds);
    struct timeval tv  = {0, 0};
    int            sel = select(sctx->sock + 1, &readfds, NULL, NULL, &tv);
#else
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sctx->sock, &readfds);
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;
    int sel    = select((int)sctx->sock + 1, &readfds, NULL, NULL, &tv);
#endif
    if (sel > 0 && FD_ISSET(sctx->sock, &readfds))
    {
        char heartbeat;
        int  peek_rc = recv(sctx->sock, &heartbeat, 1, MSG_PEEK);
        if (peek_rc == 0)
        {
            sctx->immediate_disconnect = true;
            sctx->next_reconnect_time  = time(NULL) + 180;
#ifndef RELEASE_HARDENED
            applog(LOG_ERR,
                   "Stratum server closed connection immediately after connect - possible IP ban. Cooling down 180s");
#endif
            curl_easy_cleanup(curl);
            sctx->curl = NULL;
            return false;
        }
    }

    pthread_mutex_lock(&sctx->sock_lock);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, sctx);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stratum_discard_cb);
    /* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
    curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
    pthread_mutex_unlock(&sctx->sock_lock);
    return true;
}

__attribute__((noinline)) void stratum_disconnect(struct stratum_ctx *sctx)
{
    pthread_mutex_lock(&sctx->sock_lock);
    if (sctx->curl)
    {
        curl_easy_cleanup(sctx->curl);
        sctx->curl = NULL;
    }

    // Clear socket buffer completely
    if (sctx->sockbuf)
    {
        memset(sctx->sockbuf, 0, sctx->sockbuf_size);
    }

    // Reset socket to invalid state
    sctx->sock = -1;

    // Clear any pending data flags
    sctx->new_job = false;

    pthread_mutex_unlock(&sctx->sock_lock);

    // Clear session state outside of socket lock
    pthread_mutex_lock(&sctx->work_lock);
    if (sctx->session_id)
    {
        free(sctx->session_id);
        sctx->session_id = NULL;
    }
    if (sctx->xnonce1)
    {
        free(sctx->xnonce1);
        sctx->xnonce1      = NULL;
        sctx->xnonce1_size = 0;
    }
    sctx->xnonce2_size = 0;
    sctx->next_diff    = 0.0;
    sctx->sharediff    = 0.0;

    // Clear job data
    if (sctx->job.job_id)
    {
        free(sctx->job.job_id);
        sctx->job.job_id = NULL;
    }
    pthread_mutex_unlock(&sctx->work_lock);
}

static const char *get_stratum_session_id(json_t *val)
{
    json_t *arr_val;
    int     i, n;

    arr_val = json_array_get(val, 0);
    if (!arr_val || !json_is_array(arr_val))
        return NULL;
    n = (int)json_array_size(arr_val);
    for (i = 0; i < n; i++)
    {
        const char *notify;
        json_t     *arr = json_array_get(arr_val, i);

        if (!arr || !json_is_array(arr))
            break;
        notify = json_string_value(json_array_get(arr, 0));
        if (!notify)
            continue;
        {
            char method_name[32];
            snprintf(method_name, sizeof(method_name), "%s.%s", "mining", "notify");
            if (!strcasecmp(notify, method_name))
                return json_string_value(json_array_get(arr, 1));
        }
    }
    return NULL;
}

bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
    const char *xnonce1;
    int         xn2_size;

    xnonce1 = json_string_value(json_array_get(params, pndx));
    if (!xnonce1)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Failed to get extranonce1");
#endif
        goto out;
    }
    xn2_size = (int)json_integer_value(json_array_get(params, pndx + 1));
    if (!xn2_size)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Failed to get extranonce2_size");
#endif
        goto out;
    }
    if (xn2_size < 2 || xn2_size > 16)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_INFO, "Failed to get valid n2size in parse_extranonce");
#endif
        goto out;
    }

    pthread_mutex_lock(&sctx->work_lock);
    if (sctx->xnonce1)
        free(sctx->xnonce1);
    sctx->xnonce1_size = strlen(xnonce1) / 2;
    sctx->xnonce1      = (uchar *)calloc(1, sctx->xnonce1_size);
    if (unlikely(!sctx->xnonce1))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Failed to alloc xnonce1");
#endif
        pthread_mutex_unlock(&sctx->work_lock);
        goto out;
    }
    hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
    sctx->xnonce2_size = xn2_size;
    pthread_mutex_unlock(&sctx->work_lock);

    // if (!opt_quiet) /* pool dynamic change */
    //     applog(LOG_INFO, "Stratum extranonce1 0x%s, extranonce2 size %d", xnonce1, xn2_size);

    return true;
out:
    return false;
}

__attribute__((noinline)) bool stratum_subscribe(struct stratum_ctx *sctx)
{
    char *s, *sret = NULL;
    bool  ret = false;

    // CRITICAL: Validate sctx pointer before any use
    if (!sctx || sctx < (struct stratum_ctx *)0x1000)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_subscribe: Invalid sctx pointer: %p", sctx);
#endif
        return false;
    }

    // CRITICAL: Validate socket before any socket operations
    if (sctx->sock < 0)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_subscribe: Invalid socket: %d", sctx->sock);
#endif
        return false;
    }
    json_t      *val = NULL, *res_val, *err_val;
    json_error_t err;
    bool         retry = false;
    const char  *sid;

start:
    s = (char *)malloc(128 + (sctx->session_id ? strlen(sctx->session_id) : 0));
    if (retry)
        sprintf(s, "{\"id\":1,\"method\":\"%s.%s\",\"params\":[]}", "mining", "subscribe");
    else if (sctx->session_id)
        sprintf(s,
                "{\"id\":1,\"method\":\"%s.%s\",\"params\":[\"" USER_AGENT "\",\"%s\"]}",
                "mining",
                "subscribe",
                sctx->session_id);
    else
        sprintf(s, "{\"id\":1,\"method\":\"%s.%s\",\"params\":[\"" USER_AGENT "\"]}", "mining", "subscribe");

    if (!stratum_send_line(sctx, s))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_subscribe send failed");
#endif
        goto out;
    }

    if (!socket_full(sctx->sock, 30))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_subscribe timed out");
#endif
        goto out;
    }

    sret = stratum_recv_line(sctx);
    if (!sret)
        goto out;

    val = JSON_LOADS(sret, &err);
    free(sret);
    if (!val)
    {
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    if (!res_val || json_is_null(res_val) || (err_val && !json_is_null(err_val)))
    {
        if (opt_debug || retry)
        {
            // free(s);
            if (err_val)
                s = json_dumps(err_val, JSON_INDENT(3));
            else
                s = strdup("(unknown reason)");
            applog(LOG_ERR, "JSON-RPC call failed: %s", s);
        }
        goto out;
    }

    sid = get_stratum_session_id(res_val);
    if (opt_debug && sid)
        applog_debug(LOG_DEBUG, "Stratum session id: %s", sid);

    pthread_mutex_lock(&sctx->work_lock);
    if (sctx->session_id)
        free(sctx->session_id);
    sctx->session_id = sid ? strdup(sid) : NULL;
    sctx->next_diff  = 1.0;
    pthread_mutex_unlock(&sctx->work_lock);

    // sid is param 1, extranonce params are 2 and 3
    if (!stratum_parse_extranonce(sctx, res_val, 1))
    {
        goto out;
    }

    ret = true;

out:
    free(s);
    if (val)
        json_decref(val);
    val = NULL;

    if (!ret)
    {
        if (sret && !retry)
        {
            retry = true;
            goto start;
        }
    }

    return ret;
}

__attribute__((noinline)) bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
    json_t      *val = NULL, *res_val, *err_val;
    char        *s = NULL, *sret = NULL; // Back to normal
    json_error_t err;
    bool         ret = false;

    s = (char *)malloc(120 + strlen(user) + strlen(pass) + 10); // Extra space for JSON + newline + safety
    if (!s)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_authorize: malloc failed");
#endif
        return false;
    }
    sprintf(s, "{\"id\":2,\"method\":\"%s.%s\",\"params\":[\"%s\",\"%s\"]}", "mining", "authorize", user, pass);

    if (!stratum_send_line(sctx, s))
        goto out;

    while (1)
    {
        sret = stratum_recv_line(sctx);
        if (!sret)
            goto out;
        if (!stratum_handle_method(sctx, sret))
            break;
        free(sret);
    }

    val = JSON_LOADS(sret, &err);
    free(sret);
    if (!val)
    {
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    if (!res_val || json_is_false(res_val) || (err_val && !json_is_null(err_val)))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Stratum authentication failed");
#endif
        goto out;
    }

    ret = true;

    if (!opt_extranonce)
        goto out;

    // subscribe to extranonce (optional)
    sprintf(s, "{\"id\":3,\"method\":\"%s.%s.%s\",\"params\":[]}", "mining", "extranonce", "subscribe");

    if (!stratum_send_line(sctx, s))
        goto out;

    if (!socket_full(sctx->sock, 3))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "Extranonce disabled, subscribe timed out");
#endif
        opt_extranonce = false;
        goto out;
    }

    sret = stratum_recv_line(sctx);
    if (sret)
    {
        json_t *extra = JSON_LOADS(sret, &err);
        if (!extra)
        {
            applog(LOG_WARNING, "JSON decode failed(%d): %s", err.line, err.text);
        }
        else
        {
            if (json_integer_value(json_object_get(extra, "id")) != 3)
            {
                // we receive a standard method if extranonce is ignored
#ifndef RELEASE_HARDENED
                if (!stratum_handle_method(sctx, sret))
                    applog(LOG_WARNING, "Stratum answer id is not correct!");
#else
                stratum_handle_method(sctx, sret);
#endif
            }
            else
            {
                res_val = json_object_get(extra, "result");
                if (opt_debug && (!res_val || json_is_false(res_val)))
                    applog_debug(LOG_DEBUG, "Method extranonce.subscribe is not supported");
            }
            json_decref(extra);
        }
        free(sret);
    }

out:
    // WORKAROUND: Skip freeing corrupted pointer - it was already freed properly
    if (s && ((uintptr_t)s & 0xFFFFFFFF) != 0x00000000)
    {
        free(s);
    }
    // Silent workaround - no error logging
    if (val)
        json_decref(val);

    return ret;
}

__attribute__((noinline)) bool stratum_suggest_difficulty(struct stratum_ctx *sctx, double diff)
{
    char *s;
    s       = (char *)malloc(80);
    bool rc = true;

    // response is handled seperately, what ID?
    sprintf(s, "{\"id\":1,\"method\":\"%s.%s\",\"params\":[\"%f\"]}", "mining", "suggest_difficulty", diff);
    if (!stratum_send_line(sctx, s))
    {
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "stratum.suggest_difficulty send failed");
#endif
        rc = false;
    }
    free(s);
    return rc;
}

/**
 * Complete stratum reauthentication sequence
 * Performs: disconnect -> connect -> subscribe -> authorize
 * Returns true if all steps succeed, false otherwise
 */
// CRITICAL: Mutex to prevent concurrent reauthentication attempts
pthread_mutex_t reauth_mutex       = PTHREAD_MUTEX_INITIALIZER;
static bool     reauth_in_progress = false;

// CRITICAL: Flag to suspend solution submissions during reauthentication (global for access from soj.c)
_Atomic bool solution_submission_suspended = false;

// CRITICAL: Track job ID before reauthentication to reject same job after reconnection
char             pre_reauth_job_id[64]      = {0};
_Atomic uint64_t reauth_job_rejection_epoch = 0;

__attribute__((noinline)) bool
stratum_reauthenticate(struct stratum_ctx *sctx, const char *url, const char *user, const char *pass)
{
    if (!sctx || !url || !user || !pass)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "stratum_reauthenticate: Invalid parameters");
#endif
        return false;
    }

    // CRITICAL: Prevent concurrent reauthentication attempts
    pthread_mutex_lock(&reauth_mutex);
    if (reauth_in_progress)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_WARNING, "Reauthentication already in progress, skipping duplicate request");
#endif
        pthread_mutex_unlock(&reauth_mutex);
        return true; // Return true to avoid triggering fallback
    }
    reauth_in_progress = true;
    pthread_mutex_unlock(&reauth_mutex);

    // CRITICAL: Suspend solution submissions during reauthentication
    atomic_store(&solution_submission_suspended, true);
#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Solution submissions suspended during reauthentication");
#endif

    // CRITICAL: Store current job_id to reject if pool sends same job after reauthentication
    pthread_mutex_lock(&reauth_mutex);
    if (sctx->job.job_id)
    {
        strncpy(pre_reauth_job_id, sctx->job.job_id, sizeof(pre_reauth_job_id) - 1);
        pre_reauth_job_id[sizeof(pre_reauth_job_id) - 1] = '\0';
#ifndef RELEASE_HARDENED
        applog(LOG_INFO, "Stored pre-reauth job_id: %s (will reject if pool sends same job)", pre_reauth_job_id);
#endif
    }
    else
    {
        pre_reauth_job_id[0] = '\0';
    }
    pthread_mutex_unlock(&reauth_mutex);

    // Check for potential ban - if connection fails immediately, don't retry
    static time_t last_ban_check       = 0;
    static int    consecutive_failures = 0;
    time_t        now                  = time(NULL);

    if (now - last_ban_check > 300)
    { // Reset counter every 5 minutes
        consecutive_failures = 0;
    }
    last_ban_check = now;

#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Starting complete stratum reauthentication sequence");
#endif

    // Set stratum_down to prevent mining threads from running during reauthentication
    extern bool stratum_down;
    stratum_down = true;

    // Step 1: Disconnect from current connection
    // applog_debug(LOG_DEBUG, "Step 1: Disconnecting from stratum server");
    stratum_disconnect(sctx);

    // Wait a moment for the connection to fully close
    // applog_debug(LOG_DEBUG, "Waiting 3 seconds for connection cleanup...");
    sleep(3);

    // Clear all job data to force fresh start
    if (sctx->job.job_id)
    {
        free(sctx->job.job_id);
        sctx->job.job_id = NULL;
    }
    if (sctx->session_id)
    {
        free(sctx->session_id);
        sctx->session_id = NULL;
    }
    if (sctx->xnonce1)
    {
        free(sctx->xnonce1);
        sctx->xnonce1      = NULL;
        sctx->xnonce1_size = 0;
    }

    // Clear rejected job tracking
    if (sctx->last_rejected_job_id)
    {
        free(sctx->last_rejected_job_id);
        sctx->last_rejected_job_id = NULL;
    }

    sctx->new_job   = false;
    sctx->next_diff = 0.0;
    sctx->sharediff = 0.0;

    // Step 2: Connect to stratum server with retries
    int max_retries = 3;
    int retry_count = 0;

    while (retry_count < max_retries)
    {
        // applog_debug(LOG_DEBUG, "Step 2: Connecting to stratum server: %s (attempt %d/%d)", url, retry_count + 1,
        // max_retries);
        if (stratum_connect(sctx, url))
        {
            break; // Connection successful
        }

        retry_count++;
        if (retry_count < max_retries)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "Connection attempt %d failed, retrying in 2 seconds...", retry_count);
#endif
            sleep(2);
        }
        else
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "stratum_reauthenticate: All connection attempts failed");
#endif
            consecutive_failures++;
            if (consecutive_failures >= 3)
            {
#ifndef RELEASE_HARDENED
                applog(LOG_WARNING,
                       "Multiple reauthentication failures - possible ban detected. Forcing 3-minute delay.");
#endif
                sleep(180);               // 3 minute delay for potential ban
                consecutive_failures = 0; // Reset after delay
            }
            return false;
        }
    }

    // Step 3: Subscribe to mining notifications with retries
    retry_count = 0;
    while (retry_count < max_retries)
    {
        // applog_debug(LOG_DEBUG, "Step 3: Subscribing to mining notifications (attempt %d/%d)", retry_count + 1,
        // max_retries);
        if (stratum_subscribe(sctx))
        {
            break; // Subscription successful
        }

        retry_count++;
        if (retry_count < max_retries)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "Subscription attempt %d failed, retrying in 2 seconds...", retry_count);
#endif
            sleep(2);
        }
        else
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "stratum_reauthenticate: All subscription attempts failed");
#endif
            stratum_disconnect(sctx);
            return false;
        }
    }

    // Step 4: Authorize with credentials with retries
    retry_count = 0;
    while (retry_count < max_retries)
    {
        // applog_debug(LOG_DEBUG, "Step 4: Authorizing with credentials (attempt %d/%d)", retry_count + 1,
        // max_retries);
        if (stratum_authorize(sctx, user, pass))
        {
            break; // Authorization successful
        }

        retry_count++;
        if (retry_count < max_retries)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_WARNING, "Authorization attempt %d failed, retrying in 2 seconds...", retry_count);
#endif
            sleep(2);
        }
        else
        {
#ifndef RELEASE_HARDENED
            applog(LOG_ERR, "stratum_reauthenticate: All authorization attempts failed");
#endif
            stratum_disconnect(sctx);
            return false;
        }
    }

#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Stratum reauthentication completed successfully");
#endif

    // Reset stratum_down to allow mining threads to resume
    stratum_down = false;

    // CRITICAL: Clear reauthentication flag and resume solution submissions
    pthread_mutex_lock(&reauth_mutex);
    reauth_in_progress = false;
    pthread_mutex_unlock(&reauth_mutex);

    // Wait a moment for new job to arrive before resuming submissions
    sleep(1);
    atomic_store(&solution_submission_suspended, false);
#ifndef RELEASE_HARDENED
    applog(LOG_INFO, "Solution submissions resumed after reauthentication");
#endif

    // Increment rejection epoch to enable job ID validation
    atomic_fetch_add(&reauth_job_rejection_epoch, 1);
    applog_debug(LOG_DEBUG, "Reauthentication job rejection epoch incremented");

    return true;
}

// CRITICAL: Check if solution submissions are currently suspended
bool is_solution_submission_suspended(void)
{
    return atomic_load(&solution_submission_suspended);
}
