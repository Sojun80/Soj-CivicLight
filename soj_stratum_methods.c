#include "algo-gate-api.h"
#include "soj.h"
#include "soj_protocol.h"
#include "soj_stratum_transport.h"
#include <soj-config.h>

#include <inttypes.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool method_eq2(const char *method, const char *left, const char *right)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s.%s", left, right);
    return !strcasecmp(method, tmp);
}

static uint32_t getblocheight(struct stratum_ctx *sctx)
{
    uint32_t height = 0;
    uint8_t  hlen   = 0, *p, *m;

    // find 0xffff tag
    p = (uint8_t *)sctx->job.coinbase + 32;
    m = p + sctx->job.coinbase_size - 32 - 2;
    //   m = p + 128;
    while (*p != 0xff && p < m)
        p++;
    while (*p == 0xff && p < m)
        p++;
    if (*(p - 1) == 0xff && *(p - 2) == 0xff)
    {
        p++;
        hlen = *p;
        p++;
        height = le16dec(p);
        p += 2;
        switch (hlen)
        {
        case 4:
            height += 0x10000UL * le16dec(p);
            break;
        case 3:
            height += 0x10000UL * (*p);
            break;
        }
    }
    return height;
}
static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
    const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *stime;
    size_t      coinb1_size, coinb2_size;
    bool        clean, ret = false;
    int         merkle_count, i, p = 0;
    json_t     *merkle_arr;
    uchar     **merkle    = NULL;

    job_id                = json_string_value(json_array_get(params, p++));
    prevhash = json_string_value(json_array_get(params, p++));

    coinb1     = json_string_value(json_array_get(params, p++));
    coinb2     = json_string_value(json_array_get(params, p++));
    merkle_arr = json_array_get(params, p++);
    if (!merkle_arr || !json_is_array(merkle_arr))
        goto out;
    merkle_count = (int)json_array_size(merkle_arr);
    version      = json_string_value(json_array_get(params, p++));
    nbits        = json_string_value(json_array_get(params, p++));
    stime        = json_string_value(json_array_get(params, p++));
    clean        = json_is_true(json_array_get(params, p));
    p++;

    if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime || strlen(prevhash) != 64 ||
        strlen(version) != 8 || strlen(nbits) != 8 || strlen(stime) != 8)
    {
#ifndef RELEASE_HARDENED
        applog(LOG_ERR, "Stratum notify: invalid parameters");
#endif
        goto out;
    }

    hex2bin(sctx->job.version, version, 4);

    pthread_mutex_lock(&sctx->work_lock);

    if (merkle_count)
    {
        if (merkle_count > sctx->job.merkle_buf_size)
        {
            for (i = 0; i < sctx->job.merkle_count; i++)
                free(sctx->job.merkle[i]);
            free(sctx->job.merkle);

            merkle = (uchar **)malloc(merkle_count * sizeof(char *));
            for (i = 0; i < merkle_count; i++)
                merkle[i] = (uchar *)malloc(32);
            sctx->job.merkle_buf_size = merkle_count;
            sctx->job.merkle          = merkle;
        }

        for (i = 0; i < merkle_count; i++)
        {
            const char *s = json_string_value(json_array_get(merkle_arr, i));
            if (!s || strlen(s) != 64)
            {
                sctx->job.merkle_count = 0;
                pthread_mutex_unlock(&sctx->work_lock);
#ifndef RELEASE_HARDENED
                applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
#endif
                goto out;
            }
            hex2bin(sctx->job.merkle[i], s, 32);
        }
    }
    sctx->job.merkle_count = merkle_count;

    coinb1_size             = strlen(coinb1) / 2;
    coinb2_size             = strlen(coinb2) / 2;
    sctx->job.coinbase_size = coinb1_size + sctx->xnonce1_size + sctx->xnonce2_size + coinb2_size;
    sctx->job.coinbase      = (uchar *)realloc(sctx->job.coinbase, sctx->job.coinbase_size);
    sctx->job.xnonce2       = sctx->job.coinbase + coinb1_size + sctx->xnonce1_size;
    hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
    memcpy(sctx->job.coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);
    if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
        memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
    hex2bin(sctx->job.xnonce2 + sctx->xnonce2_size, coinb2, coinb2_size);
    free(sctx->job.job_id);
    sctx->job.job_id = strdup(job_id);
    hex2bin(sctx->job.prevhash, prevhash, 32);
    sctx->block_height = getblocheight(sctx);
    hex2bin(sctx->job.nbits, nbits, 4);
    hex2bin(sctx->job.ntime, stime, 4);
    sctx->job.clean = clean;
    sctx->job.diff  = sctx->next_diff;
    pthread_mutex_unlock(&sctx->work_lock);

    ret = true;

out:
    return ret;
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
    double       diff;
    extern char *rpc_pass; // Access to password parameter

    diff = json_number_value(json_array_get(params, 0));
    if (diff == 0)
        return false;

    pthread_mutex_lock(&sctx->work_lock);

    // Check if user specified difficulty via -p d=XXX parameter
    if (rpc_pass && strstr(rpc_pass, "d="))
    {
        char  *d_param   = strstr(rpc_pass, "d=");
        double user_diff = atof(d_param + 2); // Skip "d="
        if (user_diff > 0)
        {
            if (sctx->next_diff != user_diff)
            {
#ifndef RELEASE_HARDENED
                applog(LOG_GREEN,
                       "Stratum set difficulty: %.8f (pool) -> overridden to %.8f (user -p d=%.8f)",
                       diff,
                       user_diff,
                       user_diff);
#endif
            }
            sctx->next_diff = user_diff;
        }
        else
        {
            if (sctx->next_diff != diff)
            {
#ifndef RELEASE_HARDENED
                applog(LOG_GREEN, "Stratum set difficulty: %.8f", diff);
#endif
            }
            sctx->next_diff = diff;
        }
    }
    else
    {
        if (sctx->next_diff != diff)
        {
#ifndef RELEASE_HARDENED
            applog(LOG_GREEN, "Stratum set difficulty: %.8f", diff);
#endif
        }
        sctx->next_diff = diff;
    }

    pthread_mutex_unlock(&sctx->work_lock);
    return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
    json_t     *port_val;
    char       *url;
    const char *host;
    int         port;

    host     = json_string_value(json_array_get(params, 0));
    port_val = json_array_get(params, 1);
    if (json_is_string(port_val))
        port = atoi(json_string_value(port_val));
    else
        port = (int)json_integer_value(port_val);
    if (!host || !port)
        return false;

    url = (char *)malloc(32 + strlen(host));

    strncpy(url, sctx->url, 15);
    sprintf(strstr(url, "://") + 3, "%s:%d", host, port);

    if (!opt_redirect)
    {
        applog(LOG_INFO, "Ignoring request to reconnect to %s", url);
        free(url);
        return true;
    }

    applog(LOG_NOTICE, "Server requested reconnection to %s", url);

    free(sctx->url);
    sctx->url = url;
    stratum_disconnect(sctx);

    return true;
}

static bool json_object_set_error(json_t *result, int code, const char *msg)
{
    json_t *val = json_object();
    json_object_set_new(val, "code", json_integer(code));
    json_object_set_new(val, "message", json_string(msg));
    return json_object_set_new(result, "error", val) != -1;
}

static bool stratum_unknown_method(struct stratum_ctx *sctx, json_t *id)
{
    char   *s;
    json_t *val;
    bool    ret = false;

    if (!id || json_is_null(id))
        return ret;

    val = json_object();
    json_object_set(val, "id", id);
    json_object_set_new(val, "result", json_false());
    json_object_set_error(val, 38, "unknown method"); // ENOSYS

    s   = json_dumps(val, 0);
    ret = stratum_send_line(sctx, s);
    json_decref(val);
    free(s);

    return ret;
}

static bool stratum_pong(struct stratum_ctx *sctx, json_t *id)
{
    char buf[64];
    bool ret = false;

    if (!id || json_is_null(id))
        return ret;

    sprintf(buf, "{\"id\":%d,\"result\":\"pong\",\"error\":null}", (int)json_integer_value(id));
    ret = stratum_send_line(sctx, buf);

    return ret;
}

static bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
    char    algo[64] = {0};
    char   *s;
    json_t *val;
    bool    ret = true;

    if (!id || json_is_null(id))
        return false;

    get_currentalgo(algo, sizeof(algo));

    val = json_object();
    json_object_set(val, "id", id);
    json_object_set_new(val, "error", json_null());
    json_object_set_new(val, "result", json_string(algo));

    s   = json_dumps(val, 0);
    ret = stratum_send_line(sctx, s);
    json_decref(val);
    free(s);

    return ret;
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
    char   *s;
    json_t *val;
    bool    ret;

    if (!id || json_is_null(id))
        return false;

    val = json_object();
    json_object_set(val, "id", id);
    json_object_set_new(val, "error", json_null());
    json_object_set_new(val, "result", json_string(USER_AGENT));
    s   = json_dumps(val, 0);
    ret = stratum_send_line(sctx, s);
    json_decref(val);
    free(s);

    return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
    char   *s;
    json_t *val;
    bool    ret;

    val = json_array_get(params, 0);
    if (val)
        applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));

    if (!id || json_is_null(id))
        return true;

    val = json_object();
    json_object_set(val, "id", id);
    json_object_set_new(val, "error", json_null());
    json_object_set_new(val, "result", json_true());
    s   = json_dumps(val, 0);
    ret = stratum_send_line(sctx, s);
    json_decref(val);
    free(s);

    return ret;
}
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
    json_t      *val, *id, *params;
    json_error_t err;
    const char  *method;
    bool         ret = false;

    val = JSON_LOADS(s, &err);
    if (!val)
    {
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    method = json_string_value(json_object_get(val, "method"));
    if (!method)
        goto out;

    params = json_object_get(val, "params");

    id = json_object_get(val, "id");

    if (method_eq2(method, "mining", "notify"))
    {
        ret           = stratum_notify(sctx, params);
        sctx->new_job = true;
        goto out;
    }
    if (method_eq2(method, "mining", "ping"))
    {
        // if (opt_debug) applog_debug(LOG_DEBUG, "Pool ping");
        ret = stratum_pong(sctx, id);
        goto out;
    }
    if (method_eq2(method, "mining", "set_difficulty"))
    {
        ret = stratum_set_difficulty(sctx, params);
        goto out;
    }
    if (method_eq2(method, "mining", "set_extranonce"))
    {
        ret = stratum_parse_extranonce(sctx, params, 0);
        goto out;
    }
    if (!strcasecmp(method, "client.reconnect"))
    {
        ret = stratum_reconnect(sctx, params);
        goto out;
    }
    if (!strcasecmp(method, "client.get_algo"))
    {
        // will prevent wrong algo parameters on a pool, will be used as test on
        // rejects
#ifndef RELEASE_HARDENED
        if (!opt_quiet)
            applog(LOG_NOTICE, "Pool asked your algo parameter");
#endif
        ret = stratum_get_algo(sctx, id, params);
        goto out;
    }
    if (!strcasecmp(method, "client.get_version"))
    {
        ret = stratum_get_version(sctx, id);
        goto out;
    }
    if (!strcasecmp(method, "client.show_message"))
    {
        ret = stratum_show_message(sctx, id, params);
        goto out;
    }

    if (!ret)
    {
        // don't fail = disconnect stratum on unknown (and optional?) methods
#ifndef RELEASE_HARDENED
        if (opt_debug)
            applog(LOG_WARNING, "unknown stratum method %s!", method);
#endif
        ret = stratum_unknown_method(sctx, id);
    }
out:
    if (val)
        json_decref(val);

    return ret;
}
