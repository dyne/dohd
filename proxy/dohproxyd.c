#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <nghttp2/nghttp2.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../src/libevquick.h"

#define PROXY_PORT 8443
#define BUF_MAX 65535
#define TLS_IO_TIMEOUT_SEC 10
#define DOHPROXY_REQ_MIN 16

#define DOH_ERR    LOG_EMERG
#define DOH_WARN   LOG_WARNING
#define DOH_NOTICE LOG_NOTICE
#define DOH_INFO   LOG_INFO
#define DOH_DEBUG  LOG_DEBUG

#define MAKE_NV(K, V)                                                          \
    (nghttp2_nv){                                                              \
        (uint8_t *)K, (uint8_t *)V, strlen(K), strlen(V),                     \
        NGHTTP2_NV_FLAG_NONE                                                   \
    }

struct upstream {
    char host[256];
    char authority[320];
    char path[512];
    char port[8];
};

struct forward_ctx {
    WOLFSSL *ssl;
    int failed;
    int status;
    int stream_closed;
    uint32_t stream_error_code;
    int32_t stream_id;
    uint8_t *out;
    size_t out_cap;
    size_t out_len;
};

struct req {
    struct client *owner;
    uint32_t stream_id;
    int req_type;
    char req_path[1024];
    int path_seen;
    char targethost[320];
    char targetpath[512];
    uint8_t body[BUF_MAX];
    uint32_t body_len;
    uint32_t body_off;
    uint8_t *resp;
    uint32_t resp_len;
    uint32_t resp_off;
    int status_code;
};

enum req_type {
    REQ_TYPE_NONE = 0,
    REQ_TYPE_ODOH = 1,
    REQ_TYPE_DOH = 2
};

struct target_conn {
    struct upstream up;
    int fd;
    WOLFSSL *ssl;
    nghttp2_session *session;
    struct forward_ctx *active_fx;
};

struct client {
    WOLFSSL *ssl;
    int fd;
    int tls_done;
    nghttp2_session *h2;
    struct evquick_event *ev;
    struct req req;
    struct client *next;
};

static int lfd = -1;
static WOLFSSL_CTX *srv_ctx = NULL;
static WOLFSSL_CTX *cli_ctx = NULL;
static struct client *clients = NULL;
static char *target_client_cert = NULL;
static char *target_client_key = NULL;
static struct target_conn *targets = NULL;
static size_t target_count = 0;
static int run = 1;
static int dohprint_loglevel = LOG_NOTICE;
static int dohprint_syslog = -1;

static void dohprint_init(int fg, int level)
{
    if (fg)
        dohprint_syslog = 0;
    else
        dohprint_syslog = 1;

    if (level > DOH_DEBUG)
        level = DOH_DEBUG;
    if (level < DOH_ERR)
        level = DOH_ERR;
    dohprint_loglevel = level;

    if (!fg)
        openlog("dohproxyd", LOG_PID, LOG_DAEMON);
}

static void dohprint(int lvl, const char *fmt, ...)
{
    va_list ap;

    if (dohprint_syslog) {
        va_start(ap, fmt);
        vsyslog(lvl, fmt, ap);
        va_end(ap);
        return;
    }

    if (lvl <= dohprint_loglevel) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
    }
}

static int parse_url(const char *url, struct upstream *up)
{
    const char *prefix = "https://";
    const char *p;
    const char *slash;
    const char *auth_end;
    size_t auth_len;
    char auth[320];
    int ipv6_literal = 0;

    memset(up, 0, sizeof(*up));

    if (!url || strncmp(url, prefix, strlen(prefix)) != 0)
        return -1;

    p = url + strlen(prefix);
    if (*p == '\0')
        return -1;

    slash = strchr(p, '/');
    if (slash) {
        size_t path_len = strlen(slash);
        if (path_len >= sizeof(up->path))
            return -1;
        memcpy(up->path, slash, path_len + 1);
        auth_end = slash;
    } else {
        strcpy(up->path, "/");
        auth_end = p + strlen(p);
    }

    auth_len = (size_t)(auth_end - p);
    if (auth_len == 0 || auth_len >= sizeof(auth))
        return -1;
    memcpy(auth, p, auth_len);
    auth[auth_len] = '\0';

    strcpy(up->port, "443");

    if (auth[0] == '[') {
        char *rb = strchr(auth, ']');
        char *port = NULL;
        ipv6_literal = 1;
        if (!rb)
            return -1;
        *rb = '\0';
        if (strlen(auth + 1) >= sizeof(up->host))
            return -1;
        strcpy(up->host, auth + 1);
        if (*(rb + 1) != '\0') {
            if (*(rb + 1) != ':')
                return -1;
            port = rb + 2;
            if (*port == '\0' || strlen(port) >= sizeof(up->port))
                return -1;
            strcpy(up->port, port);
        }
    } else {
        char *colon = strrchr(auth, ':');
        if (colon && strchr(auth, ':') == colon) {
            *colon = '\0';
            if (*(colon + 1) == '\0' || strlen(colon + 1) >= sizeof(up->port))
                return -1;
            strcpy(up->port, colon + 1);
        }
        if (strlen(auth) == 0 || strlen(auth) >= sizeof(up->host))
            return -1;
        strcpy(up->host, auth);
    }

    if (strcmp(up->port, "443") == 0) {
        if (ipv6_literal)
            snprintf(up->authority, sizeof(up->authority), "[%s]", up->host);
        else
            snprintf(up->authority, sizeof(up->authority), "%s", up->host);
    } else {
        if (ipv6_literal)
            snprintf(up->authority, sizeof(up->authority), "[%s]:%s", up->host, up->port);
        else
            snprintf(up->authority, sizeof(up->authority), "%s:%s", up->host, up->port);
    }

    return 0;
}

static int add_target_url(const char *url)
{
    struct target_conn *new_targets;
    struct target_conn *tc;

    if (!url || *url == '\0')
        return -1;

    new_targets = realloc(targets, (target_count + 1) * sizeof(*targets));
    if (!new_targets)
        return -1;

    targets = new_targets;
    tc = &targets[target_count];
    memset(tc, 0, sizeof(*tc));
    tc->fd = -1;
    if (parse_url(url, &tc->up) != 0)
        return -1;
    target_count++;
    return 0;
}

static int load_targets_file(const char *path)
{
    FILE *fp;
    char line[2048];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *end;

        while (*p && isspace((unsigned char)*p))
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        end = p + strlen(p);
        while (end > p && isspace((unsigned char)end[-1]))
            end--;
        *end = '\0';
        if (*p == '\0')
            continue;

        if (add_target_url(p) != 0) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static struct target_conn *select_legacy_target(void)
{
    if (target_count == 0)
        return NULL;
    {
        size_t idx = (size_t)(rand() % (int)target_count);
        return &targets[idx];
    }
}

static int parse_target_from_path(const uint8_t *value, size_t len,
    char *targethost, size_t thsz, char *targetpath, size_t tpsz)
{
    const char *q;
    const char *th;
    const char *tp;
    const char *thend;
    const char *tpend;
    char tmp[1024];

    if (len >= sizeof(tmp))
        return -1;
    memcpy(tmp, value, len);
    tmp[len] = '\0';

    q = strchr(tmp, '?');
    if (!q)
        return -1;

    th = strstr(q + 1, "targethost=");
    tp = strstr(q + 1, "targetpath=");
    if (!th || !tp)
        return -1;

    th += strlen("targethost=");
    thend = strchr(th, '&');
    if (!thend)
        thend = tmp + strlen(tmp);

    tpend = strchr(tp, '&');
    tp += strlen("targetpath=");
    if (!tpend)
        tpend = tmp + strlen(tmp);

    if (thend <= th || tpend <= tp)
        return -1;

    if ((size_t)(thend - th) >= thsz || (size_t)(tpend - tp) >= tpsz)
        return -1;

    memcpy(targethost, th, (size_t)(thend - th));
    targethost[thend - th] = '\0';
    memcpy(targetpath, tp, (size_t)(tpend - tp));
    targetpath[tpend - tp] = '\0';

    {
        size_t i = 0, o = 0;
        while (targethost[i] != '\0') {
            if (targethost[i] == '%' &&
                targethost[i + 1] != '\0' &&
                targethost[i + 2] != '\0') {
                int hi, lo;
                char c1 = targethost[i + 1];
                char c2 = targethost[i + 2];
                hi = (c1 >= '0' && c1 <= '9') ? (c1 - '0') :
                    (c1 >= 'A' && c1 <= 'F') ? (c1 - 'A' + 10) :
                    (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10) : -1;
                lo = (c2 >= '0' && c2 <= '9') ? (c2 - '0') :
                    (c2 >= 'A' && c2 <= 'F') ? (c2 - 'A' + 10) :
                    (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10) : -1;
                if (hi < 0 || lo < 0)
                    return -1;
                targethost[o++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
            targethost[o++] = targethost[i++];
        }
        targethost[o] = '\0';
    }

    {
        size_t i = 0, o = 0;
        while (targetpath[i] != '\0') {
            if (targetpath[i] == '%' &&
                targetpath[i + 1] != '\0' &&
                targetpath[i + 2] != '\0') {
                int hi, lo;
                char c1 = targetpath[i + 1];
                char c2 = targetpath[i + 2];
                hi = (c1 >= '0' && c1 <= '9') ? (c1 - '0') :
                    (c1 >= 'A' && c1 <= 'F') ? (c1 - 'A' + 10) :
                    (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10) : -1;
                lo = (c2 >= '0' && c2 <= '9') ? (c2 - '0') :
                    (c2 >= 'A' && c2 <= 'F') ? (c2 - 'A' + 10) :
                    (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10) : -1;
                if (hi < 0 || lo < 0)
                    return -1;
                targetpath[o++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
            targetpath[o++] = targetpath[i++];
        }
        targetpath[o] = '\0';
    }

    return 0;
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *rp;
    int fd = -1;
    struct timeval tv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        dohprint(DOH_WARN, "upstream resolve failed for %s:%s", host, port);
        return -1;
    }

    tv.tv_sec = TLS_IO_TIMEOUT_SEC;
    tv.tv_usec = 0;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    if (fd < 0)
        dohprint(DOH_WARN, "upstream connect failed for %s:%s", host, port);
    return fd;
}

static ssize_t out_send_cb(nghttp2_session *session, const uint8_t *data,
    size_t length, int flags, void *user_data)
{
    struct target_conn *tc = (struct target_conn *)user_data;
    int ret;
    (void)session;
    (void)flags;

    if (!tc || !tc->ssl)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    ret = wolfSSL_write(tc->ssl, data, (int)length);
    if (ret > 0)
        return ret;

    if (tc->active_fx)
        tc->active_fx->failed = 1;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int out_hdr_cb(nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data)
{
    struct target_conn *tc = (struct target_conn *)user_data;
    struct forward_ctx *fx = tc ? tc->active_fx : NULL;
    char scode[4];
    size_t cp;
    (void)session;
    (void)flags;

    if (!fx)
        return 0;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    if (frame->hd.stream_id != fx->stream_id)
        return 0;

    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        cp = valuelen >= sizeof(scode) ? sizeof(scode) - 1 : valuelen;
        memcpy(scode, value, cp);
        scode[cp] = '\0';
        fx->status = atoi(scode);
        dohprint(DOH_DEBUG, "upstream stream %d status=%d", fx->stream_id, fx->status);
    }
    return 0;
}

static int out_data_cb(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    struct target_conn *tc = (struct target_conn *)user_data;
    struct forward_ctx *fx = tc ? tc->active_fx : NULL;
    (void)session;
    (void)flags;

    if (!fx || stream_id != fx->stream_id)
        return 0;

    if (fx->out_len + len > fx->out_cap) {
        fx->failed = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    memcpy(fx->out + fx->out_len, data, len);
    fx->out_len += len;
    return 0;
}

static int out_close_cb(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code, void *user_data)
{
    struct target_conn *tc = (struct target_conn *)user_data;
    struct forward_ctx *fx = tc ? tc->active_fx : NULL;
    (void)session;
    (void)error_code;

    if (fx && stream_id == fx->stream_id)
    {
        fx->stream_error_code = error_code;
        fx->stream_closed = 1;
        if (error_code != NGHTTP2_NO_ERROR) {
            fx->failed = 1;
            dohprint(DOH_WARN, "upstream stream %d closed with error_code=%u",
                stream_id, error_code);
        }
    }
    return 0;
}

static ssize_t out_body_read_cb(nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data)
{
    struct req *req = (struct req *)source->ptr;
    size_t left;
    (void)session;
    (void)stream_id;
    (void)user_data;

    left = req->body_len - req->body_off;
    if (left == 0) {
        req->body_off = 0;
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    if (left > length)
        left = length;

    memcpy(buf, req->body + req->body_off, left);
    req->body_off += left;
    if (req->body_off == req->body_len)
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)left;
}

static void close_target_connection(struct target_conn *tc)
{
    if (!tc)
        return;
    if (tc->session) {
        nghttp2_session_del(tc->session);
        tc->session = NULL;
    }
    if (tc->ssl) {
        wolfSSL_free(tc->ssl);
        tc->ssl = NULL;
    }
    if (tc->fd >= 0) {
        close(tc->fd);
        tc->fd = -1;
    }
    tc->active_fx = NULL;
}

static int connect_target_connection(struct target_conn *tc)
{
    nghttp2_session_callbacks *cbs = NULL;
    nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
    };

    if (!tc)
        return -1;
    if (tc->session && tc->ssl && tc->fd >= 0)
        return 0;

    close_target_connection(tc);
    tc->fd = tcp_connect(tc->up.host, tc->up.port);
    if (tc->fd < 0)
        return -1;

    tc->ssl = wolfSSL_new(cli_ctx);
    if (!tc->ssl) {
        dohprint(DOH_WARN, "wolfSSL_new failed for upstream %s", tc->up.authority);
        goto fail;
    }

    wolfSSL_set_fd(tc->ssl, tc->fd);
    wolfSSL_UseSNI(tc->ssl, WOLFSSL_SNI_HOST_NAME, tc->up.host,
        (unsigned short)strlen(tc->up.host));
    wolfSSL_UseALPN(tc->ssl, "h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

    if (target_client_cert && target_client_key) {
        if (wolfSSL_use_certificate_file(tc->ssl, target_client_cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
            dohprint(DOH_WARN, "cannot load upstream client certificate %s", target_client_cert);
            goto fail;
        }
        if (wolfSSL_use_PrivateKey_file(tc->ssl, target_client_key, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
            dohprint(DOH_WARN, "cannot load upstream client key %s", target_client_key);
            goto fail;
        }
    }

    if (wolfSSL_connect(tc->ssl) != SSL_SUCCESS) {
        int err = wolfSSL_get_error(tc->ssl, -1);
        dohprint(DOH_WARN, "upstream TLS connect failed to %s (err=%d)", tc->up.authority, err);
        goto fail;
    }

    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        dohprint(DOH_WARN, "nghttp2_session_callbacks_new failed");
        goto fail;
    }
    nghttp2_session_callbacks_set_send_callback(cbs, out_send_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, out_hdr_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, out_data_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, out_close_cb);

    if (nghttp2_session_client_new(&tc->session, cbs, tc) != 0) {
        dohprint(DOH_WARN, "nghttp2_session_client_new failed for %s", tc->up.authority);
        goto fail;
    }
    nghttp2_session_callbacks_del(cbs);
    if (nghttp2_submit_settings(tc->session, NGHTTP2_FLAG_NONE, iv, 1) != 0) {
        dohprint(DOH_WARN, "nghttp2_submit_settings failed for %s", tc->up.authority);
        goto fail;
    }
    dohprint(DOH_DEBUG, "connected upstream %s%s", tc->up.authority, tc->up.path);
    return 0;

fail:
    if (cbs)
        nghttp2_session_callbacks_del(cbs);
    close_target_connection(tc);
    return -1;
}

static int forward_to_upstream(struct target_conn *tc, struct req *req,
    const char *content_type, uint8_t *out, uint32_t *out_len)
{
    uint8_t tlsbuf[4096];
    nghttp2_data_provider dp;
    nghttp2_nv nva[7];
    struct forward_ctx fx = {};
    char clen[32];
    int ret;
    int tries;

    for (tries = 0; tries < 2; tries++) {
        if (connect_target_connection(tc) != 0)
            continue;

        memset(&fx, 0, sizeof(fx));
        fx.ssl = tc->ssl;
        fx.out = out;
        fx.out_cap = *out_len;
        tc->active_fx = &fx;

        req->body_off = 0;
        snprintf(clen, sizeof(clen), "%u", req->body_len);
        nva[0] = MAKE_NV(":method", "POST");
        nva[1] = MAKE_NV(":scheme", "https");
        nva[2] = MAKE_NV(":authority", tc->up.authority);
        nva[3] = MAKE_NV(":path", tc->up.path);
        nva[4] = MAKE_NV("content-type", content_type);
        nva[5] = MAKE_NV("accept", content_type);
        nva[6] = MAKE_NV("content-length", clen);

        memset(&dp, 0, sizeof(dp));
        dp.source.ptr = req;
        dp.read_callback = out_body_read_cb;

        fx.stream_id = nghttp2_submit_request(tc->session, NULL, nva, 7, &dp, NULL);
        if (fx.stream_id < 0) {
            dohprint(DOH_WARN, "nghttp2_submit_request failed for upstream %s", tc->up.authority);
            tc->active_fx = NULL;
            close_target_connection(tc);
            continue;
        }

        while (!fx.stream_closed && !fx.failed) {
            if (nghttp2_session_send(tc->session) != 0) {
                dohprint(DOH_WARN, "nghttp2_session_send failed for upstream %s", tc->up.authority);
                fx.failed = 1;
                break;
            }

            ret = wolfSSL_read(tc->ssl, tlsbuf, sizeof(tlsbuf));
            if (ret <= 0) {
                int werr = wolfSSL_get_error(tc->ssl, ret);
                if (werr == WOLFSSL_ERROR_WANT_READ || werr == WOLFSSL_ERROR_WANT_WRITE)
                    continue;
                dohprint(DOH_WARN, "upstream TLS read failed for %s (err=%d)", tc->up.authority, werr);
                fx.failed = 1;
                break;
            }

            if (nghttp2_session_mem_recv(tc->session, tlsbuf, (size_t)ret) < 0) {
                dohprint(DOH_WARN, "nghttp2_session_mem_recv failed for upstream %s", tc->up.authority);
                fx.failed = 1;
                break;
            }
        }

        tc->active_fx = NULL;
        if (!fx.failed && fx.status == 200) {
            *out_len = (uint32_t)fx.out_len;
            dohprint(DOH_DEBUG, "upstream %s replied 200 (%u bytes)", tc->up.authority, *out_len);
            return 0;
        }
        dohprint(DOH_WARN, "upstream %s returned failure (status=%d, failed=%d, stream_err=%u, tries=%d)",
            tc->up.authority, fx.status, fx.failed, fx.stream_error_code, tries + 1);

        close_target_connection(tc);
    }
    return -1;
}

static int forward_to_dynamic_target(struct req *req, uint8_t *out, uint32_t *out_len)
{
    char full[1024];
    struct target_conn tc = {};

    if (snprintf(full, sizeof(full), "https://%s%s", req->targethost, req->targetpath) >= (int)sizeof(full))
        return -1;
    if (parse_url(full, &tc.up) != 0)
        return -1;
    tc.fd = -1;

    if (forward_to_upstream(&tc, req, "application/oblivious-dns-message", out, out_len) != 0) {
        close_target_connection(&tc);
        return -1;
    }

    close_target_connection(&tc);
    return 0;
}

static void free_client(struct client *cl)
{
    struct client **pp = &clients;
    while (*pp) {
        if (*pp == cl) {
            *pp = cl->next;
            break;
        }
        pp = &(*pp)->next;
    }

    if (cl->ev)
        evquick_delevent(cl->ev);
    if (cl->h2)
        nghttp2_session_del(cl->h2);
    if (cl->ssl)
        wolfSSL_free(cl->ssl);
    if (cl->fd >= 0)
        close(cl->fd);
    free(cl->req.resp);
    free(cl);
}

static ssize_t in_send_cb(nghttp2_session *session, const uint8_t *data,
    size_t length, int flags, void *user_data)
{
    struct client *cl = (struct client *)user_data;
    (void)session;
    (void)flags;
    return wolfSSL_write(cl->ssl, data, (int)length);
}

static ssize_t in_resp_read_cb(nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data)
{
    struct req *req = (struct req *)source->ptr;
    uint32_t left;
    (void)session;
    (void)stream_id;
    (void)user_data;

    left = req->resp_len - req->resp_off;
    if (left == 0) {
        req->resp_off = 0;
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    if (left > length)
        left = (uint32_t)length;

    memcpy(buf, req->resp + req->resp_off, left);
    req->resp_off += left;
    if (req->resp_off == req->resp_len)
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return left;
}

static int in_header_cb(nghttp2_session *session,
    const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    struct client *cl = (struct client *)user_data;
    struct req *req = &cl->req;
    const char pathn[] = ":path";
    const char ctn[] = "content-type";
    const char odoh_ct[] = "application/oblivious-dns-message";
    const char doh_ct[] = "application/dns-message";
    (void)session;
    (void)flags;

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;

    if (frame->hd.stream_id != (int32_t)req->stream_id)
        req->stream_id = frame->hd.stream_id;

    if (namelen == strlen(pathn) && memcmp(name, pathn, namelen) == 0) {
        if (valuelen >= sizeof(req->req_path))
            req->status_code = 400;
        else {
            memcpy(req->req_path, value, valuelen);
            req->req_path[valuelen] = '\0';
            req->path_seen = 1;
        }
    } else if (namelen == strlen(ctn) && memcmp(name, ctn, namelen) == 0) {
        if (valuelen == strlen(odoh_ct) && memcmp(value, odoh_ct, valuelen) == 0) {
            req->req_type = REQ_TYPE_ODOH;
        } else if (valuelen == strlen(doh_ct) && memcmp(value, doh_ct, valuelen) == 0) {
            req->req_type = REQ_TYPE_DOH;
        } else {
            req->status_code = 415;
        }
    }

    return 0;
}

static int in_data_cb(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    struct client *cl = (struct client *)user_data;
    struct req *req = &cl->req;
    (void)session;
    (void)flags;

    if (stream_id != (int32_t)req->stream_id)
        return 0;

    if ((req->body_len + len) > sizeof(req->body)) {
        req->status_code = 413;
        return 0;
    }

    memcpy(req->body + req->body_len, data, len);
    req->body_len += (uint32_t)len;
    return 0;
}

static int in_frame_recv_cb(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
    struct client *cl = (struct client *)user_data;
    struct req *req = &cl->req;
    nghttp2_nv nva[2];
    nghttp2_data_provider dp;

    if ((frame->hd.type != NGHTTP2_DATA && frame->hd.type != NGHTTP2_HEADERS) ||
        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;

    if (req->status_code == 0 && req->req_type == REQ_TYPE_NONE)
        req->status_code = 400;
    if (req->status_code == 0 && req->req_type == REQ_TYPE_ODOH) {
        if (!req->path_seen || parse_target_from_path((const uint8_t *)req->req_path,
                strlen(req->req_path), req->targethost, sizeof(req->targethost),
                req->targetpath, sizeof(req->targetpath)) != 0) {
            req->status_code = 400;
        }
    }
    if (req->status_code == 0 && req->req_type == REQ_TYPE_DOH && target_count == 0)
        req->status_code = 502;

    if (req->status_code == 0) {
        struct target_conn *legacy;
        uint32_t out_len = BUF_MAX;
        req->resp = malloc(out_len);
        if (!req->resp) {
            req->status_code = 500;
        } else {
            if (req->req_type == REQ_TYPE_ODOH) {
                if (forward_to_dynamic_target(req, req->resp, &out_len) != 0)
                    req->status_code = 502;
                else
                    req->resp_len = out_len;
            } else {
                legacy = select_legacy_target();
                if (!legacy || forward_to_upstream(legacy, req,
                        "application/dns-message", req->resp, &out_len) != 0) {
                    req->status_code = 502;
                } else {
                    req->resp_len = out_len;
                }
            }
        }
    }

    if (req->status_code == 502) {
        dohprint(DOH_WARN, "returning 502 to client (req_type=%s)",
            req->req_type == REQ_TYPE_ODOH ? "odoh" :
            req->req_type == REQ_TYPE_DOH ? "doh" : "unknown");
    }

    if (req->status_code != 0) {
        nva[0] = MAKE_NV(":status", "400");
        nva[1] = MAKE_NV("server", "dohproxyd");
        if (req->status_code == 403) nva[0] = MAKE_NV(":status", "403");
        if (req->status_code == 413) nva[0] = MAKE_NV(":status", "413");
        if (req->status_code == 415) nva[0] = MAKE_NV(":status", "415");
        if (req->status_code == 500) nva[0] = MAKE_NV(":status", "500");
        if (req->status_code == 502) nva[0] = MAKE_NV(":status", "502");
        nghttp2_submit_response(session, req->stream_id, nva, 2, NULL);
    } else {
        const char *response_ct = (req->req_type == REQ_TYPE_ODOH) ?
            "application/oblivious-dns-message" : "application/dns-message";
        nghttp2_nv oknva[] = {
            MAKE_NV(":status", "200"),
            MAKE_NV("content-type", response_ct),
            MAKE_NV("server", "dohproxyd"),
        };
        memset(&dp, 0, sizeof(dp));
        dp.source.ptr = req;
        dp.read_callback = in_resp_read_cb;
        nghttp2_submit_response(session, req->stream_id, oknva, 3, &dp);
    }

    nghttp2_session_send(session);
    free(req->resp);
    memset(req, 0, sizeof(*req));
    return 0;
}

static int in_stream_close_cb(nghttp2_session *session, int32_t stream_id,
    uint32_t error_code, void *user_data)
{
    (void)session;
    (void)stream_id;
    (void)error_code;
    (void)user_data;
    return 0;
}

static void client_read(int fd, short revents, void *arg)
{
    struct client *cl = (struct client *)arg;
    uint8_t buf[8192];
    int ret;

    (void)fd;
    (void)revents;

    if (!cl || !cl->ssl)
        return;

    if (!cl->tls_done) {
        ret = wolfSSL_accept(cl->ssl);
        if (ret != SSL_SUCCESS) {
            int err = wolfSSL_get_error(cl->ssl, ret);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
                return;
            free_client(cl);
            return;
        }

        nghttp2_session_callbacks *cbs = NULL;
        nghttp2_settings_entry iv[1] = {{ NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }};

        if (nghttp2_session_callbacks_new(&cbs) != 0) {
            free_client(cl);
            return;
        }
        nghttp2_session_callbacks_set_send_callback(cbs, in_send_cb);
        nghttp2_session_callbacks_set_on_header_callback(cbs, in_header_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, in_data_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, in_frame_recv_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, in_stream_close_cb);
        nghttp2_session_server_new(&cl->h2, cbs, cl);
        nghttp2_session_callbacks_del(cbs);
        nghttp2_submit_settings(cl->h2, NGHTTP2_FLAG_NONE, iv, 1);
        cl->tls_done = 1;
        return;
    }

    ret = wolfSSL_read(cl->ssl, buf, sizeof(buf));
    if (ret <= 0) {
        free_client(cl);
        return;
    }

    if (nghttp2_session_mem_recv(cl->h2, buf, (size_t)ret) < 0) {
        free_client(cl);
        return;
    }

    while (nghttp2_session_want_write(cl->h2)) {
        if (nghttp2_session_send(cl->h2) < 0) {
            free_client(cl);
            return;
        }
    }
}

static void client_fail(int fd, short revents, void *arg)
{
    (void)fd;
    (void)revents;
    free_client((struct client *)arg);
}

static void accept_client(int fd, short revents, void *arg)
{
    int cfd;
    int yes = 1;
    socklen_t sl = 0;
    struct client *cl;

    (void)fd;
    (void)revents;
    (void)arg;

    cfd = accept(lfd, NULL, &sl);
    if (cfd < 0)
        return;

    cl = calloc(1, sizeof(*cl));
    if (!cl) {
        close(cfd);
        return;
    }

    cl->fd = cfd;
    cl->ssl = wolfSSL_new(srv_ctx);
    if (!cl->ssl) {
        free(cl);
        close(cfd);
        return;
    }

    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));
    wolfSSL_UseALPN(cl->ssl, "h2", 2, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    wolfSSL_set_fd(cl->ssl, cfd);

    cl->ev = evquick_addevent(cfd, EVQUICK_EV_READ, client_read, client_fail, cl);
    cl->next = clients;
    clients = cl;
}

static void usage(const char *name)
{
    fprintf(stderr, "%s, ODoH proxy with legacy RFC8484 forwarding.\n", name);
    fprintf(stderr, "Usage: %s -c cert -k key [-p port] [-4|-6] [-u user] [-A cafile] [--target-url https://host/path]... [--targets-file file] [--target-cert cert --target-key key] [-F] [-v] [-V] [-h]\n", name);
    fprintf(stderr, "  cert/key: TLS server certificate and key\n");
    fprintf(stderr, "  -4: force IPv4 only\n");
    fprintf(stderr, "  -6: force IPv6 only (default: dual-stack)\n");
    fprintf(stderr, "  -A/--ca-file: CA bundle for verifying upstream target TLS certs\n");
    fprintf(stderr, "  --target-url: repeatable legacy RFC8484 target URL\n");
    fprintf(stderr, "  --targets-file: file with target URLs (one per line)\n");
    fprintf(stderr, "  target selection for legacy requests follows RFC-style random rotation\n");
    fprintf(stderr, "  --target-cert/--target-key: mTLS cert/key for target resolver\n");
}

int main(int argc, char *argv[])
{
    char *cert = NULL, *key = NULL;
    char *user = NULL;
    char *targets_file = NULL;
    char *upstream_cafile = NULL;
    uint16_t port = PROXY_PORT;
    int ip_version = 0;  /* 0 = dual-stack, 4 = IPv4 only, 6 = IPv6 only */
    int foreground = 0;
    int loglvl = DOH_WARN;
    int c, option_idx = 0;
    int yes = 1;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'V'},
        {"cert", 1, 0, 'c'},
        {"key", 1, 0, 'k'},
        {"port", 1, 0, 'p'},
        {"user", 1, 0, 'u'},
        {"verbose", 0, 0, 'v'},
        {"do-not-fork", 0, 0, 'F'},
        {"ca-file", 1, 0, 'A'},
        {"target-cert", 1, 0, 'x'},
        {"target-key", 1, 0, 'y'},
        {"target-url", 1, 0, 't'},
        {"targets-file", 1, 0, 'T'},
        {"ipv4", 0, 0, '4'},
        {"ipv6", 0, 0, '6'},
        {NULL, 0, 0, 0}
    };

    while (1) {
        c = getopt_long(argc, argv, "46hVc:k:p:u:A:vFx:y:t:T:", long_options, &option_idx);
        if (c < 0)
            break;

        switch (c) {
            case 'h': usage(argv[0]); return 0;
            case 'V': fprintf(stderr, "%s, %s\n", argv[0], VERSION); return 0;
            case 'c': cert = strdup(optarg); break;
            case 'k': key = strdup(optarg); break;
            case 'p': port = (uint16_t)atoi(optarg); break;
            case 'u': user = strdup(optarg); break;
            case 'A': upstream_cafile = strdup(optarg); break;
            case 'v': loglvl = DOH_DEBUG; break;
            case 'F': foreground = 1; break;
            case 'x': target_client_cert = strdup(optarg); break;
            case 'y': target_client_key = strdup(optarg); break;
            case '4': ip_version = 4; break;
            case '6': ip_version = 6; break;
            case 't':
                if (add_target_url(optarg) != 0)
                    return 2;
                break;
            case 'T':
                free(targets_file);
                targets_file = strdup(optarg);
                break;
            default: usage(argv[0]); return 2;
        }
    }

    if (!cert || !key)
        return 2;
    if ((target_client_cert && !target_client_key) ||
        (!target_client_cert && target_client_key))
        return 2;
    if (targets_file && load_targets_file(targets_file) != 0)
        return 2;

    if (!foreground) {
        int pid = fork();
        if (pid < 0) return 1;
        if (pid > 0) return 0;
        pid = fork();
        if (pid < 0) return 1;
        if (pid > 0) return 0;
        setsid();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    signal(SIGPIPE, SIG_IGN);
    dohprint_init(foreground, loglvl);
    srand((unsigned)time(NULL));

    wolfSSL_Init();
    evquick_init();

    srv_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    cli_ctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (!srv_ctx || !cli_ctx)
        return 1;

    wolfSSL_CTX_set_verify(cli_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (upstream_cafile) {
        if (wolfSSL_CTX_load_verify_locations(cli_ctx, upstream_cafile, NULL) != SSL_SUCCESS)
            return 1;
    } else {
        if (wolfSSL_CTX_load_system_CA_certs(cli_ctx) != SSL_SUCCESS)
            wolfSSL_CTX_set_default_verify_paths(cli_ctx);
    }

    if (wolfSSL_CTX_use_certificate_chain_file(srv_ctx, cert) != SSL_SUCCESS)
        return 1;
    if (wolfSSL_CTX_use_PrivateKey_file(srv_ctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS)
        return 1;

    /* Create listening socket based on IP version preference */
    if (ip_version == 4) {
        /* IPv4 only */
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0)
            return 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
        setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, sizeof(yes));

        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = INADDR_ANY;
        addr4.sin_port = htons(port);

        if (bind(lfd, (struct sockaddr *)&addr4, sizeof(addr4)) != 0)
            return 1;
        dohprint(DOH_NOTICE, "dohproxyd listening on 0.0.0.0:%u (IPv4 only)", port);
    } else {
        /* IPv6 (with or without dual-stack) */
        lfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (lfd < 0)
            return 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
        setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, (char *)&yes, sizeof(yes));

        if (ip_version == 6) {
            /* IPv6 only - disable dual-stack */
            int ipv6only = 1;
            setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);

        if (bind(lfd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0)
            return 1;

        if (ip_version == 6)
            dohprint(DOH_NOTICE, "dohproxyd listening on [::]:%u (IPv6 only)", port);
        else
            dohprint(DOH_NOTICE, "dohproxyd listening on [::]:%u (dual-stack)", port);
    }

    if (listen(lfd, 32) != 0)
        return 1;

    if (getuid() == 0 && user) {
        struct passwd *pwd = getpwnam(user);
        if (pwd) {
            if (setgid(pwd->pw_gid) != 0 || setuid(pwd->pw_uid) != 0)
                return 1;
        }
    }

    evquick_addevent(lfd, EVQUICK_EV_READ, accept_client, NULL, NULL);

    while (run)
        evquick_loop();

    if (targets) {
        size_t i;
        for (i = 0; i < target_count; i++)
            close_target_connection(&targets[i]);
        free(targets);
    }
    free(targets_file);
    free(target_client_cert);
    free(target_client_key);
    return 0;
}
