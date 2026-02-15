/*
 *      ns2dohd.c
 *
 *      This is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU Affero General Public License, as
 *      published by the free Software Foundation.
 *
 *      ns2dohd is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU Affero General Public
 *      License along with ns2dohd.  If not, see <http://www.gnu.org/licenses/>.
 *
 *      Author: Dyne.org Foundation <info@dyne.org>
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <nghttp2/nghttp2.h>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
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

#define NS2DOHD_PORT 53
#define DNS_BUFFER_MAXSIZE 4096
#define DNS_HEADER_MIN 12
#define TLS_IO_TIMEOUT_SEC 5
#define DOH_EXCHANGE_TIMEOUT_SEC 20
#define DEFAULT_CA_BUNDLE "/etc/ssl/certs/ca-certificates.crt"
#define DEFAULT_BOOTSTRAP_DNS_IP "1.1.1.1"
#define DEFAULT_BOOTSTRAP_DNS_PORT 53
#define DNS_TIMEOUT_SEC 2

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

struct doh_upstream {
    char host[256];
    char authority[320];
    char path[512];
    char port[8];
};

struct doh_exchange {
    const uint8_t *query;
    size_t query_len;
    size_t query_off;
    uint8_t *response;
    size_t response_cap;
    size_t response_len;
    int status_code;
    int stream_id;
    int stream_closed;
    uint32_t stream_error_code;
    int failed;
};

struct h2_conn {
    WOLFSSL *ssl;
    struct doh_exchange *xchg;
};

struct ns2dohd_stats {
    uint64_t queries;
    uint64_t replies;
    uint64_t errors;
    uint64_t servfail_replies;
};

static volatile sig_atomic_t run = 1;
static int dohprint_loglevel = LOG_NOTICE;
static int dohprint_syslog = -1;
static struct ns2dohd_stats stats = {};
static struct sockaddr_storage bootstrap_resolver = {};
static socklen_t bootstrap_resolver_len = 0;
static void dohprint(int lvl, const char *fmt, ...);

static int parse_bootstrap_resolver(const char *s,
    struct sockaddr_storage *out, socklen_t *out_len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)out;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
    struct in_addr a4;
    struct in6_addr a6;

    memset(out, 0, sizeof(*out));

    if (inet_pton(AF_INET, s, &a4) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(DEFAULT_BOOTSTRAP_DNS_PORT);
        sin->sin_addr = a4;
        *out_len = sizeof(*sin);
        return 0;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(DEFAULT_BOOTSTRAP_DNS_PORT);
        sin6->sin6_addr = a6;
        *out_len = sizeof(*sin6);
        return 0;
    }

    return -1;
}

static int drop_privileges(const char *user)
{
    struct passwd *pw;

    if (!user)
        return 0;

    if (getuid() != 0) {
        dohprint(DOH_WARN, "not running as root: '-u' ignored");
        return 0;
    }

    pw = getpwnam(user);
    if (!pw) {
        dohprint(DOH_ERR, "cannot find user '%s'", user);
        return -1;
    }

    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        dohprint(DOH_ERR, "cannot drop privileges to '%s'", user);
        return -1;
    }
    return 0;
}

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
        openlog("ns2dohd", LOG_PID, LOG_DAEMON);
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

static void usage(const char *name)
{
    fprintf(stderr, "%s, local DNS to DoH forwarder daemon.\n", name);
    fprintf(stderr, "License: AGPL\n");
    fprintf(stderr, "Usage: %s -d https://host/path [-p port] [-u user] [-r resolver] [-A cafile] [-F] [-v] [-V] [-h]\n", name);
    fprintf(stderr, "\t'-d': DoH upstream URL (mandatory, https only)\n");
    fprintf(stderr, "\t'-p': local UDP listen port (default: 53)\n");
    fprintf(stderr, "\t'-u': user to switch to after binding (root only)\n");
    fprintf(stderr, "\t'-r': bootstrap DNS resolver IP (default: 1.1.1.1)\n");
    fprintf(stderr, "\t'-A': CA certificate bundle file (PEM)\n");
    fprintf(stderr, "\t'-F': run in foreground\n");
    fprintf(stderr, "\t'-v': verbose logging\n");
    fprintf(stderr, "\t'-V': show version\n");
    fprintf(stderr, "\t'-h': help\n");
}

static void handle_sigint(int sig)
{
    (void)sig;
    run = 0;
}

static void handle_sigusr1(int sig)
{
    (void)sig;
    dohprint(DOH_NOTICE, "ns2dohd v. %s stats", VERSION);
    dohprint(DOH_NOTICE, "queries=%lu replies=%lu errors=%lu servfail=%lu",
        stats.queries, stats.replies, stats.errors, stats.servfail_replies);
}

static int parse_port(const char *s, uint16_t *out)
{
    char *end = NULL;
    long p;

    errno = 0;
    p = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || p < 1 || p > 65535)
        return -1;
    *out = (uint16_t)p;
    return 0;
}

static int parse_doh_url(const char *url, struct doh_upstream *up)
{
    const char *prefix = "https://";
    const char *p;
    const char *slash;
    const char *auth_end;
    size_t auth_len;
    char auth[320];

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
        if (auth[0] == '[')
            snprintf(up->authority, sizeof(up->authority), "[%s]", up->host);
        else
            snprintf(up->authority, sizeof(up->authority), "%s", up->host);
    } else {
        if (auth[0] == '[')
            snprintf(up->authority, sizeof(up->authority), "[%s]:%s", up->host, up->port);
        else
            snprintf(up->authority, sizeof(up->authority), "%s:%s", up->host, up->port);
    }

    return 0;
}

static int make_servfail(const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
    uint16_t flags;

    if (inlen < DNS_HEADER_MIN)
        return -1;

    if (inlen > DNS_BUFFER_MAXSIZE)
        inlen = DNS_BUFFER_MAXSIZE;

    memcpy(out, in, inlen);

    flags = ((uint16_t)in[2] << 8) | in[3];
    flags &= 0x0100;
    flags |= 0x8082;

    out[2] = (uint8_t)(flags >> 8);
    out[3] = (uint8_t)(flags & 0xff);

    out[6] = 0;
    out[7] = 0;
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;

    *outlen = inlen;
    return 0;
}

static unsigned long long monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return ((unsigned long long)ts.tv_sec * 1000ULL) +
        ((unsigned long long)ts.tv_nsec / 1000000ULL);
}

static uint16_t rd_u16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int dns_skip_name(const uint8_t *msg, size_t mlen, size_t off, size_t *next_off)
{
    size_t steps = 0;

    while (off < mlen && steps < 256) {
        uint8_t c = msg[off];
        if ((c & 0xC0) == 0xC0) {
            if ((off + 1) >= mlen)
                return -1;
            *next_off = off + 2;
            return 0;
        }
        if (c == 0) {
            *next_off = off + 1;
            return 0;
        }
        off++;
        if ((off + c) > mlen)
            return -1;
        off += c;
        steps++;
    }

    return -1;
}

static int dns_put_qname(const char *host, uint8_t *out, size_t out_cap, size_t *out_len)
{
    const char *p = host;
    size_t used = 0;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);

        if (len == 0 || len > 63 || (used + 1 + len + 1) > out_cap)
            return -1;

        out[used++] = (uint8_t)len;
        memcpy(out + used, p, len);
        used += len;

        if (!dot)
            break;
        p = dot + 1;
    }

    if ((used + 1) > out_cap)
        return -1;
    out[used++] = 0;
    *out_len = used;
    return 0;
}

static int resolve_host_bootstrap_type(const char *host, uint16_t qtype,
    struct sockaddr_storage *out, socklen_t *out_len)
{
    uint8_t qbuf[512];
    uint8_t rbuf[512];
    size_t qname_len = 0;
    size_t off;
    uint16_t id;
    int sd;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t n;
    struct timeval tv;
    int i;

    memset(qbuf, 0, sizeof(qbuf));
    if (bootstrap_resolver_len == 0)
        return -1;

    sd = socket(bootstrap_resolver.ss_family, SOCK_DGRAM, 0);
    if (sd < 0)
        return -1;

    tv.tv_sec = DNS_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        close(sd);
        return -1;
    }

    id = (uint16_t)(((unsigned)getpid() ^ (unsigned)time(NULL)) & 0xFFFF);
    qbuf[0] = (uint8_t)(id >> 8);
    qbuf[1] = (uint8_t)(id & 0xFF);
    qbuf[2] = 0x01; /* RD */
    qbuf[5] = 0x01; /* QDCOUNT */

    if (dns_put_qname(host, qbuf + DNS_HEADER_MIN, sizeof(qbuf) - DNS_HEADER_MIN, &qname_len) != 0) {
        close(sd);
        return -1;
    }

    off = DNS_HEADER_MIN + qname_len;
    if ((off + 4) > sizeof(qbuf)) {
        close(sd);
        return -1;
    }
    qbuf[off++] = (uint8_t)(qtype >> 8);
    qbuf[off++] = (uint8_t)(qtype & 0xFF);
    qbuf[off++] = 0x00; /* IN */
    qbuf[off++] = 0x01;

    if (sendto(sd, qbuf, off, 0,
            (struct sockaddr *)&bootstrap_resolver, bootstrap_resolver_len) < 0) {
        close(sd);
        return -1;
    }

    n = recvfrom(sd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &fromlen);
    close(sd);
    if (n < DNS_HEADER_MIN)
        return -1;

    if (rd_u16(rbuf) != id)
        return -1;
    if ((rbuf[2] & 0x80) == 0)
        return -1;
    if ((rbuf[3] & 0x0F) != 0)
        return -1;
    if (rd_u16(rbuf + 4) != 1)
        return -1;

    off = DNS_HEADER_MIN;
    if (dns_skip_name(rbuf, (size_t)n, off, &off) != 0)
        return -1;
    if ((off + 4) > (size_t)n)
        return -1;
    off += 4;

    for (i = 0; i < (int)rd_u16(rbuf + 6); i++) {
        uint16_t atype, aclass, rdlen;

        if (dns_skip_name(rbuf, (size_t)n, off, &off) != 0)
            return -1;
        if ((off + 10) > (size_t)n)
            return -1;

        atype = rd_u16(rbuf + off);
        aclass = rd_u16(rbuf + off + 2);
        rdlen = rd_u16(rbuf + off + 8);
        off += 10;

        if ((off + rdlen) > (size_t)n)
            return -1;

        if (aclass == 1 && atype == qtype) {
            if (qtype == 1 && rdlen == 4) {
                struct sockaddr_in *sin = (struct sockaddr_in *)out;
                memset(out, 0, sizeof(*out));
                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, rbuf + off, 4);
                *out_len = sizeof(*sin);
                return 0;
            }
            if (qtype == 28 && rdlen == 16) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
                memset(out, 0, sizeof(*out));
                sin6->sin6_family = AF_INET6;
                memcpy(&sin6->sin6_addr, rbuf + off, 16);
                *out_len = sizeof(*sin6);
                return 0;
            }
        }

        off += rdlen;
    }

    return -1;
}

static int resolve_host_bootstrap(const char *host, struct sockaddr_storage *out, socklen_t *out_len)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, host, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        memset(out, 0, sizeof(*out));
        sin->sin_family = AF_INET;
        sin->sin_addr = a4;
        *out_len = sizeof(*sin);
        return 0;
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        memset(out, 0, sizeof(*out));
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a6;
        *out_len = sizeof(*sin6);
        return 0;
    }

    if (resolve_host_bootstrap_type(host, 1, out, out_len) == 0)
        return 0;
    if (resolve_host_bootstrap_type(host, 28, out, out_len) == 0)
        return 0;
    return -1;
}

static int tcp_connect_timeout(const struct doh_upstream *up)
{
    struct sockaddr_storage resolved;
    socklen_t resolved_len = 0;
    int fd = -1;
    struct timeval tv;
    uint16_t port;
    char *end = NULL;
    long p;

    p = strtol(up->port, &end, 10);
    if (!end || *end != '\0' || p < 1 || p > 65535)
        return -1;
    port = (uint16_t)p;

    if (resolve_host_bootstrap(up->host, &resolved, &resolved_len) != 0)
        return -1;

    tv.tv_sec = TLS_IO_TIMEOUT_SEC;
    tv.tv_usec = 0;

    if (resolved.ss_family == AF_INET) {
        ((struct sockaddr_in *)&resolved)->sin_port = htons(port);
    } else if (resolved.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)&resolved)->sin6_port = htons(port);
    } else {
        return -1;
    }

    fd = socket(resolved.ss_family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&resolved, resolved_len) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t h2_read_cb(nghttp2_session *session,
    int32_t stream_id,
    uint8_t *buf,
    size_t length,
    uint32_t *data_flags,
    nghttp2_data_source *source,
    void *user_data)
{
    struct doh_exchange *x = (struct doh_exchange *)source->ptr;
    size_t left;

    (void)session;
    (void)stream_id;
    (void)user_data;

    if (!x || x->query_off > x->query_len)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    left = x->query_len - x->query_off;
    if (left == 0) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    if (left > length)
        left = length;

    memcpy(buf, x->query + x->query_off, left);
    x->query_off += left;

    if (x->query_off == x->query_len)
        *data_flags = NGHTTP2_DATA_FLAG_EOF;

    return (ssize_t)left;
}

static ssize_t h2_send_cb(nghttp2_session *session,
    const uint8_t *data,
    size_t length,
    int flags,
    void *user_data)
{
    struct h2_conn *conn = (struct h2_conn *)user_data;
    int ret;

    (void)session;
    (void)flags;

    ret = wolfSSL_write(conn->ssl, data, (int)length);
    if (ret > 0)
        return ret;

    conn->xchg->failed = 1;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int h2_on_header_cb(nghttp2_session *session,
    const nghttp2_frame *frame,
    const uint8_t *name,
    size_t namelen,
    const uint8_t *value,
    size_t valuelen,
    uint8_t flags,
    void *user_data)
{
    struct h2_conn *conn = (struct h2_conn *)user_data;

    (void)session;
    (void)flags;

    if (!conn || !conn->xchg)
        return 0;

    if (frame->hd.stream_id != conn->xchg->stream_id)
        return 0;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
        return 0;

    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        char scode[4];
        size_t cp = valuelen;
        if (cp >= sizeof(scode))
            cp = sizeof(scode) - 1;
        memcpy(scode, value, cp);
        scode[cp] = '\0';
        conn->xchg->status_code = atoi(scode);
    }

    return 0;
}

static int h2_on_data_chunk_recv_cb(nghttp2_session *session,
    uint8_t flags,
    int32_t stream_id,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    struct h2_conn *conn = (struct h2_conn *)user_data;
    struct doh_exchange *x;

    (void)session;
    (void)flags;

    if (!conn || !conn->xchg)
        return 0;

    x = conn->xchg;
    if (stream_id != x->stream_id)
        return 0;

    if ((x->response_len + len) > x->response_cap) {
        x->failed = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    memcpy(x->response + x->response_len, data, len);
    x->response_len += len;

    return 0;
}

static int h2_on_stream_close_cb(nghttp2_session *session,
    int32_t stream_id,
    uint32_t error_code,
    void *user_data)
{
    struct h2_conn *conn = (struct h2_conn *)user_data;

    (void)session;
    (void)error_code;

    if (conn && conn->xchg && stream_id == conn->xchg->stream_id) {
        conn->xchg->stream_error_code = error_code;
        conn->xchg->stream_closed = 1;
    }

    return 0;
}

static int doh_query_roundtrip(WOLFSSL_CTX *wctx,
    const struct doh_upstream *up,
    const uint8_t *query,
    size_t query_len,
    uint8_t *reply,
    size_t *reply_len)
{
    int fd = -1;
    int ret;
    WOLFSSL *ssl = NULL;
    char *proto = NULL;
    unsigned short proto_len = 0;
    nghttp2_session_callbacks *cbs = NULL;
    nghttp2_session *session = NULL;
    nghttp2_data_provider data_prd;
    nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
    };
    nghttp2_nv nva[7];
    struct doh_exchange x = {};
    struct h2_conn conn = {};
    uint8_t tlsbuf[DNS_BUFFER_MAXSIZE];
    char clength[32];
    char errbuf[160];
    unsigned long long deadline_ms;

    *reply_len = 0;
    deadline_ms = monotonic_ms() + (DOH_EXCHANGE_TIMEOUT_SEC * 1000ULL);

    fd = tcp_connect_timeout(up);
    if (fd < 0) {
        dohprint(DOH_DEBUG, "DoH connection failed");
        return -1;
    }

    ssl = wolfSSL_new(wctx);
    if (!ssl) {
        dohprint(DOH_DEBUG, "wolfSSL_new failed");
        goto fail;
    }

    wolfSSL_set_fd(ssl, fd);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, up->host, (unsigned short)strlen(up->host));

    if (wolfSSL_UseALPN(ssl, "h2", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH) != SSL_SUCCESS) {
        dohprint(DOH_DEBUG, "wolfSSL_UseALPN(h2) failed");
        goto fail;
    }

    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        int werr = wolfSSL_get_error(ssl, ret);
        wolfSSL_ERR_error_string_n((unsigned long)werr, errbuf, sizeof(errbuf));
        dohprint(DOH_DEBUG, "TLS handshake failed (err=%d: %s)", werr, errbuf);
        goto fail;
    }

    if (!wolfSSL_ALPN_GetProtocol(ssl, &proto, &proto_len)) {
        dohprint(DOH_DEBUG, "ALPN protocol not negotiated");
        goto fail;
    }
    if (!proto || proto_len != 2 || memcmp(proto, "h2", 2) != 0) {
        dohprint(DOH_DEBUG, "ALPN mismatch (proto_len=%u)", (unsigned)proto_len);
        goto fail;
    }

    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        dohprint(DOH_DEBUG, "nghttp2_session_callbacks_new failed");
        goto fail;
    }

    nghttp2_session_callbacks_set_send_callback(cbs, h2_send_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_stream_close_cb);

    conn.ssl = ssl;
    conn.xchg = &x;

    if (nghttp2_session_client_new(&session, cbs, &conn) != 0) {
        dohprint(DOH_DEBUG, "nghttp2_session_client_new failed");
        goto fail;
    }

    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1) != 0) {
        dohprint(DOH_DEBUG, "nghttp2_submit_settings failed");
        goto fail;
    }

    x.query = query;
    x.query_len = query_len;
    x.query_off = 0;
    x.response = reply;
    x.response_cap = DNS_BUFFER_MAXSIZE;
    x.response_len = 0;
    x.status_code = 0;

    snprintf(clength, sizeof(clength), "%lu", (unsigned long)query_len);

    nva[0] = MAKE_NV(":method", "POST");
    nva[1] = MAKE_NV(":scheme", "https");
    nva[2] = MAKE_NV(":authority", up->authority);
    nva[3] = MAKE_NV(":path", up->path);
    nva[4] = MAKE_NV("content-type", "application/dns-message");
    nva[5] = MAKE_NV("accept", "application/dns-message");
    nva[6] = MAKE_NV("content-length", clength);

    data_prd.source.ptr = &x;
    data_prd.read_callback = h2_read_cb;

    x.stream_id = nghttp2_submit_request(session, NULL, nva, 7, &data_prd, &x);
    if (x.stream_id < 0) {
        dohprint(DOH_DEBUG, "nghttp2_submit_request failed (%d)", x.stream_id);
        goto fail;
    }

    while (!x.stream_closed && !x.failed) {
        unsigned long long now_ms = monotonic_ms();
        if (now_ms > 0 && now_ms >= deadline_ms) {
            dohprint(DOH_DEBUG, "DoH exchange timed out");
            x.failed = 1;
            break;
        }

        ret = nghttp2_session_send(session);
        if (ret != 0) {
            dohprint(DOH_DEBUG, "nghttp2_session_send failed (%s)", nghttp2_strerror(ret));
            x.failed = 1;
            break;
        }

        ret = wolfSSL_read(ssl, tlsbuf, sizeof(tlsbuf));
        if (ret <= 0) {
            int werr = wolfSSL_get_error(ssl, ret);
            if (werr == WOLFSSL_ERROR_WANT_READ || werr == WOLFSSL_ERROR_WANT_WRITE)
                continue;
            dohprint(DOH_DEBUG, "wolfSSL_read failed (err=%d)", werr);
            x.failed = 1;
            break;
        }

        ret = (int)nghttp2_session_mem_recv(session, tlsbuf, (size_t)ret);
        if (ret < 0) {
            dohprint(DOH_DEBUG, "nghttp2_session_mem_recv failed (%s)", nghttp2_strerror(ret));
            x.failed = 1;
            break;
        }
    }

    if (x.failed || x.status_code != 200 || x.response_len < DNS_HEADER_MIN) {
        dohprint(DOH_DEBUG, "DoH exchange invalid: failed=%d status=%d len=%lu stream_err=%u",
            x.failed, x.status_code, (unsigned long)x.response_len,
            (unsigned)x.stream_error_code);
        goto fail;
    }

    *reply_len = x.response_len;

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(cbs);
    wolfSSL_free(ssl);
    close(fd);
    return 0;

fail:
    if (session)
        nghttp2_session_del(session);
    if (cbs)
        nghttp2_session_callbacks_del(cbs);
    if (ssl)
        wolfSSL_free(ssl);
    if (fd >= 0)
        close(fd);
    return -1;
}

int main(int argc, char *argv[])
{
    struct doh_upstream upstream;
    WOLFSSL_CTX *wctx = NULL;
    char *url = NULL;
    char *cafile = NULL;
    char *user = NULL;
    char *resolver_ip = NULL;
    uint16_t port = NS2DOHD_PORT;
    int foreground = 0;
    int option_idx = 0;
    int c;
    int lfd = -1;
    struct sockaddr_in addr;
    uint8_t dns_req[DNS_BUFFER_MAXSIZE];
    uint8_t dns_rep[DNS_BUFFER_MAXSIZE];
    struct sockaddr_storage cliaddr;
    socklen_t cliaddr_len;
    ssize_t n;
    int log_level = DOH_WARN;
    struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'V'},
        {"doh-url", 1, 0, 'd'},
        {"port", 1, 0, 'p'},
        {"user", 1, 0, 'u'},
        {"resolver", 1, 0, 'r'},
        {"ca-file", 1, 0, 'A'},
        {"verbose", 0, 0, 'v'},
        {"do-not-fork", 0, 0, 'F'},
        {NULL, 0, 0, '\0'}
    };
    struct sigaction sa = {};

    while (1) {
        c = getopt_long(argc, argv, "hVd:p:u:r:A:vF", long_options, &option_idx);
        if (c < 0)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'V':
                fprintf(stderr, "%s, %s\n", argv[0], VERSION);
                return 0;
            case 'd':
                free(url);
                url = strdup(optarg);
                break;
            case 'p':
                if (parse_port(optarg, &port) != 0) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return 2;
                }
                break;
            case 'u':
                free(user);
                user = strdup(optarg);
                break;
            case 'r':
                free(resolver_ip);
                resolver_ip = strdup(optarg);
                break;
            case 'A':
                free(cafile);
                cafile = strdup(optarg);
                break;
            case 'v':
                log_level = DOH_DEBUG;
                break;
            case 'F':
                foreground = 1;
                break;
            default:
                usage(argv[0]);
                return 2;
        }
    }

    if (optind < argc) {
        usage(argv[0]);
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 2;
    }

    if (!url) {
        usage(argv[0]);
        free(user);
        free(resolver_ip);
        free(cafile);
        return 2;
    }

    if (parse_doh_url(url, &upstream) != 0) {
        fprintf(stderr, "Invalid DoH URL: %s\n", url);
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 2;
    }

    if (!resolver_ip)
        resolver_ip = strdup(DEFAULT_BOOTSTRAP_DNS_IP);
    if (!resolver_ip ||
        parse_bootstrap_resolver(resolver_ip, &bootstrap_resolver, &bootstrap_resolver_len) != 0) {
        fprintf(stderr, "Invalid bootstrap resolver IP: %s\n",
            resolver_ip ? resolver_ip : "(null)");
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 2;
    }

    if (!foreground) {
        int pid = fork();
        if (pid < 0)
            return 1;
        if (pid > 0) {
            free(user);
            free(resolver_ip);
            free(cafile);
            free(url);
            return 0;
        }

        pid = fork();
        if (pid < 0)
            return 1;
        if (pid > 0) {
            free(user);
            free(resolver_ip);
            free(cafile);
            free(url);
            return 0;
        }

        setsid();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = handle_sigusr1;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    dohprint_init(foreground, log_level);
    dohprint(DOH_NOTICE, "ns2dohd v. %s", VERSION);
    dohprint(DOH_NOTICE, "DNS-to-DoH forwarding enabled");

    wolfSSL_Init();
    wctx = wolfSSL_CTX_new(wolfTLS_client_method());
    if (!wctx) {
        dohprint(DOH_ERR, "wolfSSL context initialization failed");
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 1;
    }

    wolfSSL_CTX_set_verify(wctx, WOLFSSL_VERIFY_PEER, NULL);
    if (cafile) {
        if (wolfSSL_CTX_load_verify_locations(wctx, cafile, NULL) != SSL_SUCCESS) {
            dohprint(DOH_ERR, "cannot load CA bundle file");
            wolfSSL_CTX_free(wctx);
            free(user);
            free(resolver_ip);
            free(url);
            free(cafile);
            return 1;
        }
        dohprint(DOH_NOTICE, "using custom CA bundle");
    } else {
        if (wolfSSL_CTX_load_verify_locations(wctx, DEFAULT_CA_BUNDLE, NULL) == SSL_SUCCESS) {
            dohprint(DOH_NOTICE, "using default CA bundle");
        } else if (wolfSSL_CTX_load_system_CA_certs(wctx) == SSL_SUCCESS ||
            wolfSSL_CTX_set_default_verify_paths(wctx) == SSL_SUCCESS) {
            dohprint(DOH_NOTICE, "using system default CA certificates");
        } else {
            dohprint(DOH_ERR, "cannot load CA certificates; use -A <cafile>");
            wolfSSL_CTX_free(wctx);
            free(user);
            free(resolver_ip);
            free(url);
            free(cafile);
            return 1;
        }
    }

    lfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (lfd < 0) {
        dohprint(DOH_ERR, "cannot create UDP socket: %s", strerror(errno));
        wolfSSL_CTX_free(wctx);
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        dohprint(DOH_ERR, "cannot bind 127.0.0.1:%u: %s", port, strerror(errno));
        close(lfd);
        wolfSSL_CTX_free(wctx);
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 1;
    }

    if (drop_privileges(user) != 0) {
        close(lfd);
        wolfSSL_CTX_free(wctx);
        free(user);
        free(resolver_ip);
        free(cafile);
        free(url);
        return 1;
    }

    dohprint(DOH_NOTICE, "listening on 127.0.0.1:%u", port);

    while (run) {
        size_t reply_len = 0;

        cliaddr_len = sizeof(cliaddr);
        n = recvfrom(lfd, dns_req, sizeof(dns_req), 0,
            (struct sockaddr *)&cliaddr, &cliaddr_len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            stats.errors++;
            dohprint(DOH_WARN, "recvfrom error: %s", strerror(errno));
            continue;
        }

        stats.queries++;
        if (n < DNS_HEADER_MIN) {
            stats.errors++;
            continue;
        }

        if (doh_query_roundtrip(wctx, &upstream, dns_req, (size_t)n, dns_rep, &reply_len) != 0) {
            if (strcmp(upstream.path, "/") == 0) {
                struct doh_upstream alt = upstream;
                strcpy(alt.path, "/dns-query");
                dohprint(DOH_DEBUG, "retrying DoH query on fallback path");
                if (doh_query_roundtrip(wctx, &alt, dns_req, (size_t)n, dns_rep, &reply_len) == 0)
                    goto reply_send;
            }
            stats.errors++;
            if (make_servfail(dns_req, (size_t)n, dns_rep, &reply_len) == 0)
                stats.servfail_replies++;
            else
                continue;
            dohprint(DOH_WARN, "upstream DoH request failed, returned SERVFAIL");
        }

reply_send:
        if (sendto(lfd, dns_rep, reply_len, 0,
            (struct sockaddr *)&cliaddr, cliaddr_len) < 0) {
            stats.errors++;
            dohprint(DOH_WARN, "sendto error: %s", strerror(errno));
            continue;
        }

        stats.replies++;
    }

    close(lfd);
    wolfSSL_CTX_free(wctx);
    wolfSSL_Cleanup();
    free(url);
    free(user);
    free(resolver_ip);
    free(cafile);

    if (!foreground)
        closelog();

    return 0;
}
