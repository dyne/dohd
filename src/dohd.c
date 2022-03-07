/*
 *      dohd.c
 *
 *      This is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU Affero General Public License, as
 *      published by the free Software Foundation.
 *
 *
 *      dohd is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU Affero General Public
 *      License along with dohd.  If not, see <http://www.gnu.org/licenses/>.
 *
 *      Authors: Daniele Lacamera <root@danielinux.net>
 *               Denis "Jaromil" Roio <jaromil@dyne.org> 
 *
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include "libevquick.h"
#include "url64.h"
#include <nghttp2/nghttp2.h>
#include <netinet/tcp.h>

#ifdef DMALLOC
#include "dmalloc.h"
#endif

#define DOH_PORT 8053
#define DNS_BUFFER_MAXSIZE 1460

#define LSHPACK_XXH_SEED 39378473

#define HTTP2_MODE 1 /* Change to '1' once implemented */
#define OCSP_RESPONDER 1

#define IP6_LOCALHOST { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#define DOHD_REQ_MIN 20
#define STR_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


#define MAKE_NV(K, V)                                                          \
{                                                                              \
    (uint8_t *)K, (uint8_t *)V, strlen(K), strlen(V),                          \
    NGHTTP2_NV_FLAG_NONE                                                       \
}

#define H2_DEFAULT_SETTINGS { 0x00, 0x03, 0x00, 0x00, 0x00, 0x64, \
    0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF }

#define H2_DEFAULT_SETTINGS_LEN (12)

#define DOH_ERR    LOG_EMERG
#define DOH_WARN   LOG_WARNING
#define DOH_NOTICE LOG_NOTICE
#define DOH_INFO   LOG_INFO
#define DOH_DEBUG  LOG_DEBUG

#if (HTTP2_MODE)
#   ifndef HAVE_ALPN
#       error HAVE_ALPN needs to be defined to use HTTP/2
#   endif
#endif

#define STR_TO_IOVEC(a) ((char *)a), (sizeof(a) -1)


#define MAX_RESOLVERS 256
struct sockaddr *Resolver[MAX_RESOLVERS];
unsigned n_resolvers = 0, resolver_rr = 0;


/* Resource statistics (memory, sockets, etc.) */


static struct doh_stats {
    /* Total requests/replies served */
    uint64_t tot_requests;
    uint64_t tot_replies;

    /* Requests divided by type */
    uint64_t http_notvalid_requests;
    uint64_t http2_post_requests;
    uint64_t http2_get_requests;
    uint64_t socket_errors;

    /* Memory (current, peak) */
    uint64_t mem;
    uint64_t mem_peak;

    /* Clients, pending requests (cur, peak) */
    uint32_t clients;
    uint32_t pending_requests;
    uint32_t max_clients;
    uint32_t max_pending_requests;
    /* Time */
    time_t start_time;

} DOH_Stats = {};

static inline void check_stats(void)
{
    if (DOH_Stats.mem > DOH_Stats.mem_peak)
        DOH_Stats.mem_peak = DOH_Stats.mem;

    if (DOH_Stats.clients > DOH_Stats.max_clients)
        DOH_Stats.max_clients = DOH_Stats.clients;

    if (DOH_Stats.pending_requests > DOH_Stats.max_pending_requests)
        DOH_Stats.max_pending_requests = DOH_Stats.pending_requests;
}


static int dohprint_loglevel = LOG_NOTICE;
static int dohprint_syslog = -1;

static void dohprint_init(int fg, int level)
{
    if(fg)
        dohprint_syslog = 0;
    else
        dohprint_syslog = 1;

    if (level > DOH_DEBUG)
        level = DOH_DEBUG;
    if (level < DOH_ERR)
        level = DOH_ERR;
    dohprint_loglevel = level;
    if (!fg) {
        dohprint_syslog = 1;
        openlog("DoHD", LOG_PID, LOG_DAEMON);
    }
}

#define dohprint(lvl, ...) \
{ \
    if (dohprint_syslog) \
    syslog(lvl, ##__VA_ARGS__); \
    else if (lvl <= dohprint_loglevel) {\
        fprintf(stderr, ##__VA_ARGS__); \
        fprintf(stderr, "\n"); \
    }\
}

#define UPTIME_STR_LEN 512
static char uptime_string[UPTIME_STR_LEN];

static char *uptime(void)
{
    time_t now = time(NULL);
    time_t diff = (now - DOH_Stats.start_time);
    time_t days, hrs, min, sec;

    days = diff / (3600 * 24);
    diff -= (days * 3600 * 24);

    hrs = diff / (3600);
    diff -= (hrs * 3600);

    min = diff / 60;
    diff -= (min * 60);

    sec = diff;

    uptime_string[0] = '\0';
    if (days)
        sprintf(uptime_string, "%lu days, %lu hours, %lu minutes %lu seconds", days, hrs, min, sec);
    else if (hrs)
        sprintf(uptime_string, "%lu hours, %lu minutes %lu seconds", hrs, min, sec);
    else
        sprintf(uptime_string, "%lu minutes %lu seconds", min, sec);

    return uptime_string;
}


static void printstats(void)
{
    dohprint(LOG_NOTICE, "DOHD session - detailed statistics");
    dohprint(LOG_NOTICE, "dohd v. %s - running for %s", VERSION, uptime());
    dohprint(LOG_NOTICE, "==================================");
    dohprint(LOG_NOTICE, "- Session counters");
    dohprint(LOG_NOTICE, "    - Total DNS requests forwarded: %lu", DOH_Stats.tot_requests);
    dohprint(LOG_NOTICE, "    - Total replies served        : %lu", DOH_Stats.tot_replies);
    dohprint(LOG_NOTICE, "- HTTPS Requests by type:");
    dohprint(LOG_NOTICE, "    - HTTP/2   GET : %lu", DOH_Stats.http2_get_requests);
    dohprint(LOG_NOTICE, "    - HTTP/2   POST: %lu", DOH_Stats.http2_post_requests);
    dohprint(LOG_NOTICE, "- Failures:");
    dohprint(LOG_NOTICE, "    - Invalid HTTP requests: %lu", DOH_Stats.http_notvalid_requests);
    dohprint(LOG_NOTICE, "    - Socket errors: %lu", DOH_Stats.socket_errors);
    dohprint(LOG_NOTICE, "- Memory usage:");
    dohprint(LOG_NOTICE, "    - Current: %lu Bytes, peak: %lu Bytes", DOH_Stats.mem, DOH_Stats.mem_peak);
    dohprint(LOG_NOTICE, "- Connected clients:");
    dohprint(LOG_NOTICE, "    - Current: %u, peak: %u ", DOH_Stats.clients, DOH_Stats.max_clients);
    dohprint(LOG_NOTICE, "- Concurrent pending requests:");
    dohprint(LOG_NOTICE, "    - Current: %u, peak: %u ", DOH_Stats.pending_requests, DOH_Stats.max_pending_requests);
    dohprint(LOG_NOTICE, "==================================");
}

struct __attribute__((packed)) dns_header
{
    uint16_t id;        /* Packet id */
    uint8_t rd : 1;     /* Recursion Desired */
    uint8_t tc : 1;     /* TrunCation */
    uint8_t aa : 1;     /* Authoritative Answer */
    uint8_t opcode : 4; /* Opcode */
    uint8_t qr : 1;     /* Query/Response */
    uint8_t rcode : 4;  /* Response code */
    uint8_t z : 3;      /* Zero */
    uint8_t ra : 1;     /* Recursion Available */
    uint16_t qdcount;   /* Question count */
    uint16_t ancount;   /* Answer count */
    uint16_t nscount;   /* Authority count */
    uint16_t arcount;   /* Additional count */
};
#define DNSQ_SUFFIX_LEN (4)

static int lfd = -1;
static WOLFSSL_CTX *wctx = NULL;
#ifndef _MUSL_
void *sigset(int sig, void (*disp)(int));
#endif

struct req_slot {
    struct client_data *owner;
    struct evquick_event *ev_dns;
    int dns_sd;
    uint32_t h2_stream_id;
    uint8_t h2_request_buffer[DNS_BUFFER_MAXSIZE];
    uint32_t h2_request_len;
    uint8_t *h2_response_data;
    uint32_t h2_response_len;
    uint16_t id;
    struct sockaddr *resolver;
    socklen_t resolver_sz;
    struct req_slot *next;
};

struct client_data {
    WOLFSSL *ssl;
    struct evquick_event *ev_doh;
    int tls_handshake_done;
    int h2;
    nghttp2_session *h2_session;
    int doh_sd;
    struct client_data *next;
    struct req_slot *list;
};

static void dohd_reply(int fd, short __attribute__((unused)) revents,
        void *arg);

struct client_data *Clients = NULL;

static void dohd_listen_error(int __attribute__((unused)) fd,
        short __attribute__((unused)) revents,
        void __attribute__((unused)) *arg)
{
    dohprint(DOH_ERR, "FATAL: Error on listening socket: %d", errno);
    exit(80);
}

static void sig_stats(int __attribute__((unused)) signo)
{
    printstats();
}


static void dohd_destroy_client(struct client_data *cd)
{
    struct client_data *l = Clients, *prev = NULL;
    struct req_slot *rp, *nxt;
    int found = 0;
    if (!cd)
        return;
    /* Delete from Clients */
    while (l) {
        if (cd == l) {
            if (prev)
                prev->next = cd->next;
            else
                Clients = cd->next;
            found = 1;
            break;
        }
        prev = l;
        l = l->next;
    }
    if (!found) {
        dohprint(DOH_ERR, "Unexpected client_data ptr %p not in Clients list\n", cd);
        return;
    }

    /* Cleanup pending requests */
    rp = cd->list;
    while(rp) {
        if (rp->ev_dns) {
            evquick_delevent(rp->ev_dns);
            rp->ev_dns = NULL;
        }
        if (rp->dns_sd > 0)
            close(rp->dns_sd);
        if (rp->h2_response_data) {
            DOH_Stats.mem -= rp->h2_response_len;
            free(rp->h2_response_data);
            rp->h2_response_data = NULL;
        }
        nxt = rp->next;
        free(rp);
        DOH_Stats.mem -= sizeof(struct req_slot);
        if (DOH_Stats.pending_requests > 0)
            DOH_Stats.pending_requests--;
        rp = nxt;
    }
    /* Remove events from file desc */
    if (cd->ev_doh) {
        evquick_delevent(cd->ev_doh);
        cd->ev_doh = NULL;
    }

    /* Shutdown TLS session */
    if (cd->ssl) {
        wolfSSL_free(cd->ssl);
        cd->ssl = NULL;
    }
    /* Close client socket descriptor */
    close(cd->doh_sd);

    /* Delete http2 session if present */
    if (cd->h2_session)
        nghttp2_session_del(cd->h2_session);

    /* free up client data */
    free(cd);

    /* Update statistics */
    DOH_Stats.mem -= sizeof(struct client_data);
    DOH_Stats.clients--;
    check_stats();
}

static void clean_exit(int __attribute__((unused)) signo)
{
    struct client_data *cl = Clients;
    while(cl) {
        Clients = cl->next;
        dohd_destroy_client(cl);
        cl = Clients;
    }
    fprintf(stderr, "Cleanup, exiting...\n");
#ifdef DMALLOC
    dmalloc_shutdown();
#endif
    exit(0);
}

static struct sockaddr *next_resolver(void)
{
    resolver_rr++;
    if (resolver_rr >= n_resolvers)
        resolver_rr = 0;
    return Resolver[resolver_rr];
}

struct req_slot *dns_create_request_h2(struct client_data *cd, uint32_t stream_id)
{
    struct req_slot *req = NULL;

    /* Check if the client already opened this stream */
    req = nghttp2_session_get_stream_user_data(cd->h2_session, stream_id);
    if (req) {
        dohprint(DOH_WARN, "W: request is not null for this stream id\n");

    }
    req = malloc(sizeof(struct req_slot));
    if (req == NULL) {
        dohprint(DOH_ERR, "Failed to allocate memory for a new DNS request.");
        return req;
    }
    memset(req, 0, sizeof(struct req_slot));
    req->resolver = next_resolver();
    req->resolver_sz = sizeof(struct sockaddr_in);
    /* Change AF / socksize if IPV6 */
    if (((struct sockaddr_in6 *)req->resolver)->sin6_family == AF_INET6)
        req->resolver_sz = sizeof(struct sockaddr_in6);

    /* Create local dns socket */
    req->dns_sd = socket(((struct sockaddr_in *)req->resolver)->sin_family,
            SOCK_DGRAM, 0);
    if (req->dns_sd < 0) {
        dohprint(DOH_ERR, "Failed to create traditional DNS socket to forward the request.");
        free(req);
        return NULL;
    }
    /* append to list */
    req->next = cd->list;
    cd->list = req;

    /* Update statistics */
    DOH_Stats.mem += sizeof(struct req_slot);
    check_stats();

    /* Populate req structure */
    req->owner = cd;
    req->h2_stream_id = stream_id;
    nghttp2_session_set_stream_user_data(cd->h2_session, stream_id, req);
    return req;
}

static int dns_send_request_h2(struct req_slot *req)
{
    int ret;
    struct dns_header *hdr;
    /* Parse DNS header: only check the qr flag. */
    hdr = (struct dns_header *)req->h2_request_buffer;
    if (hdr->qr != 0) {
        return -1;
    }
    req->ev_dns = evquick_addevent(req->dns_sd, EVQUICK_EV_READ, dohd_reply,
            NULL, req);
    ret = sendto(req->dns_sd, req->h2_request_buffer, req->h2_request_len, 0,
            (struct sockaddr *)req->resolver, req->resolver_sz);
    if (ret < 0) {
        dohprint(DOH_ERR, "Fatal error: could not reach any recursive resolver at address %s port 53: %s\n", "localhost", strerror(errno));
        exit(53);
    }
    DOH_Stats.pending_requests++;
    DOH_Stats.tot_requests++;
    check_stats();
    return 0;
}

static ssize_t client_ssl_write(struct client_data *cd, const void *data, size_t len)
{
#ifdef VERBOSE_HTTP_DEBUG
    int i;
    uint8_t *reply = (uint8_t *)data;
    dohprint(DOH_NOTICE,"\n\nSSL Write: %lu bytes\n", len);
    for (i = 0; i < len; i++) {
        dohprint(DOH_NOTICE,"%02x ", (reply[i]));
        if ((i % 16) == 15)
            dohprint(DOH_NOTICE,"\n");
    }
    dohprint(DOH_NOTICE,"\n\n");
#endif
    return wolfSSL_write(cd->ssl, data, len);
}

/**
 * Skip exactly one question record in the dns reply.
 *
 * Moves record pointer ahead, and returns the number of
 * bytes from the original position.
 */
static int dns_skip_question(uint8_t **record, int maxlen)
{
    int skip = 0;
    int incr;
    if (maxlen < (int)(*record[0]) + DNSQ_SUFFIX_LEN)
        return -1;
    while (skip < maxlen) {
        if (*record[0] == 0) {
            *record += 1 + DNSQ_SUFFIX_LEN; /* Skip fixed-size query suffix (type+class) */
            skip+= 1 + DNSQ_SUFFIX_LEN;
            return skip;
        }
        incr = 1 + *record[0];
        if (incr + skip > maxlen) {
            return -1;
        }
        *record += incr;
        skip += incr;
    }
    return skip;
}


static uint32_t dnsreply_min_age(const void *p, size_t len)
{
    int i = 0;
    const struct dns_header *hdr = p;
    uint8_t *record = ((uint8_t *)p + sizeof(struct dns_header));
    int skip = 0;
    int answers = ntohs(hdr->ancount) + ntohs(hdr->nscount) + ntohs(hdr->arcount);
    uint32_t min_ttl = 3600;
    if (answers < 1)
        return -1;

    for (i = 0; i < ntohs(hdr->qdcount); i++) {
        skip = dns_skip_question(&record, len);
        if (skip < DNSQ_SUFFIX_LEN) {
            dohprint(DOH_WARN, "Cannot parse DNS reply!\n");
            return min_ttl;
        }
        len -= skip;
    }
    for (i = 0; i < answers; i++) {
        uint32_t ttl;
        uint32_t datalen;
        if (len < 12)
            return min_ttl;
        ttl =       (record[6] << 24 ) +
            (record[7] << 16 ) +
            (record[8] << 8  ) +
            record[9];
        datalen   = (record[10] << 8) +
            record[11];
        if (len < (12U + datalen))
            return min_ttl;
        if (ttl && (ttl < min_ttl))
            min_ttl = ttl;
        record += 12 + datalen;
        len -= datalen;
    }
    return min_ttl;
}

#define DOHD_MAX_REPLY (DNS_BUFFER_MAXSIZE)

static void dohd_destroy_request(struct req_slot *req)
{
    struct client_data *cd = req->owner;
    struct req_slot *rd, *prev = NULL;
    /* Remove request from the list */
    rd = cd->list;
    while(rd) {
        if (rd == req) {
            if (prev)
                prev->next = req->next;
            else
                cd->list = req->next;
            break;
        }
        prev = rd;
        rd = rd->next;
    }
    if (req->ev_dns) {
        evquick_delevent(req->ev_dns);
        req->ev_dns = NULL;
    }
    close(req->dns_sd);
    if (req->h2_response_data) {
        DOH_Stats.mem -= req->h2_response_len;
        free(req->h2_response_data);
        req->h2_response_data = NULL;
    }

    if (req->owner->h2_session && req->h2_stream_id) {
        nghttp2_session_set_stream_user_data(req->owner->h2_session,
                req->h2_stream_id, NULL);
    }
    free(req);
    /* Update statistics */
    DOH_Stats.mem -= sizeof(struct req_slot);
    if (DOH_Stats.pending_requests > 0)
        DOH_Stats.pending_requests--;
    check_stats();
}

static ssize_t h2_cb_req_submit(nghttp2_session *session,
        int32_t stream_id, uint8_t *buf,
        size_t length, uint32_t *data_flags,
        nghttp2_data_source *source,
        void *user_data)
{
    struct req_slot *req = source->ptr;
    uint8_t *data;
    uint32_t len;
    (void)session;
    (void)stream_id;
    (void)user_data;
    if (!req->h2_response_data || !req->h2_response_len) {
        dohd_destroy_request(req);
        return 0;
    }
    len = req->h2_response_len;
    data = req->h2_response_data;
    if (!data) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    if (length >= len) {
        memcpy(buf, data, len);
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        DOH_Stats.mem -= req->h2_response_len;
        free(req->h2_response_data);
        req->h2_response_data = NULL;
        req->h2_response_len = 0;
        check_stats();
        return len;
    }
    return 0;
}

/**
 * Receive a reply from DNS server and forward to DoH client. Close request.
 */
static void dohd_reply(int fd, short __attribute__((unused)) revents,
        void *arg)
{
    const size_t bufsz = DOHD_MAX_REPLY;
    uint8_t buff[DOHD_MAX_REPLY];
    int len;
    struct client_data *cd, *l;
    int age = 0;
    struct req_slot *req;
    nghttp2_data_provider data_prd;
    req = (struct req_slot *)arg;
    cd = req->owner;
    len = recv(fd, buff, bufsz, 0);
    if (len < 16) {
        dohprint(DOH_ERR, "Error while receiving DNS reply: socket error %d\n", errno);
        goto destroy;
    }

    /* Safety check: client data object must still be in the list,
     * or it may have been previously freed and thus is invalid.
     */
    if (!cd)
        goto destroy;

    l = Clients;
    while (l) {
        if (l == cd)
            break;
        l = l->next;
    }
    if (!l)
        goto destroy;

    /* Fix records age and send answers to DoH client */
    age = dnsreply_min_age(buff, len);
    if (cd->h2 != 0) {
        const char max_age_tmpl[] = "max-age=%d";
        char max_age_txt[15];
        snprintf(max_age_txt, 15, max_age_tmpl, age);
        nghttp2_nv nva[] = {
            MAKE_NV(":status", "200"),
            MAKE_NV("content-type", "application/dns-message"),
            MAKE_NV("server", "dohd"),
            MAKE_NV("cache-control", max_age_txt),
        };
        req->h2_response_data = malloc(len);
        check_stats();
        if (!req->h2_response_data) {
            dohprint(DOH_ERR, "Out-of-memory!\n");
            exit(1);
        }
        DOH_Stats.mem += len;
        memcpy(req->h2_response_data, buff, len);
        req->h2_response_len = len;
        memset(&data_prd, 0, sizeof(data_prd));
        data_prd.source.ptr = req;
        data_prd.read_callback = h2_cb_req_submit;
        nghttp2_submit_response(req->owner->h2_session,
                req->h2_stream_id, nva, 4, &data_prd);

        nghttp2_session_send(req->owner->h2_session);
        /* Do not destroy request: not yet finished */
        DOH_Stats.tot_replies++;
        check_stats();
        return;
    }

destroy:
    dohd_destroy_request(req);
}

static ssize_t h2_cb_send(nghttp2_session *session, const uint8_t *data,
        size_t length, int flags, void *user_data)
{
    struct client_data *cd = (struct client_data *)user_data;
    (void)session;
    (void)flags;
    int ret;
    ret = client_ssl_write(cd, data, length);

    if (nghttp2_session_want_write(session)) {
        nghttp2_session_send(session);
    }
    return ret;
}


static int h2_cb_on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    struct req_slot *req;
    struct client_data *cd = (struct client_data *)user_data;
    if (!(flags & NGHTTP2_FLAG_END_STREAM)) {
        goto data_fail;
    }
    if (!cd) {
        return 0;
    }
    req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!req) {
        dohprint(DOH_WARN, "H2: received bogus DATA not associated to request\n");
        goto data_fail;
    }
    if (req->owner != cd) {
        dohprint(DOH_WARN, "H2: received DATA chunk with wrong stream_id\n");
        goto data_fail;
    }
    if (len > DNS_BUFFER_MAXSIZE) {
        dohprint(DOH_WARN, "H2: received DATA chunk too large (%lu)\n", len);
        goto data_fail;
    }
    memcpy(req->h2_request_buffer, data, len);
    req->h2_request_len = len;
    DOH_Stats.http2_post_requests++;
    check_stats();

data_fail:
    return 0;
}

static int h2_cb_on_frame_recv(nghttp2_session *session,
        const nghttp2_frame *frame, void *user_data)
{
    struct client_data *cd = (struct client_data *)user_data;
    (void)cd;
    switch(frame->hd.type) {
        case NGHTTP2_DATA:
        case NGHTTP2_HEADERS:
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                struct req_slot *req =
                    nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
                /* For DATA and HEADERS frame, this callback may be called after
                   on_stream_close_callback. Check that stream still alive. */
                if ((!req)) {
                    return 0;
                }
                if (req->h2_request_len > 0)
                    dns_send_request_h2(req);
                else
                    dohd_destroy_request(req);
            }
            break;
        case NGHTTP2_GOAWAY:
            break;
        case NGHTTP2_RST_STREAM:
            break;

    }
    return 0;
}

static int h2_cb_on_stream_close(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    struct client_data *cd = (struct client_data *)user_data;
    struct req_slot *req =
        nghttp2_session_get_stream_user_data(session, stream_id);

    if (cd != req->owner)
        return -1;
    (void)error_code;
    if (req)  {
        dohd_destroy_request(req);
    }
    return 0;
}

static int h2_cb_on_begin_headers(nghttp2_session *session,
        const nghttp2_frame *frame,
        void *user_data)
{
    (void)session;
    (void)frame;
    (void)user_data;
    return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int h2_cb_on_header(nghttp2_session *session,
        const nghttp2_frame *frame, const uint8_t *name,
        size_t namelen, const uint8_t *value,
        size_t valuelen, uint8_t flags, void *user_data)
{

    const char PATH[] = ":path";
    const char GETDNS[] = "/?dns=";
    struct client_data *cd = (struct client_data *)user_data;
    struct req_slot *req;
    (void)flags;
    (void)value;
    (void)valuelen;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
                break;
            }
            req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (!req) {
                req = dns_create_request_h2(cd, frame->hd.stream_id);
                if (!req) {
                    return 0;
                }
            }
            if ((namelen == strlen(PATH)) && memcmp(PATH, name, namelen) == 0) {
                if (valuelen > strlen(GETDNS) && (strncmp((char*)value, GETDNS,
                                strlen(GETDNS)) == 0) && (valuelen < DNS_BUFFER_MAXSIZE)) {
                    uint32_t outlen = DNS_BUFFER_MAXSIZE;
                    req->h2_request_len = 0;
                    if(dohd_url64_check((const char*)(value + 6)) == 0) {
                        dohd_destroy_request(req);
                        return 0;
                    }
                    outlen = dohd_url64_decode((const char*)(value + 6),
					       req->h2_request_buffer);
                    if (outlen <= 0) {
                        dohd_destroy_request(req);
                        return 0;
                    }
                    req->h2_request_len = outlen;
                    DOH_Stats.http2_get_requests++;
                    check_stats();
                }
            }
            break;
    }
    return 0;
}

/**
 * Receive a request from the DoH client, forward to the DNS
 * server.
 */
static void tls_read(__attribute__((unused)) int fd, short __attribute__((unused)) revents, void *arg)
{
    uint8_t buff[DNS_BUFFER_MAXSIZE];
    int ret;
    struct client_data *cd = arg, *l = Clients;
    if (!cd || !cd->ssl)
        return;
    while (l) {
        if (l == cd)
            break;
        l = l->next;
    }
    if (!l)
        return;
    if (!cd->tls_handshake_done) {
        /* Establish TLS connection */
        ret = wolfSSL_accept(cd->ssl);
        if (ret != SSL_SUCCESS) {
            dohd_destroy_client(cd);
        } else {
            uint16_t proto_len;
            char *proto;
            if (wolfSSL_ALPN_GetProtocol(cd->ssl, &proto, &proto_len) &&
                    (2 == proto_len) && strncmp(proto, "h2", 2) == 0) {
                nghttp2_settings_entry iv[1] = {
                    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
                };

                nghttp2_session_callbacks *h2_cbs;
                nghttp2_session_callbacks_new(&h2_cbs);
                nghttp2_session_callbacks_set_send_callback(h2_cbs, h2_cb_send);
                nghttp2_session_callbacks_set_on_frame_recv_callback(h2_cbs, h2_cb_on_frame_recv);
                nghttp2_session_callbacks_set_on_stream_close_callback(h2_cbs, h2_cb_on_stream_close);
                nghttp2_session_callbacks_set_on_header_callback(h2_cbs, h2_cb_on_header);
                nghttp2_session_callbacks_set_on_begin_headers_callback(h2_cbs, h2_cb_on_begin_headers);
                nghttp2_session_callbacks_set_on_data_chunk_recv_callback(h2_cbs, h2_cb_on_data_chunk_recv);
                nghttp2_session_server_new(&cd->h2_session, h2_cbs, cd);
                nghttp2_session_callbacks_del(h2_cbs);
                cd->h2 = 1;
                nghttp2_submit_settings(cd->h2_session, NGHTTP2_FLAG_NONE, iv, 1);
            }
            cd->tls_handshake_done = 1;
        }
        return;
    }
    /* Read the client data into our buff array */
    ret = wolfSSL_read(cd->ssl, buff, DNS_BUFFER_MAXSIZE);
    if (ret < 0) {
        dohd_destroy_client(cd);
        DOH_Stats.socket_errors++;
    } else {
        if (cd->h2) {
            ssize_t readlen;
            readlen = nghttp2_session_mem_recv(cd->h2_session, buff, ret);
            if (readlen < 0) {
                dohprint(DOH_WARN, "NGHTTP2 error: %s\n", nghttp2_strerror((int)readlen));
                return;
            }
            while (nghttp2_session_want_write(cd->h2_session)) {
                ret = nghttp2_session_send(cd->h2_session);
                if (ret < 0) {
                    dohprint(DOH_WARN, "NGHTTP2 error: %s\n", nghttp2_strerror((int)ret));
                }
            }
        } else {
            buff[ret] = 0;
            DOH_Stats.http_notvalid_requests++;
            dohd_destroy_client(cd);
        }
    }
    check_stats();
}

/**
 * Callback for error events
 */
static void tls_fail(int __attribute__((unused)) fd,
        short __attribute__((unused)) revents,
        void *arg)
{
    struct client_data *cd = arg;
    DOH_Stats.socket_errors++;
    check_stats();
    dohd_destroy_client(cd);
}

/**
 * Accept a new DoH connection, create client data object
 */
static void dohd_new_connection(int __attribute__((unused)) fd,
        short __attribute__((unused)) revents,
        void __attribute__((unused)) *arg)
{
    int connd;
    int yes = 1;
    socklen_t zero = 0;
    struct client_data *cd = NULL;
#ifdef OCSP_RESPONDER
    size_t httpreq_size = 1024;
    char httpreq[httpreq_size];
    int ret;
#endif

    cd = malloc(sizeof(struct client_data));
    if (cd == NULL) {
        dohprint(DOH_ERR, "Failed to allocate memory for a new connection\n\n");
        return;
    }

    memset(cd, 0, sizeof(struct client_data));
    /* Accept client connections */
    connd = accept(lfd, NULL, &zero);
    if (connd < 0) {
        dohprint(DOH_WARN, "Failed to accept the connection: %s\n\n", strerror(errno));
        free(cd);
        return;
    }
#ifdef OCSP_RESPONDER
    ret = recv(connd, httpreq, httpreq_size, MSG_PEEK | MSG_DONTWAIT);
    if (ret > 0) {
        httpreq[ret] = 0;
        if (strstr(httpreq, "POST /") != NULL) {
            dohprint(DOH_DEBUG, "HTTP REQ: %s\n", httpreq);
        }
    }
#endif
    setsockopt(connd, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(int));
    setsockopt(connd, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof(int));

    /* Create a WOLFSSL object */
    cd->ssl = wolfSSL_new(wctx);
    if (cd->ssl == NULL) {
        dohprint(DOH_ERR, "ERROR: failed to create WOLFSSL object\n");
        close(connd);
        free(cd);
        return;
    }
    /* Enable HTTP2 via ALPN */
    if (wolfSSL_UseALPN(cd->ssl, "h2", 2, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)
            != SSL_SUCCESS) {
        dohprint(DOH_WARN, "WARNING: failed setting ALPN extension for http/2");
    }
    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(cd->ssl, connd);


    cd->doh_sd = connd;
    cd->ev_doh = evquick_addevent(cd->doh_sd, EVQUICK_EV_READ, tls_read, tls_fail, cd);
    cd->next = Clients;
    Clients = cd;

    DOH_Stats.mem += sizeof(struct client_data);
    DOH_Stats.clients++;
    check_stats();
}

#ifndef SHARED_LIB

static void usage(const char *name)
{

    fprintf(stderr, "%s, DNSoverHTTPS minimalist daemon.\n", name);
    fprintf(stderr, "License: AGPL\n");
    fprintf(stderr, "Usage: %s -c cert -k key [-p port] [-d dnsserver] [-F] [-u user] [-V] [-v] [-h]\n", name);
    fprintf(stderr, "\t'cert' and 'key': certificate and its private key.\n");
    fprintf(stderr, "\t'user' : login name (when running as root) to switch to (dropping permissions)\n");
    fprintf(stderr, "\tDefault values: port=8053 dnsserver=\"::1\"\n");
    fprintf(stderr, "\tUse '-h' for help\n");
    fprintf(stderr, "\tUse '-V' to show version\n");
    fprintf(stderr, "\tUse '-v' for verbose mode\n");
    fprintf(stderr, "\tUse '-F' for foreground mode\n");
    exit(0);
}


int main(int argc, char *argv[])
{
    char *cert = NULL, *key = NULL;
    char *user = NULL;
    uint16_t port = DOH_PORT;
    struct sockaddr_in6 serv_addr;
    int option_idx;
    int c;
    int foreground = 0;
    int yes = 1;
    int default_loglevel = DOH_WARN;
    struct option long_options[] = {
        {"help",0 , 0, 'h'},
        {"version", 0, 0, 'V'},
        {"cert", 1, 0, 'c' },
        {"key", 1, 0, 'k'},
        {"port", 1, 0, 'p'},
        {"dnsserver", 1, 0, 'd'},
        {"user", 1, 0, 'u'},
        {"verbose", 0, 0, 'v'},
        {"do-not-fork", 0, 0, 'F'},
        {NULL, 0, 0, '\0' }
    };
    while(1) {
        c = getopt_long(argc, argv, "hvVc:k:p:d:u:F" , long_options, &option_idx);
        if (c < 0)
            break;
        switch(c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'V':
                fprintf(stderr, "%s, %s\n", argv[0], VERSION);
                exit(0);
                break;
            case 'p':
                port = (uint16_t)atoi(optarg);
                break;
            case 'v':
                default_loglevel = DOH_DEBUG;
                break;
            case 'c':
                cert = strdup(optarg);
                break;
            case 'k':
                key = strdup(optarg);
                break;
            case 'd':
                {
                    struct in_addr a4;
                    struct in6_addr a6;
                    if (inet_pton(AF_INET6, optarg, &a6) == 1) {
                        struct sockaddr_in6 *sin = malloc(sizeof(struct sockaddr_in6));

                        if (!sin) {
                            fprintf(stderr, "Cannot allocate memory for DNS resolver '%s'\n", optarg);
                            exit(2);
                        }
                        memcpy(&sin->sin6_addr.s6_addr, &a6, sizeof(struct in6_addr));
                        sin->sin6_family = AF_INET6;
                        sin->sin6_port = htons(53);
                        Resolver[n_resolvers++] = (struct sockaddr *)sin;
                    } else if (inet_pton(AF_INET, optarg, &a4) == 1) {
                        struct sockaddr_in *sin = malloc(sizeof(struct sockaddr_in));
                        if (!sin) {
                            fprintf(stderr, "Cannot allocate memory for DNS resolver '%s'\n", optarg);
                            exit(2);
                        }
                        memcpy(&sin->sin_addr.s_addr, &a4, sizeof(struct in_addr));
                        sin->sin_family = AF_INET;
                        sin->sin_port = htons(53);
                        Resolver[n_resolvers++] = (struct sockaddr *)sin;
                    } else {
                        fprintf(stderr, "Error: invalid DNS resolver address '%s'\n", optarg);
                        usage(argv[0]);
                    }
                }
                break;
            case 'u':
                if (getuid() != 0) {
                    fprintf(stderr, "Warning: -u option used, but not running as root ('user' option: ignored)\n");
                } else {
                    user = strdup(optarg);
                }
                break;
            case 'F':
                foreground = 1;
                break;
            default:
                fprintf(stderr, "Unrecognized option '%c'\n\n\n",c);
                usage(argv[0]);
        }
    }
    if (optind < argc)
        usage(argv[0]);
    /* implies exit() */

    if (!cert || !key)
        usage(argv[0]);

    if (!foreground) {
        int pid = fork();
        if (pid > 0)
            exit(1);
        pid = fork();
        if (pid > 0)
            exit(1);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        setsid();
    }
    /* End command line parsing */

    /* Set SIGUSR1 */
    sigset(SIGUSR1, sig_stats);

    /* Set SIGINT */
    sigset(SIGINT, clean_exit);

    /* Ignore SIGPIPE */
    sigset(SIGPIPE, SIG_IGN);

    /* Time 0 */
    DOH_Stats.start_time = time(NULL);

    /* Initialize logging */
    dohprint_init(foreground, default_loglevel);
    dohprint(DOH_DEBUG, "Logging initialized.");
    dohprint(DOH_NOTICE, "dohd v. %s", VERSION);

    /* Resolvers */
    if (n_resolvers == 0) {
        struct sockaddr_in6 *sin = malloc(sizeof(struct sockaddr_in6));
        uint8_t localhost[16] = IP6_LOCALHOST;

        if (!sin) {
            fprintf(stderr, "Cannot allocate memory for DNS resolver '::1'\n");
            exit(2);
        }
        memcpy(&sin->sin6_addr.s6_addr, localhost, sizeof(struct in6_addr));
        sin->sin6_family = AF_INET6;
        sin->sin6_port = htons(53);
        Resolver[n_resolvers++] = (struct sockaddr *)sin;
        dohprint(DOH_NOTICE, "Using default DNS server [::1]:53");
    }
    dohprint(DOH_NOTICE, "Using %u DNS servers", n_resolvers);

    /* Create listening socket */
    lfd = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof(int));
    setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, sizeof(int));
    if (lfd < 0) {
        dohprint(DOH_ERR, "ERROR: failed to create DoH socket\n");
        return -1;
    }
    dohprint(DOH_DEBUG, "Main HTTPS socket created.");

    /* Fill in the server address */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family      = AF_INET6;             /* using IPv4      */
    serv_addr.sin6_port        = htons(port); /* on DEFAULT_PORT */

    /* Bind the server socket to our port */
    if (bind(lfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }
    dohprint(DOH_DEBUG, "Main HTTPS socket is bound.");

    /* Drop privileges if running as root */
    if (getuid() == 0) {
        struct passwd *pwd;
        if (!user) {
            dohprint(DOH_ERR, "Error: '-u' option required when running as root to drop privileges. Exiting.\n");
            close(lfd);
            exit(2);
        }
        pwd = getpwnam(user);
        if (!pwd) {
            dohprint(DOH_ERR, "Error: invalid username '%s'\n",user);
            close(lfd);
            exit(3);
        }
        if (pwd->pw_uid == 0) {
            dohprint(DOH_ERR, "Error: invalid UID for username '%s'\n", user);
            close(lfd);
            exit(3);
        }
        if (setgid(pwd->pw_gid) < 0) {
            dohprint(DOH_ERR, "Error setting group: %s\n", strerror(errno));
            close(lfd);
            exit(4);
        }
        if (setuid(pwd->pw_uid) < 0) {
            dohprint(DOH_ERR, "Error setting user: %s\n", strerror(errno));
            close(lfd);
            exit(4);
        }
        dohprint(LOG_INFO, "Dropping privileges. setuid(%d) + setgid(%d) successful\n", pwd->pw_uid, pwd->pw_gid);
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();


    /* Enable debug, if active */
    //wolfSSL_Debugging_ON();

    /* Initialize libevquick */
    evquick_init();

    /* Create and initialize WOLFSSL_CTX */
    if ((wctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        dohprint(LOG_ERR, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }
    dohprint(DOH_DEBUG, "SSL context initialized");

    if (wolfSSL_CTX_use_certificate_chain_file(wctx, cert) != SSL_SUCCESS) {
        dohprint(LOG_ERR, "ERROR: failed to load %s, please check the file.\n", cert);
        return -1;
    }
    dohprint(DOH_DEBUG, "Certificate file correctly parsed");

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(wctx, key, SSL_FILETYPE_PEM)
            != SSL_SUCCESS) {
        dohprint(LOG_ERR, "ERROR: failed to load %s, please check the file.\n", key);
        return -1;
    }
    dohprint(DOH_DEBUG, "Private key correctly imported");


    /* Listen for a new connection, allow 10 pending connections */
    if (listen(lfd, 10) == -1) {
        dohprint(LOG_ERR, "ERROR: failed to listen\n");
        return -1;
    }
    evquick_addevent(lfd, EVQUICK_EV_READ, dohd_new_connection, dohd_listen_error, wctx);
    dohprint(DOH_NOTICE, "DNS over HTTPS proxy is now accepting requests.");

    evquick_loop();
    free(cert);
    cert = NULL;
    free(key);
    if (dohprint_syslog)
        closelog();
    return 0;
}

#endif
