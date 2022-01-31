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
 *      Author: Daniele Lacamera <root@danielinux.net>
 *
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include "libevquick.h"

#define VERSION "v0.3"

#define DOH_PORT 8053
#define DEC_BUFFER_MAXSIZE 1460

#define HTTP2_MODE 0 /* Change to '1' once implemented */
#define OCSP_RESPONDER 1

#define IP6_LOCALHOST { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#define DOHD_REQ_MIN 40
#define STR_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define STR_ACCEPT_DNS_MSG "Accept: application/dns-message"
#define STR_ACCEPT_ANY     "Accept: */*"
#define STR_CONTENT_LEN    "Content-Length: "
#define STR_REPLY "HTTP/1.1 200 OK\r\nServer: dohd\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nCache-Control: max-age=%d\r\n\r\n"


#define DOH_ERR    LOG_EMERG
#define DOH_WARN   LOG_WARNING
#define DOH_NOTICE LOG_NOTICE
#define DOH_INFO   LOG_INFO
#define DOH_DEBUG  LOG_DEBUG


#define MAX_RESOLVERS 256
struct sockaddr *Resolver[MAX_RESOLVERS];
unsigned n_resolvers = 0, resolver_rr = 0;


/* Resource statistics (memory, sockets, etc.) */

static struct doh_stats {
    /* Total requests/replies served */
    uint64_t tot_requests;
    uint64_t tot_replies;

    /* Requests divided by type */
    uint64_t http_post_requests;
    uint64_t http_get_requests;
    uint64_t http_head_requests;
    uint64_t http_notvalid_requests;
    uint64_t http2_requests;
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
    dohprint(LOG_NOTICE, "    - HTTP/1.1 GET : %lu", DOH_Stats.http_get_requests);
    dohprint(LOG_NOTICE, "    - HTTP/1.1 HEAD: %lu", DOH_Stats.http_head_requests);
    dohprint(LOG_NOTICE, "    - HTTP/1.1 POST: %lu", DOH_Stats.http_post_requests);
    dohprint(LOG_NOTICE, "    - HTTP/2       : %lu", DOH_Stats.http2_requests);
    dohprint(LOG_NOTICE, "- Failures:");
    dohprint(LOG_NOTICE, "    - Invalid HTTP requests: %lu", DOH_Stats.http_notvalid_requests);
    dohprint(LOG_NOTICE, "    - Socket errors (incl. close): %lu", DOH_Stats.socket_errors);
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
void *sigset(int sig, void (*disp)(int));


struct req_slot {
    struct client_data *owner;
    struct evquick_event *ev_dns;
    int dns_sd;
    uint16_t id;
    struct req_slot *next;
};

struct client_data {
    WOLFSSL *ssl;
    struct evquick_event *ev_doh;
    int tls_handshake_done;
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
    unsigned count_cl= 0, count_sock = 0;
    struct client_data *cl;
    struct req_slot *r;
    printstats();
    cl = Clients;
    while(cl) {
        count_cl++;
        r = cl->list;
        while(r) {
            count_sock++;
            r = r->next;
        }
        cl = cl->next;
    }
    dohprint(DOH_NOTICE, "Temporary double check on lists:");
    dohprint(DOH_NOTICE, "  - Clients: %u", count_cl);
    dohprint(DOH_NOTICE, "  - UDP sockets (active requests): %u", count_sock);
}


static void dohd_client_destroy(struct client_data *cd)
{
    struct client_data *l = Clients, *prev = NULL;
    struct req_slot *rp;
    if (!cd)
        return;
    /* Delete from Clients */
    while (l) {
        if (cd == l) {
            if (prev)
                prev->next = cd->next;
            else
                Clients = cd->next;
            break;
        }
        prev = l;
        l = l->next;
    }
    /* Shutdown TLS session */
    if (cd->ssl) {
        wolfSSL_free(cd->ssl);
    }
    /* Close client socket descriptor */
    close(cd->doh_sd);

    /* Cleanup pending requests */
    rp = cd->list;
    while(rp) {
        if (rp->dns_sd > 0)
            close(rp->dns_sd);
        evquick_delevent(rp->ev_dns);
        free(rp);
        DOH_Stats.mem -= sizeof(struct req_slot);
        DOH_Stats.pending_requests -= sizeof(struct req_slot);
        rp = rp->next;
    }
    /* Remove events from file desc */
    if (cd->ev_doh)
        evquick_delevent(cd->ev_doh);
    /* free up client data */
    free(cd);

    /* Update statistics */
    DOH_Stats.mem -= sizeof(struct client_data);
    DOH_Stats.clients--;
    check_stats();
}

static struct sockaddr *next_resolver(void)
{
    resolver_rr++;
    if (resolver_rr >= n_resolvers)
        resolver_rr = 0;
    return Resolver[resolver_rr];
}


void dns_send_request(struct client_data *cd, void *data, size_t size)
{
    int ret;
    struct req_slot *req = NULL, *l;
    struct dns_header *hdr;
    struct sockaddr_in *resolver = NULL;
    socklen_t sock_sz = sizeof(struct sockaddr_in);

    /* Parse DNS header: only check the qr flag. */
    hdr = (struct dns_header *)data;
    if (hdr->qr != 0) {
        return;
    }
    req = malloc(sizeof(struct req_slot));
    if (req == NULL) {
        dohprint(DOH_ERR, "Failed to allocate memory for a new DNS request.");
        return;
    }
    memset(req, 0, sizeof(struct req_slot));

    resolver = (struct sockaddr_in *)next_resolver();

    /* Change AF / socksize if IPV6 */
    if (resolver->sin_family == AF_INET6)
        sock_sz = sizeof(struct sockaddr_in6);

    /* Create local dns socket */
    req->dns_sd = socket(resolver->sin_family, SOCK_DGRAM, 0);
    if (req->dns_sd < 0) {
        dohprint(DOH_ERR, "Failed to create traditional DNS socket to forward the request.");
        free(req);
        return;
    }
    /* append to list */
    if (cd->list == NULL)
        cd->list = req;
    else {
        l = cd->list;
        while(l) {
            if (l->next == NULL) {
                l->next = req;
                break;
            }
            l = l->next;
        }
    }

    /* Update statistics */
    DOH_Stats.mem += sizeof(struct req_slot);
    DOH_Stats.pending_requests++;
    DOH_Stats.tot_requests++;

    /* Populate req structure */
    req->owner = cd;
    req->id = htons(hdr->id);
    req->ev_dns = evquick_addevent(req->dns_sd, EVQUICK_EV_READ, dohd_reply, NULL, req);
    ret = sendto(req->dns_sd, data, size, 0, (struct sockaddr *)resolver, sock_sz);
    if (ret < 0) {
        dohprint(DOH_ERR, "Fatal error: could not reach any recursive resolver at address %s port 53\n", "localhost");
        exit(53);
    }
    check_stats();
}

/**
 * Parse the request coming from DoH, send to DNS resolver
 */
static int dohd_request_post(struct client_data *cd, uint8_t *data, size_t len)
{
    char *hdr = (char *)data;
    char *p_clen, *start_data;
    unsigned int content_len = 0;
    if (!strstr(hdr, STR_ACCEPT_DNS_MSG)
            && (!strstr(hdr, STR_ACCEPT_ANY))
            ) {
        dohd_client_destroy(cd);
        return -1;
    }

    p_clen = strstr(hdr, STR_CONTENT_LEN);
    if (!p_clen) {
        dohd_client_destroy(cd);
        return -1;
    }
    p_clen += strlen(STR_CONTENT_LEN);

    content_len = strtol(p_clen, NULL, 10);
    if (content_len < 8) {
        dohd_client_destroy(cd);
        return -1;
    }
    if (content_len > len) {
        dohd_client_destroy(cd);
        return -1;
    }
    start_data = strstr(p_clen, "\r\n\r\n");
    if (!start_data) {
        dohd_client_destroy(cd);
        return -1;
    }
    start_data += 4;
    dns_send_request(cd, start_data, content_len);
    return 0;
}

static int dohd_request_get(struct client_data *cd, uint8_t *data,
        size_t __attribute__((unused)) len)
{
    char *hdr = (char *)data;
    char *start_data, *end_data;
    uint32_t outlen = DEC_BUFFER_MAXSIZE;
    uint8_t dec_buffer[DEC_BUFFER_MAXSIZE];
    int ret;

    if (!strstr(hdr, STR_ACCEPT_DNS_MSG)
            && (!strstr(hdr, STR_ACCEPT_ANY))
            ) {
        dohd_client_destroy(cd);
        return -1;
    }
    start_data = strstr(hdr, "?dns=");
    if (!start_data) {
        dohd_client_destroy(cd);
        return -1;
    }
    start_data += 5;
    end_data = strchr(start_data, ' ');
    if (!end_data) {
        dohd_client_destroy(cd);
        return -1;
    }
    *end_data = 0;
    ret = Base64_Decode((uint8_t *)start_data, strlen(start_data), dec_buffer, &outlen);
    if (ret != 0) {
        dohd_client_destroy(cd);
        return -1;
    }
    start_data = (char *)dec_buffer;
    dns_send_request(cd, start_data, (end_data - start_data));
    return 0;
}

static int dohd_request_http2(struct client_data *cd, uint8_t *data,
        size_t __attribute__((unused)) len)
{
    dohprint(DOH_DEBUG, "Received HTTP2 Request: %s\n", (char *)data);
    /*TODO: implement HTTP2*/
    dohd_client_destroy(cd);
    return -1;
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
        uint16_t datalen;
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


/**
 * Receive a reply from DNS server and forward to DoH client. Close request.
 */
static void dohd_reply(int fd, short __attribute__((unused)) revents,
        void *arg)
{
    const size_t bufsz = 2048;
    uint8_t buff[bufsz];
    char reply[bufsz];
    int hdrlen, len;
    struct client_data *cd, *l;
    int age = 0;
    struct req_slot *req, *rd;
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
    hdrlen = snprintf(reply, bufsz, STR_REPLY, len, age);
    memcpy(reply + hdrlen, buff, len);
    reply[hdrlen + len] = 0;
    wolfSSL_write(cd->ssl, reply, hdrlen + len);
    DOH_Stats.tot_replies++;

destroy:
    /* Remove request from the list */
    rd = cd->list;
    while(rd) {
        if (rd == req) {
            cd->list = req->next;
            break;
        }
        if (rd->next == req) {
            rd->next = req->next;
            break;
        }
        rd = rd->next;
    }
    evquick_delevent(req->ev_dns);
    close(req->dns_sd);
    free(req);
    /* Update statistics */
    DOH_Stats.mem -= sizeof(struct req_slot);
    DOH_Stats.pending_requests--;
    check_stats();
}

/**
 * Receive a request from the DoH client, forward to the DNS
 * server.
 */
static void tls_read(__attribute__((unused)) int fd, short __attribute__((unused)) revents, void *arg)
{
    const size_t bufsz = 16 * 1024;
    uint8_t buff[bufsz];
    int ret;
    struct client_data *cd = arg;
    if (!cd || !cd->ssl)
        return;
    if (!cd->tls_handshake_done) {
        /* Establish TLS connection */
        ret = wolfSSL_accept(cd->ssl);
        if (ret != SSL_SUCCESS) {
            dohd_client_destroy(cd);
        } else {
            cd->tls_handshake_done = 1;
        }
    } else {
        /* Read the client data into our buff array */
        ret = wolfSSL_read(cd->ssl, buff, bufsz - 1);
        if (ret < 0) {
            dohd_client_destroy(cd);
            DOH_Stats.socket_errors++;
        } else {
            if (ret < DOHD_REQ_MIN) {
                dohd_client_destroy(cd);
                return;
            }
            if (strncmp((char*)buff, "POST /", 6) == 0) {
                /* Safety null-termination because
                 * dohd_request uses strstr() to parse
                 * the request */
                buff[ret] = 0;
                if (dohd_request_post(cd, buff, ret) == 0)
                    DOH_Stats.http_post_requests++;
                else {
                    DOH_Stats.http_notvalid_requests++;
                }
            } else if (strncmp((char *)buff, "GET /?dns=", 10) == 0) {
                buff[ret] = 0;
                if (dohd_request_get(cd, buff, ret) == 0)
                    DOH_Stats.http_get_requests++;
                else {
                    DOH_Stats.http_notvalid_requests++;
                }
            } else if (strncmp((char *)buff, "HEAD /?dns=", 11) == 0) {
                buff[ret] = 0;
                if (dohd_request_get(cd, buff, ret) == 0)
                    DOH_Stats.http_head_requests++;
                else {
                    DOH_Stats.http_notvalid_requests++;
                }

            } else if (strncmp((char *)buff, STR_HTTP2_PREFACE, 24) == 0) {
                if(dohd_request_http2(cd, buff, ret) == 0)
                    DOH_Stats.http2_requests++;
                else
                    DOH_Stats.http_notvalid_requests++;
            } else {
                buff[ret] = 0;
                DOH_Stats.http_notvalid_requests++;
                dohd_client_destroy(cd);
            }
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
    dohd_client_destroy(cd);
}

/**
 * Accept a new DoH connection, create client data object
 */
static void dohd_new_connection(int __attribute__((unused)) fd,
        short __attribute__((unused)) revents,
        void __attribute__((unused)) *arg)
{
    int connd;
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

    /* Create a WOLFSSL object */
    cd->ssl = wolfSSL_new(wctx);
    if (cd->ssl == NULL) {
        dohprint(DOH_ERR, "ERROR: failed to create WOLFSSL object\n");
        close(connd);
        free(cd);
        return;
    }
    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(cd->ssl, connd);

#if (HTTP2_MODE)
    /* Enable HTTP2 via ALPN */
    wolfSSL_UseALPN(cd->ssl, "h2", 2, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
#endif

    cd->doh_sd = connd;
    cd->ev_doh = evquick_addevent(cd->doh_sd, EVQUICK_EV_READ, tls_read, tls_fail, cd);
    cd->next = Clients;
    Clients = cd;

    DOH_Stats.mem += sizeof(struct client_data);
    DOH_Stats.clients++;
}

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
