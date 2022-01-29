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
#include <pwd.h>
#include "libevquick.h"

#define VERSION "v0.2"

#define DOH_PORT 8053
#define DEC_BUFFER_MAXSIZE 1460

#define HTTP2_MODE 0 /* Change to '1' once implemented */

#define IP6_LOCALHOST { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#define DOHD_REQ_MIN 40
#define STR_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define STR_ACCEPT_DNS_MSG "Accept: application/dns-message"
#define STR_CONTENT_LEN    "Content-Length: "
#define STR_REPLY "HTTP/1.1 200 OK\r\nServer: dohd\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nCache-Control: max-age=%d\r\n\r\n"

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
    fprintf(stderr, "FATAL: Error on listening socket\n");
    exit(80);
}

static void dohd_client_destroy(struct client_data *cd)
{
    struct client_data *l = Clients, *prev = NULL;
    struct req_slot *rp;
    if (!cd)
        return;
    wolfSSL_write(cd->ssl, "HTTP/1.1 404 Not Found\r\n\r\n", 26);
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
        if (cd->tls_handshake_done)
            wolfSSL_shutdown(cd->ssl);
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
        rp = rp->next;
    }
    /* Remove events from file desc */
    if (cd->ev_doh)
        evquick_delevent(cd->ev_doh);
    /* free up client data */
    free(cd);
}


void dns_send_request(struct client_data *cd, void *data, size_t size)
{
    int ret;
    struct req_slot *req = NULL, *l;
    struct dns_header *hdr;
    struct sockaddr_in6 local_dns_addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(53),
        .sin6_addr.s6_addr = IP6_LOCALHOST
    };

    /* Parse DNS header: only check the qr flag. */
    hdr = (struct dns_header *)data;
    if (hdr->qr != 0) {
        return;
    }
    req = malloc(sizeof(struct req_slot));
    if (req == NULL) {
        fprintf(stderr, "ERROR: failed to allocate memory for a new DNS request\n\n");
        return;
    }
    memset(req, 0, sizeof(struct req_slot));

    /* Create local dns socket */
    req->dns_sd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (req->dns_sd < 0) {
        fprintf(stderr, "ERROR: failed to create local dns socket\n");
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
    req->owner = cd;
    req->id = htons(hdr->id);
    req->ev_dns = evquick_addevent(req->dns_sd, EVQUICK_EV_READ, dohd_reply, NULL, req);
    ret = sendto(req->dns_sd, data, size, 0, (struct sockaddr *)&local_dns_addr, sizeof(struct sockaddr_in6));
    if (ret < 0) {
        fprintf(stderr, "FATAL: localhost DNS on port 53: socket error\n");
        exit(53);
    }
}

/**
 * Parse the request coming from DoH, send to DNS resolver
 */
static void dohd_request_post(struct client_data *cd, uint8_t *data, size_t len)
{
    char *hdr = (char *)data;
    char *p_clen, *start_data;
    unsigned int content_len = 0;
    if (!strstr(hdr, STR_ACCEPT_DNS_MSG)) {
        dohd_client_destroy(cd);
        return;
    }

    p_clen = strstr(hdr, STR_CONTENT_LEN);
    if (!p_clen) {
        dohd_client_destroy(cd);
        return;
    }
    p_clen += strlen(STR_CONTENT_LEN);

    content_len = strtol(p_clen, NULL, 10);
    if (content_len < 8) {
        dohd_client_destroy(cd);
        return;
    }
    if (content_len > len) {
        dohd_client_destroy(cd);
        return;
    }
    start_data = strstr(p_clen, "\r\n\r\n");
    if (!start_data) {
        dohd_client_destroy(cd);
        return;
    }
    start_data += 4;
    dns_send_request(cd, start_data, content_len);
}

static void dohd_request_get(struct client_data *cd, uint8_t *data,
        size_t __attribute__((unused)) len)
{
    char *hdr = (char *)data;
    char *start_data, *end_data;
    uint32_t outlen = DEC_BUFFER_MAXSIZE;
    uint8_t dec_buffer[DEC_BUFFER_MAXSIZE];
    int ret;

    if (!strstr(hdr, STR_ACCEPT_DNS_MSG)) {
        dohd_client_destroy(cd);
        return;
    }
    start_data = strstr(hdr, "?dns=");
    if (!start_data) {
        dohd_client_destroy(cd);
        return;
    }
    start_data += 5;
    end_data = strchr(start_data, ' ');
    if (!end_data) {
        dohd_client_destroy(cd);
        return;
    }
    *end_data = 0;
    ret = Base64_Decode((uint8_t *)start_data, strlen(start_data), dec_buffer, &outlen);
    if (ret != 0) {
        dohd_client_destroy(cd);
        return;
    }
    start_data = (char *)dec_buffer;
    dns_send_request(cd, start_data, (end_data - start_data));
}

static void dohd_request_http2(struct client_data *cd, uint8_t *data,
        size_t __attribute__((unused)) len)
{
    fprintf(stderr, "Received HTTP2 Request: %s\n", (char *)data);
    /*TODO: implement HTTP2*/
    dohd_client_destroy(cd);
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
            fprintf(stderr, "Cannot parse DNS reply!\n");
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
        fprintf(stderr, "FATAL: localhost DNS on port 53: socket error\n");
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
}

/**
 * Receive a request from the DoH client, forward to the DNS
 * server.
 */
static void tls_read(__attribute__((unused)) int fd, short __attribute__((unused)) revents, void *arg)
{
    const size_t bufsz = 4096;
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
        if (ret < 0)
            dohd_client_destroy(cd);
        else {
            if (ret < DOHD_REQ_MIN) {
                dohd_client_destroy(cd);
                return;
            }
            if (strncmp((char*)buff, "POST /", 6) == 0) {
                /* Safety null-termination because
                 * dohd_request uses strstr() to parse
                 * the request */
                buff[ret] = 0;
                dohd_request_post(cd, buff, ret);
            } else if (strncmp((char *)buff, "GET /?dns=", 10) == 0) {
                buff[ret] = 0;
                dohd_request_get(cd, buff, ret);
            } else if (strncmp((char *)buff, STR_HTTP2_PREFACE, 24) == 0) {
                dohd_request_http2(cd, buff, ret);
            } else {
                buff[ret] = 0;
                dohd_client_destroy(cd);
            }
        }
    }
}

/**
 * Callback for error events
 */
static void tls_fail(int __attribute__((unused)) fd,
        short __attribute__((unused)) revents,
        void *arg)
{
    struct client_data *cd = arg;
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

    cd = malloc(sizeof(struct client_data));
    if (cd == NULL) {
        fprintf(stderr, "ERROR: failed to allocate memory for a new connection\n\n");
        return;
    }

    memset(cd, 0, sizeof(struct client_data));
    /* Accept client connections */
    connd = accept(lfd, NULL, &zero);
    if (connd < 0) {
        fprintf(stderr, "ERROR: failed to accept the connection: %s\n\n", strerror(errno));
        free(cd);
        return;
    }

    /* Create a WOLFSSL object */
    cd->ssl = wolfSSL_new(wctx);
    if (cd->ssl == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
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
}

static void usage(const char *name)
{

    fprintf(stderr, "%s, DNSoverHTTPS minimalist daemon.\n", name);
    fprintf(stderr, "License: AGPL\n");
    fprintf(stderr, "Usage: %s -c cert -k key [-p port] [-d dnsserver] [-F] [-u user]\n", name);
    fprintf(stderr, "\t'cert' and 'key': certificate and its private key.\n");
    fprintf(stderr, "\t'user' : login name (when running as root) to switch to (dropping permissions)\n");
    fprintf(stderr, "\tDefault values: port=8053 dnsserver=\"::1\"\n");
    fprintf(stderr, "\tUse '-F' for foreground mode\n\n");
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
    struct option long_options[] = {
            {"help",0 , 0, 'h'},
            {"version", 0, 0, 'v'},
            {"cert", 1, 0, 'c' },
            {"key", 1, 0, 'k'},
            {"port", 1, 0, 'p'},
            {"dnsserver", 1, 0, 'd'},
            {"user", 1, 0, 'u'},
            {"do-not-fork", 0, 0, 'F'},
            {NULL, 0, 0, '\0' }
    };
    while(1) {
        c = getopt_long(argc, argv, "hvc:k:p:d:u:F" , long_options, &option_idx);
        if (c < 0)
            break;
        switch(c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'v':
                fprintf(stderr, "%s, %s\n", argv[0], VERSION);
                exit(0);
                break;
            case 'p':
                port = (uint16_t)atoi(optarg);
                break;
            case 'c':
                cert = strdup(optarg);
                break;
            case 'k':
                key = strdup(optarg);
                break;
            case 'd':
                /* TODO */
                fprintf(stderr, "DNS server selection not available yet.\n");
                exit(1);
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

    /* Create listening socket */
    lfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (lfd < 0) {
        fprintf(stderr, "ERROR: failed to create DoH socket\n");
        return -1;
    }

    /* Fill in the server address */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family      = AF_INET6;             /* using IPv4      */
    serv_addr.sin6_port        = htons(port); /* on DEFAULT_PORT */

    /* Bind the server socket to our port */
    if (bind(lfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }

    /* Drop privileges if running as root */
    if (getuid() == 0) {
        struct passwd *pwd;
        if (!user) {
            fprintf(stderr, "Error: '-u' option required when running as root to drop privileges. Exiting.\n");
            close(lfd);
            exit(2);
        }
        pwd = getpwnam(user);
        if (!pwd) {
            fprintf(stderr, "Error: invalid username '%s'\n",user);
            close(lfd);
            exit(3);
        }
        if (pwd->pw_uid == 0) {
            fprintf(stderr, "Error: invalid UID for username '%s'\n", user);
            close(lfd);
            exit(3);
        }
        if (setgid(pwd->pw_gid) < 0) {
            perror("setgid");
            close(lfd);
            exit(4);
        }
        if (setuid(pwd->pw_uid) < 0) {
            perror("setuid");
            close(lfd);
            exit(4);
        }
        fprintf(stderr, "setuid(%d) + setgid(%d)\n", pwd->pw_uid, pwd->pw_gid);
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Enable debug, if active */
    //wolfSSL_Debugging_ON();

    /* Initialize libevquick */
    evquick_init();

    /* Create and initialize WOLFSSL_CTX */
    if ((wctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    if (wolfSSL_CTX_use_certificate_file(wctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", cert);
        return -1;
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(wctx, key, SSL_FILETYPE_PEM)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", key);
        return -1;
    }


    /* Listen for a new connection, allow 10 pending connections */
    if (listen(lfd, 10) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

    evquick_addevent(lfd, EVQUICK_EV_READ, dohd_new_connection, dohd_listen_error, wctx);
    evquick_loop();
    free(cert);
    cert = NULL;
    free(key);
    return 0;
}
