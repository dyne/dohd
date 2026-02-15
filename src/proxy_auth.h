#ifndef DOHD_PROXY_AUTH_H
#define DOHD_PROXY_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define PROXY_AUTH_HASH_LEN 32

typedef struct {
    uint8_t *hashes;
    size_t count;
} proxy_auth_set;

int proxy_auth_load_dir(const char *dirpath, proxy_auth_set *set);
void proxy_auth_free(proxy_auth_set *set);
int proxy_auth_peer_allowed(WOLFSSL *ssl, const proxy_auth_set *set);

#endif
