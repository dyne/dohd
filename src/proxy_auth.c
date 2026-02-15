#include "proxy_auth.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/hash.h>

static int pkey_to_hash(WOLFSSL_EVP_PKEY *pkey, uint8_t out[PROXY_AUTH_HASH_LEN])
{
    unsigned char *der = NULL;
    int der_len;

    if (!pkey)
        return -1;

    der_len = wolfSSL_i2d_PUBKEY(pkey, &der);
    if (der_len <= 0 || !der)
        return -1;

    if (wc_Sha256Hash(der, (word32)der_len, out) != 0) {
        free(der);
        return -1;
    }

    free(der);
    return 0;
}

void proxy_auth_free(proxy_auth_set *set)
{
    if (!set)
        return;
    free(set->hashes);
    set->hashes = NULL;
    set->count = 0;
}

int proxy_auth_load_dir(const char *dirpath, proxy_auth_set *set)
{
    DIR *d;
    struct dirent *de;
    proxy_auth_set tmp = {};

    if (!dirpath || !set)
        return -1;

    d = opendir(dirpath);
    if (!d)
        return -1;

    while ((de = readdir(d)) != NULL) {
        char path[PATH_MAX];
        struct stat st;
        WOLFSSL_BIO *bio = NULL;
        WOLFSSL_EVP_PKEY *pkey = NULL;
        uint8_t hash[PROXY_AUTH_HASH_LEN];
        uint8_t *nptr;
        size_t i;
        int dup = 0;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dirpath, de->d_name);
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        bio = wolfSSL_BIO_new_file(path, "rb");
        if (!bio)
            continue;

        pkey = wolfSSL_PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        wolfSSL_BIO_free(bio);
        if (!pkey)
            continue;

        if (pkey_to_hash(pkey, hash) != 0) {
            wolfSSL_EVP_PKEY_free(pkey);
            continue;
        }
        wolfSSL_EVP_PKEY_free(pkey);

        for (i = 0; i < tmp.count; i++) {
            if (memcmp(tmp.hashes + (i * PROXY_AUTH_HASH_LEN), hash, PROXY_AUTH_HASH_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;

        nptr = realloc(tmp.hashes, (tmp.count + 1) * PROXY_AUTH_HASH_LEN);
        if (!nptr) {
            proxy_auth_free(&tmp);
            closedir(d);
            return -1;
        }

        tmp.hashes = nptr;
        memcpy(tmp.hashes + (tmp.count * PROXY_AUTH_HASH_LEN), hash, PROXY_AUTH_HASH_LEN);
        tmp.count++;
    }

    closedir(d);

    proxy_auth_free(set);
    *set = tmp;
    return 0;
}

int proxy_auth_peer_allowed(WOLFSSL *ssl, const proxy_auth_set *set)
{
    WOLFSSL_X509 *cert = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    uint8_t hash[PROXY_AUTH_HASH_LEN];
    size_t i;
    int allowed = 0;

    if (!ssl || !set || set->count == 0)
        return 0;

    cert = wolfSSL_get_peer_certificate(ssl);
    if (!cert)
        return 0;

    pkey = wolfSSL_X509_get_pubkey(cert);
    wolfSSL_X509_free(cert);
    if (!pkey)
        return 0;

    if (pkey_to_hash(pkey, hash) != 0) {
        wolfSSL_EVP_PKEY_free(pkey);
        return 0;
    }

    wolfSSL_EVP_PKEY_free(pkey);

    for (i = 0; i < set->count; i++) {
        if (memcmp(set->hashes + (i * PROXY_AUTH_HASH_LEN), hash, PROXY_AUTH_HASH_LEN) == 0) {
            allowed = 1;
            break;
        }
    }

    return allowed;
}
