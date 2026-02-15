#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hpke.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ODOH_VERSION 0x0001

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static int write_file(const char *path, const uint8_t *buf, size_t len, mode_t mode)
{
    int fd;
    ssize_t w;
    size_t off = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    while (off < len) {
        w = write(fd, buf + off, len - off);
        if (w <= 0) {
            close(fd);
            fprintf(stderr, "Cannot write %s: %s\n", path, strerror(errno));
            return -1;
        }
        off += (size_t)w;
    }

    if (close(fd) != 0) {
        fprintf(stderr, "Cannot close %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

static int write_odoh_config(const char *path, const uint8_t *pub, size_t pub_len)
{
    uint8_t header[2 + 2 + 2 + 2 + 2 + 2 + 2];
    uint16_t cfg_contents_len;
    uint16_t cfg_record_len;
    uint16_t total_len;

    if (pub_len > 65535u)
        return -1;

    cfg_contents_len = (uint16_t)(8u + pub_len);
    cfg_record_len = (uint16_t)(4u + cfg_contents_len);
    total_len = cfg_record_len;

    put16(header + 0, total_len);
    put16(header + 2, ODOH_VERSION);
    put16(header + 4, cfg_contents_len);
    put16(header + 6, DHKEM_X25519_HKDF_SHA256);
    put16(header + 8, HKDF_SHA256);
    put16(header + 10, HPKE_AES_128_GCM);
    put16(header + 12, (uint16_t)pub_len);

    if (write_file(path, header, sizeof(header), 0644) != 0)
        return -1;

    {
        int fd = open(path, O_WRONLY | O_APPEND, 0644);
        ssize_t w;
        if (fd < 0) {
            fprintf(stderr, "Cannot append to %s: %s\n", path, strerror(errno));
            return -1;
        }
        w = write(fd, pub, pub_len);
        if (w != (ssize_t)pub_len) {
            close(fd);
            fprintf(stderr, "Cannot append public key to %s\n", path);
            return -1;
        }
        if (close(fd) != 0) {
            fprintf(stderr, "Cannot close %s: %s\n", path, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void usage(const char *name)
{
    fprintf(stderr, "%s, generate ODoH X25519 key material in dohd formats.\n", name);
    fprintf(stderr, "Usage: %s [-s secret.bin] [-p public.bin] [-c odoh.config]\n", name);
    fprintf(stderr, "Defaults: secret=odoh-target.secret public=odoh-target.public config=odoh-target.config\n");
}

int main(int argc, char *argv[])
{
    const char *secret_path = "odoh-target.secret";
    const char *public_path = "odoh-target.public";
    const char *config_path = "odoh-target.config";
    WC_RNG rng;
    curve25519_key key;
    uint8_t priv[CURVE25519_KEYSIZE];
    uint8_t pub[CURVE25519_PUB_KEY_SIZE];
    word32 priv_len = sizeof(priv);
    word32 pub_len = sizeof(pub);
    int c;

    while ((c = getopt(argc, argv, "hs:p:c:")) >= 0) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 's':
                secret_path = optarg;
                break;
            case 'p':
                public_path = optarg;
                break;
            case 'c':
                config_path = optarg;
                break;
            default:
                usage(argv[0]);
                return 2;
        }
    }

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "wc_InitRng failed\n");
        return 1;
    }
    if (wc_curve25519_init(&key) != 0) {
        wc_FreeRng(&rng);
        fprintf(stderr, "wc_curve25519_init failed\n");
        return 1;
    }
    if (wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key) != 0) {
        wc_curve25519_free(&key);
        wc_FreeRng(&rng);
        fprintf(stderr, "wc_curve25519_make_key failed\n");
        return 1;
    }
    if (wc_curve25519_export_key_raw(&key, priv, &priv_len, pub, &pub_len) != 0) {
        wc_curve25519_free(&key);
        wc_FreeRng(&rng);
        fprintf(stderr, "wc_curve25519_export_key_raw failed\n");
        return 1;
    }
    wc_curve25519_free(&key);
    wc_FreeRng(&rng);

    if (priv_len != CURVE25519_KEYSIZE || pub_len != CURVE25519_PUB_KEY_SIZE) {
        fprintf(stderr, "Unexpected key sizes: priv=%u pub=%u\n", priv_len, pub_len);
        return 1;
    }

    if (write_file(secret_path, priv, priv_len, 0600) != 0)
        return 1;
    if (write_file(public_path, pub, pub_len, 0644) != 0)
        return 1;
    if (write_odoh_config(config_path, pub, pub_len) != 0)
        return 1;

    fprintf(stderr, "Generated:\n");
    fprintf(stderr, "  secret (raw 32 bytes): %s\n", secret_path);
    fprintf(stderr, "  public (raw 32 bytes): %s\n", public_path);
    fprintf(stderr, "  ODoH config blob      : %s\n", config_path);
    fprintf(stderr, "HPKE suite: KEM=0x%04x KDF=0x%04x AEAD=0x%04x\n",
        DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM);

    return 0;
}
