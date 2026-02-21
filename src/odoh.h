#ifndef DOHD_ODOH_H
#define DOHD_ODOH_H

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/curve25519.h>

#define ODOH_MSG_QUERY 0x01
#define ODOH_MSG_RESPONSE 0x02
#define ODOH_MAX_CONFIG 2048
#define ODOH_MAX_MESSAGE 65535
#define ODOH_MAX_KEY_ID 64
#define ODOH_MAX_PUBLIC_KEY 133

typedef struct {
    uint16_t version;
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
    uint8_t public_key[ODOH_MAX_PUBLIC_KEY];
    uint16_t public_key_len;
    uint8_t key_id[ODOH_MAX_KEY_ID];
    uint16_t key_id_len;
} odoh_config;

typedef struct {
    uint8_t message_type;
    const uint8_t *key_id;
    uint16_t key_id_len;
    const uint8_t *encrypted;
    uint16_t encrypted_len;
} odoh_message_view;

typedef struct {
    Hpke hpke;
    HpkeBaseContext hpke_ctx;
    odoh_config cfg;
    uint8_t q_plain[ODOH_MAX_MESSAGE];
    uint16_t q_plain_len;
    int valid;
} odoh_client_ctx;

typedef odoh_client_ctx odoh_req_ctx;

typedef struct {
    odoh_config cfg;
    curve25519_key priv;
    int loaded;
} odoh_target_ctx;

int odoh_config_load_file(const char *path, odoh_config *cfg);
int odoh_target_load_files(const char *cfg_path, const char *secret_path,
    odoh_target_ctx *target);
void odoh_target_free(odoh_target_ctx *target);

int odoh_parse_message(const uint8_t *in, size_t in_len, odoh_message_view *msg);

int odoh_client_encrypt_query(const odoh_config *cfg,
    const uint8_t *dns_msg, uint16_t dns_len,
    uint8_t *out, uint16_t *out_len,
    odoh_client_ctx *client_ctx);

int odoh_client_decrypt_response(odoh_client_ctx *client_ctx,
    const uint8_t *in, uint16_t in_len,
    uint8_t *dns_out, uint16_t *dns_out_len);

int odoh_target_decrypt_query(odoh_target_ctx *target,
    const uint8_t *in, uint16_t in_len,
    uint8_t *dns_out, uint16_t *dns_out_len,
    odoh_req_ctx *req_ctx);

int odoh_target_encrypt_response(const odoh_req_ctx *req_ctx,
    const uint8_t *dns_msg, uint16_t dns_len,
    uint8_t *out, uint16_t *out_len);

#endif
