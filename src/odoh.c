#include "odoh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#define ODOH_VERSION 0x0001
#define ODOH_INFO_QUERY "odoh query"
#define ODOH_LABEL_KEYID "odoh key id"
#define ODOH_LABEL_RESPONSE "odoh response"
#define ODOH_LABEL_KEY "odoh key"
#define ODOH_LABEL_NONCE "odoh nonce"

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static int kdf_to_hash(uint16_t kdf_id)
{
    switch (kdf_id) {
        case HKDF_SHA256: return WC_SHA256;
        case HKDF_SHA384: return WC_SHA384;
        case HKDF_SHA512: return WC_SHA512;
        default: return -1;
    }
}

static uint16_t kdf_nh(uint16_t kdf_id)
{
    switch (kdf_id) {
        case HKDF_SHA256: return 32;
        case HKDF_SHA384: return 48;
        case HKDF_SHA512: return 64;
        default: return 0;
    }
}

static int hpke_init_for_cfg(const odoh_config *cfg, Hpke *hpke)
{
    return wc_HpkeInit(hpke, cfg->kem_id, cfg->kdf_id, cfg->aead_id, NULL);
}

static int odoh_compute_key_id(const odoh_config *cfg, uint8_t *out, uint16_t *out_len)
{
    uint8_t content[2 + 2 + 2 + 2 + ODOH_MAX_PUBLIC_KEY];
    uint8_t prk[64];
    uint16_t nh;
    int htype;
    int ret;
    uint16_t content_len;

    if (!cfg || !out || !out_len)
        return -1;

    htype = kdf_to_hash(cfg->kdf_id);
    nh = kdf_nh(cfg->kdf_id);
    if (htype < 0 || nh == 0)
        return -1;

    put16(content + 0, cfg->kem_id);
    put16(content + 2, cfg->kdf_id);
    put16(content + 4, cfg->aead_id);
    put16(content + 6, cfg->public_key_len);
    memcpy(content + 8, cfg->public_key, cfg->public_key_len);
    content_len = (uint16_t)(8 + cfg->public_key_len);

    ret = wc_HKDF_Extract(htype, NULL, 0, content, content_len, prk);
    if (ret != 0)
        return -1;

    ret = wc_HKDF_Expand(htype, prk, nh,
        (const uint8_t *)ODOH_LABEL_KEYID, (word32)strlen(ODOH_LABEL_KEYID), out, nh);
    if (ret != 0)
        return -1;

    *out_len = nh;
    return 0;
}

static int parse_configs_blob(const uint8_t *buf, size_t sz, odoh_config *cfg)
{
    size_t off = 0;
    uint16_t total_len;

    if (sz < 2)
        return -1;

    total_len = be16(buf);
    off = 2;
    if (total_len + 2 > sz)
        return -1;

    while ((off + 4) <= (size_t)(2 + total_len)) {
        uint16_t version = be16(buf + off);
        uint16_t clen = be16(buf + off + 2);
        size_t cstart = off + 4;

        if ((cstart + clen) > (size_t)(2 + total_len))
            return -1;

        if (version == ODOH_VERSION && clen >= 8) {
            cfg->version = version;
            cfg->kem_id = be16(buf + cstart + 0);
            cfg->kdf_id = be16(buf + cstart + 2);
            cfg->aead_id = be16(buf + cstart + 4);
            cfg->public_key_len = be16(buf + cstart + 6);

            if ((size_t)(8 + cfg->public_key_len) > clen)
                return -1;
            if (cfg->public_key_len > ODOH_MAX_PUBLIC_KEY)
                return -1;

            memcpy(cfg->public_key, buf + cstart + 8, cfg->public_key_len);

            if (odoh_compute_key_id(cfg, cfg->key_id, &cfg->key_id_len) != 0)
                return -1;

            return 0;
        }

        off = cstart + clen;
    }

    return -1;
}

int odoh_config_load_file(const char *path, odoh_config *cfg)
{
    FILE *fp;
    uint8_t buf[ODOH_MAX_CONFIG];
    size_t n;

    if (!path || !cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    fp = fopen(path, "rb");
    if (!fp)
        return -1;

    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    if (n < 2)
        return -1;

    return parse_configs_blob(buf, n, cfg);
}

int odoh_target_load_files(const char *cfg_path, const char *secret_path,
    odoh_target_ctx *target)
{
    FILE *fp;
    uint8_t priv[32];

    if (!target || !cfg_path || !secret_path)
        return -1;

    memset(target, 0, sizeof(*target));

    if (odoh_config_load_file(cfg_path, &target->cfg) != 0)
        return -1;

    if (target->cfg.kem_id != DHKEM_X25519_HKDF_SHA256)
        return -1;

    fp = fopen(secret_path, "rb");
    if (!fp)
        return -1;
    if (fread(priv, 1, sizeof(priv), fp) != sizeof(priv)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (wc_curve25519_init(&target->priv) != 0)
        return -1;

    if (wc_curve25519_import_private_raw(priv, sizeof(priv),
            target->cfg.public_key, target->cfg.public_key_len,
            &target->priv) != 0) {
        wc_curve25519_free(&target->priv);
        return -1;
    }

    target->loaded = 1;
    return 0;
}

void odoh_target_free(odoh_target_ctx *target)
{
    if (!target)
        return;
    if (target->loaded)
        wc_curve25519_free(&target->priv);
    memset(target, 0, sizeof(*target));
}

int odoh_parse_message(const uint8_t *in, size_t in_len, odoh_message_view *msg)
{
    size_t off = 0;
    uint16_t klen;
    uint16_t elen;

    if (!in || !msg || in_len < 5)
        return -1;

    memset(msg, 0, sizeof(*msg));

    msg->message_type = in[off++];
    klen = be16(in + off);
    off += 2;
    if ((off + klen + 2) > in_len)
        return -1;

    msg->key_id = in + off;
    msg->key_id_len = klen;
    off += klen;

    elen = be16(in + off);
    off += 2;
    if (elen == 0 || (off + elen) > in_len)
        return -1;

    msg->encrypted = in + off;
    msg->encrypted_len = elen;
    return 0;
}

static int build_plaintext(const uint8_t *dns, uint16_t dns_len,
    uint8_t *out, uint16_t *out_len)
{
    if (!dns || !out || !out_len)
        return -1;
    if (dns_len == 0 || dns_len > (ODOH_MAX_MESSAGE - 4))
        return -1;

    put16(out + 0, dns_len);
    memcpy(out + 2, dns, dns_len);
    put16(out + 2 + dns_len, 0);
    *out_len = (uint16_t)(dns_len + 4);
    return 0;
}

static int parse_plaintext_dns(const uint8_t *plain, uint16_t plain_len,
    uint8_t *dns_out, uint16_t *dns_out_len)
{
    uint16_t dns_len;
    uint16_t pad_len;
    size_t i;

    if (!plain || !dns_out || !dns_out_len || plain_len < 4)
        return -1;

    dns_len = be16(plain + 0);
    if ((size_t)(2 + dns_len + 2) > plain_len)
        return -1;

    pad_len = be16(plain + 2 + dns_len);
    if ((size_t)(2 + dns_len + 2 + pad_len) > plain_len)
        return -1;

    for (i = 0; i < pad_len; i++) {
        if (plain[2 + dns_len + 2 + i] != 0)
            return -1;
    }

    memcpy(dns_out, plain + 2, dns_len);
    *dns_out_len = dns_len;
    return 0;
}

static int build_query_aad(const uint8_t *key_id, uint16_t key_id_len,
    uint8_t *aad, uint16_t *aad_len)
{
    if (!aad || !aad_len || !key_id)
        return -1;
    aad[0] = ODOH_MSG_QUERY;
    put16(aad + 1, key_id_len);
    memcpy(aad + 3, key_id, key_id_len);
    *aad_len = (uint16_t)(3 + key_id_len);
    return 0;
}

static int build_response_aad(const uint8_t *resp_nonce, uint16_t nonce_len,
    uint8_t *aad, uint16_t *aad_len)
{
    aad[0] = ODOH_MSG_RESPONSE;
    put16(aad + 1, nonce_len);
    memcpy(aad + 3, resp_nonce, nonce_len);
    *aad_len = (uint16_t)(3 + nonce_len);
    return 0;
}

static int derive_response_secret(const Hpke *hpke, const HpkeBaseContext *ctx,
    uint8_t *out, uint16_t out_len)
{
    int htype = kdf_to_hash((uint16_t)hpke->kdf);
    if (htype < 0)
        return -1;
    return wc_HKDF_Expand(htype, ctx->exporter_secret, hpke->Nsecret,
        (const uint8_t *)ODOH_LABEL_RESPONSE, (word32)strlen(ODOH_LABEL_RESPONSE),
        out, out_len);
}

static int derive_response_key_nonce(const Hpke *hpke, const HpkeBaseContext *ctx,
    const uint8_t *q_plain, uint16_t q_plain_len,
    const uint8_t *resp_nonce, uint16_t resp_nonce_len,
    uint8_t *key_out, uint16_t key_len,
    uint8_t *nonce_out, uint16_t nonce_len)
{
    int htype = kdf_to_hash((uint16_t)hpke->kdf);
    uint8_t secret[64];
    uint8_t prk[64];
    uint8_t salt[ODOH_MAX_MESSAGE + 2 + 64];
    uint16_t salt_len;

    if (htype < 0)
        return -1;

    if ((size_t)q_plain_len + 2 + resp_nonce_len > sizeof(salt))
        return -1;

    if (derive_response_secret(hpke, ctx, secret, key_len) != 0)
        return -1;

    memcpy(salt, q_plain, q_plain_len);
    put16(salt + q_plain_len, resp_nonce_len);
    memcpy(salt + q_plain_len + 2, resp_nonce, resp_nonce_len);
    salt_len = (uint16_t)(q_plain_len + 2 + resp_nonce_len);

    if (wc_HKDF_Extract(htype, salt, salt_len, secret, key_len, prk) != 0)
        return -1;

    if (wc_HKDF_Expand(htype, prk, kdf_nh((uint16_t)hpke->kdf),
            (const uint8_t *)ODOH_LABEL_KEY, (word32)strlen(ODOH_LABEL_KEY),
            key_out, key_len) != 0)
        return -1;

    if (wc_HKDF_Expand(htype, prk, kdf_nh((uint16_t)hpke->kdf),
            (const uint8_t *)ODOH_LABEL_NONCE, (word32)strlen(ODOH_LABEL_NONCE),
            nonce_out, nonce_len) != 0)
        return -1;

    return 0;
}

int odoh_client_encrypt_query(const odoh_config *cfg,
    const uint8_t *dns_msg, uint16_t dns_len,
    uint8_t *out, uint16_t *out_len,
    odoh_client_ctx *client_ctx)
{
    uint8_t plain[ODOH_MAX_MESSAGE];
    uint16_t plain_len;
    uint8_t aad[3 + ODOH_MAX_KEY_ID];
    uint16_t aad_len;
    uint8_t enc[ODOH_MAX_PUBLIC_KEY];
    word16 enc_len = sizeof(enc);
    uint8_t ct[ODOH_MAX_MESSAGE];
    size_t off = 0;
    int ct_len;
    void *receiver = NULL;
    void *eph = NULL;
    WC_RNG rng;

    if (!cfg || !dns_msg || !out || !out_len || !client_ctx)
        return -1;

    memset(client_ctx, 0, sizeof(*client_ctx));

    if (build_plaintext(dns_msg, dns_len, plain, &plain_len) != 0)
        return -1;

    if (hpke_init_for_cfg(cfg, &client_ctx->hpke) != 0)
        return -1;

    if (wc_HpkeDeserializePublicKey(&client_ctx->hpke, &receiver,
            cfg->public_key, cfg->public_key_len) != 0)
        return -1;

    if (wc_InitRng(&rng) != 0)
        return -1;

    if (wc_HpkeGenerateKeyPair(&client_ctx->hpke, &eph, &rng) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    if (wc_HpkeInitSealContext(&client_ctx->hpke, &client_ctx->hpke_ctx,
            eph, receiver, (byte *)ODOH_INFO_QUERY, (word32)strlen(ODOH_INFO_QUERY)) != 0) {
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
        wc_FreeRng(&rng);
        return -1;
    }

    if (wc_HpkeSerializePublicKey(&client_ctx->hpke, eph, enc, &enc_len) != 0) {
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
        wc_FreeRng(&rng);
        return -1;
    }

    if (build_query_aad(cfg->key_id, cfg->key_id_len, aad, &aad_len) != 0) {
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
        wc_FreeRng(&rng);
        return -1;
    }

    ct_len = plain_len + client_ctx->hpke.Nt;
    if (wc_HpkeContextSealBase(&client_ctx->hpke, &client_ctx->hpke_ctx,
            aad, aad_len, plain, plain_len, ct) != 0) {
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
        wc_FreeRng(&rng);
        return -1;
    }

    if ((size_t)(1 + 2 + cfg->key_id_len + 2 + enc_len + ct_len) > ODOH_MAX_MESSAGE) {
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
        wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
        wc_FreeRng(&rng);
        return -1;
    }

    out[off++] = ODOH_MSG_QUERY;
    put16(out + off, cfg->key_id_len);
    off += 2;
    memcpy(out + off, cfg->key_id, cfg->key_id_len);
    off += cfg->key_id_len;
    put16(out + off, (uint16_t)(enc_len + ct_len));
    off += 2;
    memcpy(out + off, enc, enc_len);
    off += enc_len;
    memcpy(out + off, ct, ct_len);
    off += ct_len;

    memcpy(&client_ctx->cfg, cfg, sizeof(*cfg));
    memcpy(client_ctx->q_plain, plain, plain_len);
    client_ctx->q_plain_len = plain_len;
    client_ctx->valid = 1;

    *out_len = (uint16_t)off;

    wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, eph, NULL);
    wc_HpkeFreeKey(&client_ctx->hpke, cfg->kem_id, receiver, NULL);
    wc_FreeRng(&rng);
    return 0;
}

int odoh_target_decrypt_query(odoh_target_ctx *target,
    const uint8_t *in, uint16_t in_len,
    uint8_t *dns_out, uint16_t *dns_out_len,
    odoh_req_ctx *req_ctx)
{
    odoh_message_view msg;
    uint8_t aad[3 + ODOH_MAX_KEY_ID];
    uint16_t aad_len;
    uint16_t enc_len;
    const uint8_t *enc;
    const uint8_t *ct;
    uint16_t ct_len;
    uint8_t plain[ODOH_MAX_MESSAGE];

    if (!target || !target->loaded || !in || !dns_out || !dns_out_len || !req_ctx)
        return -1;

    memset(req_ctx, 0, sizeof(*req_ctx));
    memcpy(&req_ctx->cfg, &target->cfg, sizeof(target->cfg));
    if (hpke_init_for_cfg(&req_ctx->cfg, &req_ctx->hpke) != 0)
        return -1;

    if (odoh_parse_message(in, in_len, &msg) != 0)
        return -1;

    if (msg.message_type != ODOH_MSG_QUERY)
        return -1;

    if (msg.key_id_len != target->cfg.key_id_len ||
        memcmp(msg.key_id, target->cfg.key_id, msg.key_id_len) != 0)
        return -1;

    enc_len = (uint16_t)req_ctx->hpke.Npk;
    if (msg.encrypted_len <= enc_len)
        return -1;

    enc = msg.encrypted;
    ct = msg.encrypted + enc_len;
    ct_len = (uint16_t)(msg.encrypted_len - enc_len);

    if (wc_HpkeInitOpenContext(&req_ctx->hpke, &req_ctx->hpke_ctx,
            &target->priv, enc, enc_len,
            (byte *)ODOH_INFO_QUERY, (word32)strlen(ODOH_INFO_QUERY)) != 0)
        return -1;

    if (build_query_aad(target->cfg.key_id, target->cfg.key_id_len, aad, &aad_len) != 0)
        return -1;

    if (wc_HpkeContextOpenBase(&req_ctx->hpke, &req_ctx->hpke_ctx,
            aad, aad_len, (byte *)ct, ct_len, plain) != 0)
        return -1;

    if (parse_plaintext_dns(plain, (uint16_t)(ct_len - req_ctx->hpke.Nt), dns_out, dns_out_len) != 0)
        return -1;

    memcpy(req_ctx->q_plain, plain, (size_t)(ct_len - req_ctx->hpke.Nt));
    req_ctx->q_plain_len = (uint16_t)(ct_len - req_ctx->hpke.Nt);
    req_ctx->valid = 1;

    return 0;
}

int odoh_target_encrypt_response(const odoh_req_ctx *req_ctx,
    const uint8_t *dns_msg, uint16_t dns_len,
    uint8_t *out, uint16_t *out_len)
{
    uint8_t plain[ODOH_MAX_MESSAGE];
    uint16_t plain_len;
    uint8_t resp_nonce[64];
    uint16_t resp_nonce_len;
    uint8_t aad[3 + 64];
    uint16_t aad_len;
    uint8_t aead_key[32];
    uint8_t aead_nonce[16];
    uint8_t ct[ODOH_MAX_MESSAGE];
    Aes aes;
    int ret;
    WC_RNG rng;
    size_t off = 0;

    if (!req_ctx || !req_ctx->valid || !dns_msg || !out || !out_len)
        return -1;

    if (build_plaintext(dns_msg, dns_len, plain, &plain_len) != 0)
        return -1;

    resp_nonce_len = (uint16_t)((req_ctx->hpke.Nn > req_ctx->hpke.Nk) ? req_ctx->hpke.Nn : req_ctx->hpke.Nk);
    if (resp_nonce_len > sizeof(resp_nonce))
        return -1;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_RNG_GenerateBlock(&rng, resp_nonce, resp_nonce_len) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    wc_FreeRng(&rng);

    if (derive_response_key_nonce(&req_ctx->hpke, &req_ctx->hpke_ctx,
            req_ctx->q_plain, req_ctx->q_plain_len,
            resp_nonce, resp_nonce_len,
            aead_key, req_ctx->hpke.Nk,
            aead_nonce, req_ctx->hpke.Nn) != 0)
        return -1;

    if (build_response_aad(resp_nonce, resp_nonce_len, aad, &aad_len) != 0)
        return -1;

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, aead_key, req_ctx->hpke.Nk);
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, ct, plain, plain_len,
            aead_nonce, req_ctx->hpke.Nn,
            ct + plain_len, req_ctx->hpke.Nt,
            aad, aad_len);
    }
    wc_AesFree(&aes);
    if (ret != 0)
        return -1;

    if ((size_t)(1 + 2 + resp_nonce_len + 2 + plain_len + req_ctx->hpke.Nt) > ODOH_MAX_MESSAGE)
        return -1;

    out[off++] = ODOH_MSG_RESPONSE;
    put16(out + off, resp_nonce_len);
    off += 2;
    memcpy(out + off, resp_nonce, resp_nonce_len);
    off += resp_nonce_len;
    put16(out + off, (uint16_t)(plain_len + req_ctx->hpke.Nt));
    off += 2;
    memcpy(out + off, ct, plain_len + req_ctx->hpke.Nt);
    off += plain_len + req_ctx->hpke.Nt;

    *out_len = (uint16_t)off;
    return 0;
}

int odoh_client_decrypt_response(odoh_client_ctx *client_ctx,
    const uint8_t *in, uint16_t in_len,
    uint8_t *dns_out, uint16_t *dns_out_len)
{
    odoh_message_view msg;
    uint8_t aad[3 + 64];
    uint16_t aad_len;
    uint8_t aead_key[32];
    uint8_t aead_nonce[16];
    uint8_t plain[ODOH_MAX_MESSAGE];
    Aes aes;
    int ret;

    if (!client_ctx || !client_ctx->valid || !in || !dns_out || !dns_out_len)
        return -1;

    if (odoh_parse_message(in, in_len, &msg) != 0)
        return -1;

    if (msg.message_type != ODOH_MSG_RESPONSE)
        return -1;

    if (msg.key_id_len == 0 || msg.key_id_len > 64)
        return -1;

    if (msg.encrypted_len <= client_ctx->hpke.Nt)
        return -1;

    if (derive_response_key_nonce(&client_ctx->hpke, &client_ctx->hpke_ctx,
            client_ctx->q_plain, client_ctx->q_plain_len,
            msg.key_id, msg.key_id_len,
            aead_key, client_ctx->hpke.Nk,
            aead_nonce, client_ctx->hpke.Nn) != 0)
        return -1;

    if (build_response_aad(msg.key_id, msg.key_id_len, aad, &aad_len) != 0)
        return -1;

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, aead_key, client_ctx->hpke.Nk);
    if (ret == 0) {
        uint16_t pt_len = (uint16_t)(msg.encrypted_len - client_ctx->hpke.Nt);
        ret = wc_AesGcmDecrypt(&aes, plain,
            msg.encrypted, pt_len,
            aead_nonce, client_ctx->hpke.Nn,
            msg.encrypted + pt_len, client_ctx->hpke.Nt,
            aad, aad_len);
        if (ret == 0)
            ret = parse_plaintext_dns(plain, pt_len, dns_out, dns_out_len);
    }
    wc_AesFree(&aes);

    return ret == 0 ? 0 : -1;
}
