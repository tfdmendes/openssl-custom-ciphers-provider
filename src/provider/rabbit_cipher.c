/**
 * @file rabbit_cipher.c
 * @brief Rabbit stream cipher exposed to OpenSSL as a provider cipher.
 *
 * This file is only the OpenSSL glue: the cipher itself lives in
 * src/ciphers/rabbit.c. Rabbit is a stream cipher: no blocks, no padding, and
 * encrypting and decrypting are the same XOR with the keystream.
 *
 * References:
 *  - https://docs.openssl.org/3.0/man7/provider-cipher/
 */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "provider/rabbit_cipher.h"
#include "ciphers/rabbit.h"

/** Working state of one operation ("the work sheet"), one per newctx. */
typedef struct {
    rabbit_ctx_t rabbit;                 /**< Key, IV and keystream state. */
    uint8_t iv[RABBIT_IV_SIZE];          /**< Last IV given, re-applied if the key is set after it. */
    int have_iv;                         /**< 1 once an IV was given. */
} rabbit_cipher_ctx_t;

static void *rabbit_newctx(void *provctx) {
    (void)provctx;
    return OPENSSL_zalloc(sizeof(rabbit_cipher_ctx_t));
}

/** Destroys a work sheet. Wipes it first because it holds the key. */
static void rabbit_freectx(void *vctx) {
    OPENSSL_clear_free(vctx, sizeof(rabbit_cipher_ctx_t));
}

/** Photocopies a work sheet (OpenSSL does this to duplicate an operation mid-way). */
static void *rabbit_dupctx(void *vctx) {
    const rabbit_cipher_ctx_t *src = vctx;

    return src == NULL ? NULL : OPENSSL_memdup(src, sizeof(*src));
}

/* ---- Parameters ---- */

static int rabbit_fill_common(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, RABBIT_KEY_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, RABBIT_IV_SIZE))
        return 0;
    return 1;
}

/** Algorithm-level facts: stream mode, block size 1 (output size equals input size). */
static int rabbit_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_STREAM_CIPHER))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    return rabbit_fill_common(params);
}

static const OSSL_PARAM rabbit_gettable_params_table[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rabbit_gettable_params(void *provctx) {
    (void)provctx;
    return rabbit_gettable_params_table;
}

static int rabbit_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    (void)vctx;
    return rabbit_fill_common(params);
}

static const OSSL_PARAM rabbit_gettable_ctx_params_table[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rabbit_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return rabbit_gettable_ctx_params_table;
}

/** Only the key length can be "set", and only to the one Rabbit supports. */
static int rabbit_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;
    size_t keylen;

    (void)vctx;
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &keylen) || keylen != RABBIT_KEY_SIZE))
        return 0;
    return 1;
}

static const OSSL_PARAM rabbit_settable_ctx_params_table[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *rabbit_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return rabbit_settable_ctx_params_table;
}

/* ---- Operation ---- */

/**
 * @brief Key and IV setup (shared by encrypt/decrypt init, which are identical here).
 *
 * Either may be NULL, meaning "leave that one as it is". A new key restarts
 * the stream, so a previously given IV is applied again on top of it.
 *
 * @return 1 on success, 0 if key or IV have the wrong size.
 */
static int rabbit_init(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[]) {
    rabbit_cipher_ctx_t *ctx = vctx;

    if (key != NULL) {
        if (keylen != RABBIT_KEY_SIZE)
            return 0;
        rabbit_set_key(&ctx->rabbit, key);
        if (ctx->have_iv)
            rabbit_set_iv(&ctx->rabbit, ctx->iv);
    }
    if (iv != NULL) {
        if (ivlen != RABBIT_IV_SIZE)
            return 0;
        memcpy(ctx->iv, iv, RABBIT_IV_SIZE);
        ctx->have_iv = 1;
        rabbit_set_iv(&ctx->rabbit, iv);
    }
    return rabbit_set_ctx_params(vctx, params);
}

/* Distinct entry points because the API has two, even though the work is the same. */
static int rabbit_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[]) {
    return rabbit_init(vctx, key, keylen, iv, ivlen, params);
}

static int rabbit_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[]) {
    return rabbit_init(vctx, key, keylen, iv, ivlen, params);
}

/** XORs the keystream into the data: any length, output size equals input size. */
static int rabbit_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl) {
    rabbit_cipher_ctx_t *ctx = vctx;

    if (inl > outsize)
        return 0;
    if (inl > 0)
        rabbit_crypt(&ctx->rabbit, in, out, inl);
    *outl = inl;
    return 1;
}

/** A stream cipher has nothing left to flush. */
static int rabbit_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    (void)vctx;
    (void)out;
    (void)outsize;
    *outl = 0;
    return 1;
}

const OSSL_DISPATCH rabbit_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))rabbit_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))rabbit_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))rabbit_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))rabbit_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))rabbit_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))rabbit_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))rabbit_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))rabbit_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))rabbit_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))rabbit_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))rabbit_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))rabbit_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))rabbit_settable_ctx_params },
    { 0, NULL }
};
