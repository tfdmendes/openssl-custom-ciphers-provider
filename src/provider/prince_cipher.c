/**
 * @file prince_cipher.c
 * @brief PRINCE block cipher exposed to OpenSSL (ECB, CBC, CTR, OFB, CFB)
 *
 * This file is only the OpenSSL glue: the cipher itself lives in
 * src/ciphers/prince.c and the modes in src/modes/.
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

#include "provider/prince_cipher.h"
#include "ciphers/prince.h"
#include "modes/modes.h"
#include "modes/padding.h"

/** Chaining mode of one PRINCE algorithm. */
typedef enum {
    PRINCE_MODE_ECB,
    PRINCE_MODE_CBC,
    PRINCE_MODE_CTR,
    PRINCE_MODE_OFB,
    PRINCE_MODE_CFB
} prince_mode_t;

/**
 * @brief Working state of one encrypt/decrypt operation ("the work sheet").
 *
 * OpenSSL creates one per operation (newctx) and hands it back on every call.
 */
typedef struct {
    prince_mode_t mode;
    int encrypt;                         /**< 1 = encrypting, 0 = decrypting. */
    int padding;                         /**< 1 = PKCS#7 padding enabled (ECB/CBC). */
    prince_ctx_t key;                    /**< Expanded key (k0, k0', k1). */
    int key_set;
    uint8_t iv[PRINCE_BLOCK_SIZE];
    uint8_t original_iv[PRINCE_BLOCK_SIZE];
    int iv_set;
    uint8_t buf[PRINCE_BLOCK_SIZE];      /**< ECB/CBC: bytes waiting to fill a block. */
    size_t buf_len;                      /**< How many bytes of buf are in use. */
    uint8_t ecount[PRINCE_BLOCK_SIZE];
    unsigned int num;
} prince_cipher_ctx_t;

static int prince_is_stream(prince_mode_t mode) {
    return mode == PRINCE_MODE_CTR || mode == PRINCE_MODE_OFB || mode == PRINCE_MODE_CFB;
}

static int prince_restores_iv(prince_mode_t mode) {
    return mode == PRINCE_MODE_CBC || mode == PRINCE_MODE_OFB || mode == PRINCE_MODE_CFB;
}

/** Creates a work sheet for the given mode, padding on by default (as in AES). */
static void *prince_newctx_mode(prince_mode_t mode) {
    prince_cipher_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->mode = mode;
    ctx->padding = !prince_is_stream(mode);
    return ctx;
}

/* newctx receives no "mode" argument, hence one tiny wrapper per mode. */
static void *prince_ecb_newctx(void *provctx) { (void)provctx; return prince_newctx_mode(PRINCE_MODE_ECB); }
static void *prince_cbc_newctx(void *provctx) { (void)provctx; return prince_newctx_mode(PRINCE_MODE_CBC); }
static void *prince_ctr_newctx(void *provctx) { (void)provctx; return prince_newctx_mode(PRINCE_MODE_CTR); }
static void *prince_ofb_newctx(void *provctx) { (void)provctx; return prince_newctx_mode(PRINCE_MODE_OFB); }
static void *prince_cfb_newctx(void *provctx) { (void)provctx; return prince_newctx_mode(PRINCE_MODE_CFB); }

/** Destroys a work sheet. Wipes it first because it holds the key. */
static void prince_freectx(void *vctx) {
    OPENSSL_clear_free(vctx, sizeof(prince_cipher_ctx_t));
}

/**
 * @brief Prepares the work sheet for a new operation (shared by encrypt/decrypt init).
 *
 * A NULL key keeps the existing key. A NULL IV restores the original CBC/OFB/CFB IV
 * when available and keeps the current IV in other modes
 *
 * @return 1 on success, 0 if key or IV have the wrong size.
 */
static int prince_init(prince_cipher_ctx_t *ctx, int encrypt,
                       const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen) {
    ctx->encrypt = encrypt;

    /* A new operation starts with nothing pending. */
    ctx->buf_len = 0;
    ctx->num = 0;

    if (key != NULL) {
        if (keylen != PRINCE_KEY_SIZE)
            return 0;
        prince_set_key(&ctx->key, key);
        ctx->key_set = 1;
    }

    /* Every mode except ECB uses an 8-byte IV */
    if (iv != NULL && ctx->mode != PRINCE_MODE_ECB) {
        if (ivlen != PRINCE_BLOCK_SIZE)
            return 0;
        memcpy(ctx->iv, iv, PRINCE_BLOCK_SIZE);
        if (prince_restores_iv(ctx->mode)) {
            memcpy(ctx->original_iv, iv, PRINCE_BLOCK_SIZE);
            ctx->iv_set = 1;
        }
    } else if (prince_restores_iv(ctx->mode) && ctx->iv_set) {
        memcpy(ctx->iv, ctx->original_iv, PRINCE_BLOCK_SIZE);
    }
    return 1;
}

/* ---- Parameters: how OpenSSL asks and tells us things ---- */

/** Fills the answers common to get_params (per algorithm) and get_ctx_params. */
static int prince_fill_common(OSSL_PARAM params[], prince_mode_t mode) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, PRINCE_KEY_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, mode == PRINCE_MODE_ECB ? 0 : PRINCE_BLOCK_SIZE))
        return 0;
    return 1;
}

/** Algorithm-level facts (no work sheet involved): mode, block size, key/IV sizes. */
static int prince_get_params_mode(OSSL_PARAM params[], prince_mode_t mode) {
    static const unsigned int evp_mode[] = {
        EVP_CIPH_ECB_MODE, EVP_CIPH_CBC_MODE, EVP_CIPH_CTR_MODE,
        EVP_CIPH_OFB_MODE, EVP_CIPH_CFB_MODE
    };
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, evp_mode[mode]))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    /* Stream modes return one output byte for each input byte */
    if (p != NULL && !OSSL_PARAM_set_size_t(p, prince_is_stream(mode) ? 1 : PRINCE_BLOCK_SIZE))
        return 0;
    return prince_fill_common(params, mode);
}

static int prince_ecb_get_params(OSSL_PARAM params[]) { return prince_get_params_mode(params, PRINCE_MODE_ECB); }
static int prince_cbc_get_params(OSSL_PARAM params[]) { return prince_get_params_mode(params, PRINCE_MODE_CBC); }
static int prince_ctr_get_params(OSSL_PARAM params[]) { return prince_get_params_mode(params, PRINCE_MODE_CTR); }
static int prince_ofb_get_params(OSSL_PARAM params[]) { return prince_get_params_mode(params, PRINCE_MODE_OFB); }
static int prince_cfb_get_params(OSSL_PARAM params[]) { return prince_get_params_mode(params, PRINCE_MODE_CFB); }

static const OSSL_PARAM prince_gettable_params_table[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prince_gettable_params(void *provctx) {
    (void)provctx;
    return prince_gettable_params_table;
}

/** Facts about one running operation: sizes and whether padding is on. */
static int prince_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    const prince_cipher_ctx_t *ctx = vctx;
    OSSL_PARAM *p;

    if (!prince_fill_common(params, ctx->mode))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, (unsigned int)ctx->padding))
        return 0;
    return 1;
}

static const OSSL_PARAM prince_gettable_ctx_params_table[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prince_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return prince_gettable_ctx_params_table;
}

/**
 * @brief Applies settings from OpenSSL: padding on/off (what -nopad does) and
 *        key length (accepted only if it is the one PRINCE supports).
 */
static int prince_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    prince_cipher_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;
    unsigned int pad;
    size_t keylen;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        ctx->padding = (!prince_is_stream(ctx->mode) && pad != 0);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &keylen) || keylen != PRINCE_KEY_SIZE)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM prince_settable_ctx_params_table[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prince_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return prince_settable_ctx_params_table;
}

static int prince_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[]) {
    return prince_init(vctx, 1, key, keylen, iv, ivlen)
           && prince_set_ctx_params(vctx, params);
}

static int prince_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[]) {
    return prince_init(vctx, 0, key, keylen, iv, ivlen)
           && prince_set_ctx_params(vctx, params);
}

/* Adapters: block_cipher_fn takes a const void *, the PRINCE functions a typed key. */
static void prince_enc_block(const void *key, const uint8_t *in, uint8_t *out) {
    prince_encrypt_block(key, in, out);
}

static void prince_dec_block(const void *key, const uint8_t *in, uint8_t *out) {
    prince_decrypt_block(key, in, out);
}

/** Runs ECB or CBC over whole blocks. len must be a multiple of the block size. */
static void prince_crypt_blocks(prince_cipher_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    block_cipher_fn fn = ctx->encrypt ? prince_enc_block : prince_dec_block;

    if (ctx->mode == PRINCE_MODE_ECB)
        mode_ecb_crypt(&ctx->key, fn, PRINCE_BLOCK_SIZE, in, out, len);
    else if (ctx->encrypt)
        mode_cbc_encrypt(&ctx->key, fn, PRINCE_BLOCK_SIZE, ctx->iv, in, out, len, ctx->iv);
    else
        mode_cbc_decrypt(&ctx->key, fn, PRINCE_BLOCK_SIZE, ctx->iv, in, out, len, ctx->iv);
}

/**
 * @brief update for ECB/CBC: joins pending bytes with the new input, processes
 *        the whole blocks and keeps the remainder in ctx->buf.
 *
 * When decrypting with padding, the last full block is always kept back: only
 * final() may decrypt it, validate the padding and strip it.
 */
static int prince_update_blocks(prince_cipher_ctx_t *ctx, unsigned char *out, size_t *outl,
                                size_t outsize, const unsigned char *in, size_t inl) {
    const size_t total = ctx->buf_len + inl;
    const int hold_back = !ctx->encrypt && ctx->padding;
    uint8_t tail[PRINCE_BLOCK_SIZE];
    size_t keep = total % PRINCE_BLOCK_SIZE;
    size_t n;

    if (hold_back && keep == 0 && total > 0)
        keep = PRINCE_BLOCK_SIZE;
    n = total - keep;                       /* bytes we can output now */

    if (n > outsize)
        return 0;

    if (n == 0) {                           /* not even one block yet: just store */
        if (inl > 0)
            memcpy(ctx->buf + ctx->buf_len, in, inl);
        ctx->buf_len = total;
        *outl = 0;
        return 1;
    }

    /*
     * Save the remainder first, then lay the data out in out[] as
     * [pending bytes][input] and transform it in place. memmove (not memcpy)
     * because in and out may be the same buffer.
     */
    memcpy(tail, in + inl - keep, keep);
    memmove(out + ctx->buf_len, in, n - ctx->buf_len);
    memcpy(out, ctx->buf, ctx->buf_len);
    prince_crypt_blocks(ctx, out, out, n);

    memcpy(ctx->buf, tail, keep);
    ctx->buf_len = keep;
    *outl = n;
    return 1;
}

static int prince_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl) {
    prince_cipher_ctx_t *ctx = vctx;

    *outl = 0;
    if (!ctx->key_set)
        return 0;

    if (!prince_is_stream(ctx->mode))
        return prince_update_blocks(ctx, out, outl, outsize, in, inl);

    if (inl > outsize)
        return 0;
    if (inl > 0) {
        if (ctx->mode == PRINCE_MODE_CTR)
            mode_ctr_crypt(&ctx->key, prince_enc_block, PRINCE_BLOCK_SIZE,
                           ctx->iv, ctx->ecount, &ctx->num, in, out, inl);
        else if (ctx->mode == PRINCE_MODE_OFB)
            mode_ofb_crypt(&ctx->key, prince_enc_block, PRINCE_BLOCK_SIZE,
                           ctx->iv, ctx->ecount, &ctx->num, in, out, inl);
        else if (ctx->encrypt)
            mode_cfb_encrypt(&ctx->key, prince_enc_block, PRINCE_BLOCK_SIZE,
                             ctx->iv, ctx->ecount, &ctx->num, in, out, inl);
        else
            mode_cfb_decrypt(&ctx->key, prince_enc_block, PRINCE_BLOCK_SIZE,
                             ctx->iv, ctx->ecount, &ctx->num, in, out, inl);
    }
    *outl = inl;
    return 1;
}

/**
 * @brief Closes the operation: handles whatever update() left in ctx->buf.
 *
 * - CTR/OFB/CFB: nothing to do
 * - Encrypt + padding: pads the pending bytes to one block (a full padding
 *   block if none are pending) and encrypts it.
 * - Decrypt + padding: decrypts the block update() held back, validates the
 *   PKCS#7 padding and outputs only the real data (0 to 7 bytes).
 * - No padding: pending bytes cannot form a block, so it is an error.
 *
 * @return 1 on success, 0 on error (bad padding, partial block, output too small).
 */
static int prince_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    prince_cipher_ctx_t *ctx = vctx;
    uint8_t block[PRINCE_BLOCK_SIZE];
    size_t len;

    *outl = 0;
    if (!ctx->key_set)
        return 0;
    if (prince_is_stream(ctx->mode))
        return 1;

    if (!ctx->padding)
        return ctx->buf_len == 0;

    if (ctx->encrypt) {
        if (outsize < PRINCE_BLOCK_SIZE)
            return 0;
        pkcs7_pad(ctx->buf, ctx->buf_len, PRINCE_BLOCK_SIZE, block, &len);
        prince_crypt_blocks(ctx, block, out, len);
        *outl = len;
    } else {
        if (ctx->buf_len != PRINCE_BLOCK_SIZE)
            return 0;
        prince_crypt_blocks(ctx, ctx->buf, block, PRINCE_BLOCK_SIZE);
        if (pkcs7_unpad(block, PRINCE_BLOCK_SIZE, PRINCE_BLOCK_SIZE, &len) != 0 || len > outsize)
            return 0;
        memcpy(out, block, len);
        *outl = len;
    }
    ctx->buf_len = 0;
    return 1;
}

/** Photocopies a work sheet (OpenSSL does this to duplicate an operation mid-way). */
static void *prince_dupctx(void *vctx) {
    const prince_cipher_ctx_t *src = vctx;

    return src == NULL ? NULL : OPENSSL_memdup(src, sizeof(*src));
}

/* ---- Registration: the menu of functions per algorithm ---- */

/* One table per mode (exported, see prince_cipher.h); only newctx and get_params differ. */
#define PRINCE_DISPATCH_TABLE(name) \
    const OSSL_DISPATCH name##_functions[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX,             (void (*)(void))name##_newctx }, \
        { OSSL_FUNC_CIPHER_FREECTX,            (void (*)(void))prince_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX,             (void (*)(void))prince_dupctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,       (void (*)(void))prince_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,       (void (*)(void))prince_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE,             (void (*)(void))prince_update }, \
        { OSSL_FUNC_CIPHER_FINAL,              (void (*)(void))prince_final }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS,         (void (*)(void))name##_get_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,    (void (*)(void))prince_gettable_params }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,     (void (*)(void))prince_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))prince_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,     (void (*)(void))prince_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))prince_settable_ctx_params }, \
        { 0, NULL } \
    }

PRINCE_DISPATCH_TABLE(prince_ecb);
PRINCE_DISPATCH_TABLE(prince_cbc);
PRINCE_DISPATCH_TABLE(prince_ctr);
PRINCE_DISPATCH_TABLE(prince_ofb);
PRINCE_DISPATCH_TABLE(prince_cfb);
