/**
 * @file provider.c
 * @brief Entry point of the custom OpenSSL 3 provider.
 *
 * OpenSSL loads this shared library and calls OSSL_provider_init(). From there
 * the provider tells OpenSSL who it is (name, version) and which algorithms it
 * offers (PRINCE in five modes, and Rabbit)
 *
 * References:
 *  - https://docs.openssl.org/3.0/man7/provider-base/
 */

#include <stdlib.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "provider/prince_cipher.h"
#include "provider/rabbit_cipher.h"

#define PROV_NAME      "Custom Ciphers Provider"
#define PROV_VERSION   "0.1.0"
#define PROV_BUILDINFO "PRINCE + Rabbit (work in progress)"

/**
 * @brief Provider-wide private data, handed back to us on every call.
 *
 * OpenSSL never looks inside it; it only stores the pointer for us.
 */
typedef struct {
    const OSSL_CORE_HANDLE *handle;
} prov_ctx_t;

/**
 * @brief Parameters that OpenSSL may ask about ("who are you?").
 */
static const OSSL_PARAM prov_gettable_params_table[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prov_gettable_params(void *provctx) {
    (void)provctx;
    return prov_gettable_params_table;
}

/**
 * @brief Fills in the answers OpenSSL asked for.
 *
 * OpenSSL passes a list of "empty forms"; we fill the ones we know.
 */
static int prov_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_NAME))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PROV_BUILDINFO))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* 1 = running */
        return 0;

    return 1;
}

#define PROV_PROPERTIES "provider=customprov"

/** Every cipher we offer: name, properties, function table, description. */
static const OSSL_ALGORITHM prov_ciphers[] = {
    { "PRINCE-ECB", PROV_PROPERTIES, prince_ecb_functions, "PRINCE block cipher, ECB mode" },
    { "PRINCE-CBC", PROV_PROPERTIES, prince_cbc_functions, "PRINCE block cipher, CBC mode" },
    { "PRINCE-CTR", PROV_PROPERTIES, prince_ctr_functions, "PRINCE block cipher, CTR mode" },
    { "PRINCE-OFB", PROV_PROPERTIES, prince_ofb_functions, "PRINCE block cipher, OFB mode" },
    { "PRINCE-CFB", PROV_PROPERTIES, prince_cfb_functions, "PRINCE block cipher, CFB mode (64-bit feedback)" },
    { "RABBIT",     PROV_PROPERTIES, rabbit_functions,     "Rabbit stream cipher (RFC 4503)" },
    { NULL, NULL, NULL, NULL }
};

/**
 * @brief "Which algorithms do you have for this kind of operation?"
 *
 * For OSSL_OP_CIPHER, returns our cipher list; for anything else, NULL.
 */
static const OSSL_ALGORITHM *prov_query_operation(void *provctx, int operation_id, int *no_store) {
    (void)provctx;
    *no_store = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return prov_ciphers;
    return NULL;
}

/**
 * @brief Called when OpenSSL unloads the provider. Frees what init allocated.
 */
static void prov_teardown(void *provctx) {
    free(provctx);
}

/**
 * @brief The "menu" of functions this provider hands to OpenSSL.
 */
static const OSSL_DISPATCH prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query_operation },
    { 0, NULL }
};

/**
 * @brief The only symbol OpenSSL looks for when loading the library.
 *
 * @param[in]  handle  Identifies this provider to OpenSSL.
 * @param[in]  in      Functions OpenSSL offers us (unused for now).
 * @param[out] out     Our menu of functions (prov_dispatch_table).
 * @param[out] provctx Our private data, passed back on every call.
 * @return 1 on success, 0 on failure.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) {
    prov_ctx_t *ctx;
    (void)in;

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    *provctx = ctx;
    *out = prov_dispatch_table;
    return 1;
}
