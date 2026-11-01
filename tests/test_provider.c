/*
 * Tests of the provider through the public EVP API (the same path the openssl
 * CLI uses): streaming update/final behaviour, in-place operation, parameter
 * handling and context copies. Usage: test_provider <directory with customprov.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static int failed = 0;

#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failed = 1; } \
} while (0)

static const unsigned char KEY[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const unsigned char IV[8] = {9, 8, 7, 6, 5, 4, 3, 2};
static const char *ALGS[] = {"PRINCE-ECB", "PRINCE-CBC", "PRINCE-CTR", "RABBIT"};
static const int NUM_ALGS = 4;

/* Runs init + update (in pieces of `chunk` bytes, 0 = all at once) + final. Returns output length or -1. */
static int run(EVP_CIPHER *c, int enc, int pad, const unsigned char *in, size_t inl,
               size_t chunk, int in_place, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *buf = malloc(inl + 64);
    size_t pos = 0, total = 0;
    int n, ok = ctx != NULL && buf != NULL;

    ok = ok && EVP_CipherInit_ex2(ctx, c, KEY, IV, enc, NULL);
    ok = ok && EVP_CIPHER_CTX_set_padding(ctx, pad);
    while (ok && pos < inl) {
        size_t len = (chunk == 0 || chunk > inl - pos) ? inl - pos : chunk;
        if (in_place) {
            memcpy(buf + total, in + pos, len);
            ok = EVP_CipherUpdate(ctx, buf + total, &n, buf + total, (int)len);
        } else {
            ok = EVP_CipherUpdate(ctx, buf + total, &n, in + pos, (int)len);
        }
        total += (size_t)n;
        pos += len;
    }
    ok = ok && EVP_CipherFinal_ex(ctx, buf + total, &n);
    total += (size_t)n;
    if (ok)
        memcpy(out, buf, total);
    free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok ? (int)total : -1;
}

static void test_sizes_and_chunks(EVP_CIPHER *c, const char *name) {
    static const size_t sizes[] = {0, 1, 7, 8, 9, 16, 17, 40, 200};
    static const size_t chunks[] = {1, 3, 5, 9, 22};
    unsigned char plain[256], ref[300], got[300], dec[300];

    for (size_t i = 0; i < sizeof(plain); i++)
        plain[i] = (unsigned char)(i * 7 + 1);

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        int rl = run(c, 1, 1, plain, n, 0, 0, ref);
        int dl;

        if (rl < 0) { printf("FAIL %s: encrypt size %zu\n", name, n); failed = 1; continue; }
        dl = run(c, 0, 1, ref, (size_t)rl, 0, 0, dec);
        CHECK(dl == (int)n && memcmp(dec, plain, n) == 0);

        for (size_t k = 0; k < sizeof(chunks) / sizeof(chunks[0]); k++) {
            for (int in_place = 0; in_place < 2; in_place++) {
                int gl = run(c, 1, 1, plain, n, chunks[k], in_place, got);
                if (gl != rl || memcmp(got, ref, (size_t)rl) != 0) {
                    printf("FAIL %s: encrypt size %zu chunk %zu in_place %d\n", name, n, chunks[k], in_place);
                    failed = 1;
                }
                gl = run(c, 0, 1, ref, (size_t)rl, chunks[k], in_place, got);
                if (gl != (int)n || memcmp(got, plain, n) != 0) {
                    printf("FAIL %s: decrypt size %zu chunk %zu in_place %d\n", name, n, chunks[k], in_place);
                    failed = 1;
                }
            }
        }
    }
}

static void test_padding(EVP_CIPHER *c, const char *name) {
    unsigned char plain[32] = {0}, enc[64], out[64];
    int rl;

    /* Block ciphers with padding: 8 bytes -> 16 (a whole block of padding is added). */
    rl = run(c, 1, 1, plain, 8, 0, 0, enc);
    printf("     %s: 8 bytes with padding -> %d bytes\n", name, rl);

    /* Without padding: multiples of the block work, others must fail. */
    CHECK(run(c, 1, 0, plain, 16, 0, 0, enc) == 16);
    CHECK(run(c, 0, 0, enc, 16, 0, 0, out) == 16 && memcmp(out, plain, 16) == 0);
    if (EVP_CIPHER_get_block_size(c) > 1) {
        CHECK(run(c, 1, 0, plain, 15, 0, 0, enc) == -1);
        /* Corrupted padding: flip the last ciphertext byte. */
        rl = run(c, 1, 1, plain, 5, 0, 0, enc);
        enc[rl - 1] ^= 0xff;
        CHECK(run(c, 0, 1, enc, (size_t)rl, 0, 0, out) == -1);
        /* Ciphertext that is not a whole number of blocks. */
        CHECK(run(c, 0, 1, enc, 13, 0, 0, out) == -1);
    }
}

static void test_key_required(EVP_CIPHER *c, const char *name) {
    unsigned char plain[16] = {0}, ref[32], out[32], untouched[32];

    memset(untouched, 0xa5, sizeof(untouched));
    for (int enc = 0; enc < 2; enc++) {
        int rl = run(c, enc, 0, plain, sizeof(plain), 0, 0, ref);

        CHECK(rl == (int)sizeof(plain));
        for (int iv_first = 0; iv_first < 2; iv_first++) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX *copy = EVP_CIPHER_CTX_new();
            int n = -1, f = -1;

            CHECK(ctx != NULL && copy != NULL);
            if (ctx == NULL || copy == NULL) {
                EVP_CIPHER_CTX_free(ctx);
                EVP_CIPHER_CTX_free(copy);
                return;
            }
            CHECK(EVP_CipherInit_ex2(ctx, c, NULL, iv_first ? IV : NULL, enc, NULL));
            CHECK(EVP_CIPHER_CTX_set_padding(ctx, 0));
            CHECK(EVP_CIPHER_CTX_copy(copy, ctx));

            memcpy(out, untouched, sizeof(out));
            CHECK(EVP_CipherUpdate(ctx, out, &n, plain, sizeof(plain)) == 0);
            CHECK(n == 0 && memcmp(out, untouched, sizeof(out)) == 0);
            CHECK(EVP_CipherFinal_ex(copy, out, &f) == 0);
            CHECK(f == 0 && memcmp(out, untouched, sizeof(out)) == 0);

            CHECK(EVP_CipherInit_ex2(ctx, NULL, KEY, iv_first ? NULL : IV, enc, NULL));
            n = f = 0;
            CHECK(EVP_CipherUpdate(ctx, out, &n, plain, sizeof(plain)));
            CHECK(EVP_CipherFinal_ex(ctx, out + n, &f));
            CHECK(n + f == rl && memcmp(out, ref, sizeof(plain)) == 0);

            CHECK(EVP_CipherInit_ex2(ctx, NULL, NULL, IV, enc, NULL));
            n = f = 0;
            CHECK(EVP_CipherUpdate(ctx, out, &n, plain, sizeof(plain)));
            CHECK(EVP_CipherFinal_ex(ctx, out + n, &f));
            CHECK(n + f == rl && memcmp(out, ref, sizeof(plain)) == 0);

            EVP_CIPHER_CTX_free(ctx);
            EVP_CIPHER_CTX_free(copy);
        }
    }
    printf("     %s: key required, staged setup and key reuse preserved\n", name);
}

static void test_cbc_reinit(EVP_CIPHER *c) {
    unsigned char plain[32] = {0}, ciphertext[48], out[48];

    for (int pad = 0; pad < 2; pad++) {
        int clen = run(c, 1, pad, plain, sizeof(plain), 0, 0, ciphertext);

        CHECK(clen > 0);
        if (clen <= 0)
            return;
        for (int enc = 0; enc < 2; enc++) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            const unsigned char *input = enc ? plain : ciphertext;
            const unsigned char *expected = enc ? ciphertext : plain;
            int inl = enc ? (int)sizeof(plain) : clen;
            int expected_len = enc ? clen : (int)sizeof(plain);

            CHECK(ctx != NULL);
            if (ctx == NULL)
                return;
            CHECK(EVP_CipherInit_ex2(ctx, c, KEY, IV, enc, NULL));
            CHECK(EVP_CIPHER_CTX_set_padding(ctx, pad));
            for (int repeat = 0; repeat < 4; repeat++) {
                int n = 0, f = 0;

                if (repeat > 0)
                    CHECK(EVP_CipherInit_ex2(ctx, NULL, NULL, repeat == 2 ? IV : NULL, enc, NULL));
                CHECK(EVP_CipherUpdate(ctx, out, &n, input, inl));
                CHECK(EVP_CipherFinal_ex(ctx, out + n, &f));
                CHECK(n + f == expected_len && memcmp(out, expected, (size_t)expected_len) == 0);
            }
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    printf("     PRINCE-CBC: reinitialization restores the original IV\n");
}

static void test_wrong_key_sizes(EVP_CIPHER *c, const char *name) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    printf("     %s: wrong key sizes are rejected\n", name);
    CHECK(EVP_CIPHER_get_key_length(c) == 16);
    CHECK(EVP_CipherInit_ex2(ctx, c, KEY, IV, 1, NULL) == 1);
    /* The EVP layer takes the key length from the cipher, so ask for another one explicitly. */
    CHECK(EVP_CIPHER_CTX_set_key_length(ctx, 32) == 0);
    CHECK(EVP_CIPHER_CTX_set_key_length(ctx, 16) == 1);
    EVP_CIPHER_CTX_free(ctx);
}

static void test_wrong_iv_sizes(EVP_CIPHER *c, const char *name) {
    const OSSL_PROVIDER *prov = EVP_CIPHER_get0_provider(c);
    OSSL_FUNC_cipher_newctx_fn *newctx = NULL;
    OSSL_FUNC_cipher_freectx_fn *freectx = NULL;
    OSSL_FUNC_cipher_encrypt_init_fn *init[2] = {NULL, NULL};
    const size_t lengths[] = {0, sizeof(IV) - 1, sizeof(IV) + 1, sizeof(IV)};
    unsigned char iv[sizeof(IV) + 1] = {0};
    int no_cache = 0;

    if (EVP_CIPHER_get_iv_length(c) == 0)
        return;
    CHECK(EVP_CIPHER_get_iv_length(c) == (int)sizeof(IV));

    /* EVP takes only an IV pointer, so test explicit lengths through provider callbacks */
    const OSSL_ALGORITHM *algorithms = OSSL_PROVIDER_query_operation(prov, OSSL_OP_CIPHER, &no_cache);
    CHECK(algorithms != NULL);
    if (algorithms == NULL)
        return;
    for (const OSSL_ALGORITHM *a = algorithms; a->algorithm_names != NULL; a++) {
        if (strcmp(a->algorithm_names, name) != 0)
            continue;
        for (const OSSL_DISPATCH *f = a->implementation; f->function_id != 0; f++) {
            if (f->function_id == OSSL_FUNC_CIPHER_NEWCTX)
                newctx = OSSL_FUNC_cipher_newctx(f);
            else if (f->function_id == OSSL_FUNC_CIPHER_FREECTX)
                freectx = OSSL_FUNC_cipher_freectx(f);
            else if (f->function_id == OSSL_FUNC_CIPHER_ENCRYPT_INIT)
                init[0] = OSSL_FUNC_cipher_encrypt_init(f);
            else if (f->function_id == OSSL_FUNC_CIPHER_DECRYPT_INIT)
                init[1] = OSSL_FUNC_cipher_decrypt_init(f);
        }
        break;
    }
    CHECK(newctx != NULL && freectx != NULL && init[0] != NULL && init[1] != NULL);
    if (newctx != NULL && freectx != NULL && init[0] != NULL && init[1] != NULL) {
        for (int direction = 0; direction < 2; direction++) {
            for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
                void *ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(prov));

                CHECK(ctx != NULL);
                if (ctx != NULL) {
                    CHECK(init[direction](ctx, KEY, sizeof(KEY), iv, lengths[i], NULL)
                          == (lengths[i] == sizeof(IV)));
                    freectx(ctx);
                }
            }
        }
    }
    OSSL_PROVIDER_unquery_operation(prov, OSSL_OP_CIPHER, algorithms);
    printf("     %s: provider rejects invalid IV lengths and accepts 8 bytes\n", name);
}

/* Copying a context in the middle of a stream must continue identically. */
static void test_copy(EVP_CIPHER *c, const char *name) {
    unsigned char plain[100], full[128], tail[128];
    EVP_CIPHER_CTX *a = EVP_CIPHER_CTX_new(), *b = EVP_CIPHER_CTX_new();
    int n1, n2, f1, f2;

    for (size_t i = 0; i < sizeof(plain); i++)
        plain[i] = (unsigned char)i;
    CHECK(EVP_CipherInit_ex2(a, c, KEY, IV, 1, NULL));
    CHECK(EVP_CipherUpdate(a, full, &n1, plain, 37));
    CHECK(EVP_CIPHER_CTX_copy(b, a));
    CHECK(EVP_CipherUpdate(a, full + n1, &n2, plain + 37, 63));
    CHECK(EVP_CipherFinal_ex(a, full + n1 + n2, &f1));
    CHECK(EVP_CipherUpdate(b, tail, &n2, plain + 37, 63) && n2 >= 0);
    CHECK(EVP_CipherFinal_ex(b, tail + n2, &f2));
    CHECK(memcmp(full + n1, tail, (size_t)(n2 + f2)) == 0);
    CHECK(f1 == f2);
    EVP_CIPHER_CTX_free(a);
    EVP_CIPHER_CTX_free(b);
    printf("     %s: context copy continues identically\n", name);
}

int main(int argc, char **argv) {
    OSSL_PROVIDER *def, *prov;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <provider dir>\n", argv[0]);
        return 2;
    }
    OSSL_PROVIDER_set_default_search_path(NULL, argv[1]);
    def = OSSL_PROVIDER_load(NULL, "default");
    prov = OSSL_PROVIDER_load(NULL, "customprov");
    if (prov == NULL) {
        fprintf(stderr, "cannot load customprov from %s\n", argv[1]);
        return 2;
    }

    for (int i = 0; i < NUM_ALGS; i++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, ALGS[i], "provider=customprov");

        if (c == NULL) { printf("FAIL: cannot fetch %s\n", ALGS[i]); failed = 1; continue; }
        printf("%s (block %d, iv %d)\n", ALGS[i], EVP_CIPHER_get_block_size(c), EVP_CIPHER_get_iv_length(c));
        test_sizes_and_chunks(c, ALGS[i]);
        test_padding(c, ALGS[i]);
        test_wrong_key_sizes(c, ALGS[i]);
        test_wrong_iv_sizes(c, ALGS[i]);
        test_key_required(c, ALGS[i]);
        test_copy(c, ALGS[i]);
        if (strcmp(ALGS[i], "PRINCE-CBC") == 0)
            test_cbc_reinit(c);
        EVP_CIPHER_free(c);
    }

    OSSL_PROVIDER_unload(prov);
    OSSL_PROVIDER_unload(def);
    printf(failed ? "SOME PROVIDER TESTS FAILED\n" : "All provider tests passed successfully!\n");
    return failed;
}
