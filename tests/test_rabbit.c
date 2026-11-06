#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ciphers/rabbit.h"
#include "test_output.h"
#include "vectors/rabbit_kat.h"

#define KAT_STREAM_LEN (3 * RABBIT_BLOCK_SIZE)

static int failed = 0;

// The RFC vectors are big-endian, our implementation is little-endian
static void reverse_bytes(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[len - 1 - i];
    }
}

static void kat_setup(rabbit_ctx_t *ctx, const rabbit_kat_vector_t *v) {
    uint8_t key[RABBIT_KEY_SIZE];
    uint8_t iv[RABBIT_IV_SIZE];

    reverse_bytes(key, v->key, RABBIT_KEY_SIZE);
    rabbit_set_key(ctx, key);
    if (v->has_iv) {
        reverse_bytes(iv, v->iv, RABBIT_IV_SIZE);
        rabbit_set_iv(ctx, iv);
    }
}

static void kat_expected(const rabbit_kat_vector_t *v, uint8_t expected[KAT_STREAM_LEN]) {
    for (size_t b = 0; b < 3; b++) {
        reverse_bytes(expected + b * RABBIT_BLOCK_SIZE, v->s[b], RABBIT_BLOCK_SIZE);
    }
}

static void test_kat(void) {
    printf("[1/5] Testing RFC 4503 Appendix A keystream KATs...\n");

    for (size_t i = 0; i < RABBIT_KAT_COUNT; i++) {
        const rabbit_kat_vector_t *v = &RABBIT_KAT_VECTORS[i];
        rabbit_ctx_t ctx;
        uint8_t zeros[KAT_STREAM_LEN] = {0};
        uint8_t expected[KAT_STREAM_LEN];
        uint8_t ks[KAT_STREAM_LEN];
        uint8_t ks_bytewise[KAT_STREAM_LEN];
        uint8_t key[RABBIT_KEY_SIZE];
        uint8_t iv[RABBIT_IV_SIZE];

        kat_expected(v, expected);
        reverse_bytes(key, v->key, sizeof(key));
        if (v->has_iv) reverse_bytes(iv, v->iv, sizeof(iv));

        // Encrypting zeros gives the keystream
        kat_setup(&ctx, v);
        rabbit_crypt(&ctx, zeros, ks, KAT_STREAM_LEN);

        // Same thing one byte at a time, to test the keystream buffer
        kat_setup(&ctx, v);
        for (size_t j = 0; j < KAT_STREAM_LEN; j++) {
            rabbit_crypt(&ctx, zeros + j, ks_bytewise + j, 1);
        }

        test_output_case(2 * i + 1, "Rabbit encryption", key, sizeof(key),
                         v->has_iv ? iv : NULL, sizeof(iv), "Original Text", zeros, sizeof(zeros));
        int matches = test_output_result(expected, sizeof(expected), ks, sizeof(ks));
        test_output_case(2 * i + 2, "Rabbit encryption, one-byte updates", key, sizeof(key),
                         v->has_iv ? iv : NULL, sizeof(iv), "Original Text", zeros, sizeof(zeros));
        int bytewise_matches = test_output_result(expected, sizeof(expected), ks_bytewise, sizeof(ks_bytewise));
        if (!matches || !bytewise_matches) failed++;
        rabbit_cleanup(&ctx);
    }
}

static int state_matches(const rabbit_state_t *s, const uint32_t x[8], const uint32_t c[8], uint32_t carry) {
    return memcmp(s->x, x, sizeof(s->x)) == 0 &&
           memcmp(s->c, c, sizeof(s->c)) == 0 &&
           s->carry == carry;
}

static void test_inner_state(void) {
    printf("[2/5] Testing RFC 4503 Appendix B inner state...\n");

    rabbit_ctx_t ctx;
    uint8_t key[RABBIT_KEY_SIZE];
    uint8_t iv[RABBIT_IV_SIZE];

    reverse_bytes(key, RABBIT_DEBUG_KEY, RABBIT_KEY_SIZE);
    reverse_bytes(iv, RABBIT_DEBUG_IV, RABBIT_IV_SIZE);

    rabbit_set_key(&ctx, key);
    if (!state_matches(&ctx.master, RABBIT_DEBUG_MASTER_X, RABBIT_DEBUG_MASTER_C, 0)) {
        printf("      [FAIL] Master state after key setup (B.1) mismatch!\n");
        failed++;
    } else {
        printf("      [PASS] Master state after key setup (B.1)\n");
    }

    rabbit_set_iv(&ctx, iv);
    if (!state_matches(&ctx.work, RABBIT_DEBUG_IV_X, RABBIT_DEBUG_IV_C, 1)) {
        printf("      [FAIL] State after IV setup (B.2) mismatch!\n");
        failed++;
    } else {
        printf("      [PASS] State after IV setup (B.2)\n");
    }

    rabbit_cleanup(&ctx);
}

static void test_iv_reuse_master(void) {
    printf("[3/5] Testing IV re-initialization from the master state...\n");

    // All the A.2 vectors use the same key, so set it once and only change the IV
    rabbit_ctx_t ctx;
    uint8_t key[RABBIT_KEY_SIZE];
    uint8_t iv[RABBIT_IV_SIZE];
    uint8_t zeros[KAT_STREAM_LEN] = {0};
    uint8_t expected[KAT_STREAM_LEN];
    uint8_t ks[KAT_STREAM_LEN];
    int key_set = 0;
    int ok = 1;

    for (size_t i = 0; i < RABBIT_KAT_COUNT; i++) {
        const rabbit_kat_vector_t *v = &RABBIT_KAT_VECTORS[i];
        if (!v->has_iv) continue;

        if (!key_set) {
            reverse_bytes(key, v->key, RABBIT_KEY_SIZE);
            rabbit_set_key(&ctx, key);
            key_set = 1;
        }

        // Twice, to check the same IV gives the same stream again
        for (int run = 0; run < 2; run++) {
            reverse_bytes(iv, v->iv, RABBIT_IV_SIZE);
            rabbit_set_iv(&ctx, iv);
            rabbit_crypt(&ctx, zeros, ks, 7);  // leaves unused bytes in the buffer
            rabbit_set_iv(&ctx, iv);
            rabbit_crypt(&ctx, zeros, ks, KAT_STREAM_LEN);

            kat_expected(v, expected);
            if (memcmp(ks, expected, KAT_STREAM_LEN) != 0) ok = 0;
        }
    }

    if (!ok) {
        printf("      [FAIL] Re-running the IV setup did not restart the stream!\n");
        failed++;
    } else {
        printf("      [PASS] IV setup restarts the stream correctly\n");
    }
    rabbit_cleanup(&ctx);
}

static void test_sizes(void) {
    printf("[4/5] Testing round-trip and chunked processing for several sizes...\n");

    static const size_t sizes[] = {0, 1, 15, 16, 17, 31, 32, 33, 1000, 1024 * 1024 + 3};
    static const size_t chunks[] = {1, 7, 16, 17, 3, 100, 5};
    const uint8_t key[RABBIT_KEY_SIZE] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t iv[RABBIT_IV_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t len = sizes[s];
        uint8_t *pt = malloc(len + 1);
        uint8_t *ct = malloc(len + 1);
        uint8_t *ct_chunked = malloc(len + 1);
        uint8_t *dec = malloc(len + 1);
        rabbit_ctx_t ctx;
        int ok = 1;

        if (!pt || !ct || !ct_chunked || !dec) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }

        for (size_t i = 0; i < len; i++) pt[i] = (uint8_t)(i * 31 + 7);

        // One-shot encryption
        rabbit_set_key(&ctx, key);
        rabbit_set_iv(&ctx, iv);
        rabbit_crypt(&ctx, pt, ct, len);

        // Chunked encryption with irregular chunk sizes
        rabbit_set_iv(&ctx, iv);
        for (size_t off = 0, c = 0; off < len; c++) {
            size_t n = chunks[c % (sizeof(chunks) / sizeof(chunks[0]))];
            if (n > len - off) n = len - off;
            rabbit_crypt(&ctx, pt + off, ct_chunked + off, n);
            off += n;
        }
        if (memcmp(ct, ct_chunked, len) != 0) ok = 0;

        // In-place decryption
        memcpy(dec, ct, len);
        rabbit_set_iv(&ctx, iv);
        rabbit_crypt(&ctx, dec, dec, len);
        if (memcmp(dec, pt, len) != 0) ok = 0;

        // Make sure it actually encrypted something
        if (len >= 16 && memcmp(ct, pt, len) == 0) ok = 0;

        if (!ok) {
            printf("      [FAIL] %zu bytes\n", len);
            failed++;
        } else {
            printf("      [PASS] %zu bytes\n", len);
        }

        rabbit_cleanup(&ctx);
        free(pt);
        free(ct);
        free(ct_chunked);
        free(dec);
    }
}

static void test_cleanup(void) {
    printf("[5/5] Testing context cleanup...\n");

    rabbit_ctx_t ctx;
    const uint8_t key[RABBIT_KEY_SIZE] = {0x42};
    rabbit_set_key(&ctx, key);
    rabbit_cleanup(&ctx);

    const uint8_t *p = (const uint8_t *)&ctx;
    for (size_t i = 0; i < sizeof(ctx); i++) {
        if (p[i] != 0) {
            printf("      [FAIL] Context not wiped\n");
            failed++;
            return;
        }
    }
    printf("      [PASS] Context wiped\n");
}

int main(void) {
    printf("Running Rabbit Standalone Tests...\n\n");

    test_kat();
    test_inner_state();
    test_iv_reuse_master();
    test_sizes();
    test_cleanup();

    if (failed == 0) {
        printf("\nAll Rabbit tests passed successfully!\n");
        return 0;
    }
    printf("\n%d test(s) failed.\n", failed);
    return 1;
}
