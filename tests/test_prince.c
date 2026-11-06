#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ciphers/prince.h"
#include "test_output.h"
#include "vectors/prince_kat.h"

int main(void) {
    int failed = 0;
    printf("Running PRINCE Standalone Known-Answer Tests (KAT)...\n\n");

    for (size_t i = 0; i < PRINCE_KAT_COUNT; i++) {
        const prince_kat_vector_t *v = &PRINCE_KAT_VECTORS[i];
        prince_ctx_t ctx;
        uint8_t ct[PRINCE_BLOCK_SIZE];
        uint8_t pt[PRINCE_BLOCK_SIZE];

        prince_set_key(&ctx, v->key);
        prince_encrypt_block(&ctx, v->pt, ct);

        test_output_case(2 * i + 1, "PRINCE encryption", v->key, sizeof(v->key),
                         NULL, 0, "Original Text", v->pt, sizeof(v->pt));
        if (!test_output_result(v->ct, sizeof(v->ct), ct, sizeof(ct))) {
            failed++;
            continue;
        }

        prince_decrypt_block(&ctx, ct, pt);
        test_output_case(2 * i + 2, "PRINCE decryption", v->key, sizeof(v->key),
                         NULL, 0, "Ciphertext", ct, sizeof(ct));
        if (!test_output_result(v->pt, sizeof(v->pt), pt, sizeof(pt))) {
            failed++;
            continue;
        }
    }

    // Multi-block functions must give the same result as the single-block ones
    {
        enum { MAXB = 70 };
        static uint8_t pt[MAXB * 8], ref[MAXB * 8], out[MAXB * 8], back[MAXB * 8];
        prince_ctx_t ctx;
        prince_set_key(&ctx, PRINCE_KAT_VECTORS[0].key);
        for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 73 + 5);

        for (int avx2 = 0; avx2 < 2; avx2++) {
            if (avx2 && !ctx.use_avx2) continue;
            prince_ctx_t c = ctx;
            c.use_avx2 = avx2;
            int ok = 1;
            for (size_t n = 0; n <= MAXB && ok; n++) {
                for (size_t b = 0; b < n; b++) prince_encrypt_block(&c, pt + 8 * b, ref + 8 * b);
                memcpy(out, pt, n * 8);
                prince_encrypt_blocks(&c, out, out, n);
                prince_decrypt_blocks(&c, out, back, n);
                if (memcmp(out, ref, n * 8) != 0 || memcmp(back, pt, n * 8) != 0) {
                    printf("[FAIL] Multi-block %s, %zu blocks\n", avx2 ? "AVX2" : "64-bit", n);
                    ok = 0;
                    failed++;
                }
            }
            if (ok)
                printf("[PASS] Multi-block %s.\n", avx2 ? "AVX2" : "64-bit");
        }
        if (!ctx.use_avx2)
            printf("[SKIP] Multi-block AVX2 (not supported).\n");
    }

    if (failed == 0) {
        printf("\nAll %zu PRINCE KAT tests passed successfully!\n", PRINCE_KAT_COUNT);
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failed);
        return 1;
    }
}
