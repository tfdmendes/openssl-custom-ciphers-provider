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

    if (failed == 0) {
        printf("\nAll %zu PRINCE KAT tests passed successfully!\n", PRINCE_KAT_COUNT);
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failed);
        return 1;
    }
}
