#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ciphers/prince.h"
#include "vectors/prince_kat.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

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

        if (memcmp(ct, v->ct, PRINCE_BLOCK_SIZE) != 0) {
            printf("[FAIL] Vector %zu Encryption Mismatch!\n", i+1);
            print_hex("   Expected CT", v->ct, PRINCE_BLOCK_SIZE);
            print_hex("   Actual CT  ", ct, PRINCE_BLOCK_SIZE);
            failed++;
            continue;
        }

        prince_decrypt_block(&ctx, ct, pt);
        if (memcmp(pt, v->pt, PRINCE_BLOCK_SIZE) != 0) {
            printf("[FAIL] Vector %zu Decryption Round-Trip Mismatch!\n", i+1);
            print_hex("   Expected PT", v->pt, PRINCE_BLOCK_SIZE);
            print_hex("   Actual PT  ", pt, PRINCE_BLOCK_SIZE);
            failed++;
            continue;
        }

        printf("[PASS] Vector %zu passed encryption and decryption.\n", i+1);
    }

    if (failed == 0) {
        printf("\nAll %zu PRINCE KAT tests passed successfully!\n", PRINCE_KAT_COUNT);
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failed);
        return 1;
    }
}
