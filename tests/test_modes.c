#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ciphers/prince.h"
#include "modes/modes.h"
#include "modes/padding.h"

static void test_pkcs7_padding(void) {
    printf("[1/4] Testing PKCS#7 padding...\n");

    const size_t block_size = 8;
    uint8_t in[32];
    uint8_t padded[64];
    size_t padded_len = 0;
    size_t unpadded_len = 0;

    for (size_t len = 0; len <= 24; len++) {
        for (size_t i = 0; i < len; i++) in[i] = (uint8_t)(i + 1);

        if (pkcs7_pad(in, len, block_size, padded, &padded_len) != 0) {
            fprintf(stderr, "pkcs7_pad failed for len %zu\n", len);
            exit(1);
        }

        if (padded_len % block_size != 0 || padded_len <= len) {
            fprintf(stderr, "Invalid padded length %zu for input len %zu\n", padded_len, len);
            exit(1);
        }

        if (pkcs7_unpad(padded, padded_len, block_size, &unpadded_len) != 0) {
            fprintf(stderr, "pkcs7_unpad failed for len %zu\n", len);
            exit(1);
        }

        if (unpadded_len != len || memcmp(in, padded, len) != 0) {
            fprintf(stderr, "Unpadded data mismatch for len %zu\n", len);
            exit(1);
        }
    }

    /* Test invalid padding detection */
    padded[padded_len - 1] ^= 0xFF;
    if (pkcs7_unpad(padded, padded_len, block_size, &unpadded_len) == 0) {
        fprintf(stderr, "Failed to detect corrupted PKCS#7 padding\n");
        exit(1);
    }

    printf("      PKCS#7 padding passed.\n");
}

static void test_prince_ecb(void) {
    printf("[2/4] Testing PRINCE ECB mode...\n");
    prince_ctx_t ctx;
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    prince_set_key(&ctx, key);

    uint8_t pt[24] = "Hello, PRINCE ECB Mode!";
    uint8_t ct[24];
    uint8_t decrypted[24];

    mode_ecb_crypt(&ctx, (block_cipher_fn)prince_encrypt_block, 8, pt, ct, 24);
    mode_ecb_crypt(&ctx, (block_cipher_fn)prince_decrypt_block, 8, ct, decrypted, 24);

    if (memcmp(pt, decrypted, 24) != 0) {
        fprintf(stderr, "ECB round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE ECB passed.\n");
}

static void test_prince_cbc(void) {
    printf("[3/4] Testing PRINCE CBC mode...\n");
    prince_ctx_t ctx;
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    prince_set_key(&ctx, key);

    uint8_t pt[32] = "Testing PRINCE CBC Block Mode!!";
    uint8_t ct[32];
    uint8_t decrypted[32];

    mode_cbc_encrypt(&ctx, (block_cipher_fn)prince_encrypt_block, 8, iv, pt, ct, 32, NULL);
    mode_cbc_decrypt(&ctx, (block_cipher_fn)prince_decrypt_block, 8, iv, ct, decrypted, 32, NULL);

    if (memcmp(pt, decrypted, 32) != 0) {
        fprintf(stderr, "CBC round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE CBC passed.\n");
}

static void test_prince_ctr(void) {
    printf("[4/4] Testing PRINCE CTR mode (arbitrary length stream)...\n");
    prince_ctx_t ctx;
    uint8_t key[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    uint8_t iv1[8] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87};
    uint8_t iv2[8];
    memcpy(iv2, iv1, 8);

    prince_set_key(&ctx, key);

    uint8_t pt[37] = "Arbitrary length non-aligned stream!";
    uint8_t ct[37];
    uint8_t decrypted[37];

    uint8_t ecount1[8] = {0};
    uint8_t ecount2[8] = {0};
    unsigned int num1 = 0;
    unsigned int num2 = 0;

    mode_ctr_crypt(&ctx, (block_cipher_fn)prince_encrypt_block, 8, iv1, ecount1, &num1, pt, ct, 37);
    mode_ctr_crypt(&ctx, (block_cipher_fn)prince_encrypt_block, 8, iv2, ecount2, &num2, ct, decrypted, 37);

    if (memcmp(pt, decrypted, 37) != 0) {
        fprintf(stderr, "CTR stream round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE CTR passed.\n");
}

int main(void) {
    printf("Running Block Cipher Modes and PKCS#7 Tests...\n\n");
    test_pkcs7_padding();
    test_prince_ecb();
    test_prince_cbc();
    test_prince_ctr();
    printf("\nAll Modes and Padding tests passed successfully!\n");
    return 0;
}
