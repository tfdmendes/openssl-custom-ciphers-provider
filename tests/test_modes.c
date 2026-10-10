#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ciphers/prince.h"
#include "modes/modes.h"
#include "modes/padding.h"
#include "vectors/prince_modes_kat.h"

// The modes take a block_cipher_fn, these just call PRINCE with the right types
static void prince_enc_fn(const void *ctx, const uint8_t *in, uint8_t *out) {
    prince_encrypt_block((const prince_ctx_t *)ctx, in, out);
}

static void prince_dec_fn(const void *ctx, const uint8_t *in, uint8_t *out) {
    prince_decrypt_block((const prince_ctx_t *)ctx, in, out);
}

static void test_pkcs7_padding(void) {
    printf("[1/5] Testing PKCS#7 padding...\n");

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
    printf("[2/5] Testing PRINCE ECB mode...\n");
    prince_ctx_t ctx;
    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    prince_set_key(&ctx, key);

    uint8_t pt[24] = "Hello, PRINCE ECB Mode!";
    uint8_t ct[24];
    uint8_t decrypted[24];

    mode_ecb_crypt(&ctx, prince_enc_fn, 8, pt, ct, 24);
    mode_ecb_crypt(&ctx, prince_dec_fn, 8, ct, decrypted, 24);

    if (memcmp(pt, decrypted, 24) != 0) {
        fprintf(stderr, "ECB round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE ECB passed.\n");
}

static void test_prince_cbc(void) {
    printf("[3/5] Testing PRINCE CBC mode...\n");
    prince_ctx_t ctx;
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t iv[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    prince_set_key(&ctx, key);

    uint8_t pt[32] = "Testing PRINCE CBC Block Mode!!";
    uint8_t ct[32];
    uint8_t decrypted[32];

    mode_cbc_encrypt(&ctx, prince_enc_fn, 8, iv, pt, ct, 32, NULL);
    mode_cbc_decrypt(&ctx, prince_dec_fn, 8, iv, ct, decrypted, 32, NULL);

    if (memcmp(pt, decrypted, 32) != 0) {
        fprintf(stderr, "CBC round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE CBC passed.\n");
}

static void test_prince_ctr(void) {
    printf("[4/5] Testing PRINCE CTR mode (arbitrary length stream)...\n");
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

    mode_ctr_crypt(&ctx, prince_enc_fn, 8, iv1, ecount1, &num1, pt, ct, 37);
    mode_ctr_crypt(&ctx, prince_enc_fn, 8, iv2, ecount2, &num2, ct, decrypted, 37);

    if (memcmp(pt, decrypted, 37) != 0) {
        fprintf(stderr, "CTR stream round-trip failed\n");
        exit(1);
    }
    printf("      PRINCE CTR passed.\n");
}

// Encrypts with the mode of the vector, returns the ciphertext length
static size_t kat_encrypt(const prince_modes_kat_vector_t *v, const prince_ctx_t *ctx, const uint8_t *pt, uint8_t *ct) {
    uint8_t buf[PRINCE_MODES_KAT_MAX_LEN];
    size_t len = v->pt_len;

    if (v->mode == PRINCE_MODE_CTR) {
        uint8_t counter[8];
        uint8_t ecount[8];
        unsigned int num = 0;
        memcpy(counter, v->iv, 8);
        mode_ctr_crypt(ctx, prince_enc_fn, 8, counter, ecount, &num, pt, ct, len);
        return len;
    }

    pkcs7_pad(pt, v->pt_len, 8, buf, &len);
    if (v->mode == PRINCE_MODE_ECB) {
        mode_ecb_crypt(ctx, prince_enc_fn, 8, buf, ct, len);
    } else {
        mode_cbc_encrypt(ctx, prince_enc_fn, 8, v->iv, buf, ct, len, NULL);
    }
    return len;
}

// Decrypts v->ct, returns the plaintext length or -1 if the padding is wrong
static long kat_decrypt(const prince_modes_kat_vector_t *v, const prince_ctx_t *ctx, uint8_t *pt) {
    size_t len = v->ct_len;

    if (v->mode == PRINCE_MODE_CTR) {
        uint8_t counter[8];
        uint8_t ecount[8];
        unsigned int num = 0;
        memcpy(counter, v->iv, 8);
        mode_ctr_crypt(ctx, prince_enc_fn, 8, counter, ecount, &num, v->ct, pt, len);
        return (long)len;
    }

    if (v->mode == PRINCE_MODE_ECB) {
        mode_ecb_crypt(ctx, prince_dec_fn, 8, v->ct, pt, len);
    } else {
        mode_cbc_decrypt(ctx, prince_dec_fn, 8, v->iv, v->ct, pt, len, NULL);
    }
    if (pkcs7_unpad(pt, v->ct_len, 8, &len) != 0) return -1;
    return (long)len;
}

static void test_prince_modes_kat(void) {
    printf("[5/5] Testing PRINCE ECB/CBC/CTR test vectors...\n");
    const char *mode_names[] = {"ECB", "CBC", "CTR"};

    for (size_t i = 0; i < PRINCE_MODES_KAT_COUNT; i++) {
        const prince_modes_kat_vector_t *v = &PRINCE_MODES_KAT_VECTORS[i];
        prince_ctx_t ctx;
        uint8_t pt[PRINCE_MODES_KAT_MAX_LEN];
        uint8_t ct[PRINCE_MODES_KAT_MAX_LEN];
        uint8_t decrypted[PRINCE_MODES_KAT_MAX_LEN];

        for (size_t j = 0; j < v->pt_len; j++) pt[j] = (uint8_t)(j * 31 + 7);
        prince_set_key(&ctx, v->key);

        size_t ct_len = kat_encrypt(v, &ctx, pt, ct);
        if (ct_len != v->ct_len || memcmp(ct, v->ct, ct_len) != 0) {
            fprintf(stderr, "Vector %zu (%s, %zu bytes): wrong ciphertext\n", i + 1, mode_names[v->mode], v->pt_len);
            exit(1);
        }

        long pt_len = kat_decrypt(v, &ctx, decrypted);
        if (pt_len != (long)v->pt_len || memcmp(decrypted, pt, v->pt_len) != 0) {
            fprintf(stderr, "Vector %zu (%s, %zu bytes): wrong plaintext\n", i + 1, mode_names[v->mode], v->pt_len);
            exit(1);
        }
    }
    printf("      %zu vectors passed.\n", (size_t)PRINCE_MODES_KAT_COUNT);
}

int main(void) {
    printf("Running Block Cipher Modes and PKCS#7 Tests...\n\n");
    test_pkcs7_padding();
    test_prince_ecb();
    test_prince_cbc();
    test_prince_ctr();
    test_prince_modes_kat();
    printf("\nAll Modes and Padding tests passed successfully!\n");
    return 0;
}
