#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
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
    printf("[1/7] Testing PKCS#7 padding...\n");

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
    printf("[2/7] Testing PRINCE ECB mode...\n");
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
    printf("[3/7] Testing PRINCE CBC mode...\n");
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
    printf("[4/7] Testing PRINCE CTR mode (arbitrary length stream)...\n");
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

    if (v->mode >= PRINCE_MODE_CTR) {
        uint8_t counter[8];
        uint8_t ecount[8];
        unsigned int num = 0;
        memcpy(counter, v->iv, 8);
        if (v->mode == PRINCE_MODE_OFB)
            mode_ofb_crypt(ctx, prince_enc_fn, 8, counter, ecount, &num, pt, ct, len);
        else if (v->mode == PRINCE_MODE_CFB)
            mode_cfb_encrypt(ctx, prince_enc_fn, 8, counter, ecount, &num, pt, ct, len);
        else
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

    if (v->mode >= PRINCE_MODE_CTR) {
        uint8_t counter[8];
        uint8_t ecount[8];
        unsigned int num = 0;
        memcpy(counter, v->iv, 8);
        if (v->mode == PRINCE_MODE_OFB)
            mode_ofb_crypt(ctx, prince_enc_fn, 8, counter, ecount, &num, v->ct, pt, len);
        else if (v->mode == PRINCE_MODE_CFB)
            mode_cfb_decrypt(ctx, prince_enc_fn, 8, counter, ecount, &num, v->ct, pt, len);
        else
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

typedef void (*stream_mode_fn)(const void *, block_cipher_fn, size_t, uint8_t *, uint8_t *, unsigned int *, const uint8_t *, uint8_t *, size_t);

static void check_feedback_stream(const char *name, stream_mode_fn mode, const void *ctx,
                                  block_cipher_fn enc_fn, size_t block_size, const uint8_t *iv,
                                  const uint8_t *input, const uint8_t *expected, size_t len) {
    uint8_t reference_iv[16], reference_cache[16], reference[80];
    unsigned int reference_num = 0;

    memcpy(reference_iv, iv, block_size);
    memset(reference_cache, 0x5a, sizeof(reference_cache));
    mode(ctx, enc_fn, block_size, reference_iv, reference_cache, &reference_num, input, reference, len);
    if (memcmp(reference, expected, len) != 0) {
        fprintf(stderr, "%s: wrong reference output for %zu bytes\n", name, len);
        exit(1);
    }

    for (size_t split = 0; split <= len; split++) {
        for (int in_place = 0; in_place < 2; in_place++) {
            uint8_t feedback[16], cache[16], out[80], saved_feedback[16], saved_cache[16];
            unsigned int num = 0;
            memcpy(feedback, iv, block_size);
            memset(cache, 0x5a, sizeof(cache));
            memset(out, 0xa5, sizeof(out));
            if (in_place)
                memcpy(out, input, len);

            mode(ctx, enc_fn, block_size, feedback, cache, &num,
                 in_place ? out : input, out, split);
            memcpy(saved_feedback, feedback, block_size);
            memcpy(saved_cache, cache, block_size);
            unsigned int saved_num = num;
            mode(ctx, enc_fn, block_size, feedback, cache, &num,
                 in_place ? out + split : input + split, out + split, 0);
            if (num != saved_num || memcmp(feedback, saved_feedback, block_size) != 0
                    || memcmp(cache, saved_cache, block_size) != 0) {
                fprintf(stderr, "%s: zero-length update changed state\n", name);
                exit(1);
            }
            mode(ctx, enc_fn, block_size, feedback, cache, &num,
                 in_place ? out + split : input + split, out + split, len - split);
            if (memcmp(out, expected, len) != 0 || out[len] != 0xa5
                    || num != len % block_size || num != reference_num
                    || memcmp(feedback, reference_iv, block_size) != 0
                    || memcmp(cache, reference_cache, block_size) != 0) {
                fprintf(stderr, "%s: length %zu split %zu in_place %d failed\n", name, len, split, in_place);
                exit(1);
            }
        }
    }
}

static void test_prince_modes_kat(void) {
    printf("[5/7] Testing PRINCE ECB/CBC/CTR/OFB/CFB test vectors...\n");
    const char *mode_names[] = {"ECB", "CBC", "CTR", "OFB", "CFB"};

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
        if (v->mode == PRINCE_MODE_OFB || v->mode == PRINCE_MODE_CFB) {
            stream_mode_fn encrypt = v->mode == PRINCE_MODE_OFB ? mode_ofb_crypt : mode_cfb_encrypt;
            stream_mode_fn decrypt = v->mode == PRINCE_MODE_OFB ? mode_ofb_crypt : mode_cfb_decrypt;
            check_feedback_stream(mode_names[v->mode], encrypt, &ctx, prince_enc_fn, 8,
                                  v->iv, pt, v->ct, v->pt_len);
            check_feedback_stream(mode_names[v->mode], decrypt, &ctx, prince_enc_fn, 8,
                                  v->iv, v->ct, pt, v->ct_len);
        }
    }
    printf("      %zu vectors passed.\n", (size_t)PRINCE_MODES_KAT_COUNT);
}

static void aes_enc_fn(const void *ctx, const uint8_t *in, uint8_t *out) {
    int len = 0;
    if (!EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx, out, &len, in, 16) || len != 16) {
        fprintf(stderr, "AES block encryption failed\n");
        exit(1);
    }
}

static void decode_hex(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%2x", &value) != 1) {
            fprintf(stderr, "Invalid test vector\n");
            exit(1);
        }
        out[i] = (uint8_t)value;
    }
}

static void test_nist_feedback_vectors(void) {
    /* NIST SP 800-38A F.3.13/F.3.14 and F.4.1/F.4.2, including every byte prefix */
    const char *plaintext = "6bc1bee22e409f96e93d7e117393172a"
                            "ae2d8a571e03ac9c9eb76fac45af8e51"
                            "30c81c46a35ce411e5fbc1191a0a52ef"
                            "f69f2445df4f9b17ad2b417be66c3710";
    const char *ciphertexts[] = {
        "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
        "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"
    };
    uint8_t key[16], iv[16], pt[64], ct[64];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    printf("[6/7] Testing NIST AES OFB/CFB128 vectors, byte splits and in-place operation...\n");
    decode_hex("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    decode_hex("000102030405060708090a0b0c0d0e0f", iv, sizeof(iv));
    decode_hex(plaintext, pt, sizeof(pt));
    if (!ctx || !EVP_EncryptInit_ex2(ctx, EVP_aes_128_ecb(), key, NULL, NULL)
            || !EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        fprintf(stderr, "AES setup failed\n");
        exit(1);
    }
    for (int cfb = 0; cfb < 2; cfb++) {
        const char *name = cfb ? "AES-CFB128" : "AES-OFB";
        stream_mode_fn encrypt = cfb ? mode_cfb_encrypt : mode_ofb_crypt;
        stream_mode_fn decrypt = cfb ? mode_cfb_decrypt : mode_ofb_crypt;
        decode_hex(ciphertexts[cfb], ct, sizeof(ct));
        for (size_t len = 0; len <= sizeof(pt); len++) {
            check_feedback_stream(name, encrypt, ctx, aes_enc_fn, 16, iv, pt, ct, len);
            check_feedback_stream(name, decrypt, ctx, aes_enc_fn, 16, iv, ct, pt, len);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    printf("      NIST OFB/CFB128 vectors and streaming checks passed.\n");
}

static void prince_enc_blocks_fn(const void *ctx, const uint8_t *in, uint8_t *out, size_t nblocks) {
    prince_encrypt_blocks((const prince_ctx_t *)ctx, in, out, nblocks);
}

static void prince_dec_blocks_fn(const void *ctx, const uint8_t *in, uint8_t *out, size_t nblocks) {
    prince_decrypt_blocks((const prince_ctx_t *)ctx, in, out, nblocks);
}

static void test_multi_block_modes(void) {
    printf("[7/7] Testing multi-block ECB/CBC/CTR...\n");
    enum { MAX = 8 * 160 };
    static uint8_t pt[MAX], ref[MAX], out[MAX], back[MAX];
    uint8_t key[16], iv[8];
    prince_ctx_t ctx;

    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i * 17 + 3);
    for (size_t i = 0; i < sizeof(iv); i++) iv[i] = (uint8_t)(0xf0 - i * 9);
    for (size_t i = 0; i < MAX; i++) pt[i] = (uint8_t)(i * 131 + 11);
    prince_set_key(&ctx, key);

    for (int avx2 = 0; avx2 < 2; avx2++) {
        if (avx2 && !ctx.use_avx2) continue;
        prince_ctx_t c = ctx;
        c.use_avx2 = avx2;

        for (size_t len = 0; len <= MAX; len += 8) {
            for (int in_place = 0; in_place < 2; in_place++) {
                uint8_t next_ref[8], next[8];

                /* ECB */
                mode_ecb_crypt(&c, prince_enc_fn, 8, pt, ref, len);
                memcpy(out, pt, len);
                mode_ecb_crypt_blocks(&c, prince_enc_blocks_fn, 8, in_place ? out : pt, out, len);
                memcpy(back, out, len);
                mode_ecb_crypt_blocks(&c, prince_dec_blocks_fn, 8, back, back, len);
                if (memcmp(out, ref, len) != 0 || memcmp(back, pt, len) != 0) {
                    fprintf(stderr, "multi-block ECB failed (len %zu, avx2 %d)\n", len, avx2);
                    exit(1);
                }

                /* CBC decryption */
                mode_cbc_encrypt(&c, prince_enc_fn, 8, iv, pt, ref, len, NULL);
                mode_cbc_decrypt(&c, prince_dec_fn, 8, iv, ref, back, len, next_ref);
                memcpy(out, ref, len);
                mode_cbc_decrypt_blocks(&c, prince_dec_blocks_fn, 8, iv, in_place ? out : ref, out, len, next);
                if (memcmp(out, pt, len) != 0 || memcmp(back, pt, len) != 0 || memcmp(next, next_ref, 8) != 0) {
                    fprintf(stderr, "multi-block CBC decrypt failed (len %zu, avx2 %d)\n", len, avx2);
                    exit(1);
                }
            }
        }

        // CTR split in two calls
        const size_t lens[] = {0, 1, 7, 8, 9, 31, 32, 33, 127, 128, 129, 511, 512, 513, 777, MAX};
        for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
            const size_t len = lens[li];
            uint8_t ctr_ref[8], ec_ref[8] = {0};
            unsigned int num_ref = 0;
            memcpy(ctr_ref, iv, 8);
            mode_ctr_crypt(&c, prince_enc_fn, 8, ctr_ref, ec_ref, &num_ref, pt, ref, len);

            for (size_t split = 0; split <= len; split += (len > 64 ? 13 : 1)) {
                uint8_t ctr[8], ec[8] = {0};
                unsigned int num = 0;
                memcpy(ctr, iv, 8);
                memcpy(out, pt, len);
                mode_ctr_crypt_blocks(&c, prince_enc_blocks_fn, 8, ctr, ec, &num, out, out, split);
                mode_ctr_crypt_blocks(&c, prince_enc_blocks_fn, 8, ctr, ec, &num, out + split, out + split, len - split);
                if (memcmp(out, ref, len) != 0 || num != num_ref || memcmp(ctr, ctr_ref, 8) != 0
                        || (num != 0 && memcmp(ec, ec_ref, 8) != 0)) {
                    fprintf(stderr, "multi-block CTR failed (len %zu, split %zu, avx2 %d)\n", len, split, avx2);
                    exit(1);
                }
            }
        }
    }
    printf("      Multi-block modes passed.\n");
}

int main(void) {
    printf("Running Block Cipher Modes and PKCS#7 Tests...\n\n");
    test_pkcs7_padding();
    test_prince_ecb();
    test_prince_cbc();
    test_prince_ctr();
    test_prince_modes_kat();
    test_nist_feedback_vectors();
    test_multi_block_modes();
    printf("\nAll Modes and Padding tests passed successfully!\n");
    return 0;
}
