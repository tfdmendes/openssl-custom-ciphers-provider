#include "modes/modes.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void ctr_inc(uint8_t *counter, size_t block_size) {
    for (size_t i = block_size; i > 0; i--) {
        if (++counter[i - 1] != 0) {
            return;
        }
    }
}

void mode_ecb_crypt(const void *ctx, block_cipher_fn cipher_fn, size_t block_size, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !cipher_fn || !in || !out || block_size == 0) return;

    for (size_t offset = 0; offset < len; offset += block_size) {
        cipher_fn(ctx, in + offset, out + offset);
    }
}

void mode_cbc_encrypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len, uint8_t *next_iv) {
    if (!ctx || !enc_fn || !iv || !in || !out || block_size == 0) return;

    uint8_t current_iv[64]; // Supports block sizes up to 64 bytes
    if (block_size > sizeof(current_iv)) return;

    memcpy(current_iv, iv, block_size);

    for (size_t offset = 0; offset < len; offset += block_size) {
        uint8_t block[64];
        for (size_t i = 0; i < block_size; i++) {
            block[i] = in[offset + i] ^ current_iv[i];
        }
        enc_fn(ctx, block, out + offset);
        memcpy(current_iv, out + offset, block_size);
    }

    if (next_iv) {
        memcpy(next_iv, current_iv, block_size);
    }
}

void mode_cbc_decrypt(const void *ctx, block_cipher_fn dec_fn, size_t block_size, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len, uint8_t *next_iv) {
    if (!ctx || !dec_fn || !iv || !in || !out || block_size == 0) return;

    uint8_t prev_iv[64];
    uint8_t next_block_iv[64];
    if (block_size > sizeof(prev_iv)) return;

    memcpy(prev_iv, iv, block_size);

    for (size_t offset = 0; offset < len; offset += block_size) {
        uint8_t decrypted_block[64];
        memcpy(next_block_iv, in + offset, block_size);

        dec_fn(ctx, in + offset, decrypted_block);

        for (size_t i = 0; i < block_size; i++) {
            out[offset + i] = decrypted_block[i] ^ prev_iv[i];
        }
        memcpy(prev_iv, next_block_iv, block_size);
    }

    if (next_iv) {
        memcpy(next_iv, prev_iv, block_size);
    }
}

void mode_ctr_crypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !enc_fn || !ivec || !ecount_buf || !num || !in || !out || block_size == 0) return;

    unsigned int n = *num;

    while (len--) {
        if (n == 0) {
            enc_fn(ctx, ivec, ecount_buf);
            ctr_inc(ivec, block_size);
        }
        *(out++) = *(in++) ^ ecount_buf[n];
        n = (n + 1 ) % block_size;
    }

    *num = n;
}
