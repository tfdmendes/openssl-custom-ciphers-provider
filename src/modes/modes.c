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

void mode_ofb_crypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !enc_fn || !ivec || !ecount_buf || !num || !in || !out || block_size == 0 || *num >= block_size) return;

    unsigned int n = *num;
    while (len--) {
        if (n == 0) {
            enc_fn(ctx, ivec, ecount_buf);
            memcpy(ivec, ecount_buf, block_size);
        }
        *(out++) = *(in++) ^ ecount_buf[n];
        n = (n + 1) % block_size;
    }
    *num = n;
}

static void mode_cfb_crypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len, int encrypt) {
    if (!ctx || !enc_fn || !ivec || !ecount_buf || !num || !in || !out || block_size == 0 || *num >= block_size) return;

    unsigned int n = *num;
    while (len--) {
        if (n == 0)
            enc_fn(ctx, ivec, ecount_buf);
        uint8_t input = *(in++);
        uint8_t output = input ^ ecount_buf[n];
        /* Save the ciphertext before an in-place decrypt overwrites it */
        ivec[n] = encrypt ? output : input;
        *(out++) = output;
        n = (n + 1) % block_size;
    }
    *num = n;
}

void mode_cfb_encrypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len) {
    mode_cfb_crypt(ctx, enc_fn, block_size, ivec, ecount_buf, num, in, out, len, 1);
}

void mode_cfb_decrypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len) {
    mode_cfb_crypt(ctx, enc_fn, block_size, ivec, ecount_buf, num, in, out, len, 0);
}

#define MODE_BATCH_BYTES 512

void mode_ecb_crypt_blocks(const void *ctx, blocks_cipher_fn cipher_fn, size_t block_size, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !cipher_fn || !in || !out || block_size == 0) return;

    cipher_fn(ctx, in, out, len / block_size);
}

void mode_cbc_decrypt_blocks(const void *ctx, blocks_cipher_fn dec_fn, size_t block_size, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len, uint8_t *next_iv) {
    if (!ctx || !dec_fn || !iv || !in || !out || block_size == 0 || block_size > 64) return;

    uint8_t prev[64];
    uint8_t saved[MODE_BATCH_BYTES];  // copy of the ciphertext, needed when in == out
    const size_t batch = (MODE_BATCH_BYTES / block_size) * block_size;

    memcpy(prev, iv, block_size);

    for (size_t offset = 0; offset < len; ) {
        size_t chunk = len - offset < batch ? len - offset : batch;
        chunk -= chunk % block_size;
        if (chunk == 0) break;

        memcpy(saved, in + offset, chunk);
        dec_fn(ctx, saved, out + offset, chunk / block_size);

        for (size_t i = 0; i < block_size; i++)
            out[offset + i] ^= prev[i];
        for (size_t i = block_size; i < chunk; i++)
            out[offset + i] ^= saved[i - block_size];

        memcpy(prev, saved + chunk - block_size, block_size);
        offset += chunk;
    }

    if (next_iv) {
        memcpy(next_iv, prev, block_size);
    }
}

void mode_ctr_crypt_blocks(const void *ctx, blocks_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx || !enc_fn || !ivec || !ecount_buf || !num || !in || !out || block_size == 0 || block_size > 64 || *num >= block_size) return;

    uint8_t stream[MODE_BATCH_BYTES];
    const size_t batch_blocks = MODE_BATCH_BYTES / block_size;
    unsigned int n = *num;

    // Rest of the previous block
    while (n != 0 && len > 0) {
        *(out++) = *(in++) ^ ecount_buf[n];
        n = (unsigned int)((n + 1) % block_size);
        len--;
    }

    while (len >= block_size) {
        size_t blocks = len / block_size;
        if (blocks > batch_blocks) blocks = batch_blocks;
        const size_t bytes = blocks * block_size;

        for (size_t b = 0; b < blocks; b++) {
            memcpy(stream + b * block_size, ivec, block_size);
            ctr_inc(ivec, block_size);
        }
        enc_fn(ctx, stream, stream, blocks);
        for (size_t i = 0; i < bytes; i++)
            out[i] = in[i] ^ stream[i];

        in += bytes;
        out += bytes;
        len -= bytes;
    }

    // Partial block at the end, keystream stays in ecount_buf
    if (len > 0) {
        enc_fn(ctx, ivec, ecount_buf, 1);
        ctr_inc(ivec, block_size);
        for (size_t i = 0; i < len; i++)
            out[i] = in[i] ^ ecount_buf[i];
        n = (unsigned int)len;
    }

    *num = n;
}
