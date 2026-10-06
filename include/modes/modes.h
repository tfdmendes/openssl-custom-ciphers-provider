#ifndef MODES_H
#define MODES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*block_cipher_fn)(const void *ctx, const uint8_t *in, uint8_t *out);

/*
 * ECB Mode Encryption / Decryption.
 * len must be a multiple of block_size
 */
void mode_ecb_crypt(const void *ctx, block_cipher_fn cipher_fn, size_t block_size, const uint8_t *in, uint8_t *out, size_t len);

/*
 * CBC Mode Encryption.
 * len must be a multiple of block_size.
 * iv: pointer to initial IV (must be block_size bytes).
 * next_iv: if not NULL, receives the updated IV (last ciphertext block).
 */
void mode_cbc_encrypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len, uint8_t *next_iv);

/*
 * CBC Mode Decryption.
 * len must be a multiple of block_size.
 * iv: pointer to initial IV (must be block_size bytes).
 * next_iv: if not NULL, receives the updated IV (last ciphertext block).
 */
void mode_cbc_decrypt(const void *ctx, block_cipher_fn dec_fn, size_t block_size, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len, uint8_t *next_iv);

/*
 * CTR Mode (Streaming) Encryption & Decryption (symmetric).
 * ivec: counter block (block_size bytes).
 * ecount_buf: keystream cache buffer (block_size bytes).
 * num: pointer to index inside ecount_buf (0 to block_size -1).
 * len: arbitrary byte length (does not need to be block-aligned).
 */
void mode_ctr_crypt(const void *ctx, block_cipher_fn enc_fn, size_t block_size, uint8_t *ivec, uint8_t *ecount_buf, unsigned int *num, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MODES_H */
