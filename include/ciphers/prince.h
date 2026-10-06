#ifndef PRINCE_H
#define PRINCE_H

#include <cstdint>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRINCE_BLOCK_SIZE 8
#define PRINCE_KEY_SIZE 16

typedef struct {
    uint64_t k0;
    uint64_t k0_prime;
    uint64_t k1;
} prince_ctx_t;

/*
 * Initializes the PRINCE context with a 128-bit key (16 bytes).
 * key: pointer to 16 bytes (k0 || k1).
 */
void prince_set_key(prince_ctx_t *ctx, const uint8_t key[PRINCE_KEY_SIZE]);

/*
 * Encrypts a single 64-bit (8-byte) block.
 * in: 8-byte plaintext
 * out: 8-byte ciphertext
 */
void prince_encrypt_block(const prince_ctx_t *ctx, const uint8_t in[PRINCE_BLOCK_SIZE], uint8_t out[PRINCE_BLOCK_SIZE]);

/*
 * Decrypts a single 64-bit (8-byte) block.
 * in: 8-byte ciphertext
 * out: 8-byte plaintext
 */
void prince_decrypt_block(const prince_ctx_t *ctx, const uint8_t in[PRINCE_BLOCK_SIZE], uint8_t out[PRINCE_BLOCK_SIZE]);

#ifdef  __cplusplus
}
#endif

#endif /* PRINCE_H */
