#ifndef RABBIT_H
#define RABBIT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RABBIT_WORD_SIZE 0x100000000ULL
#define RABBIT_KEY_SIZE 16   // bytes
#define RABBIT_IV_SIZE 8     // bytes
#define RABBIT_BLOCK_SIZE 16 // bytes of keystream produced per iteration


/**
 * @brief Stores the internal Rabbit state
 *
 * x holds eight 32-bit state words
 * c holds eight 32-bit counter words
 * carry holds the carry bit preserved between counter updates
 */
typedef struct {
    uint32_t x[8];
    uint32_t c[8];
    uint32_t carry;
} rabbit_state_t;


/**
 * @brief Stores everything needed to encrypt/decrypt a stream
 *
 * master is the state after the key setup, kept so a new IV can be set
 * without doing the key setup again (RFC 4503 2.4)
 * work is the state used to generate the keystream
 * keystream is the last 16-byte keystream block
 * ks_pos is the next unused byte in keystream (RABBIT_BLOCK_SIZE = empty)
 */
typedef struct {
    rabbit_state_t master;
    rabbit_state_t work;
    uint8_t keystream[RABBIT_BLOCK_SIZE];
    size_t ks_pos;
} rabbit_ctx_t;


// Key, IV and keystream are little-endian: key[0] = K[7..0], iv[0] = IV[7..0]
// and the first keystream byte is S[7..0] (same as the eSTREAM reference code).
// The RFC 4503 test vectors are printed big-endian, so they have to be reversed.


/**
 * @brief Key setup, after this the context can already be used without an IV
 *
 * @param[out] ctx Context to initialize
 * @param[in] key 16-byte key
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.3
 */
void rabbit_set_key(rabbit_ctx_t *ctx, const uint8_t key[RABBIT_KEY_SIZE]);

/**
 * @brief IV setup, starting from the master state
 *
 * @param[in,out] ctx Context with a key already set
 * @param[in] iv 8-byte IV
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.4
 *
 * @note Can be called again to restart the stream with another IV
 */
void rabbit_set_iv(rabbit_ctx_t *ctx, const uint8_t iv[RABBIT_IV_SIZE]);

/**
 * @brief Encrypts or decrypts len bytes (it is the same operation)
 *
 * @param[in,out] ctx Context with a key (and optionally an IV) set
 * @param[in] in Input data
 * @param[out] out Output data, may be the same buffer as in
 * @param[in] len Number of bytes, does not need to be a multiple of 16
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.8
 *
 * @note Leftover keystream bytes are kept for the next call, so the
 *       message can be split into several calls
 */
void rabbit_crypt(rabbit_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len);

/**
 * @brief Zeroes the whole context
 *
 * @param[in,out] ctx Context to wipe
 */
void rabbit_cleanup(rabbit_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RABBIT_H */
