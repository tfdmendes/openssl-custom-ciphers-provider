#include <string.h>
#include <stdint.h>
#include "ciphers/rabbit.h"


static const uint32_t RABBIT_CONSTANTS[8] = {
    0x4D34D34D,     // A0
    0xD34D34D3,     // A1
    0x34D34D34,     // A2
    0x4D34D34D,     // A3
    0xD34D34D3,     // A4
    0x34D34D34,     // A5
    0x4D34D34D,     // A6
    0xD34D34D3      // A7
};


/**
 * @brief Computes one intermediate value for the next state
 *
 * @param[in] u A 32-bit state word
 * @param[in] v A 32-bit counter word
 * @return A 32-bit value used to compute the next state
 *
 * // https://www.rfc-editor.org/rfc/rfc4503.html#section-2.6
 * 
 * @note This function does not modify the Rabbit state
 */
static uint32_t rabbit_g(uint32_t u, uint32_t v) {
    // No need to `(u + v) mod 2^32`
    // The sum already only saves the least 32 bits
    uint32_t sum = u + v;
    uint64_t square = (uint64_t)sum * sum;

    uint32_t lsw = (uint32_t) square;
    uint32_t msw = (uint32_t) (square >> 32);

    uint32_t result = lsw ^ msw;

    return result; 
}

/**
 * @brief Updates the eight counters and the carry bit
 *
 * @param[in,out] state Rabbit state to update
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.5
 * 
 * @note Each addition uses the carry from the previous addition
 * @note The final carry is preserved for the next iteration
 */
static void rabbit_update_counters(rabbit_state_t *state) {

    for (int j = 0; j < 8; j++) {
        uint64_t temp = (uint64_t) state->c[j] + RABBIT_CONSTANTS[j] + state->carry;
        state->carry = temp / RABBIT_WORD_SIZE;
        state->c[j] = temp % RABBIT_WORD_SIZE;
    }
}

static inline uint32_t rotl32(uint32_t v, unsigned int n) {
    return (v << n) | (v >> (32 - n));
}

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
 * @brief Computes the next internal state
 *
 * @param[in,out] state Rabbit state to update
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.6
 *
 * @note All the G values have to be computed before changing X
 * @note Additions are mod 2^32, uint32_t already does that
 */
static void rabbit_next_state(rabbit_state_t *state) {
    uint32_t g[8];
    uint32_t *x = state->x;

    for (int j = 0; j < 8; j++) {
        g[j] = rabbit_g(x[j], state->c[j]);
    }

    x[0] = g[0] + rotl32(g[7], 16) + rotl32(g[6], 16);
    x[1] = g[1] + rotl32(g[0],  8) + g[7];
    x[2] = g[2] + rotl32(g[1], 16) + rotl32(g[0], 16);
    x[3] = g[3] + rotl32(g[2],  8) + g[1];
    x[4] = g[4] + rotl32(g[3], 16) + rotl32(g[2], 16);
    x[5] = g[5] + rotl32(g[4],  8) + g[3];
    x[6] = g[6] + rotl32(g[5], 16) + rotl32(g[4], 16);
    x[7] = g[7] + rotl32(g[6],  8) + g[5];
}

/**
 * @brief Runs one full iteration of the system
 *
 * @param[in,out] state Rabbit state to update
 *
 * @note Counter update followed by the next-state function
 */
static void rabbit_iterate(rabbit_state_t *state) {
    rabbit_update_counters(state);
    rabbit_next_state(state);
}

/**
 * @brief Iterates once and extracts 16 bytes of keystream
 *
 * @param[in,out] state Rabbit state to update
 * @param[out] out Keystream, least significant byte of S first
 *
 * https://www.rfc-editor.org/rfc/rfc4503.html#section-2.7
 *
 * @note Each word below has two 16-bit parts of S, for example
 *       S[31..0] = (X0[31..16] ^ X3[15..0]) || (X0[15..0] ^ X5[31..16])
 */
static void rabbit_next_block(rabbit_state_t *state, uint8_t out[RABBIT_BLOCK_SIZE]) {
    rabbit_iterate(state);

    const uint32_t *x = state->x;
    store32_le(out +  0, x[0] ^ (x[5] >> 16) ^ (x[3] << 16));
    store32_le(out +  4, x[2] ^ (x[7] >> 16) ^ (x[5] << 16));
    store32_le(out +  8, x[4] ^ (x[1] >> 16) ^ (x[7] << 16));
    store32_le(out + 12, x[6] ^ (x[3] >> 16) ^ (x[1] << 16));
}

void rabbit_set_key(rabbit_ctx_t *ctx, const uint8_t key[RABBIT_KEY_SIZE]) {
    rabbit_state_t *state = &ctx->master;
    uint32_t k[8];

    // Subkeys K0 = K[15..0], ..., K7 = K[127..112]
    for (int j = 0; j < 8; j++) {
        k[j] = (uint32_t)key[2 * j] | ((uint32_t)key[2 * j + 1] << 8);
    }

    for (int j = 0; j < 8; j++) {
        if (j % 2 == 0) {
            state->x[j] = (k[(j + 1) % 8] << 16) | k[j];
            state->c[j] = (k[(j + 4) % 8] << 16) | k[(j + 5) % 8];
        } else {
            state->x[j] = (k[(j + 5) % 8] << 16) | k[(j + 4) % 8];
            state->c[j] = (k[j] << 16) | k[(j + 1) % 8];
        }
    }
    state->carry = 0;

    for (int i = 0; i < 4; i++) {
        rabbit_iterate(state);
    }

    for (int j = 0; j < 8; j++) {
        state->c[j] ^= state->x[(j + 4) % 8];
    }

    ctx->work = ctx->master;
    ctx->ks_pos = RABBIT_BLOCK_SIZE;

    memset(k, 0, sizeof(k));
}

void rabbit_set_iv(rabbit_ctx_t *ctx, const uint8_t iv[RABBIT_IV_SIZE]) {
    rabbit_state_t *state = &ctx->work;

    uint32_t iv_lo = load32_le(iv);      // IV[31..0]
    uint32_t iv_hi = load32_le(iv + 4);  // IV[63..32]
    uint32_t i0 = iv_lo;
    uint32_t i1 = (iv_hi & 0xFFFF0000) | (iv_lo >> 16);  // IV[63..48] || IV[31..16]
    uint32_t i2 = iv_hi;
    uint32_t i3 = (iv_hi << 16) | (iv_lo & 0x0000FFFF);  // IV[47..32] || IV[15..0]

    // Start from the master state so the IV can be changed later
    *state = ctx->master;

    state->c[0] ^= i0;
    state->c[1] ^= i1;
    state->c[2] ^= i2;
    state->c[3] ^= i3;
    state->c[4] ^= i0;
    state->c[5] ^= i1;
    state->c[6] ^= i2;
    state->c[7] ^= i3;

    for (int i = 0; i < 4; i++) {
        rabbit_iterate(state);
    }

    ctx->ks_pos = RABBIT_BLOCK_SIZE;
}

void rabbit_crypt(rabbit_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    // Leftover keystream from the last call
    while (len > 0 && ctx->ks_pos < RABBIT_BLOCK_SIZE) {
        *out++ = *in++ ^ ctx->keystream[ctx->ks_pos++];
        len--;
    }

    // Whole blocks
    while (len >= RABBIT_BLOCK_SIZE) {
        rabbit_next_block(&ctx->work, ctx->keystream);
        for (size_t i = 0; i < RABBIT_BLOCK_SIZE; i++) {
            out[i] = in[i] ^ ctx->keystream[i];
        }
        in += RABBIT_BLOCK_SIZE;
        out += RABBIT_BLOCK_SIZE;
        len -= RABBIT_BLOCK_SIZE;
    }

    // Last partial block, the unused bytes stay in the buffer
    if (len > 0) {
        rabbit_next_block(&ctx->work, ctx->keystream);
        ctx->ks_pos = 0;
        while (len > 0) {
            *out++ = *in++ ^ ctx->keystream[ctx->ks_pos++];
            len--;
        }
    }
}

void rabbit_cleanup(rabbit_ctx_t *ctx) {
    // volatile so the compiler doesn't optimize the memset away
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof(*ctx); i++) {
        p[i] = 0;
    }
}
