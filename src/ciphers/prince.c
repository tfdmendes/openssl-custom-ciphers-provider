#include "ciphers/prince.h"
#include <stdint.h>

static const uint64_t PRINCE_ALPHA = UINT64_C(0xc0ac29b7c97c50dd);

static const uint64_t PRINCE_RC[12] = {
    UINT64_C(0x0000000000000000),
    UINT64_C(0x13198a2e03707344),
    UINT64_C(0xa4093822299f31d0),
    UINT64_C(0x082efa98ec4e6c89),
    UINT64_C(0x452821e638d01377),
    UINT64_C(0xbe5466cf34e90c6c),
    UINT64_C(0x7ef84f78fd955cb1),
    UINT64_C(0x85840851f1ac43aa),
    UINT64_C(0xc882d32f25323c54),
    UINT64_C(0x64a51195e0e3610d),
    UINT64_C(0xd3b5a399ca0c2399),
    UINT64_C(0xc0ac29b7c97c50dd)
};

static const uint8_t PRINCE_SBOX[16] = {
    0xb, 0xf, 0x3, 0x2,
    0xa, 0xc, 0x9, 0x1,
    0x6, 0x7, 0x8, 0x0,
    0xe, 0x5, 0xd, 0x4
};

static const uint8_t PRINCE_ISBOX[16] = {
    0xb, 0x7, 0x3, 0x2,
    0xf, 0xd, 0x8, 0x9,
    0xa, 0x6, 0x4, 0x0,
    0x5, 0xe, 0xc, 0x1
};

static const uint16_t PRINCE_M16[2][16] = {
    {
        0x0111, 0x2220, 0x4404, 0x8088,
        0x1011, 0x0222, 0x4440, 0x8808,
        0x1101, 0x2022, 0x0444, 0x8880,
        0x1110, 0x2202, 0x4044, 0x0888
    },
    {
        0x1110, 0x2202, 0x4044, 0x0888,
        0x0111, 0x2220, 0x4404, 0x8088,
        0x1011, 0x0222, 0x4440, 0x8808,
        0x1101, 0x2022, 0x0444, 0x8880
    }
};

static inline uint64_t load64_be(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)b[i];
    }
    return v;
}

static inline void store64_be(uint64_t v, uint8_t b[8]) {
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> ((7 - i) * 8));
    }
}

static inline uint64_t compute_k0_prime(uint64_t k0) {
    uint64_t ror1 = (k0 >> 1) | (k0 << 63);
    return ror1 ^ (k0 >> 63);
}

static inline uint64_t s_layer(uint64_t in) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        unsigned int shift = (unsigned int)(i * 4);
        uint8_t nib = (uint8_t)((in >> shift) & 0x0F);
        out |= ((uint64_t)PRINCE_SBOX[nib]) << shift;
    }
    return out;
}

static inline uint64_t inv_s_layer(uint64_t in) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        unsigned int shift = (unsigned int)(i * 4);
        uint8_t nib = (uint8_t)((in >> shift) & 0x0F);
        out |= ((uint64_t)PRINCE_ISBOX[nib]) << shift;
    }
    return out;
}

static inline uint16_t mat_mult16(uint16_t in, const uint16_t mat[16]) {
    uint16_t out = 0;
    for (int i = 0; i < 16; i++) {
        if ((in >> i) & 1) {
            out ^= mat[i];
        }
    }
    return out;
}

static inline uint64_t m_prime_layer(uint64_t in) {
    uint16_t c0 = mat_mult16((uint16_t)(in >> 0), PRINCE_M16[0]);
    uint16_t c1 = mat_mult16((uint16_t)(in >> 16), PRINCE_M16[1]);
    uint16_t c2 = mat_mult16((uint16_t)(in >> 32), PRINCE_M16[1]);
    uint16_t c3 = mat_mult16((uint16_t)(in >> 48), PRINCE_M16[0]);

    return ((uint64_t)c3 << 48) | ((uint64_t)c2 << 32) | ((uint64_t)c1 << 16) | ((uint64_t)c0);
}

static inline uint64_t shift_rows_layer(uint64_t in, int inverse) {
    const uint64_t row_mask = UINT64_C(0xF000F000F000F000);
    uint64_t out = in & row_mask;
    for (unsigned int i = 1; i < 4; i++) {
        uint64_t row = in & (row_mask >> (4 * i));
        unsigned int shift = inverse ? (i * 16) : (64 - i * 16);
        out |= (row >> shift) | (row << (64 - shift));
    }
    return out;
}

static inline uint64_t m_layer(uint64_t in) {
    return shift_rows_layer(m_prime_layer(in), 0);
}

static inline uint64_t inv_m_layer(uint64_t in) {
    return m_prime_layer(shift_rows_layer(in, 1));
}

static uint64_t prince_core(uint64_t in, uint64_t k1) {
    uint64_t st = in ^ k1 ^ PRINCE_RC[0];

    for (int r = 1; r < 6; r++) {
        st = s_layer(st);
        st = m_layer(st);
        st ^= k1 ^ PRINCE_RC[r];
    }

    st = s_layer(st);
    st = m_prime_layer(st);
    st = inv_s_layer(st);

    for (int r = 6; r < 11; r++) {
        st ^= k1 ^ PRINCE_RC[r];
        st = inv_m_layer(st);
        st = inv_s_layer(st);
    }

    st ^= k1 ^ PRINCE_RC[11];
    return st;
}

void prince_set_key(prince_ctx_t *ctx, const uint8_t key[PRINCE_KEY_SIZE]) {
    if (!ctx || !key) return;
    ctx->k0 = load64_be(key);
    ctx->k0_prime = compute_k0_prime(ctx->k0);
    ctx->k1 = load64_be(key + 8);
}

void prince_encrypt_block(const prince_ctx_t *ctx, const uint8_t in[PRINCE_BLOCK_SIZE], uint8_t out[PRINCE_BLOCK_SIZE]) {
    uint64_t state = load64_be(in);
    state ^= ctx->k0;
    state = prince_core(state, ctx->k1);
    state ^= ctx->k0_prime;
    store64_be(state, out);
}

void prince_decrypt_block(const prince_ctx_t *ctx, const uint8_t in[PRINCE_BLOCK_SIZE], uint8_t out[PRINCE_BLOCK_SIZE]) {
    uint64_t state = load64_be(in);
    state ^= ctx->k0_prime;
    state = prince_core(state, ctx->k1 ^ PRINCE_ALPHA);
    state ^= ctx->k0;
    store64_be(state, out);
}
