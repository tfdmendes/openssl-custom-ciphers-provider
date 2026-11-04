#include "ciphers/prince.h"
#include <stdint.h>
#include <string.h>

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

#define REP4(v)  ((uint64_t)(v) * UINT64_C(0x1111111111111111))
#define REP16(v) ((uint64_t)(v) * UINT64_C(0x0001000100010001))

// S-box and inverse S-box as boolean functions (ANF), x0 is the low bit of the nibble
#define PRINCE_SBOX_BF(T, x0, x1, x2, x3, ONE, y0, y1, y2, y3) do { \
        const T a01 = (x0) & (x1), a02 = (x0) & (x2), a12 = (x1) & (x2); \
        const T a03 = (x0) & (x3), a13 = (x1) & (x3), a23 = (x2) & (x3); \
        const T a012 = a01 & (x2), a013 = a01 & (x3), a023 = a02 & (x3), a123 = a12 & (x3); \
        (y0) = (ONE) ^ a01 ^ (x2) ^ a12 ^ a012 ^ (x3) ^ a03 ^ a23; \
        (y1) = (ONE) ^ a02 ^ a12 ^ a012 ^ a13 ^ a123; \
        (y2) = (x0) ^ a01 ^ (x3) ^ a03 ^ a13 ^ a013 ^ a123; \
        (y3) = (ONE) ^ (x1) ^ a12 ^ a012 ^ (x3) ^ a013 ^ a23 ^ a023; \
    } while (0)

#define PRINCE_ISBOX_BF(T, x0, x1, x2, x3, ONE, y0, y1, y2, y3) do { \
        const T a01 = (x0) & (x1), a02 = (x0) & (x2), a12 = (x1) & (x2); \
        const T a13 = (x1) & (x3), a23 = (x2) & (x3); \
        const T a012 = a01 & (x2), a013 = a01 & (x3), a023 = a02 & (x3), a123 = a12 & (x3); \
        (y0) = (ONE) ^ a01 ^ a12 ^ (x3) ^ a013 ^ a23 ^ a023; \
        (y1) = (ONE) ^ a02 ^ a12 ^ a012 ^ a13 ^ a23; \
        (y2) = (x0) ^ a01 ^ (x2) ^ a02 ^ a12 ^ a012 ^ a13 ^ a013; \
        (y3) = (ONE) ^ (x0) ^ (x1) ^ a01 ^ a02 ^ a12 ^ a012 ^ a23 ^ a023 ^ a123; \
    } while (0)

// M': each output bit is the XOR of the 4 nibbles of its 16-bit chunk,
// plus one extra term. PRINCE_MR[r] selects it from the chunk rotated by 4r bits
static const uint64_t PRINCE_MR[4] = {
    UINT64_C(0x8282414141418282),
    UINT64_C(0x4141282828284141),
    UINT64_C(0x2828141414142828),
    UINT64_C(0x1414828282821414)
};

// Same masks for the bitsliced layout, one per bit plane
static const uint64_t PRINCE_PM[4][4] = {
    {REP16(0x0550), REP16(0x5005), REP16(0x0aa0), REP16(0xa00a)},
    {REP16(0x5005), REP16(0x0aa0), REP16(0xa00a), REP16(0x0550)},
    {REP16(0x0aa0), REP16(0xa00a), REP16(0x0550), REP16(0x5005)},
    {REP16(0xa00a), REP16(0x0550), REP16(0x5005), REP16(0x0aa0)}
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
    const uint64_t m = REP4(1);
    uint64_t y0, y1, y2, y3;
    PRINCE_SBOX_BF(uint64_t, in & m, (in >> 1) & m, (in >> 2) & m, (in >> 3) & m, m, y0, y1, y2, y3);
    return y0 | (y1 << 1) | (y2 << 2) | (y3 << 3);
}

static inline uint64_t inv_s_layer(uint64_t in) {
    const uint64_t m = REP4(1);
    uint64_t y0, y1, y2, y3;
    PRINCE_ISBOX_BF(uint64_t, in & m, (in >> 1) & m, (in >> 2) & m, (in >> 3) & m, m, y0, y1, y2, y3);
    return y0 | (y1 << 1) | (y2 << 2) | (y3 << 3);
}

#define ROTL16(x, s) ((((x) << (s)) & REP16((0xFFFFu << (s)) & 0xFFFFu)) | (((x) >> (16 - (s))) & REP16((1u << (s)) - 1u)))

/* Unoptimized
static inline uint64_t m_prime_layer(uint64_t x) {
    uint64_t r1 = ROTL16(x, 4), r2 = ROTL16(x, 8), r3 = ROTL16(x, 12);
    return x ^ r1 ^ r2 ^ r3 ^ (x & PRINCE_MR[0]) ^ (r1 & PRINCE_MR[1]) ^
           (r2 & PRINCE_MR[2]) ^ (r3 & PRINCE_MR[3]);
}
*/
static inline uint64_t m_prime_layer(uint64_t x) {
    uint64_t r2 = ROTL16(x, 8);
    uint64_t sum = x ^ r2;
    uint64_t all_rot = sum ^ ROTL16(sum, 4);

    uint64_t r1 = ROTL16(x, 4);
    uint64_t r3 = ROTL16(r1, 8); // Reuses the 8-bit rotate masks already in registers

    return all_rot ^ (x & PRINCE_MR[0]) ^ (r1 & PRINCE_MR[1]) ^ (r2 & PRINCE_MR[2]) ^ (r3 & PRINCE_MR[3]);}

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

// Bitsliced core for 4 blocks (uint64_t) and 16 blocks (AVX2)
#define BS_T uint64_t
#define BS(name) prince_bs64_##name
#define BS_ATTR
#define BS_LOAD(in, j) load64_be((in) + 8 * (j))
#define BS_STORE(out, j, w) store64_be((w), (out) + 8 * (j))
#include "prince_bitslice.inc"
#undef BS_T
#undef BS
#undef BS_ATTR
#undef BS_LOAD
#undef BS_STORE

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define PRINCE_HAVE_AVX2 1
typedef uint64_t prince_v4_t __attribute__((vector_size(32)));
#define BS_T prince_v4_t
#define BS(name) prince_bs256_##name
#define BS_ATTR __attribute__((target("avx2")))
#define BS_LOAD(in, j) ((prince_v4_t){ load64_be((in) + 8 * (j)), load64_be((in) + 8 * (4 + (j))), \
                                       load64_be((in) + 8 * (8 + (j))), load64_be((in) + 8 * (12 + (j))) })
#define BS_STORE(out, j, w) do { for (int l = 0; l < 4; l++) store64_be((w)[l], (out) + 8 * (4 * l + (j))); } while (0)
#include "prince_bitslice.inc"
#undef BS_T
#undef BS
#undef BS_ATTR
#undef BS_LOAD
#undef BS_STORE
#endif

static void to_planes(uint64_t key, uint64_t planes[4]) {
    for (int b = 0; b < 4; b++) {
        planes[b] = REP16(prince_bs64_compress(key >> b));
    }
}

static void crypt_blocks(const prince_ctx_t *ctx, const uint64_t kp[12][4], int decrypt,
                         const uint8_t *in, uint8_t *out, size_t nblocks) {
    if (!ctx || !in || !out) return;

#ifdef PRINCE_HAVE_AVX2
    if (ctx->use_avx2) {
        for (; nblocks >= 16; nblocks -= 16, in += 128, out += 128) {
            prince_bs256_crypt(kp, in, out);
        }
    }
#endif
    for (; nblocks >= 4; nblocks -= 4, in += 32, out += 32) {
        prince_bs64_crypt(kp, in, out);
    }
    for (; nblocks > 0; nblocks--, in += 8, out += 8) {
        if (decrypt)
            prince_decrypt_block(ctx, in, out);
        else
            prince_encrypt_block(ctx, in, out);
    }
}

void prince_set_key(prince_ctx_t *ctx, const uint8_t key[PRINCE_KEY_SIZE]) {
    if (!ctx || !key) return;
    ctx->k0 = load64_be(key);
    ctx->k0_prime = compute_k0_prime(ctx->k0);
    ctx->k1 = load64_be(key + 8);

    // Decryption uses k1 ^ alpha and swaps k0 and k0'
    const uint64_t k1d = ctx->k1 ^ PRINCE_ALPHA;
    for (int r = 0; r < 12; r++) {
        uint64_t ke = ctx->k1 ^ PRINCE_RC[r];
        uint64_t kd = k1d ^ PRINCE_RC[r];
        if (r == 0) { ke ^= ctx->k0; kd ^= ctx->k0_prime; }
        if (r == 11) { ke ^= ctx->k0_prime; kd ^= ctx->k0; }
        to_planes(ke, ctx->kp_enc[r]);
        to_planes(kd, ctx->kp_dec[r]);
    }

#ifdef PRINCE_HAVE_AVX2
    ctx->use_avx2 = __builtin_cpu_supports("avx2") ? 1 : 0;
#else
    ctx->use_avx2 = 0;
#endif
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

void prince_encrypt_blocks(const prince_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t nblocks) {
    if (!ctx) return;
    crypt_blocks(ctx, ctx->kp_enc, 0, in, out, nblocks);
}

void prince_decrypt_blocks(const prince_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t nblocks) {
    if (!ctx) return;
    crypt_blocks(ctx, ctx->kp_dec, 1, in, out, nblocks);
}
