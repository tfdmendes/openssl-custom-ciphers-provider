// Bitsliced PRINCE, included by prince.c with BS_T, BS, BS_ATTR, BS_LOAD and BS_STORE defined
// Plane b has bit b of every nibble, 4 blocks per uint64_t (16 bits each)

#define BS_ROTG(x, r)   ((((x) << (r)) & REP4((0xFu << (r)) & 0xFu)) | (((x) >> (4 - (r))) & REP4((1u << (r)) - 1u)))
#define BS_ROTL16(x, s) ((((x) << (s)) & REP16((0xFFFFu << (s)) & 0xFFFFu)) | (((x) >> (16 - (s))) & REP16((1u << (s)) - 1u)))

// Bits 0, 4, ..., 60 to bits 0..15
static BS_ATTR inline BS_T BS(compress)(BS_T x) {
    BS_T t = x & REP4(1);
    t = (t | (t >> 3)) & UINT64_C(0x0303030303030303);
    t = (t | (t >> 6)) & UINT64_C(0x000F000F000F000F);
    t = (t | (t >> 12)) & UINT64_C(0x000000FF000000FF);
    return (t | (t >> 24)) & UINT64_C(0xFFFF);
}

// Bits 0..15 to bits 0, 4, ..., 60
static BS_ATTR inline BS_T BS(spread)(BS_T t) {
    t = (t | (t << 24)) & UINT64_C(0x000000FF000000FF);
    t = (t | (t << 12)) & UINT64_C(0x000F000F000F000F);
    t = (t | (t << 6)) & UINT64_C(0x0303030303030303);
    return (t | (t << 3)) & REP4(1);
}

static BS_ATTR inline void BS(sbox)(BS_T s[4]) {
    BS_T y0, y1, y2, y3;
    PRINCE_SBOX_BF(BS_T, s[0], s[1], s[2], s[3], ~UINT64_C(0), y0, y1, y2, y3);
    s[0] = y0; s[1] = y1; s[2] = y2; s[3] = y3;
}

static BS_ATTR inline void BS(isbox)(BS_T s[4]) {
    BS_T y0, y1, y2, y3;
    PRINCE_ISBOX_BF(BS_T, s[0], s[1], s[2], s[3], ~UINT64_C(0), y0, y1, y2, y3);
    s[0] = y0; s[1] = y1; s[2] = y2; s[3] = y3;
}

static BS_ATTR inline void BS(m_prime)(BS_T s[4]) {
    for (int b = 0; b < 4; b++) {
        BS_T x = s[b], r1 = BS_ROTG(x, 1), r2 = BS_ROTG(x, 2), r3 = BS_ROTG(x, 3);
        s[b] = x ^ r1 ^ r2 ^ r3 ^ (x & PRINCE_PM[0][b]) ^ (r1 & PRINCE_PM[1][b]) ^
               (r2 & PRINCE_PM[2][b]) ^ (r3 & PRINCE_PM[3][b]);
    }
}

static BS_ATTR inline void BS(shift_rows)(BS_T s[4]) {
    for (int b = 0; b < 4; b++) {
        BS_T x = s[b];
        s[b] = (x & REP16(0x8888)) | BS_ROTL16(x & REP16(0x4444), 4) |
               BS_ROTL16(x & REP16(0x2222), 8) | BS_ROTL16(x & REP16(0x1111), 12);
    }
}

static BS_ATTR inline void BS(inv_shift_rows)(BS_T s[4]) {
    for (int b = 0; b < 4; b++) {
        BS_T x = s[b];
        s[b] = (x & REP16(0x8888)) | BS_ROTL16(x & REP16(0x4444), 12) |
               BS_ROTL16(x & REP16(0x2222), 8) | BS_ROTL16(x & REP16(0x1111), 4);
    }
}

static BS_ATTR inline void BS(add_key)(BS_T s[4], const uint64_t k[4]) {
    for (int b = 0; b < 4; b++) s[b] ^= k[b];
}

// kp[0] and kp[11] already include k0 and k0'
static BS_ATTR void BS(crypt)(const uint64_t kp[12][4], const uint8_t *in, uint8_t *out) {
    BS_T w[4], s[4];

    for (int j = 0; j < 4; j++) w[j] = BS_LOAD(in, j);
    for (int b = 0; b < 4; b++)
        s[b] = BS(compress)(w[0] >> b) | (BS(compress)(w[1] >> b) << 16) |
               (BS(compress)(w[2] >> b) << 32) | (BS(compress)(w[3] >> b) << 48);

    BS(add_key)(s, kp[0]);
    for (int r = 1; r < 6; r++) {
        BS(sbox)(s); BS(m_prime)(s); BS(shift_rows)(s); BS(add_key)(s, kp[r]);
    }
    BS(sbox)(s); BS(m_prime)(s); BS(isbox)(s);
    for (int r = 6; r < 11; r++) {
        BS(add_key)(s, kp[r]); BS(inv_shift_rows)(s); BS(m_prime)(s); BS(isbox)(s);
    }
    BS(add_key)(s, kp[11]);

    for (int j = 0; j < 4; j++) {
        w[j] = BS(spread)((s[0] >> (16 * j)) & UINT64_C(0xFFFF)) |
               (BS(spread)((s[1] >> (16 * j)) & UINT64_C(0xFFFF)) << 1) |
               (BS(spread)((s[2] >> (16 * j)) & UINT64_C(0xFFFF)) << 2) |
               (BS(spread)((s[3] >> (16 * j)) & UINT64_C(0xFFFF)) << 3);
        BS_STORE(out, j, w[j]);
    }
}

#undef BS_ROTG
#undef BS_ROTL16
