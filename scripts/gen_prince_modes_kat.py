#!/usr/bin/env python3
# Generates tests/vectors/prince_modes_kat.h (PRINCE ECB/CBC/CTR/OFB/CFB vectors)
#
# There are no official vectors for PRINCE in modes of operation, so we compute
# them here with a separate implementation of PRINCE written from the paper
# (Borghoff et al., ASIACRYPT 2012), not from src/ciphers/prince.c. It is
# checked against the paper's test vectors before anything is written.
#
# ECB and CBC use PKCS#7 padding. CTR uses the 8-byte IV as a big-endian
# counter (+1 per block), like in NIST SP 800-38A
# OFB feeds back encrypted IV blocks; CFB feeds back full ciphertext blocks
#
# python3 scripts/gen_prince_modes_kat.py > tests/vectors/prince_modes_kat.h

import sys

RC = [
    0x0000000000000000, 0x13198A2E03707344, 0xA4093822299F31D0,
    0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C,
    0x7EF84F78FD955CB1, 0x85840851F1AC43AA, 0xC882D32F25323C54,
    0x64A51195E0E3610D, 0xD3B5A399CA0C2399, 0xC0AC29B7C97C50DD,
]
ALPHA = 0xC0AC29B7C97C50DD
SBOX = [0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4]
SBOX_INV = [SBOX.index(i) for i in range(16)]
SR = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
SR_INV = [SR.index(i) for i in range(16)]


def m(i):
    # M0..M3 from the paper: identity with the i-th 1 removed
    return [[1 if (r == c and r != i) else 0 for c in range(4)] for r in range(4)]


def block_matrix(rows):
    out = [[0] * 16 for _ in range(16)]
    for br, row in enumerate(rows):
        for bc, idx in enumerate(row):
            sub = m(idx)
            for r in range(4):
                for c in range(4):
                    out[4 * br + r][4 * bc + c] = sub[r][c]
    return out


M_HAT0 = block_matrix([[0, 1, 2, 3], [1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2]])
M_HAT1 = block_matrix([[1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2], [0, 1, 2, 3]])


def to_bits(x):
    return [(x >> (63 - i)) & 1 for i in range(64)]


def from_bits(bits):
    x = 0
    for b in bits:
        x = (x << 1) | b
    return x


def m_prime(x):
    # M' = diag(M_hat0, M_hat1, M_hat1, M_hat0)
    bits = to_bits(x)
    out = []
    for blk, mat in enumerate([M_HAT0, M_HAT1, M_HAT1, M_HAT0]):
        v = bits[16 * blk:16 * blk + 16]
        out += [sum(mat[r][c] & v[c] for c in range(16)) & 1 for r in range(16)]
    return from_bits(out)


def nibbles(x):
    return [(x >> (60 - 4 * i)) & 0xF for i in range(16)]


def from_nibbles(n):
    x = 0
    for v in n:
        x = (x << 4) | v
    return x


def s(x, box):
    return from_nibbles([box[v] for v in nibbles(x)])


def perm(x, p):
    n = nibbles(x)
    return from_nibbles([n[p[i]] for i in range(16)])


def core(x, k1):
    x ^= k1 ^ RC[0]
    for r in range(1, 6):
        x = perm(m_prime(s(x, SBOX)), SR)
        x ^= k1 ^ RC[r]
    x = s(m_prime(s(x, SBOX)), SBOX_INV)
    for r in range(6, 11):
        x ^= k1 ^ RC[r]
        x = s(m_prime(perm(x, SR_INV)), SBOX_INV)
    return x ^ k1 ^ RC[11]


def keys(key):
    k0 = int.from_bytes(key[:8], "big")
    k1 = int.from_bytes(key[8:], "big")
    k0p = ((k0 >> 1) | (k0 << 63)) & (2**64 - 1) ^ (k0 >> 63)
    return k0, k0p, k1


def enc_block(key, blk):
    k0, k0p, k1 = keys(key)
    x = int.from_bytes(blk, "big")
    return (core(x ^ k0, k1) ^ k0p).to_bytes(8, "big")


def dec_block(key, blk):
    k0, k0p, k1 = keys(key)
    x = int.from_bytes(blk, "big")
    return (core(x ^ k0p, k1 ^ ALPHA) ^ k0).to_bytes(8, "big")


# Test vectors from the paper: plaintext, k0, k1, ciphertext
PAPER_VECTORS = [
    ("0000000000000000", "0000000000000000", "0000000000000000", "818665aa0d02dfda"),
    ("ffffffffffffffff", "0000000000000000", "0000000000000000", "604ae6ca03c20ada"),
    ("0000000000000000", "ffffffffffffffff", "0000000000000000", "9fb51935fc3df524"),
    ("0000000000000000", "0000000000000000", "ffffffffffffffff", "78a54cbe737bb7ef"),
    ("0123456789abcdef", "0000000000000000", "fedcba9876543210", "ae25ad3ca8fa9ccf"),
]


def self_test():
    for pt, k0, k1, ct in PAPER_VECTORS:
        key = bytes.fromhex(k0 + k1)
        got = enc_block(key, bytes.fromhex(pt))
        if got.hex() != ct or dec_block(key, got).hex() != pt:
            sys.exit(f"PRINCE test vector failed: pt={pt} got={got.hex()} expected={ct}")


def pkcs7(data):
    n = 8 - len(data) % 8
    return data + bytes([n]) * n


def ecb(key, pt):
    p = pkcs7(pt)
    return b"".join(enc_block(key, p[i:i + 8]) for i in range(0, len(p), 8))


def cbc(key, iv, pt):
    p, prev, out = pkcs7(pt), iv, b""
    for i in range(0, len(p), 8):
        prev = enc_block(key, bytes(a ^ b for a, b in zip(p[i:i + 8], prev)))
        out += prev
    return out


def ctr(key, iv, pt):
    ctr_val, ks = int.from_bytes(iv, "big"), b""
    while len(ks) < len(pt):
        ks += enc_block(key, ctr_val.to_bytes(8, "big"))
        ctr_val = (ctr_val + 1) % 2**64
    return bytes(a ^ b for a, b in zip(pt, ks))


def ofb(key, iv, pt):
    feedback, out = iv, b""
    for i in range(0, len(pt), 8):
        feedback = enc_block(key, feedback)
        out += bytes(a ^ b for a, b in zip(pt[i:i + 8], feedback))
    return out


def cfb(key, iv, pt):
    feedback, out = iv, b""
    for i in range(0, len(pt), 8):
        stream = enc_block(key, feedback)
        feedback = bytes(a ^ b for a, b in zip(pt[i:i + 8], stream))
        out += feedback
    return out


KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("0102030405060708")
IV_WRAP = bytes.fromhex("fffffffffffffffe")  # counter overflows on the 3rd block
# empty, 1 byte, 1 block - 1, 1 block, 1 block + 1, several blocks
LENGTHS = [0, 1, 7, 8, 9, 16, 37, 64]


def plaintext(n):
    return bytes((i * 31 + 7) & 0xFF for i in range(n))


def c_bytes(b):
    if not b:
        return "{0}"
    return "{" + ",".join(f"0x{x:02x}" for x in b) + "}"


def main():
    self_test()
    rows = []
    for n in LENGTHS:
        pt = plaintext(n)
        rows.append(("PRINCE_MODE_ECB", IV, pt, ecb(KEY, pt)))
        rows.append(("PRINCE_MODE_CBC", IV, pt, cbc(KEY, IV, pt)))
        rows.append(("PRINCE_MODE_CTR", IV, pt, ctr(KEY, IV, pt)))
        rows.append(("PRINCE_MODE_OFB", IV, pt, ofb(KEY, IV, pt)))
        rows.append(("PRINCE_MODE_CFB", IV, pt, cfb(KEY, IV, pt)))
    pt = plaintext(37)
    rows.append(("PRINCE_MODE_CTR", IV_WRAP, pt, ctr(KEY, IV_WRAP, pt)))

    max_len = max(len(r[3]) for r in rows)
    print("""#ifndef PRINCE_MODES_KAT_H
#define PRINCE_MODES_KAT_H

#include <stdint.h>
#include <stddef.h>

/*
 * PRINCE test vectors for ECB, CBC, CTR, OFB and full-block CFB
 * Generated with scripts/gen_prince_modes_kat.py, don't edit by hand
 *
 * ECB/CBC use PKCS#7 padding, CTR uses the IV as a big-endian counter
 * OFB/CFB preserve the input length, CFB uses 64-bit segments
 * Plaintext byte i is (i * 31 + 7) & 0xff
 */

typedef enum { PRINCE_MODE_ECB, PRINCE_MODE_CBC, PRINCE_MODE_CTR, PRINCE_MODE_OFB, PRINCE_MODE_CFB } prince_mode_t;
""")
    print(f"#define PRINCE_MODES_KAT_MAX_LEN {max_len}\n")
    print("typedef struct {")
    print("    prince_mode_t mode;")
    print("    uint8_t key[16];")
    print("    uint8_t iv[8];")
    print("    size_t pt_len;")
    print("    size_t ct_len;")
    print("    uint8_t ct[PRINCE_MODES_KAT_MAX_LEN];")
    print("} prince_modes_kat_vector_t;\n")
    print("static const prince_modes_kat_vector_t PRINCE_MODES_KAT_VECTORS[] = {")
    for mode, iv, pt, ct in rows:
        print(f"    {{ {mode}, {c_bytes(KEY)},")
        print(f"      {c_bytes(iv)}, {len(pt)}, {len(ct)},")
        print(f"      {c_bytes(ct)} }},")
    print("};\n")
    print("#define PRINCE_MODES_KAT_COUNT (sizeof(PRINCE_MODES_KAT_VECTORS) / sizeof(PRINCE_MODES_KAT_VECTORS[0]))\n")
    print("#endif /* PRINCE_MODES_KAT_H */")


if __name__ == "__main__":
    main()
