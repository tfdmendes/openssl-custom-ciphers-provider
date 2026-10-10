# Rabbit

This document gives an explanation on how the Rabbit cipher works.


## Introduction

Rabbit was introduced in 2003 at FSE and was later selected for the final **eSTREAM portfolio** (software profile). Its goal is to be a very fast stream cipher in software, so it only uses simple 32-bit operations: additions, XORs, rotations and one 32x32 -> 64-bit multiplication per state word.
Since it does not use any lookup tables (no S-boxes), it is also resistant to cache timing attacks, which is a problem for table based ciphers like AES in software.

The cipher is described in [RFC 4503](https://www.rfc-editor.org/rfc/rfc4503.html), and no attack better than brute force is known against the full cipher.


## The Overall Structure

Rabbit uses a **128-bit key** and an optional **64-bit IV**. Like any stream cipher, it generates a keystream that is XORed with the plaintext, so encryption and decryption are the same operation:
`Ciphertext = Plaintext ⊕ Keystream`

Each iteration of the cipher produces **128 bits of keystream**.

The internal state has 513 bits:
- **State words:** eight 32-bit words, `X0` to `X7`.
- **Counters:** eight 32-bit words, `C0` to `C7`.
- **Carry bit:** one bit, `b`, that is kept between counter updates.


## Inside an Iteration

Every iteration of the system consists of two steps:
1. **Counter Update:** each counter `Cj` is increased by a fixed constant `Aj`, plus the carry of the previous addition. The last carry is stored in `b` for the next iteration. This works like a single big 256-bit counter, and it guarantees that the state has a very long period.
2. **Next-State Function:** for every pair `(Xj, Cj)` the **g function** is computed: `g(u, v) = LSW((u+v)^2) ⊕ MSW((u+v)^2)`. The 32-bit sum is squared into 64 bits and the low and high halves are XORed. This is the only non-linear part of Rabbit. The new `Xj` values are then sums of three `g` results, some of them rotated by 8 or 16 bits, which mixes every state word with its neighbours.


## Key Setup

1. The 128-bit key is split into eight 16-bit subkeys, `K0` to `K7`.
2. The state words and the counters are filled by joining pairs of subkeys (with different rules for even and odd `j`).
3. The system is iterated **4 times**.
4. Each counter is XORed with a state word, `Cj = Cj ⊕ X(j+4 mod 8)`, so the counters can not be recovered from the key alone.

The state after this is called the **master state**.


## IV Setup

The 64-bit IV is XORed into the counters of the master state (each counter gets 32 bits of the IV) and the system is iterated **4 more times**.
Since it always starts from the master state, the IV can be changed without repeating the key setup. The same IV must never be used twice with the same key.


## Keystream Extraction

After each iteration, the 128-bit keystream block `S` is built from 16-bit halves of the state words, for example:
`S[15..0] = X0[15..0] ⊕ X5[31..16]`

When the message is not a multiple of 16 bytes, the unused bytes of the last block are kept for the next call, so a message can be encrypted in several parts and still give the same result.
