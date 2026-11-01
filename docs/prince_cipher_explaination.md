# PRINCE

This document gives an explanation on how the PRINCE cipher works.


## Intruduction

PRINCE was introduced in 2012 with the goal of being a low-latency block cipher suitable for pervasive computing and hardware that needs to encrypt data almost instantaneously, ideally within a single clock cicle.
Unlike many lightweight ciphers that focus on minimizing area (like PRESENT), PRINCE prioritizes speed and low latency by using a very small number of rounds and simple, fast operations.

A major challenge in block cipher design is that decryption ofter requires a separate, reversed circuit, which doubles the hardware cost. PRINCE solves this with a property called **a-reflection**, which makes decryption almost identical to encryption, just with a slightly modified key.


## The Overall Structure: FX Construction

PRINCE uses a **128-bit key** and a **64-bit block size**. It follows the **FX Construction**, which is a general method for building a cipher from a smaller core function.

- **Key Splitting:** the 128-bit key, `k`, is split into two 64-bit halves: `k0` and `k1`.
- **Core and Whitening:** the cipher uses a core function, **PRINCE_core**, which is a 64-bit block cipher itself. This code is "wrapped" by the other key halves. The `k0` half (and a derived, `k0'`) is used for **pre- and post-whitening**, which are simple XOR operations before and after the core. The `k1` half is used inside the core rounds.

The overall encryption looks like this:
`Ciphertext = k0' ⊕ PRINCE_core(Plaintext ⊕ k0, k1)`

This structure is simple but effective, providing the main diffusion and confusion within the core, while the whitening keys add an extra layer of security.


## Inside the Core: the PRINCE_core Rounds

The [original paper](prince_cipher_paper.pdf), Section 2, page 4, defines PRINCE_core as a **12-round Substitution-Permutation Network (SPN)**. The implementation groups its operations into **5 forward rounds, a middle transformation, and 5 backwards rounds**. The middle transformation contains two non-linear layers, S and inverse S, so these eleven groups include all twelve non-linear layers. This symmetric structure supports the a-reflection property; no round is missing from the code.

The regular rounds use the following operations, designed for short logic depth in hardware:
1. **S-box Layer (S):** every 4-bit nibble in the state is substituted using a single **4x4-bit S-box**. This provides non-linearity and confusion.
2. **Linear Layer (M'):** this layer diffuses the bits across the 64-bit state. It uses two **16x16 binary matrices**, `M0` and `M1`. The state is split into four 16-bit chuncks. `M0` is applied to chunks 1 and 4, and `M1` to chunks 2 and 3.
3. **ShiftRows (SR):** this operation, identical in concept to the one in AES, shuffles the nibbles across the 4x4 state matrix. This ensures that nibbles affected by one S-box are spread to different columns for the next round.
4. **Round Constant XOR (RC_i):** a unique 64-bit constant is XORed into the state each round to disrupt any inherent symmetries.
5. **Round Key XOR (k1):** the core key, `k1`, is XORed into the state every round.

The **forward rounds** apply these operations in order: S -> M' -> ShiftRows -> XOR RC -> XOR k1. The **backwards rounds** apply them in reverse order using the inverse operations.

The **middle transformation** is keyless and provides the crucial link for the reflection property. It consists of three operations: a forward S-box layer, the M' matrix multiplication and an inverse S-box layer.

## Test Vectors

Vectors 1–5 in `tests/vectors/prince_kat.h` come from Appendix A of the [original paper](prince_cipher_paper.pdf), page 19. Vectors 6–9 were supplied through ChatGPT Sol 6.1 as additional test cases.