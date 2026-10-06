#ifndef PADDING_H
#define PADDING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Applies PKCS#7 padding to a buffer.
 * in: input plaintext buffer
 * in_len: length of input data
 * block_size: cipher block size in bytes (e.g. 8 for PRINCE)
 * out: buffer receiving padded length is stored
 *
 * Returns 0 on success, -1 on error
 */
int pkcs7_pad(const uint8_t *in, size_t in_len, size_t block_size, uint8_t *out, size_t *out_len);

/*
 * Validates and removes PKCS#7 padding from a buffer.
 * in: padded ciphertext/decrypted buffer (length must be a multiple of block size)
 * in_len: length of padded data
 * block_size: cipher block size in bytes
 * out_len: pointer where original unpadded length is stored
 *
 * Returns 0 on valid padding, -1 on invalid padding.
 */
int pkcs7_unpad(const uint8_t *in, size_t in_len, size_t block_size, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* PADDING_H */
