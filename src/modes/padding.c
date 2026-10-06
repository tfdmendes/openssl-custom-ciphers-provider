#include "modes/padding.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int pkcs7_pad(const uint8_t *in, size_t in_len, size_t block_size, uint8_t *out, size_t *out_len) {
    if (!out || !out_len || block_size == 0 || block_size > 255) {
        return -1;
    }

    uint8_t pad_val = (uint8_t)(block_size - (in_len % block_size));
    size_t total_len = in_len + pad_val;

    if (in && in != out) {
        memcpy(out, in, in_len);
    }
    memset(out + in_len, pad_val, pad_val);

    *out_len = total_len;
    return 0;
}

int pkcs7_unpad(const uint8_t *in, size_t in_len, size_t block_size, size_t *out_len) {
    if (!in || !out_len || in_len == 0 || block_size == 0 || (in_len % block_size) != 0) {
        return -1;
    }

    uint8_t pad_val = in[in_len - 1];

    if (pad_val == 0 || pad_val > block_size || pad_val > in_len) {
        return -1;
    }

    /* Verify all padding bytes match pad_val */
    for (size_t i = 0; i < pad_val; i++) {
        if (in[in_len - 1 - i] != pad_val) {
            return -1;
        }
    }

    *out_len = in_len - pad_val;
    return 0;
}
