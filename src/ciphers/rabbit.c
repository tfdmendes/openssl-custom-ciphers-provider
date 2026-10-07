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