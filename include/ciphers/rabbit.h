#ifndef RABBIT_H
#define RABBIT_H

#include <stdint.h>

#define RABBIT_WORD_SIZE 0x100000000
#define RABBIT_KEY_SIZE 16   // bytes
#define RABBIT_IV_SIZE 8     // bytes


/**
 * @brief Stores the internal Rabbit state
 *
 * x holds eight 32-bit state words
 * c holds eight 32-bit counter words
 * carry holds the carry bit preserved between counter updates
 */
typedef struct {
    uint32_t x[8];
    uint32_t c[8];
    uint32_t carry;
} rabbit_state_t;



#endif