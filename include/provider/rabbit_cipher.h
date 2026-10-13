/**
 * @file rabbit_cipher.h
 * @brief Function table of the Rabbit stream cipher.
 *
 * provider.c pairs the table with a name in the OSSL_ALGORITHM list.
 */

#ifndef PROVIDER_RABBIT_CIPHER_H
#define PROVIDER_RABBIT_CIPHER_H

#include <openssl/core.h>

extern const OSSL_DISPATCH rabbit_functions[];

#endif /* PROVIDER_RABBIT_CIPHER_H */
