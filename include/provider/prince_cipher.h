/**
 * @file prince_cipher.h
 * @brief Function tables of the PRINCE algorithms (one per mode).
 *
 * provider.c pairs each table with a name in the OSSL_ALGORITHM list.
 */

#ifndef PROVIDER_PRINCE_CIPHER_H
#define PROVIDER_PRINCE_CIPHER_H

#include <openssl/core.h>

extern const OSSL_DISPATCH prince_ecb_functions[];
extern const OSSL_DISPATCH prince_cbc_functions[];
extern const OSSL_DISPATCH prince_ctr_functions[];
extern const OSSL_DISPATCH prince_ofb_functions[];
extern const OSSL_DISPATCH prince_cfb_functions[];

#endif /* PROVIDER_PRINCE_CIPHER_H */
