#include <zephyr.h>
#include <crypto/hash_structs.h>
#include "sha_alt.h"

#ifndef MBEDTLS_SHA512_ALT_H
#define MBEDTLS_SHA512_ALT_H

#if defined(MBEDTLS_SHA512_ALT)
typedef struct mbedtls_sha_context mbedtls_sha512_context;
#endif

#endif /* MBEDTLS_SHA512_ALT_H */
