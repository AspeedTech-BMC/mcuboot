#include <zephyr.h>
#include <crypto/hash_structs.h>
#include "sha_alt.h"

#ifndef MBEDTLS_SHA256_ALT_H
#define MBEDTLS_SHA256_ALT_H

#if defined(MBEDTLS_SHA256_ALT)
typedef struct mbedtls_sha_context mbedtls_sha256_context;
#endif

#endif /* MBEDTLS_SHA256_ALT_H */
