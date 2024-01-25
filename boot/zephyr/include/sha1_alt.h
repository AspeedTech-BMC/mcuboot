#include <zephyr/kernel.h>
#include <zephyr/crypto/hash.h>
#include "sha_alt.h"

#ifndef MBEDTLS_SHA1_ALT_H
#define MBEDTLS_SHA1_ALT_H

#if defined(MBEDTLS_SHA1_ALT)
typedef struct mbedtls_sha_context mbedtls_sha1_context;
#endif

#endif /* MBEDTLS_SHA1_ALT_H */
