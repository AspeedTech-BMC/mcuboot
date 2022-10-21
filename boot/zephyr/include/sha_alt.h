#include <zephyr.h>
#include <crypto/hash_structs.h>
#include "mcuboot-mbedtls-cfg.h"

#ifndef MBEDTLS_SHA_ALT_H
#define MBEDTLS_SHA_ALT_H

#if defined(MBEDTLS_SHA1_ALT) || defined(MBEDTLS_SHA256_ALT) || defined(MBEDTLS_SHA512_ALT)
typedef struct mbedtls_sha_context
{
	struct hash_ctx ini;
	struct hash_pkt pkt;
	const struct device *dev;
	uint8_t digest[64];
	enum hash_algo algo;
} mbedtls_sha_context;
#endif

#endif /* MBEDTLS_SHA_ALT_H */
