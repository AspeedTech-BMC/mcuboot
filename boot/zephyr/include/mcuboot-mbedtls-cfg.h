/*
 *  Copyright (C) 2018 Open Source Foundries Limited
 *  SPDX-License-Identifier: Apache-2.0
 */

#ifndef _MCUBOOT_MBEDTLS_CONFIG_
#define _MCUBOOT_MBEDTLS_CONFIG_

/**
 * @file
 *
 * This is the top-level mbedTLS configuration file for MCUboot. The
 * configuration depends on the signature type, so this file just
 * pulls in the right header depending on that setting.
 */

/*
 * IMPORTANT:
 *
 * If you put any "generic" definitions in here, make sure to update
 * the simulator build.rs accordingly.
 */

#if defined(CONFIG_BOOT_SIGNATURE_TYPE_RSA) || defined(CONFIG_BOOT_ENCRYPT_RSA)
#include "config-rsa.h"
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256) || \
      defined(CONFIG_BOOT_ENCRYPT_EC256) || \
      (defined(CONFIG_BOOT_ENCRYPT_X25519) && !defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519))
#include "config-asn1.h"
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519)
#include "config-ed25519.h"
#else
#error "Cannot configure mbedTLS; signature type is unknown."
#endif


#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PEM_CERTIFICATE_FORMAT
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_PK_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_SHA1_C

// Configs for reducing firmware image size
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0
#define MBEDTLS_SHA1_PROCESS_ALT
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SHA512_SMALLER

// Using ASPEED crypto engine to replace mbedtls function
#define MBEDTLS_SHA1_ALT
//#define MBEDTLS_SHA256_ALT
//#define MBEDTLS_SHA512_ALT

#endif
