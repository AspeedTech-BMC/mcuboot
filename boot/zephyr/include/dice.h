#pragma once
#include "bootutil/bootutil.h"
#include <stddef.h>

#define PAGE_SIZE                         (4 * 1024)

/*
 Key usage definition and keyCertSign usage are extracted from rfc5280
 KeyUsage ::= BIT STRING {
      digitalSignature        (0),
      nonRepudiation          (1), -- recent editions of X.509 have
                                   -- renamed this bit to contentCommitment
      keyEncipherment         (2),
      dataEncipherment        (3),
      keyAgreement            (4),
      keyCertSign             (5),
      cRLSign                 (6),
      encipherOnly            (7),
      decipherOnly            (8) }

 Note:
 The keyCertSign bit is asserted when the subject public key is
 used for verifying signatures on public key certificates.  If the
 keyCertSign bit is asserted, then the cA bit in the basic
 constraints extension (Section 4.2.1.9) MUST also be asserted.

 So, the keyCertSign bit should not be set if the cA bit is set to false.
 */

typedef enum {
	KEY_USAGE_ENCIPHER_ONLY = 0x1,
	KEY_USAGE_CRLSIGN = 0x2,
	KEY_USAGE_KEYCERTSIGN = 0x4,
	KEY_USAGE_KEYAGREEMENT = 0x8,
	KEY_USAGE_DATAENCIPHERMENT = 0x10,
	KEY_USAGE_KEYENCIPHERMENT = 0x20,
	KEY_USAGE_NONREPUDIATION = 0x40,
	KEY_USAGE_DIGITALSIGNATURE = 0x80,
} X509_KEY_USAGE;

int dice_start(size_t cert_type, struct boot_rsp *boot_rsp);

