#include <zephyr.h>
#include <logging/log.h>
#include <drivers/flash.h>
#include <sys/base64.h>
#include <net/net_ip.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <mbedtls/base64.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "bootutil/image.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"
#include "dice.h"

MCUBOOT_LOG_MODULE_REGISTER(dice);

#define ASRT(_X)    if(!(_X))      {goto error;}
#define CHK(_X)     if(((_X)) < 0) {goto error;}
#define CHECK_SPACE(_X)      if((_X->length-_X->position)<32)        {goto error;}
#define CHECK_SPACE2(_X, _N) if(((_X->length-_X->position)+(_N))<32) {goto error;}

#define CDI_LENGTH                        64
#define CDI_ADDRESS                       0x79001800
#define SHA1_HASH_LENGTH                  20
#define SHA256_HASH_LENGTH                32
#define SHA384_HASH_LENGTH                48
#define ECDSA384_PRIVATE_KEY_SIZE         SHA384_HASH_LENGTH + 1
#define ECDSA384_PUBLIC_KEY_SIZE          SHA384_HASH_LENGTH * 2 + 1

#define X509_SERIAL_NUM_LENGTH            8

#define DER_MAX_PEM                       0x500
#define DER_MAX_TBS                       0x500
#define DER_MAX_NESTED                    0x10

#define RIOT_X509_KEY_USAGE               0x04    // keyCertSign
#define RIOT_X509_SNUM_LEN                0x08    // In bytes

#define CERT_INFO_MAGIC_NUM               0x43455254    // hex of 'CERT'
#define DEVID_CERT_ADDR                   0
#define ALIAS_CERT_ADDR                   0x2000
#define CERT_REGION_SIZE                  0x2000

#define BASE64_LEN(l) ((l == 0) ? (1) : (((((l - 1) / 3) + 1) * 4) + 1))

typedef struct {
	uint8_t *buffer;
	uint32_t length;
	uint32_t position;
	int collection_start[DER_MAX_NESTED];
	int collection_position;
} PFR_DER_CTX;

typedef struct {
	mbedtls_mpi r;
	mbedtls_mpi s;
} PFR_ECC_SIG;

typedef struct {
	uint16_t    hLen;
	uint16_t    fLen;
	const char *header;
	const char *footer;
} PEM_HDR_FOOTERS;

typedef struct {
	uint32_t magic;
	uint32_t length;
	uint8_t data[0x1000];
	uint8_t hash[SHA256_HASH_LENGTH];
} PFR_CERT_INFO;

typedef struct {
	PFR_CERT_INFO cert;
	uint8_t pubkey[ECDSA384_PUBLIC_KEY_SIZE];
	uint8_t cert_type;
} PFR_DEVID_CERT_INFO;

typedef struct {
	PFR_CERT_INFO cert;
	uint8_t privkey[ECDSA384_PRIVATE_KEY_SIZE];
	uint8_t pubkey[ECDSA384_PUBLIC_KEY_SIZE];
} PFR_ALIAS_CERT_INFO;

typedef enum {
	CERT_INFO_VALID = 0,
	CERT_INFO_EMPTY_MAGIC,
	CERT_INFO_INVALID,
} cert_status;

enum cert_type {
	CERT_TYPE = 0,
	PUBLICKEY_TYPE,
	ECC_PRIVATEKEY_TYPE,
	CERT_REQ_TYPE,
	LAST_CERT_TYPE
};

uint8_t flash_buf[PAGE_SIZE] __attribute__((aligned(16), section(".nocache.bss")));

// OIDs
static int oid_ecdsa_with_sha384[] = { 1,2,840,10045,4,3,3,-1 };
static int oid_common_name[] = { 2,5,4,3,-1 };
static int oid_country_name[] = { 2,5,4,6,-1 };
static int oid_org_name[] = { 2,5,4,10,-1 };
static int oid_ec_pubkey[] = { 1,2,840,10045, 2,1,-1 };
static int oid_curve_ecdsa384[] = { 1,3,132,0,34,-1 };
static int oid_key_usage[] = { 2,5,29,15,-1 };
static int oid_ext_key_usage[] = { 2,5,29,37,-1 };
static int oid_client_auth[] = { 1,3,6,1,5,5,7,3,2,-1 };
static int oid_auth_key_identifier[] = { 2,5,29,35,-1 };
static int oid_basic_constraints[] = { 2,5,29,19,-1 };

static mbedtls_hmac_drbg_context hmac_drbg_ctx = {0};
static uint8_t cdi_digest[SHA384_HASH_LENGTH] = {0};
static uint8_t dev_fwid[SHA384_HASH_LENGTH] = {0};
static uint8_t alias_digest[SHA384_HASH_LENGTH] = {0};

uint8_t devid_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t devid_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};
uint8_t alias_priv_key_buf[ECDSA384_PRIVATE_KEY_SIZE] = {0};
uint8_t alias_pub_key_buf[ECDSA384_PUBLIC_KEY_SIZE] = {0};

PFR_DEVID_CERT_INFO devid_cert_info __attribute__((aligned(16), section(".nocache.bss")));
PFR_ALIAS_CERT_INFO alias_cert_info __attribute__((aligned(16), section(".nocache.bss")));
PFR_ALIAS_CERT_INFO fl_alias_cert_info __attribute__((aligned(16), section(".nocache.bss")));

#ifdef GEN_PEM_CERT
uint8_t alias_cert_pem[DER_MAX_PEM] = {0};
uint8_t devid_cert_pem[DER_MAX_PEM] = {0};
#endif


// We only have a small subset of potential PEM encodings
const PEM_HDR_FOOTERS pem_hf[LAST_CERT_TYPE] = {
	{28, 26, "-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n"},
	{27, 25, "-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n\0"},
	{31, 29, "-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n"},
	{36, 34, "-----BEGIN CERTIFICATE REQUEST-----\n", "-----END CERTIFICATE REQUEST-----\n"}
};

void x509_der_init_context(PFR_DER_CTX *ctx, uint8_t *buffer, uint32_t length)
{
	ctx->buffer = buffer;
	ctx->length = length;
	ctx->position = 0;
	memset(buffer, 0, length);
	for (int i = 0; i < DER_MAX_NESTED; i++) {
		ctx->collection_start[i] = -1;
	}
	ctx->collection_position = 0;
}

int x509_start_seq_or_set(PFR_DER_CTX *ctx, bool sequence)
{
	uint8_t tp = sequence ? 0x30 : 0x31;

	CHECK_SPACE(ctx);
	ASRT(ctx->collection_position < DER_MAX_NESTED);

	ctx->buffer[ctx->position++] = tp;
	ctx->collection_start[ctx->collection_position++] = ctx->position;
	return 0;
error:
	return -1;
}

int x509_add_int_from_array(PFR_DER_CTX *ctx, uint8_t *val, uint32_t bytes)
{
	uint32_t i, num_leading_zeros = 0;
	bool negative;

	ASRT(bytes < 128);
	CHECK_SPACE2(ctx, bytes);

	for (i = 0; i < bytes; i++) {
		if (val[i] != 0)
			break;

		num_leading_zeros++;
	}

	negative = val[num_leading_zeros] >= 128;
	ctx->buffer[ctx->position++] = 0x02;

	if (bytes == num_leading_zeros) {
		ctx->buffer[ctx->position++] = 1;
		ctx->buffer[ctx->position++] = 0;
	} else {
		if (negative) {
			ctx->buffer[ctx->position++] = (uint8_t)(bytes - num_leading_zeros + 1);
			ctx->buffer[ctx->position++] = 0;
		} else {
			ctx->buffer[ctx->position++] = (uint8_t)(bytes - num_leading_zeros);
		}

		for (i = num_leading_zeros; i < bytes; i++)
			ctx->buffer[ctx->position++] = val[i];
	}

	return 0;
error:
	return -1;
}

int x509_add_short_explicit_int(PFR_DER_CTX *ctx, int val)
{
	long valx;
	ASRT(val < 127);

	ctx->buffer[ctx->position++] = 0xA0;
	ctx->buffer[ctx->position++] = 3;

	valx = htonl(val);

	return (x509_add_int_from_array(ctx, (uint8_t *)&valx, 4));
error:
	return -1;
}

int x509_add_int(PFR_DER_CTX *ctx, int val)
{
	long valx = htonl(val);

	return (x509_add_int_from_array(ctx, (uint8_t *)&valx, 4));
}

int x509_add_bool(PFR_DER_CTX *ctx, bool val)
{
	CHECK_SPACE(ctx);
	ctx->buffer[ctx->position++] = 0x01;
	ctx->buffer[ctx->position++] = 0x01;
	ctx->buffer[ctx->position++] = (val == true) ? 0xFF : 0x00;

	return 0;
error:
	return -1;
}

int x509_add_oid(PFR_DER_CTX *ctx, int *values)
{
	int     j, k;
	int     lenPos, digitPos = 0;
	int     val, digit;
	int     num_values = 0;

	for (j = 0; j < 16; j++) {
		if (values[j] < 0)
			break;
		num_values++;
	}

	ASRT(num_values < 16);
	CHECK_SPACE(ctx);

	ctx->buffer[ctx->position++] = 6;

	// Save space for length (only <128 supported)
	lenPos = ctx->position;
	ctx->position++;

	// DER-encode the OID, first octet is special
	val = num_values == 1 ? 0 : values[1];
	ctx->buffer[ctx->position++] = (uint8_t)(values[0] * 40 + val);

	// Others are base-128 encoded with the most significant bit of each byte,
	// apart from the least significant byte, set to 1.
	if (num_values >= 2) {
		uint8_t digits[5] = { 0 };

		for (j = 2; j < num_values; j++) {
			digitPos = 0;
			val = values[j];

			// Convert to B128
			while (true) {
				digit = val % 128;
				digits[digitPos++] = (uint8_t)digit;
				val = val / 128;
				if (val == 0) {
					break;
				}
			}

			// Reverse into the buffer, setting the MSB as needed.
			for (k = digitPos - 1; k >= 0; k--) {
				val = digits[k];
				if (k != 0) {
					val += 128;
				}
				ctx->buffer[ctx->position++] = (uint8_t)val;
			}
			CHECK_SPACE(ctx);
		}
	}

	ctx->buffer[lenPos] = (uint8_t)(ctx->position - 1 - lenPos);
	return 0;
error:
	return -1;
}

int x509_get_int_encoded_num_bytes(int val)
{
	ASRT(val < 166536);
	if (val < 128) {
		return 1;
	}
	if (val < 256) {
		return 2;
	}
	return 3;
error:
	return -1;
}

int x509_encode_int(uint8_t *buf, int val)
{
	ASRT(val < 166536);
	if (val <128) {
		buf[0] = (uint8_t)val;
		return 0;
	}
	if (val < 256) {
		buf[0] = 0x81;
		buf[1] = (uint8_t)val;
		return 0;
	}
	buf[0] = 0x82;
	buf[1] = (uint8_t)(val / 256);
	buf[2] = val % 256;

	return 0;
error:
	return -1;
}

int x509_pop_nesting(PFR_DER_CTX *ctx)
{
	int start_pos, num_bytes, encoded_len_size;

	CHECK_SPACE(ctx);
	ASRT(ctx->collection_position > 0);

	start_pos = ctx->collection_start[--ctx->collection_position];
	num_bytes = ctx->position - start_pos;

	encoded_len_size = x509_get_int_encoded_num_bytes(num_bytes);

	memmove(ctx->buffer + start_pos + encoded_len_size,
			ctx->buffer + start_pos,
			num_bytes);

	x509_encode_int(ctx->buffer + start_pos, num_bytes);

	ctx->position += encoded_len_size;

	return 0;
error:
	return -1;
}

int x509_add_utf8_str(PFR_DER_CTX *ctx, uint8_t *str)
{
	uint32_t i, num_char = (uint32_t)strlen(str);

	ASRT(num_char < 127);
	CHECK_SPACE2(ctx, num_char);

	ctx->buffer[ctx->position++] = 0x0c;
	ctx->buffer[ctx->position++] = (uint8_t)num_char;

	for (i = 0; i < num_char; i++) {
		ctx->buffer[ctx->position++] = str[i];
	}
	return 0;
error:
	return -1;
}

int x509_add_x501_name(PFR_DER_CTX *ctx, uint8_t *common, uint8_t *org, uint8_t *country)
{
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_start_seq_or_set(ctx, false));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_common_name));
	CHK(x509_add_utf8_str(ctx, common));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_start_seq_or_set(ctx, false));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_country_name));
	CHK(x509_add_utf8_str(ctx, country));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_start_seq_or_set(ctx, false));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_org_name));
	CHK(x509_add_utf8_str(ctx, org));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	return 0;
error:
	return -1;
}

int x509_add_utc_time(PFR_DER_CTX *ctx, uint8_t *str)
{
	uint32_t i, num_char = (uint32_t)strlen(str);

	ASRT(num_char == 13);
	CHECK_SPACE(ctx);

	ctx->buffer[ctx->position++] = 0x17;
	ctx->buffer[ctx->position++] = (uint8_t)num_char;

	for (i = 0; i < num_char; i++) {
		ctx->buffer[ctx->position++] = str[i];
	}

	return 0;
error:
	return -1;
}

int x509_add_bit_str(PFR_DER_CTX *ctx, uint8_t *bit_str, uint32_t bit_str_num_bytes)
{
	int len = bit_str_num_bytes + 1;

	CHECK_SPACE2(ctx, bit_str_num_bytes);
	ctx->buffer[ctx->position++] = 0x03;
	x509_encode_int(ctx->buffer + ctx->position, len);
	ctx->position += x509_get_int_encoded_num_bytes(len);
	ctx->buffer[ctx->position++] = 0;
	memcpy(ctx->buffer + ctx->position, bit_str, bit_str_num_bytes);
	ctx->position += bit_str_num_bytes;

	return 0;
error:
	return -1;
}

int x509_add_oct_str(PFR_DER_CTX *ctx, uint8_t *oct_str, uint32_t oct_str_len)
{
	CHECK_SPACE2(ctx, oct_str_len);
	ctx->buffer[ctx->position++] = 0x04;
	x509_encode_int(ctx->buffer + ctx->position, oct_str_len);
	ctx->position += x509_get_int_encoded_num_bytes(oct_str_len);
	memcpy(ctx->buffer + ctx->position, oct_str, oct_str_len);
	ctx->position += oct_str_len;

	return 0;
error:
	return -1;
}

int x509_start_explicit(PFR_DER_CTX *ctx, uint32_t num)
{
	CHECK_SPACE(ctx);
	ASRT(ctx->collection_position < DER_MAX_NESTED);
	ctx->buffer[ctx->position++] = 0xA0 + (uint8_t)num;
	ctx->collection_start[ctx->collection_position++] = ctx->position;

	return 0;
error:
	return -1;
}

int x509_envelop_oct_str(PFR_DER_CTX *ctx)
{
	CHECK_SPACE(ctx);
	ASRT(ctx->collection_position < DER_MAX_NESTED);

	ctx->buffer[ctx->position++] = 0x04;
	ctx->collection_start[ctx->collection_position++] = ctx->position;

	return 0;
error:
	return -1;
}

int x509_envelop_bit_str(PFR_DER_CTX *ctx)
{
	CHECK_SPACE(ctx);
	ASRT(ctx->collection_position < DER_MAX_NESTED);

	ctx->buffer[ctx->position++] = 0x03;
	ctx->collection_start[ctx->collection_position++] = ctx->position;
	ctx->buffer[ctx->position++] = 0;

	return 0;
error:
	return -1;
}

int x509_tbs_to_cert(PFR_DER_CTX *ctx)
{
	ASRT(ctx->collection_position == 0);
	CHECK_SPACE(ctx);

	memmove(ctx->buffer + 1, ctx->buffer, ctx->position);
	ctx->position++;

	// sequence tag
	ctx->buffer[0] = 0x30;
	ctx->collection_start[ctx->collection_position++] = 1;

	return 0;
error:
	return -1;
}

int x509_der_to_pem(PFR_DER_CTX *ctx, uint32_t type, uint8_t *pem, uint32_t *length)
{
	uint32_t req_len, olen;
	uint32_t base64_len = BASE64_LEN(ctx->position);

	req_len = base64_len + pem_hf[type].hLen + pem_hf[type].fLen;

	if (length && (*length < req_len)) {
		*length = req_len;
		return -1;
	}

	memcpy(pem, pem_hf[type].header, pem_hf[type].hLen);
	pem += pem_hf[type].hLen;

	base64_encode(pem, DER_MAX_PEM, &olen, ctx->buffer, ctx->position);
	pem += base64_len;
	memcpy(pem, pem_hf[type].footer, pem_hf[type].fLen);
	pem += pem_hf[type].fLen;

	if (length)
		*length = req_len;

	return 0;
}

int x509_add_extentions(PFR_DER_CTX *ctx, uint8_t *devid_pub_key, uint32_t devid_pub_key_len,
		uint8_t *dev_fwid, uint32_t fwid_len)
{
	uint8_t auth_key_identifier[SHA1_HASH_LENGTH];
	uint8_t key_usage = RIOT_X509_KEY_USAGE;
	uint8_t ext_len = 1;


	mbedtls_sha1(devid_pub_key, devid_pub_key_len, auth_key_identifier);

	CHK(x509_start_explicit(ctx, 3));
	CHK(x509_start_seq_or_set(ctx, true));

	// key usage
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_key_usage));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_add_bit_str(ctx, &key_usage, ext_len));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	// extended key usage
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ext_key_usage));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_client_auth));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	// authority key identifier
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_auth_key_identifier));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_start_explicit(ctx, 0));
	CHK(x509_add_oct_str(ctx, auth_key_identifier, SHA1_HASH_LENGTH));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	// basic constraints
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_basic_constraints));
	// is critical
	CHK(x509_add_bool(ctx, true));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_start_seq_or_set(ctx, true));
	// cA = false
	CHK(x509_add_bool(ctx, false));
	CHK(x509_add_int(ctx, 1));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	return 0;
error:
	return -1;
}

int x509_get_alias_cert_tbs(PFR_DER_CTX *ctx, uint8_t *serial_num,
		uint8_t *alias_pub_key, uint8_t *devid_pub_key,
		uint8_t *dev_fwid, uint32_t fwid_len)
{
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_short_explicit_int(ctx, 2));
	CHK(x509_add_int_from_array(ctx, serial_num, X509_SERIAL_NUM_LENGTH));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ecdsa_with_sha384));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_x501_name(ctx, CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_NAME,
			CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_ORG,
			CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_COUNTRY));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_utc_time(ctx, CONFIG_ASPEED_DICE_CERT_VALID_FROM));
	CHK(x509_add_utc_time(ctx, CONFIG_ASPEED_DICE_CERT_VALID_TO));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_x501_name(ctx, CONFIG_ASPEED_DICE_CERT_ALIAS_SUBJECT_NAME,
			CONFIG_ASPEED_DICE_CERT_ALIAS_SUBJECT_ORG,
			CONFIG_ASPEED_DICE_CERT_ALIAS_SUBJECT_COUNTRY));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ec_pubkey));
	CHK(x509_add_oid(ctx, oid_curve_ecdsa384));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_bit_str(ctx, alias_pub_key, ECDSA384_PUBLIC_KEY_SIZE));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_add_extentions(ctx, devid_pub_key, ECDSA384_PUBLIC_KEY_SIZE, dev_fwid, fwid_len));
	CHK(x509_pop_nesting(ctx));

	ASRT(ctx->collection_position == 0);

	return 0;
error:
	return -1;
}

int x509_get_device_cert_tbs(PFR_DER_CTX *ctx, uint8_t *serial_num)
{
	uint8_t key_usage = RIOT_X509_KEY_USAGE;
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_short_explicit_int(ctx, 2));
	CHK(x509_add_int_from_array(ctx, serial_num, X509_SERIAL_NUM_LENGTH));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ecdsa_with_sha384));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_x501_name(ctx, CONFIG_ASPEED_DICE_CERT_DEVID_ISSUER_NAME,
			CONFIG_ASPEED_DICE_CERT_DEVID_ISSUER_ORG,
			CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_COUNTRY));

	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_utc_time(ctx, CONFIG_ASPEED_DICE_CERT_VALID_FROM));
	CHK(x509_add_utc_time(ctx, CONFIG_ASPEED_DICE_CERT_VALID_TO));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_x501_name(ctx, CONFIG_ASPEED_DICE_CERT_DEVID_SUBJECT_NAME,
			CONFIG_ASPEED_DICE_CERT_DEVID_SUBJECT_ORG,
			CONFIG_ASPEED_DICE_CERT_ALIAS_SUBJECT_COUNTRY));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ec_pubkey));
	CHK(x509_add_oid(ctx, oid_curve_ecdsa384));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_add_bit_str(ctx, devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_start_explicit(ctx, 3));
	CHK(x509_start_seq_or_set(ctx, true));

	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_key_usage));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_add_bit_str(ctx, &key_usage, 1));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_basic_constraints));
	CHK(x509_add_bool(ctx, true));
	CHK(x509_envelop_oct_str(ctx));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_bool(ctx, true));
	CHK(x509_add_int(ctx, 1));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	ASRT(ctx->collection_position == 0);

	return 0;
error:
	return -1;
}

int x509_get_csr_tbs(PFR_DER_CTX *ctx)
{
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_int(ctx, 0));
	CHK(x509_add_x501_name(ctx, CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_NAME,
			CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_ORG,
			CONFIG_ASPEED_DICE_CERT_ALIAS_ISSUER_COUNTRY));

	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_start_seq_or_set(ctx, true));
	CHK(x509_add_oid(ctx, oid_ec_pubkey));
	CHK(x509_add_oid(ctx, oid_curve_ecdsa384));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_add_bit_str(ctx, devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_start_explicit(ctx, 0));
	CHK(x509_pop_nesting(ctx));
	CHK(x509_pop_nesting(ctx));

	ASRT(ctx->collection_position == 0);

	return 0;
error:
	return -1;
}

void x509_set_serial_number(uint8_t *serial_num, uint8_t *digest, uint8_t digest_len)
{
	uint8_t dice_seed[9] = "DICE_SEED";
	uint8_t dice_seed_digest[SHA384_HASH_LENGTH];
	uint8_t final_digest[SHA384_HASH_LENGTH];
	mbedtls_sha512_context sha_ctx;
	mbedtls_sha512(dice_seed, sizeof(dice_seed), dice_seed_digest, 1);

	mbedtls_sha512_starts(&sha_ctx, 1 /* SHA-384 */);
	mbedtls_sha512_update(&sha_ctx, dice_seed_digest, SHA384_HASH_LENGTH);
	mbedtls_sha512_update(&sha_ctx, digest, SHA384_HASH_LENGTH);
	mbedtls_sha512_finish(&sha_ctx, final_digest);
	memcpy(serial_num, final_digest, X509_SERIAL_NUM_LENGTH);

	// DER encoded serial number must be positive and the first byte must not be zero
	serial_num[0] &= 0x7f;
	serial_num[0] |= 0x01;
}

int hash_device_firmware(uint32_t addr, uint32_t fw_size, uint8_t *hash, uint32_t hash_len
		/*, enum hash_algo algo */)
{
	const struct device *flash_dev = NULL;
	uint32_t read_len;
	flash_dev = device_get_binding("fmc_cs0");

	if (flash_dev == NULL) {
		LOG_ERR("Failed to bind fmc_cs0");
	} else {
		LOG_INF("fmc_cs0 = %p", flash_dev);
	}

	mbedtls_sha512_context sha_ctx;
	printk("%s %p\n", __func__, &sha_ctx);
	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, 1 /* SHA-384 */);

	while (fw_size > 0) {
		read_len = (fw_size < PAGE_SIZE) ? fw_size : PAGE_SIZE;
		flash_read(flash_dev, addr, flash_buf, read_len);
		mbedtls_sha512_update(&sha_ctx, flash_buf, read_len);
		addr += read_len;
		fw_size -= read_len;
	}

	mbedtls_sha512_finish(&sha_ctx, hash);
	mbedtls_sha512_free(&sha_ctx);
	return 0;
}

// TODO:
// Since srand() is not supported in current zephyr, we use the hash of cdi digest
// as the seed of mbedtls random number generator.
#if 0
int get_rand_bytes( void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);
	for (; length; length--)
		*output++ = (uint8_t)rand();

	return 0;
}

int seed_drbg(uint8_t *digest, uint32_t digest_len)
{
	uint32_t i, seed;
	mbedtls_md_info_t *md_sha384;
	int ret = -1;

	for (i = 0; i < digest_len; i++) {
		seed += ~(digest[i]);
	}
	srand(~seed);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, get_rand_bytes, NULL, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}
#else

// Temporary solution
int get_rand_bytes_by_cdi(void *rngState, uint8_t *output, size_t length)
{
	uint8_t cdi_digest_digest[SHA384_HASH_LENGTH];
	ARG_UNUSED(rngState);

	mbedtls_sha512(cdi_digest, SHA384_HASH_LENGTH, cdi_digest_digest, 1 /* SHA-384 */);
	memset(output, 0, length);
	memcpy(output, cdi_digest_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);

	return 0;
}

int get_rand_bytes_by_cdi_fwid(void *rngState, uint8_t *output, size_t length)
{
	ARG_UNUSED(rngState);
	// Combine CDI and FWID for deriving alias key
	mbedtls_sha512_context sha_ctx;
	mbedtls_sha512_init(&sha_ctx);

	mbedtls_sha512_starts(&sha_ctx, 1 /* SHA-384 */);
	mbedtls_sha512_update(&sha_ctx, cdi_digest, SHA384_HASH_LENGTH);
	mbedtls_sha512_update(&sha_ctx, dev_fwid, SHA384_HASH_LENGTH);
	mbedtls_sha512_finish(&sha_ctx, alias_digest);

	mbedtls_sha512_free(&sha_ctx);
	memset(output, 0, length);
	memcpy(output, alias_digest,
			(length <= SHA384_HASH_LENGTH) ? length : SHA384_HASH_LENGTH);
	return 0;
}

int seed_drbg(int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy)
{
	const mbedtls_md_info_t *md_sha384;
	int ret = -1;

	if (hmac_drbg_ctx.MBEDTLS_PRIVATE(entropy_len))
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	mbedtls_hmac_drbg_init(&hmac_drbg_ctx);

	if (!(md_sha384 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384)))
		goto free_drbg;

	if (mbedtls_hmac_drbg_seed(&hmac_drbg_ctx, md_sha384, f_entropy,
				p_entropy, NULL, 0))
		goto free_drbg;

	ret = 0;

free_drbg:
	if (ret)
		mbedtls_hmac_drbg_free(&hmac_drbg_ctx);

	return ret;
}

#endif


int derive_key_pair(mbedtls_ecdsa_context *ctx_sign, uint8_t *privkey_buf, uint8_t *pubkey_buf,
		int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy)
{
	size_t len;
	// Seed drbg with cdi digest
	seed_drbg(f_entropy, p_entropy);

	mbedtls_ecdsa_init(ctx_sign);

	if (mbedtls_ecdsa_genkey(ctx_sign, MBEDTLS_ECP_DP_SECP384R1, mbedtls_hmac_drbg_random,
				&hmac_drbg_ctx)) {
		return -1;
	}

	if (mbedtls_mpi_write_binary(&ctx_sign->MBEDTLS_PRIVATE(d), privkey_buf,
			ECDSA384_PRIVATE_KEY_SIZE)) {
		LOG_ERR("Failed to get ecdsa privkey");
		return -1;
	}

	if (mbedtls_ecp_point_write_binary(&ctx_sign->MBEDTLS_PRIVATE(grp),
			&ctx_sign->MBEDTLS_PRIVATE(Q),
			MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pubkey_buf, 128)) {
		LOG_ERR("Failed to get ecdsa pubkey");
		return -1;
	}

	return 0;
}

int x509_digest_sign(PFR_ECC_SIG *sig, uint8_t *digest, uint32_t digest_len,
		mbedtls_ecdsa_context *ctx)
{

	return (mbedtls_ecdsa_sign(&ctx->MBEDTLS_PRIVATE(grp), &sig->r, &sig->s,
				&ctx->MBEDTLS_PRIVATE(d), digest, digest_len,
				mbedtls_hmac_drbg_random, &hmac_drbg_ctx));
}

int x509_cert_sign(PFR_ECC_SIG *sig, void *data, uint32_t size, mbedtls_ecdsa_context *ctx)
{
	uint8_t digest[SHA384_HASH_LENGTH];

	mbedtls_sha512(data, size, digest, 1 /* SHA-384 */);

	return (x509_digest_sign(sig, digest, sizeof(digest), ctx));
}

int x509_mpi_to_int(mbedtls_mpi *mpi, uint8_t *buf, uint32_t buf_len)
{
	return (mbedtls_mpi_write_binary(mpi, buf, buf_len));
}

int x509_gen_cert(PFR_DER_CTX *cert, PFR_ECC_SIG *tbs_sig)
{
	uint8_t enc_buf[SHA384_HASH_LENGTH] = {0};
	uint32_t enc_buf_len = sizeof(enc_buf);

	CHK(x509_tbs_to_cert(cert));
	CHK(x509_start_seq_or_set(cert, true));
	CHK(x509_add_oid(cert, oid_ecdsa_with_sha384));
	CHK(x509_pop_nesting(cert));
	CHK(x509_envelop_bit_str(cert));
	CHK(x509_start_seq_or_set(cert, true));
	CHK(x509_mpi_to_int(&tbs_sig->r, enc_buf, enc_buf_len));
	CHK(x509_add_int_from_array(cert, enc_buf, enc_buf_len));
	CHK(x509_mpi_to_int(&tbs_sig->s, enc_buf, enc_buf_len));
	CHK(x509_add_int_from_array(cert, enc_buf, enc_buf_len));
	CHK(x509_pop_nesting(cert));
	CHK(x509_pop_nesting(cert));
	CHK(x509_pop_nesting(cert));

	ASRT(cert->collection_position == 0);

	return 0;
error:
	return -1;
}

void clear_global_sensitive_info(void)
{
	// Clear sensitive data
	memset((void *)CDI_ADDRESS, 0, CDI_LENGTH);
	memset(cdi_digest, 0, sizeof(cdi_digest));
	memset(dev_fwid, 0, sizeof(dev_fwid));
	memset(alias_digest, 0, sizeof(alias_digest));
	memset(devid_priv_key_buf, 0, sizeof(devid_priv_key_buf));
	memset(devid_pub_key_buf, 0, sizeof(devid_pub_key_buf));
	memset(alias_priv_key_buf, 0, sizeof(alias_priv_key_buf));
	memset(alias_pub_key_buf, 0, sizeof(alias_pub_key_buf));
	memset(&alias_cert_info, 0, sizeof(alias_cert_info));
	memset(&fl_alias_cert_info, 0, sizeof(fl_alias_cert_info));
	memset(&devid_cert_info, 0, sizeof(devid_cert_info));
}

cert_status is_devid_certificate_valid(PFR_DEVID_CERT_INFO *cert_info, uint8_t *devid_pubkey)
{
	uint8_t hash_output[SHA256_HASH_LENGTH];

	if (cert_info->cert.magic == 0xFFFFFFFF)
		return CERT_INFO_EMPTY_MAGIC;

	if (cert_info->cert.magic == CERT_INFO_MAGIC_NUM) {
		if (memcmp(cert_info->pubkey, devid_pubkey, ECDSA384_PUBLIC_KEY_SIZE))
			return CERT_INFO_INVALID;

		mbedtls_sha256(cert_info->cert.data, cert_info->cert.length, hash_output, 0);
		if (!memcmp(cert_info->cert.hash, hash_output, sizeof(hash_output)))
			return CERT_INFO_VALID;
	}

	return CERT_INFO_INVALID;
}

void generate_certificate_info(PFR_CERT_INFO *cert_info, PFR_DER_CTX *der_ctx)
{
	cert_info->magic = CERT_INFO_MAGIC_NUM;
	cert_info->length = der_ctx->position;
	memset(cert_info->data, 0, sizeof(cert_info->data));
	memcpy(cert_info->data, der_ctx->buffer, cert_info->length);
	mbedtls_sha256(cert_info->data, cert_info->length, cert_info->hash, 0);
}

int dice_start(size_t cert_type, struct boot_rsp *rsp)
{
	uint8_t alias_serial_num[X509_SERIAL_NUM_LENGTH] =
		{0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd};
	uint8_t devid_serial_num[X509_SERIAL_NUM_LENGTH] =
		{0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd};

	mbedtls_ecdsa_context ctx_devid;
	mbedtls_ecdsa_context ctx_alias;
	PFR_DER_CTX der_ctx;
	PFR_ECC_SIG tbs_sig;

	uint8_t der_buf[DER_MAX_TBS];
	const struct flash_area *fap;
	cert_status rc;

	// Hash CDI
	mbedtls_sha512((uint8_t *)CDI_ADDRESS, CDI_LENGTH, cdi_digest, 1 /* SHA-384 */);
	//LOG_HEXDUMP_INF((uint8_t *)CDI_ADDRESS, CDI_LENGTH, "CDI :");
	//LOG_HEXDUMP_INF(cdi_digest, SHA384_HASH_LENGTH, "CDI digest :");

	// Derive DeviceID key pair from CDI
	CHK(derive_key_pair(&ctx_devid, devid_priv_key_buf, devid_pub_key_buf,
			get_rand_bytes_by_cdi, NULL));
	//LOG_HEXDUMP_INF(devid_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE, "DEVID PRIKEY :");
	//LOG_HEXDUMP_INF(devid_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE, "DEVID PUBKEY :");

	// Set serial number of DeviceID certificate
	x509_set_serial_number(devid_serial_num, cdi_digest, sizeof(cdi_digest));

	// Hash device firmware as FWID
	hash_device_firmware(rsp->br_image_off, rsp->br_hdr->ih_img_size, dev_fwid,
			SHA384_HASH_LENGTH/*, HASH_SHA384*/);

	// Derive Alias key pair from CDI and FWID
	CHK(derive_key_pair(&ctx_alias, alias_priv_key_buf, alias_pub_key_buf,
			get_rand_bytes_by_cdi_fwid, NULL));
	//LOG_HEXDUMP_INF(alias_priv_key_buf, ECDSA384_PRIVATE_KEY_SIZE, "Alias PRIKEY :");
	//LOG_HEXDUMP_INF(alias_pub_key_buf, ECDSA384_PUBLIC_KEY_SIZE, "Alias PUBKEY :");

	// Set serial number of Alias certificate
	x509_set_serial_number(alias_serial_num, alias_digest, sizeof(alias_digest));

	x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
	CHK(x509_get_alias_cert_tbs(&der_ctx, alias_serial_num, alias_pub_key_buf,
			devid_pub_key_buf, dev_fwid, SHA384_HASH_LENGTH));

	mbedtls_mpi_init(&tbs_sig.r);
	mbedtls_mpi_init(&tbs_sig.s);
	CHK(x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid));
	CHK(x509_gen_cert(&der_ctx, &tbs_sig));

	generate_certificate_info(&alias_cert_info.cert, &der_ctx);
	memcpy(alias_cert_info.privkey, alias_priv_key_buf, sizeof(alias_cert_info.privkey));
	memcpy(alias_cert_info.pubkey, alias_pub_key_buf, sizeof(alias_cert_info.pubkey));

	// Read alias certificate from flash and compare with generated alias certificate
	CHK(flash_area_open(FLASH_AREA_ID(certificate), &fap));
	flash_area_read(fap, ALIAS_CERT_ADDR, &fl_alias_cert_info, sizeof(fl_alias_cert_info));
	if (memcmp(&alias_cert_info, &fl_alias_cert_info, sizeof(alias_cert_info))) {
		BOOT_LOG_INF("Generate Alias certificate");
		flash_area_erase(fap, ALIAS_CERT_ADDR, CERT_REGION_SIZE);
		flash_area_write(fap, ALIAS_CERT_ADDR, &alias_cert_info, sizeof(alias_cert_info));
	}
	flash_area_close(fap);

#ifdef GEN_PEM_CERT
	uint32_t len = sizeof(alias_cert_pem);
	CHK(x509_der_to_pem(&der_ctx, CERT_TYPE, alias_cert_pem, &len));
#endif
	//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "Alias Cert DER :");
	//LOG_HEXDUMP_INF(alias_cert_pem, sizeof(alias_cert_pem), "Alias Cert PEM :");

	CHK(flash_area_open(FLASH_AREA_ID(certificate), &fap));
	flash_area_read(fap, DEVID_CERT_ADDR, &devid_cert_info, sizeof(devid_cert_info));
	rc = is_devid_certificate_valid(&devid_cert_info, devid_pub_key_buf);
	switch (rc) {
	case CERT_INFO_INVALID:
		BOOT_LOG_INF("layer 0 firmware is tampered");
		goto error;
	case CERT_INFO_VALID:
		BOOT_LOG_INF("Device ID certificate was generated and is valid");
		goto done;
	case CERT_INFO_EMPTY_MAGIC:
	default:
		BOOT_LOG_INF("Generate Device ID certificate");
		break;
	}

	if(cert_type) {
		// Self-Signed
		x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
		CHK(x509_get_device_cert_tbs(&der_ctx, devid_serial_num));
		CHK(x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid));
		CHK(x509_gen_cert(&der_ctx, &tbs_sig));
#ifdef GEN_PEM_CERT
		len = sizeof(devid_cert_pem);
		CHK(x509_der_to_pem(&der_ctx, CERT_TYPE, devid_cert_pem, &len));
#endif
		devid_cert_info.cert_type = CERT_TYPE;
		//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "DevID Cert DER :");
		//LOG_HEXDUMP_INF(devid_cert_pem, sizeof(devid_cert_pem), "DevID Cert PEM :");
	} else {
		// CSR
		x509_der_init_context(&der_ctx, der_buf, DER_MAX_TBS);
		CHK(x509_get_csr_tbs(&der_ctx));
		CHK(x509_cert_sign(&tbs_sig, der_ctx.buffer, der_ctx.position, &ctx_devid));
		CHK(x509_gen_cert(&der_ctx, &tbs_sig));
#ifdef GEN_PEM_CERT
		len = sizeof(devid_cert_pem);
		CHK(x509_der_to_pem(&der_ctx, CERT_REQ_TYPE, devid_cert_pem, &len));
#endif
		devid_cert_info.cert_type = CERT_REQ_TYPE;
		//LOG_HEXDUMP_INF(der_ctx.buffer, der_ctx.position, "DevID CSR DER :");
		//LOG_HEXDUMP_INF(devid_cert_pem, sizeof(devid_cert_pem), "DevID CSR PEM :");
	}

	generate_certificate_info(&devid_cert_info.cert, &der_ctx);
	memcpy(devid_cert_info.pubkey, devid_pub_key_buf, sizeof(devid_pub_key_buf));
	flash_area_erase(fap, DEVID_CERT_ADDR, CERT_REGION_SIZE);
	flash_area_write(fap, DEVID_CERT_ADDR, &devid_cert_info, sizeof(devid_cert_info));
	flash_area_close(fap);
	//LOG_HEXDUMP_INF(devid_priv_key_buf, sizeof(devid_priv_key_buf), "devid priv key :");
	//LOG_HEXDUMP_INF(devid_pub_key_buf, sizeof(devid_pub_key_buf), "devid pub key :");
	//LOG_HEXDUMP_INF(alias_priv_key_buf, sizeof(alias_priv_key_buf), "alias priv key :");
	//LOG_HEXDUMP_INF(alias_pub_key_buf, sizeof(alias_pub_key_buf), "alias pub key :");

done:
	clear_global_sensitive_info();
	mbedtls_ecdsa_free(&ctx_devid);
	mbedtls_ecdsa_free(&ctx_alias);
	memset(&der_ctx, 0, sizeof(der_ctx));
	memset(&tbs_sig, 0, sizeof(tbs_sig));

	return 0;
error:
	clear_global_sensitive_info();
	mbedtls_ecdsa_free(&ctx_devid);
	mbedtls_ecdsa_free(&ctx_alias);
	memset(&der_ctx, 0, sizeof(der_ctx));
	memset(&tbs_sig, 0, sizeof(tbs_sig));

	return -1;
}
