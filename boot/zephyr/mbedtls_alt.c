#include <zephyr.h>
#include <stddef.h>
#include <string.h>

#include "mcuboot-mbedtls-cfg.h"

#if defined(MBEDTLS_SHA1_ALT)
#include "sha1_alt.h"
#endif
#if defined(MBEDTLS_SHA256_ALT)
#include "sha256_alt.h"
#endif
#if defined(MBEDTLS_SHA512_ALT)
#include "sha512_alt.h"
#endif

#include <crypto/hash.h>

#define HASH_DRV_NAME CONFIG_CRYPTO_ASPEED_HASH_DRV_NAME

#if defined(MBEDTLS_SHA1_ALT) || defined(MBEDTLS_SHA256_ALT) || defined(MBEDTLS_SHA512_ALT)
void sha_init(mbedtls_sha_context *ctx)
{
	ctx->dev = device_get_binding(HASH_DRV_NAME);
}

void sha_free(mbedtls_sha_context *ctx)
{
	hash_free_session(ctx->dev, &ctx->ini);
	printk("%s %p\n",__func__, ctx);
}

int sha_start(mbedtls_sha_context *ctx, enum hash_algo algo)
{
	printk("%s %p %d\n",__func__, ctx, algo);
	ctx->algo = algo;
	return hash_begin_session(ctx->dev, &ctx->ini, algo);
}

int sha_update(mbedtls_sha_context *ctx,const unsigned char *input,size_t ilen )
{
	ctx->pkt.in_buf = (uint8_t *)input;
	ctx->pkt.in_len = ilen;

	// printk("%s %p\n",__func__, ctx);
	return hash_update(&ctx->ini, &ctx->pkt);
}

int sha_finish(mbedtls_sha_context *ctx, unsigned char *output, size_t len)
{
	ctx->pkt.out_buf = ctx->digest;
	ctx->pkt.out_buf_max = sizeof(ctx->digest);
	hash_final(&ctx->ini, &ctx->pkt);

	memcpy(output, ctx->pkt.out_buf, len);

	return 0;
}
#endif

#if defined(MBEDTLS_SHA1_ALT)
void mbedtls_sha1_init( mbedtls_sha1_context *ctx )
{
	return sha_init((mbedtls_sha_context *)ctx);
}

void mbedtls_sha1_free( mbedtls_sha1_context *ctx )
{
	return sha_free((mbedtls_sha_context *)ctx);
}

void mbedtls_sha1_clone( mbedtls_sha1_context *dst, const mbedtls_sha1_context *src )
{

}

int mbedtls_sha1_starts( mbedtls_sha1_context *ctx )
{
	return sha_start(ctx, HASH_SHA1);
}

int mbedtls_sha1_update( mbedtls_sha1_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
	return sha_update(ctx, input, ilen);
}

int mbedtls_sha1_finish( mbedtls_sha1_context *ctx,
                         unsigned char output[20] )
{
	return sha_finish(ctx, output, 20);
}
#endif

#if defined(MBEDTLS_SHA256_ALT)
void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
	return sha_init((mbedtls_sha_context *)ctx);
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
	return sha_free((mbedtls_sha_context *)ctx);
}

void mbedtls_sha256_clone( mbedtls_sha256_context *dst, const mbedtls_sha256_context *src )
{

}

int mbedtls_sha256_starts( mbedtls_sha256_context *ctx, int is224 )
{
	return sha_start(ctx, is224 ? HASH_SHA224:HASH_SHA256);
}

int mbedtls_sha256_update( mbedtls_sha256_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
	return sha_update(ctx, input, ilen);
}

int mbedtls_sha256_finish( mbedtls_sha256_context *ctx,
                         unsigned char output )
{
	return sha_finish(ctx, output, ctx->algo == HASH_SHA224 ? 28 : 32);
}
#endif

#if defined(MBEDTLS_SHA512_ALT)
void mbedtls_sha512_init( mbedtls_sha512_context *ctx )
{
	return sha_init((mbedtls_sha_context *)ctx);
}

void mbedtls_sha512_free( mbedtls_sha512_context *ctx )
{
	return sha_free((mbedtls_sha_context *)ctx);
}

void mbedtls_sha512_clone( mbedtls_sha512_context *dst, const mbedtls_sha512_context *src )
{

}

int mbedtls_sha512_starts( mbedtls_sha512_context *ctx, int is384 )
{
	return sha_start(ctx, is384 ? HASH_SHA384:HASH_SHA512);
}

int mbedtls_sha512_update( mbedtls_sha512_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
	return sha_update(ctx, input, ilen);
}

int mbedtls_sha512_finish( mbedtls_sha512_context *ctx,
                         unsigned char output )
{
	return sha_finish(ctx, output, ctx->algo == HASH_SHA384 ? 48 : 64);
}
#endif
