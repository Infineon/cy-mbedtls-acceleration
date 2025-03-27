/*
 *  mbed Microcontroller Library
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2019-2024 Cypress Semiconductor Corporation
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * \file    sha1_alt_mxcrypto.c
 * \version 2.3.0
 *
 * \brief   Source file - wrapper for mbedtls SHA1 HW acceleration
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#include "mbedtls/build_info.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_SHA1_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/sha1.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/compat-2.x.h"

#if defined(MBEDTLS_SHA1_ALT)

#include "crypto_common.h"

/* Parameter validation macros based on platform_util.h */
#define SHA1_VALIDATE_RET(cond)                             \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA1_BAD_INPUT_DATA )
#define SHA1_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )

void mbedtls_sha1_init( mbedtls_sha1_context *ctx )
{
    SHA1_VALIDATE( ctx != NULL );
    cy_hw_sha_init(ctx, sizeof( mbedtls_sha1_context ));

    ctx->hashState = (cy_stc_crypto_sha_state_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)ctx->hashState_t);
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    ctx->shaBuffers = (cy_stc_crypto_v1_sha1_buffers_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)ctx->shaBuffers_t);
#else
    ctx->shaBuffers = (cy_stc_crypto_v2_sha1_buffers_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)ctx->shaBuffers_t);
#endif

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ctx->output_array_ptr = (uint8_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)ctx->output_array);
#endif

}

void mbedtls_sha1_free( mbedtls_sha1_context *ctx )
{
    if (ctx == NULL)
        return;

    cy_hw_sha_free(ctx, sizeof( mbedtls_sha1_context ));
}

void mbedtls_sha1_clone( mbedtls_sha1_context *dst, const mbedtls_sha1_context *src )
{
    SHA1_VALIDATE( dst != NULL );
    SHA1_VALIDATE( src != NULL );

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    dst->hashState = (cy_stc_crypto_sha_state_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)dst->hashState_t);
	ifx_mbedtls_memcpy((void *)dst->hashState, (void *)src->hashState, sizeof(cy_stc_crypto_sha_state_t));
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    dst->shaBuffers = (cy_stc_crypto_v1_sha1_buffers_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)dst->shaBuffers_t);
	ifx_mbedtls_memcpy((void *)dst->shaBuffers, (void *)src->shaBuffers, sizeof(cy_stc_crypto_v1_sha1_buffers_t));
#else
    dst->shaBuffers = (cy_stc_crypto_v2_sha1_buffers_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)dst->shaBuffers_t);
	ifx_mbedtls_memcpy((void *)dst->shaBuffers, (void *)src->shaBuffers, sizeof(cy_stc_crypto_v2_sha1_buffers_t));
#endif
    dst->output_array_ptr = (uint8_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)dst->output_array);
	dst->obj = src->obj;
#endif

    cy_hw_sha_clone(dst, src, sizeof(mbedtls_sha1_context), dst->hashState, dst->shaBuffers);
}

/*
 * SHA-1 context setup
 */
int mbedtls_sha1_starts( mbedtls_sha1_context *ctx )
{
    SHA1_VALIDATE_RET( ctx != NULL );

    return cy_hw_sha_start(&ctx->obj, ctx->hashState, CY_CRYPTO_MODE_SHA1, ctx->shaBuffers);
}

/*
 * SHA-1 process buffer
 */
int mbedtls_sha1_update( mbedtls_sha1_context *ctx,
                             const unsigned char *input,
                             size_t ilen )
{
    SHA1_VALIDATE_RET( ctx != NULL );
    SHA1_VALIDATE_RET( input != NULL );

    if (ilen == 0)
        return (0);

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, ilen) )
    {
        int ret = 0;
        uint32_t blk_cnt;
		uint32_t blk_frag;
		uint8_t *input_ptr;
		uint8_t *input_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_SHA1_BLOCK_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == input_data)
        {
            return MBEDTLS_ERR_SHA1_BAD_INPUT_DATA;
        }
        uint8_t *aligned_input_data = (uint8_t*)CY_CRYPTO_DCAHCE_ALIGN_ADDRESS((size_t)input_data);

		blk_cnt = ilen >> 6u;	// div by CY_CRYPTO_SHA1_BLOCK_SIZE;
		blk_frag = ilen & (size_t)(CY_CRYPTO_SHA1_BLOCK_SIZE - 1);
		input_ptr = (uint8_t *)input;

		while(blk_cnt > 0u)
		{
			ifx_mbedtls_memcpy((void *)aligned_input_data, (void *)input_ptr, CY_CRYPTO_SHA1_BLOCK_SIZE);
			ret = cy_hw_sha_update(&ctx->obj, ctx->hashState, (uint8_t *)aligned_input_data, CY_CRYPTO_SHA1_BLOCK_SIZE);
			if(ret != 0)
			{
				ifx_mbedtls_free(input_data);
				return ret;
			}
			input_ptr += CY_CRYPTO_SHA1_BLOCK_SIZE;
			blk_cnt--;
		}
		if(blk_frag != 0u)
		{
			ifx_mbedtls_memcpy((void *)aligned_input_data, (void *)input_ptr, blk_frag);
			ret = cy_hw_sha_update(&ctx->obj, ctx->hashState, (uint8_t *)aligned_input_data, blk_frag);
		}

        ifx_mbedtls_free(input_data);
        return ret;
    }
#endif
    return cy_hw_sha_update(&ctx->obj, ctx->hashState, input, ilen);
}

/*
 * SHA-1 final digest
 */
int mbedtls_sha1_finish( mbedtls_sha1_context *ctx, unsigned char output[20] )
{
    SHA1_VALIDATE_RET( ctx != NULL );
    SHA1_VALIDATE_RET( (unsigned char *)output != NULL );

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
   if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, 20))
    {
       int ret;

        ret = cy_hw_sha_finish(&ctx->obj, ctx->hashState, ctx->output_array_ptr);

        ifx_mbedtls_memcpy(output, ctx->output_array_ptr, CY_CRYPTO_SHA1_DIGEST_SIZE);
        return ret;
    }
#endif
    return cy_hw_sha_finish(&ctx->obj, ctx->hashState, output);
}

int mbedtls_internal_sha1_process( mbedtls_sha1_context *ctx, const unsigned char data[64] )
{
    SHA1_VALIDATE_RET( ctx != NULL );
    SHA1_VALIDATE_RET( (const unsigned char *)data != NULL );

    return cy_hw_sha_process(&ctx->obj, ctx->hashState, data);
}

#endif /* MBEDTLS_SHA1_ALT */

#endif /* MBEDTLS_SHA1_C */

#endif /* CY_IP_MXCRYPTO */
