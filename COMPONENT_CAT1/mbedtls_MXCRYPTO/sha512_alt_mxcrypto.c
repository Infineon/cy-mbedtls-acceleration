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
 * \file    sha512_alt_mxcrypto.c
 * \version 2.3.0
 *
 * \brief   Source file - wrapper for mbedtls SHA512 HW acceleration
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#include "mbedtls/build_info.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_SHA512_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/sha512.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/compat-2.x.h"

#if defined(MBEDTLS_SHA512_ALT)

/* Parameter validation macros based on platform_util.h */
#define SHA512_VALIDATE_RET(cond)                           \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA512_BAD_INPUT_DATA )
#define SHA512_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )

void mbedtls_sha512_init( mbedtls_sha512_context *ctx )
{
    SHA512_VALIDATE( ctx != NULL );

    cy_hw_sha_init(ctx, sizeof( mbedtls_sha512_context ));
    #if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ctx->output_array_ptr = (uint8_t*)((size_t)ctx->output_array + ((size_t)DCACHE_LINE_ALIGNMENT_SIZE - ((size_t)ctx->output_array & 0x1F)));
    #endif    
}

void mbedtls_sha512_free( mbedtls_sha512_context *ctx )
{
    if (ctx == NULL)
        return;

    cy_hw_sha_free(ctx, sizeof( mbedtls_sha512_context ));
}

void mbedtls_sha512_clone( mbedtls_sha512_context *dst, const mbedtls_sha512_context *src )
{
    SHA512_VALIDATE( dst != NULL );
    SHA512_VALIDATE( src != NULL );

    cy_hw_sha_clone(dst, src, sizeof(mbedtls_sha512_context), &dst->hashState, &dst->shaBuffers);
}

/*
 * SHA-512 context setup
 */
int mbedtls_sha512_starts( mbedtls_sha512_context *ctx, int is384)
{
    SHA512_VALIDATE_RET( ctx != NULL );

    return cy_hw_sha_start(&ctx->obj, &ctx->hashState,
                           ( is384 == 0 ) ? CY_CRYPTO_MODE_SHA512 : CY_CRYPTO_MODE_SHA384,
                           &ctx->shaBuffers);
}

/*
 * SHA-512 process buffer
 */
int mbedtls_sha512_update( mbedtls_sha512_context *ctx, const unsigned char *input, size_t ilen )
{
    SHA512_VALIDATE_RET( ctx != NULL );

    if (ilen == 0)
        return (0);

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( Cy_Syslib_IsMemCacheable(MPU, (uint32_t)input, ilen) && ((size_t)input % DCACHE_LINE_ALIGNMENT_SIZE != 0 || ilen % DCACHE_LINE_ALIGNMENT_SIZE != 0) )
    {
    int ret;
    uint8_t *input_data = (uint8_t *)malloc(ilen + (2*DCACHE_LINE_ALIGNMENT_SIZE));
    if (NULL == input_data)
    {
        return MBEDTLS_ERR_SHA512_BAD_INPUT_DATA;
    }
    uint8_t *aligned_input_data = (uint8_t*)((size_t)input_data + ((size_t)DCACHE_LINE_ALIGNMENT_SIZE - ((size_t)input_data & 0x1F)));

    memcpy((void *)aligned_input_data, (void *)input, ilen);

    ret = cy_hw_sha_update(&ctx->obj, &ctx->hashState, (uint8_t *)aligned_input_data, ilen);

    free(input_data);
    return ret;
    }
#endif
    return cy_hw_sha_update(&ctx->obj, &ctx->hashState, input, ilen);
}

/*
 * SHA-512 final digest
 */
int mbedtls_sha512_finish( mbedtls_sha512_context *ctx, unsigned char *output )
{
    SHA512_VALIDATE_RET( ctx != NULL );
    SHA512_VALIDATE_RET( (unsigned char *)output != NULL );

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( Cy_Syslib_IsMemCacheable(MPU, (uint32_t)output, 32) && ((size_t)output % DCACHE_LINE_ALIGNMENT_SIZE != 0) )
    {
    int ret;
    
    ret = cy_hw_sha_finish(&ctx->obj, &ctx->hashState, ctx->output_array_ptr);

    if(CY_CRYPTO_MODE_SHA384 == ctx->hashState.mode)
    {
        memcpy(output, ctx->output_array_ptr, CY_CRYPTO_SHA384_DIGEST_SIZE);
    }
    else if(CY_CRYPTO_MODE_SHA512 == ctx->hashState.mode)
    {
        memcpy(output, ctx->output_array_ptr, CY_CRYPTO_SHA512_DIGEST_SIZE);
    }
    else
    {
        /* Do Nothing */
    }

    return ret;
    }
#endif
    return cy_hw_sha_finish(&ctx->obj, &ctx->hashState, output);
}

int mbedtls_internal_sha512_process( mbedtls_sha512_context *ctx, const unsigned char data[128] )
{
    SHA512_VALIDATE_RET( ctx != NULL );
    SHA512_VALIDATE_RET( (const unsigned char *)data != NULL );

    return cy_hw_sha_process(&ctx->obj, &ctx->hashState, data);
}

#endif /* MBEDTLS_SHA512_ALT */

#endif /* MBEDTLS_SHA512_C */

#endif /* CY_IP_MXCRYPTO */
