/*
 *  Source file for mbedtls AES HW acceleration functions
 *
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

/*
 * \file    aes_alt_mxcrypto.c
 * \version 2.3.0
 *
 * \brief   This file contains AES functions implementation.
 *
 *          The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *          http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *          http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_AES_C)

#include <string.h>

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/aes.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/compat-2.x.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_AES_ALT)

#include "crypto_common.h"
#include "cy_crypto_core.h"

/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    AES_VALIDATE( ctx != NULL );
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ifx_mbedtls_memset((void*)ctx, 0u, sizeof( mbedtls_aes_context ));
#else
    cy_hw_zeroize(ctx, sizeof( mbedtls_aes_context ) );
#endif
    /*Align context members*/
    ctx->aes_state = (cy_stc_crypto_aes_state_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS(ctx->aes_state_t);
    ctx->aes_buffers = (cy_stc_crypto_aes_buffers_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS(ctx->aes_buffers_t);
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ctx->input_array_ptr  = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS(ctx->input_array);
    ctx->output_array_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS(ctx->output_array);
#endif

    (void)cy_hw_crypto_reserve((cy_cmgr_crypto_hw_t *)ctx, CY_CMGR_CRYPTO_COMMON);
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    if (ctx->aes_state->buffers != NULL) {
        Cy_Crypto_Core_Aes_Free(ctx->obj.base, ctx->aes_state);
    }
    cy_hw_crypto_release((cy_cmgr_crypto_hw_t *)ctx);
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ifx_mbedtls_memset((void*)ctx, 0u, sizeof( mbedtls_aes_context ));
#else
    cy_hw_zeroize(ctx, sizeof( mbedtls_aes_context ) );
#endif
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
void mbedtls_aes_xts_init( mbedtls_aes_xts_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    mbedtls_aes_init( &ctx->crypt );
    mbedtls_aes_init( &ctx->tweak );
}

void mbedtls_aes_xts_free( mbedtls_aes_xts_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_aes_free( &ctx->crypt );
    mbedtls_aes_free( &ctx->tweak );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*
 * Set CY HW AES keys
 */

static int aes_set_keys( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    int ret = 0;
    unsigned char *key_ptr;
    cy_en_crypto_aes_key_length_t key_length;
    cy_en_crypto_status_t status;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *key_array = NULL;
#endif
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    switch( keybits )
    {
        case 128: key_length = CY_CRYPTO_KEY_AES_128; break;
        case 192: key_length = CY_CRYPTO_KEY_AES_192; break;
        case 256: key_length = CY_CRYPTO_KEY_AES_256; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    key_ptr = (unsigned char *)key;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    unsigned int keybytes = keybits >> 3;
    if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key, keybytes) )
    {
        key_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(keybytes)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == key_array)
        {
            return AES_MEM_ALLOC_FAILED;
        }
        key_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_array);
        ifx_mbedtls_memcpy((void*)key_ptr, (void*)key, keybytes);

    }
#endif

    status = Cy_Crypto_Core_Aes_InitContext(ctx->obj.base, key_ptr, key_length, ctx->aes_state, ctx->aes_buffers);

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(key_array != NULL)
    {
        ifx_mbedtls_free(key_array);
    }
#endif
    if (CY_CRYPTO_SUCCESS != status)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return( ret );
}

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    return aes_set_keys( ctx, key, keybits );
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    return aes_set_keys( ctx, key, keybits );
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int mbedtls_aes_xts_decode_keys( const unsigned char *key,
                                        unsigned int keybits,
                                        const unsigned char **key1,
                                        unsigned int *key1bits,
                                        const unsigned char **key2,
                                        unsigned int *key2bits )
{
    const unsigned int half_keybits = keybits / 2;
    const unsigned int half_keybytes = half_keybits / 8;

    switch( keybits )
    {
        case 256: break;
        case 512: break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    *key1bits = half_keybits;
    *key2bits = half_keybits;
    *key1 = &key[0];
    *key2 = &key[half_keybytes];

    return 0;
}

int mbedtls_aes_xts_setkey_enc( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for the encryption mode. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for encryption. */
    return mbedtls_aes_setkey_enc( &ctx->crypt, key1, key1bits );
}

int mbedtls_aes_xts_setkey_dec( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for encryption. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for decryption. */
    return mbedtls_aes_setkey_dec( &ctx->crypt, key1, key1bits );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*
 * AES-ECB block encryption
 */
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int ret = 0;
    cy_en_crypto_status_t status;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( ctx->aes_state->buffers != NULL );

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    const void *input_ptr = NULL;
    void *output_ptr = NULL;
    if( CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, 16) )
    {
        input_ptr = input;
    }
    else
    {
        ifx_mbedtls_memcpy((void*)ctx->input_array_ptr, (void*)input, CY_CRYPTO_AES_BLOCK_SIZE);
        input_ptr = ctx->input_array_ptr;
    }
    if( CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, 16) )
    {
        output_ptr = output;
    }
    else
    {
        output_ptr = ctx->output_array_ptr;
    }

    status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_ENCRYPT, output_ptr, input_ptr, ctx->aes_state);

    if( output_ptr != output )
    {
        ifx_mbedtls_memcpy((void*)output, (void*)output_ptr, CY_CRYPTO_AES_BLOCK_SIZE);
    }

#else
    status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_ENCRYPT, output, input, ctx->aes_state);
#endif
    if (CY_CRYPTO_SUCCESS != status)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_aes_encrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    mbedtls_internal_aes_encrypt( ctx, input, output );
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/*
 * AES-ECB block decryption
 */
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int ret = 0;
    cy_en_crypto_status_t status;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( ctx->aes_state->buffers != NULL );

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    const void *input_ptr = NULL;
    void *output_ptr = NULL;
    if( CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, 16) )
    {
        input_ptr = input;
    }
    else
    {
        ifx_mbedtls_memcpy((void*)ctx->input_array_ptr, (void*)input, CY_CRYPTO_AES_BLOCK_SIZE);
        input_ptr = ctx->input_array_ptr;
    }
    if( CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, 16) )
    {
        output_ptr = output;
    }
    else
    {
        output_ptr = ctx->output_array_ptr;
    }

    status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_DECRYPT, output_ptr, input_ptr, ctx->aes_state);
    if( output_ptr != output )
    {
        ifx_mbedtls_memcpy((void*)output, (void*)output_ptr, CY_CRYPTO_AES_BLOCK_SIZE);
    }

#else
    status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_DECRYPT, output, input, ctx->aes_state);
#endif

    if (CY_CRYPTO_SUCCESS != status)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_aes_decrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    mbedtls_internal_aes_decrypt( ctx, input, output );
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( mode == MBEDTLS_AES_ENCRYPT )
        return( mbedtls_internal_aes_encrypt( ctx, input, output ) );
    else
        return( mbedtls_internal_aes_decrypt( ctx, input, output ) );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int ret = 0;
    cy_en_crypto_status_t status;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *iv_array = NULL;
    uint8_t *input_array = NULL;
    uint8_t *output_array = NULL;
#endif

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( length % CY_CRYPTO_AES_BLOCK_SIZE )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    AES_VALIDATE_RET( ctx->aes_state->buffers != NULL);

    if( mode == MBEDTLS_AES_DECRYPT )
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *temp_array = NULL;
        uint8_t *aligned_iv_array = (uint8_t *)iv;
        uint8_t *aligned_input_array = (uint8_t *)input;
        uint8_t *aligned_output_array = (uint8_t *)output;
        uint8_t *aligned_temp_array = NULL;
        uint8_t *input_ptr = (uint8_t *)input;

        if( (! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)iv, CY_CRYPTO_AES_BLOCK_SIZE)))
        {
            iv_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((iv_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_iv_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)iv_array);
            ifx_mbedtls_memcpy((void*)aligned_iv_array, (void*)iv, CY_CRYPTO_AES_BLOCK_SIZE);
        }
        if(! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, length))
        {
            input_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((input_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_input_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_array);
        }
        if(! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, length))
        {
            output_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((output_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_output_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)output_array);
        }

        temp_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((temp_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
        aligned_temp_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)temp_array);

        while(( length > 0 ) )
        {
            if(aligned_input_array != input_ptr)
            {
                ifx_mbedtls_memcpy((void*)aligned_input_array, input_ptr, CY_CRYPTO_AES_BLOCK_SIZE);
            }
            Cy_Crypto_Core_MemCpy(ctx->obj.base, aligned_temp_array, aligned_input_array, CY_CRYPTO_AES_BLOCK_SIZE);

            status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_DECRYPT, aligned_output_array, aligned_input_array, ctx->aes_state);

            Cy_Crypto_Core_MemXor(ctx->obj.base, aligned_output_array, aligned_output_array, aligned_iv_array, CY_CRYPTO_AES_BLOCK_SIZE);
            Cy_Crypto_Core_MemCpy(ctx->obj.base, aligned_iv_array, aligned_temp_array, CY_CRYPTO_AES_BLOCK_SIZE);

            if(aligned_output_array != output)
            {
                ifx_mbedtls_memcpy(output, aligned_output_array, (uint16_t)CY_CRYPTO_AES_BLOCK_SIZE);
            }
            else
            {
                aligned_output_array += CY_CRYPTO_AES_BLOCK_SIZE;
            }

            if(aligned_input_array == input_ptr)
            {
                aligned_input_array += CY_CRYPTO_AES_BLOCK_SIZE;
            }

            output += CY_CRYPTO_AES_BLOCK_SIZE;
            input_ptr += CY_CRYPTO_AES_BLOCK_SIZE;
            length -= CY_CRYPTO_AES_BLOCK_SIZE;

            if (CY_CRYPTO_SUCCESS != status)
            {
                ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                ifx_mbedtls_free(temp_array);
                break;
            }
        }
        if(aligned_iv_array != iv)
        {
            ifx_mbedtls_memcpy((void*)iv, (void*)aligned_iv_array, CY_CRYPTO_AES_BLOCK_SIZE);
        }
        if(temp_array != NULL)
        {
            ifx_mbedtls_free(temp_array);
        }
        goto cleanup;
#else
        unsigned char temp[CY_CRYPTO_AES_BLOCK_SIZE];
        while(( length > 0 ) && (ret == 0))
        {
            Cy_Crypto_Core_MemCpy(ctx->obj.base, temp, input, CY_CRYPTO_AES_BLOCK_SIZE);

            status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_DECRYPT, output, input, ctx->aes_state);

            Cy_Crypto_Core_MemXor(ctx->obj.base, output, output, iv, CY_CRYPTO_AES_BLOCK_SIZE);
            Cy_Crypto_Core_MemCpy(ctx->obj.base, iv, temp, CY_CRYPTO_AES_BLOCK_SIZE);


            input  += CY_CRYPTO_AES_BLOCK_SIZE;
            output += CY_CRYPTO_AES_BLOCK_SIZE;
            length -= CY_CRYPTO_AES_BLOCK_SIZE;

            if (CY_CRYPTO_SUCCESS != status)
            {
                ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            }
        }
#endif
    }
    else
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *aligned_iv_array = (uint8_t *)iv;
        uint8_t *aligned_input_array = (uint8_t *)input;
        uint8_t *aligned_output_array = (uint8_t *)output;
        uint8_t *input_ptr = (uint8_t *)input;

        if(! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)iv, CY_CRYPTO_AES_BLOCK_SIZE))
        {
            iv_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((iv_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_iv_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)iv_array);
            ifx_mbedtls_memcpy((void*)aligned_iv_array, (void*)iv, CY_CRYPTO_AES_BLOCK_SIZE);
        }
        if(! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, length))
        {
            input_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((input_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_input_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_array);
        }
        if(! CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, length))
        {
            output_array = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((output_array == NULL) ? AES_MEM_ALLOC_FAILED : 0);
            aligned_output_array = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)output_array);
        }
        while(( length > 0 ))
        {
            if(aligned_input_array != input_ptr)
            {
                ifx_mbedtls_memcpy((void*)aligned_input_array, input_ptr, CY_CRYPTO_AES_BLOCK_SIZE);
            }
            Cy_Crypto_Core_MemXor(ctx->obj.base, aligned_output_array, aligned_input_array, aligned_iv_array, CY_CRYPTO_AES_BLOCK_SIZE);

            status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_ENCRYPT, aligned_output_array, aligned_output_array, ctx->aes_state);

            Cy_Crypto_Core_MemCpy(ctx->obj.base, aligned_iv_array, aligned_output_array, CY_CRYPTO_AES_BLOCK_SIZE);

            if(output != aligned_output_array)
            {
                ifx_mbedtls_memcpy(output, aligned_output_array, (uint16_t)CY_CRYPTO_AES_BLOCK_SIZE);
            }
            else
            {
                aligned_output_array +=CY_CRYPTO_AES_BLOCK_SIZE;
            }

            if(aligned_input_array == input_ptr)
            {
                aligned_input_array += CY_CRYPTO_AES_BLOCK_SIZE;
            }

            output += CY_CRYPTO_AES_BLOCK_SIZE;
            input_ptr  += CY_CRYPTO_AES_BLOCK_SIZE;
            length -= CY_CRYPTO_AES_BLOCK_SIZE;

            if (CY_CRYPTO_SUCCESS != status)
            {
                ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                break;
            }
        }

        if(aligned_iv_array != iv)
        {
            ifx_mbedtls_memcpy((void*)iv, (void*)aligned_iv_array, CY_CRYPTO_AES_BLOCK_SIZE);
        }

        goto cleanup;
#else
        while(( length > 0 ) && (ret == 0))
        {
            Cy_Crypto_Core_MemXor(ctx->obj.base, output, input, iv, CY_CRYPTO_AES_BLOCK_SIZE);

            status = Cy_Crypto_Core_Aes_Ecb(ctx->obj.base, CY_CRYPTO_ENCRYPT, output, output, ctx->aes_state);

            Cy_Crypto_Core_MemCpy(ctx->obj.base, iv, output, CY_CRYPTO_AES_BLOCK_SIZE);

            input  += CY_CRYPTO_AES_BLOCK_SIZE;
            output += CY_CRYPTO_AES_BLOCK_SIZE;
            length -= CY_CRYPTO_AES_BLOCK_SIZE;

            if (CY_CRYPTO_SUCCESS != status)
            {
                ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            }
        }
#endif
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
cleanup:
    if(iv_array != NULL)
    {
        ifx_mbedtls_free(iv_array);
    }
    if(input_array != NULL)
    {
        ifx_mbedtls_free(input_array);
    }
    if(output_array != NULL)
    {
        ifx_mbedtls_free(output_array);
    }
#endif
    return( ret );
}

#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_XTS)

/* Endianess with 64 bits values */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )             \
        | ( (uint64_t) (b)[(i) + 6] << 48 )             \
        | ( (uint64_t) (b)[(i) + 5] << 40 )             \
        | ( (uint64_t) (b)[(i) + 4] << 32 )             \
        | ( (uint64_t) (b)[(i) + 3] << 24 )             \
        | ( (uint64_t) (b)[(i) + 2] << 16 )             \
        | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint64_t) (b)[(i)    ]       );            \
}
#endif

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
{                                                       \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * GF(2^128) multiplication function
 *
 * This function multiplies a field element by x in the polynomial field
 * representation. It uses 64-bit word operations to gain speed but compensates
 * for machine endianess and hence works correctly on both big and little
 * endian machines.
 */
static void mbedtls_gf128mul_x_ble( unsigned char r[16],
                                    const unsigned char x[16] )
{
    uint64_t a, b, ra, rb;

    GET_UINT64_LE( a, x, 0 );
    GET_UINT64_LE( b, x, 8 );

    ra = ( a << 1 )  ^ 0x0087 >> ( 8 - ( ( b >> 63 ) << 3 ) );
    rb = ( a >> 63 ) | ( b << 1 );

    PUT_UINT64_LE( ra, r, 0 );
    PUT_UINT64_LE( rb, r, 8 );
}

/*
 * AES-XTS buffer encryption/decryption
 */
int mbedtls_aes_crypt_xts( mbedtls_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t blocks = length / 16;
    size_t leftover = length % 16;
    unsigned char tweak[16];
    unsigned char prev_tweak[16];
    unsigned char tmp[16];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( data_unit != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    /* Data units must be at least 16 bytes long. */
    if( length < 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
    if( length > ( 1 << 20 ) * 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* Compute the tweak. */
    ret = mbedtls_aes_crypt_ecb( &ctx->tweak, MBEDTLS_AES_ENCRYPT,
                                 data_unit, tweak );
    if( ret != 0 )
        return( ret );

    while( blocks-- )
    {
        size_t i;

        if( leftover && ( mode == MBEDTLS_AES_DECRYPT ) && blocks == 0 )
        {
            /* We are on the last block in a decrypt operation that has
             * leftover bytes, so we need to use the next tweak for this block,
             * and this tweak for the lefover bytes. Save the current tweak for
             * the leftovers and then update the current tweak for use on this,
             * the last full block. */
            ifx_mbedtls_memcpy( prev_tweak, tweak, sizeof( tweak ) );
            mbedtls_gf128mul_x_ble( tweak, tweak );
        }

        for( i = 0; i < 16; i++ )
            tmp[i] = input[i] ^ tweak[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return( ret );

        for( i = 0; i < 16; i++ )
            output[i] = tmp[i] ^ tweak[i];

        /* Update the tweak for the next block. */
        mbedtls_gf128mul_x_ble( tweak, tweak );

        output += 16;
        input += 16;
    }

    if( leftover )
    {
        /* If we are on the leftover bytes in a decrypt operation, we need to
         * use the previous tweak for these bytes (as saved in prev_tweak). */
        unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;

        /* We are now on the final part of the data unit, which doesn't divide
         * evenly by 16. It's time for ciphertext stealing. */
        size_t i;
        unsigned char *prev_output = output - 16;

        /* Copy ciphertext bytes from the previous block to our output for each
         * byte of cyphertext we won't steal. At the same time, copy the
         * remainder of the input for this final round (since the loop bounds
         * are the same). */
        for( i = 0; i < leftover; i++ )
        {
            output[i] = prev_output[i];
            tmp[i] = input[i] ^ t[i];
        }

        /* Copy ciphertext bytes from the previous block for input in this
         * round. */
        for( ; i < 16; i++ )
            tmp[i] = prev_output[i] ^ t[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return ret;

        /* Write the result back to the previous block, overriding the previous
         * output we copied. */
        for( i = 0; i < 16; i++ )
            prev_output[i] = tmp[i] ^ t[i];
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n = *iv_off;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( n > 15 )
        return (MBEDTLS_ERR_AES_BAD_INPUT_DATA);

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_internal_aes_encrypt( ctx, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_internal_aes_encrypt( ctx, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    while( length-- )
    {
        ifx_mbedtls_memcpy( ov, iv, 16 );
        mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        ifx_mbedtls_memcpy( iv, ov + 1, 16 );
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
 */
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t n = *iv_off;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( n > 15 )
        return (MBEDTLS_ERR_AES_BAD_INPUT_DATA);

    while( length-- )
    {
        if( n == 0 )
        {
            ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
            if( ret != 0 )
                goto exit;
        }
        *output++ =  *input++ ^ iv[n];

        n = ( n + 1 ) & 0x0F;
    }

    *iv_off = n;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( nc_off != NULL );
    AES_VALIDATE_RET( nonce_counter != NULL );
    AES_VALIDATE_RET( stream_block != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if ( n > 0x0F )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* MBEDTLS_AES_ALT */

#endif /* MBEDTLS_AES_C */

#endif /* CY_IP_MXCRYPTO */
