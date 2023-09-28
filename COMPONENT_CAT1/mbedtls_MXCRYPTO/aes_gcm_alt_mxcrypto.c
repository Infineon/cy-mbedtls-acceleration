/*
 *  Source file for mbedtls AES GCM HW acceleration functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (c) (2019-2023), Cypress Semiconductor Corporation (an Infineon company) or
 *  an affiliate of Cypress Semiconductor Corporation.
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
 * \file    aes_gcm_alt_mxcrypto.c
 * \version 2.1.1
 *
 * \brief   This file contains AES GCM functions implementation.
 *
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_GCM_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/gcm.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_GCM_ALT)

/* Parameter validation macros */
#define GCM_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_GCM_BAD_INPUT )
#define GCM_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#include "crypto_common.h"
#include "cy_crypto_core.h"

/*
 * Initialize a context
 */
void mbedtls_gcm_init(mbedtls_gcm_context *ctx)
{

    GCM_VALIDATE( ctx != NULL );
    cy_hw_zeroize(ctx, sizeof( mbedtls_gcm_context ) );

    (void)cy_hw_crypto_reserve((cy_cmgr_crypto_hw_t *)ctx, CY_CMGR_CRYPTO_COMMON);
}


int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits)
{

    cy_en_crypto_aes_key_length_t key_length;
    cy_en_crypto_status_t status;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( key != NULL );

    if(cipher != MBEDTLS_CIPHER_ID_AES)
    {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    switch( keybits )
    {
        case 128: key_length = CY_CRYPTO_KEY_AES_128; break;
        case 192: key_length = CY_CRYPTO_KEY_AES_192; break;
        case 256: key_length = CY_CRYPTO_KEY_AES_256; break;
        default : return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    status = Cy_Crypto_Core_Aes_GCM_Init(ctx->obj.base, &ctx->aes_buffers, &ctx->aes_state);
    if (CY_CRYPTO_SUCCESS == status)
    {
        status = Cy_Crypto_Core_Aes_GCM_SetKey(ctx->obj.base, key, key_length, &ctx->aes_state);
    }

    if (CY_CRYPTO_SUCCESS != status)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;
}


int mbedtls_gcm_starts(mbedtls_gcm_context *ctx, int mode, const unsigned char *iv, size_t iv_len)
{

    cy_en_crypto_status_t status;
    cy_en_crypto_dir_mode_t aes_mode;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );

    /* IV is limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if (iv_len == 0 || (uint64_t) iv_len >> 61 != 0) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    switch( mode )
    {
        case MBEDTLS_GCM_ENCRYPT: aes_mode = CY_CRYPTO_ENCRYPT; break;
        case MBEDTLS_GCM_DECRYPT: aes_mode = CY_CRYPTO_DECRYPT; break;
        default : return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    status = Cy_Crypto_Core_Aes_GCM_Start(ctx->obj.base, aes_mode, iv, iv_len, &ctx->aes_state);

    if (CY_CRYPTO_SUCCESS != status)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;
}


int mbedtls_gcm_update_ad( mbedtls_gcm_context *ctx,
                           const unsigned char *add, size_t add_len )

{
    cy_en_crypto_status_t status;

    GCM_VALIDATE_RET( add_len == 0 || add != NULL );

    /* IV is limited to 2^64 bits, so 2^61 bytes */
    if( (uint64_t) add_len >> 61 != 0 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    status = Cy_Crypto_Core_Aes_GCM_AAD_Update(ctx->obj.base, (uint8_t *)add, add_len, &ctx->aes_state);

    if (CY_CRYPTO_SUCCESS != status)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;
}


int mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                        const unsigned char *input, size_t input_length,
                        unsigned char *output, size_t output_size,
                        size_t *output_length )
{
    cy_en_crypto_status_t status;

    if( output_size < input_length )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    GCM_VALIDATE_RET( output_length != NULL );
    *output_length = input_length;

    if( input_length == 0 )
    return( 0 );

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( input != NULL );
    GCM_VALIDATE_RET( output != NULL );

    if( output > input && (size_t) ( output - input ) < input_length )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if( ctx->aes_state.data_size + input_length < ctx->aes_state.data_size  ||
        (uint64_t) ctx->aes_state.data_size + input_length > 0xFFFFFFFE0ull )
    {
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    status = Cy_Crypto_Core_Aes_GCM_Update(ctx->obj.base, input,  input_length, output, &ctx->aes_state);

    if (CY_CRYPTO_SUCCESS != status)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;
}


int mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                        unsigned char *output, size_t output_size,
                        size_t *output_length,
                        unsigned char *tag, size_t tag_len )
{
    cy_en_crypto_status_t status;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    /* We never pass any output in finish(). The output parameter exists only
     * for the sake of alternative implementations. */
    (void) output;
    (void) output_size;
    *output_length = 0;

    if (tag_len > 16 || tag_len < 4) {
        return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    status = Cy_Crypto_Core_Aes_GCM_Finish(ctx->obj.base, tag, tag_len,  &ctx->aes_state);

    if (CY_CRYPTO_SUCCESS != status)
    {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    return 0;

}

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag)
{

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    if( ( ret = mbedtls_gcm_starts( ctx, mode, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_update_ad( ctx, add, add_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_update( ctx, input, length,
                                    output, length, &olen ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_finish( ctx, NULL, 0, &olen, tag, tag_len ) ) != 0 )
        return( ret );

    return( 0 );

}


int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char check_tag[16];

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( tag != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );

    if( ( ret = mbedtls_gcm_crypt_and_tag( ctx, MBEDTLS_GCM_DECRYPT, length,
                                   iv, iv_len, add, add_len,
                                   input, output, tag_len, check_tag ) ) != 0 )
    {
        return( ret );
    }

    if(Cy_Crypto_Core_MemCmp(ctx->obj.base, tag, check_tag, tag_len) != 0U)
    {
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }

    return 0;
}

void mbedtls_gcm_free(mbedtls_gcm_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->aes_state.aes_buffer != NULL) {
        Cy_Crypto_Core_Aes_GCM_Free(ctx->obj.base, &ctx->aes_state);
    }

    cy_hw_crypto_release((cy_cmgr_crypto_hw_t *)ctx);
    cy_hw_zeroize(ctx, sizeof(mbedtls_gcm_context));
}

#endif /* MBEDTLS_GCM_ALT */
#endif /* MBEDTLS_GCM_C */
#endif /* CY_IP_MXCRYPTO */
