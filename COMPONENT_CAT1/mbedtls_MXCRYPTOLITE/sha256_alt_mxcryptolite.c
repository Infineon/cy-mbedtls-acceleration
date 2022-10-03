/*
 *  mbed Microcontroller Library
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2019-2022 Cypress Semiconductor Corporation
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
 * \file     sha256_alt_mxcryptolite.c
 * \version  2.0
 *
 * \brief    Source file - wrapper for mbedtls SHA256 HW acceleration
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_SHA256_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/compat-2.x.h"

#include <string.h>

#if defined(MBEDTLS_SHA256_ALT)

/* Parameter validation macros based on platform_util.h */
#define SHA256_VALIDATE_RET(cond)                           \
     MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA256_BAD_INPUT_DATA )
#define SHA256_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )

void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    SHA256_VALIDATE( ctx != NULL );
    Cy_Cryptolite_Sha256_Init(CRYPTOLITE, &ctx->hashState);
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    if( ctx == NULL )
        return;

    Cy_Cryptolite_Sha256_Free(CRYPTOLITE, &ctx->hashState);
}

void mbedtls_sha256_clone( mbedtls_sha256_context *dst, const mbedtls_sha256_context *src )
{
    SHA256_VALIDATE( dst != NULL );
    SHA256_VALIDATE( src != NULL );

    *dst = *src;
	Cy_Cryptolite_Sha256_Init(CRYPTOLITE, &dst->hashState);
}

/*
 * SHA-256 context setup
 */
int mbedtls_sha256_starts( mbedtls_sha256_context *ctx, int is224)
{
	cy_en_cryptolite_status_t status;

    SHA256_VALIDATE_RET( ctx != NULL );

    if( is224 == 1 )
        return(-1);

    /*only support sha256*/
    status = Cy_Cryptolite_Sha256_Start(CRYPTOLITE, &ctx->hashState);
    if (CY_CRYPTOLITE_SUCCESS != status)
        return (-1);

    return (0);
}

/*
 * SHA-256 process buffer
 */
int mbedtls_sha256_update( mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen )
{
	cy_en_cryptolite_status_t status;

    SHA256_VALIDATE_RET( ctx != NULL );
    SHA256_VALIDATE_RET( input != NULL );

    if( ilen == 0 )
        return( 0 );

    status = Cy_Cryptolite_Sha256_Update(CRYPTOLITE, (uint8_t *)input, ilen, &ctx->hashState);
    if (CY_CRYPTOLITE_SUCCESS != status)
        return (-1);

    return (0);
	
}

/*
 * SHA-256 final digest
 */
int mbedtls_sha256_finish( mbedtls_sha256_context *ctx, unsigned char *output )
{
	cy_en_cryptolite_status_t status;

    SHA256_VALIDATE_RET( ctx != NULL );
    SHA256_VALIDATE_RET( (unsigned char *)output != NULL );

    if (output == NULL)
        return (-1);

    status = Cy_Cryptolite_Sha256_Finish(CRYPTOLITE, output, &ctx->hashState);
    if (CY_CRYPTOLITE_SUCCESS != status)
        return (-1);

    return (0);
}

int mbedtls_internal_sha256_process( mbedtls_sha256_context *ctx, const unsigned char data[64] )
{
    cy_en_cryptolite_status_t status;

    SHA256_VALIDATE_RET( ctx != NULL );
    SHA256_VALIDATE_RET( (const unsigned char *)data != NULL );

    status = Cy_Cryptolite_Sha256_Update(CRYPTOLITE, (unsigned char *)data, CY_CRYPTOLITE_SHA256_BLOCK_SIZE, &ctx->hashState);
    if (CY_CRYPTOLITE_SUCCESS != status)
        return (-1);

    return (0);
}

#endif /* MBEDTLS_SHA256_ALT */

#endif /* MBEDTLS_SHA256_C */

#endif /* CY_IP_MXCRYPTOLITE */
