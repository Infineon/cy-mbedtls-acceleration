/*******************************************************************************
* \file eddsa_alt_sha512.c
* \version 2.3.0
*
* \brief
* This source file provides the sha512 functions for eddsa alt.
* Cryptolite does not support hw based SHA512. This file provides common function
* interface to be implemented by the user. This example implementaion uses the
* standard mbedTLS lib SHA512
********************************************************************************
* \copyright
* Copyright 2025, Cypress Semiconductor Corporation (an Infineon company)
* SPDX-License-Identifier: Apache-2.0
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

/*******************************************************************************
* Header Files
*******************************************************************************/
#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#include <string.h>
#include "cy_cryptolite_common.h"
#include "mbedtls/sha512.h"

/*******************************************************************************
 * Macros
 ******************************************************************************/

 /*******************************************************************************
 * Global Variables
 ******************************************************************************/
mbedtls_sha512_context cy_alt_eddsa_sha512_ctx;
void *Cy_ed25519_sha512_ctx = (void*)&cy_alt_eddsa_sha512_ctx;

cy_en_cryptolite_status_t Cy_ed25519_sha512_init(void *context)
{
    if (context != NULL)
    {
        mbedtls_sha512_init(context);
        return CY_CRYPTOLITE_SUCCESS;
    }
    else
    {
        return CY_CRYPTOLITE_BAD_PARAMS;
    }

}

cy_en_cryptolite_status_t Cy_ed25519_sha512_free(void *context)
{
    if (NULL == context)
    {
        return CY_CRYPTOLITE_BAD_PARAMS;
    }

    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)context;
    memset(ctx, 0, sizeof(mbedtls_sha512_context));

    return CY_CRYPTOLITE_SUCCESS;
}

cy_en_cryptolite_status_t Cy_ed25519_sha512_start(void *context)
{
    if (NULL == context)
    {
        return CY_CRYPTOLITE_BAD_PARAMS;
    }

    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)context;

    if (mbedtls_sha512_starts(ctx, 0) != 0)
    {
        return CY_CRYPTOLITE_HW_ERROR;
    }
    else
    {
        return CY_CRYPTOLITE_SUCCESS;
    }
}

cy_en_cryptolite_status_t Cy_ed25519_sha512_update(void *context, uint8_t const *input, uint32_t ilen)
{
    if ((NULL == context) || (NULL == input))
    {
        return CY_CRYPTOLITE_BAD_PARAMS;
    }

    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)context;

    if (mbedtls_sha512_update(ctx, (const unsigned char *)input, (size_t)ilen) != 0)
    {
        return CY_CRYPTOLITE_HW_ERROR;
    }
    else
    {
        return CY_CRYPTOLITE_SUCCESS;
    }
}

cy_en_cryptolite_status_t Cy_ed25519_sha512_finish(void *context, uint8_t *output)
{
    if ((NULL == context) || (NULL == output))
    {
        return CY_CRYPTOLITE_BAD_PARAMS;
    }

    mbedtls_sha512_context *ctx = (mbedtls_sha512_context *)context;

    if (mbedtls_sha512_finish(ctx, (unsigned char *)output) != 0)
    {
        return CY_CRYPTOLITE_HW_ERROR;
    }
    else
    {
        return CY_CRYPTOLITE_SUCCESS;
    }
}
#endif //#if defined (CY_IP_MXCRYPTOLITE)
