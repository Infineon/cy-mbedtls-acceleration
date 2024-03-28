/*
 *  Source file for mbedtls TRNG entropy source functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (c) (2019-2024), Cypress Semiconductor Corporation (an Infineon company) or
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
 * \file    trng_alt_mxcrypto.c
 * \version 1.6
 *
 * \brief   This file contains TRNG functions implementation.
 *
 */

#include "cy_device.h"
#include "cy_syslib.h"

#if CY_CPU_CORTEX_M0P || ((CY_CPU_CORTEX_M7 || CY_CPU_CORTEX_M4 || CY_CPU_CORTEX_M33) && !defined(CY_DEVICE_SECURE))
#if defined (CY_IP_MXCRYPTO)

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#if defined(MBEDTLS_ENTROPY_C)

#include <string.h>
#include "mbedtls/entropy.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

#include "crypto_common.h"
#include "cy_crypto_core.h"
#include "cy_crypto_common.h"

#if ((CY_CRYPTO_DRV_VERSION_MAJOR == 2) && ( CY_CRYPTO_DRV_VERSION_MINOR < 70))
/* Initialization polynomial values from True Random Generator */
#define GARO31_INITSTATE          (0x04c11db7u)
#define FIRO31_INITSTATE          (0x04c11db7u)
#else
#include "cy_crypto_core_trng_config.h"
#endif

#define MBEDTLS_ERR_TRNG_BAD_INPUT_DATA  (-1)
#define MAX_TRNG_BIT_SIZE                (32UL)

/* Parameter validation macros based on platform_util.h */
#define TRNG_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_TRNG_BAD_INPUT_DATA )
#define TRNG_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/**
 * \brief           Entropy poll callback for a hardware source
 *
 * \warning         This is not provided by mbed TLS!
 *                  See \c MBEDTLS_ENTROPY_HARDWARE_ALT in mbedtls_config.h.
 *
 * \note            This must accept NULL as its first argument.
 */


#if ((CY_CRYPTO_DRV_VERSION_MAJOR == 2) && ( CY_CRYPTO_DRV_VERSION_MINOR < 70))
int mbedtls_hardware_poll( void * data,
                           unsigned char *output,
                           size_t len,
                           size_t *olen )
{
    int ret = 0;
    *olen = 0;
    /* temporary random data buffer */
    uint32_t random = 0u;
    (void)data;
    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;

    TRNG_VALIDATE_RET(output != NULL);
    TRNG_VALIDATE_RET(olen != NULL);

    (void)cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_TRNG);

    /* Get Random byte */
    while ((*olen < len) && (ret == 0))
    {
        if ( Cy_Crypto_Core_Trng(CRYPTO, GARO31_INITSTATE, FIRO31_INITSTATE,
                                             MAX_TRNG_BIT_SIZE, &random) != CY_CRYPTO_SUCCESS)
        {
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        } else {
            for (uint8_t i = 0; (i < 4) && (*olen < len) ; i++)
            {
                *output++ = ((uint8_t *)&random)[i];
                *olen += 1;
            }
        }
    }
    random = 0uL;

    cy_hw_crypto_release(&crypto_obj);

    return (ret);
}
#else
int mbedtls_hardware_poll( void * data,
                           unsigned char *output,
                           size_t len,
                           size_t *olen )
{
    int ret = 0;
    *olen = 0;
    /* temporary random data buffer */
    uint32_t random = 0u;
    (void)data;
    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;

    TRNG_VALIDATE_RET(output != NULL);
    TRNG_VALIDATE_RET(olen != NULL);

    (void)cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_TRNG);

    /* Get Random byte */
    while ((*olen < len) && (ret == 0))
    {
        if ( Cy_Crypto_Core_Trng(CRYPTO, CY_CRYPTO_DEF_TR_GARO, CY_CRYPTO_DEF_TR_FIRO,
                                             MAX_TRNG_BIT_SIZE, &random) != CY_CRYPTO_SUCCESS)
        {
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        } else {
            for (uint8_t i = 0; (i < 4) && (*olen < len) ; i++)
            {
                *output++ = ((uint8_t *)&random)[i];
                *olen += 1;
            }
        }
    }
    random = 0uL;

    Cy_Crypto_Core_Trng_DeInit(CRYPTO);
    cy_hw_crypto_release(&crypto_obj);

    return (ret);
}
#endif
#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* CY_IP_MXCRYPTO */
#endif /* CY_CPU_CORTEX_M0P || ((CY_CPU_CORTEX_M7 || CY_CPU_CORTEX_M4 || CY_CPU_CORTEX_M33) && !defined(CY_DEVICE_SECURE))
*/