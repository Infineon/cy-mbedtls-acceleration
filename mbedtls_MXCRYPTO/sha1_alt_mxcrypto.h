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
 * \file    sha1_alt_mxcrypto.h
 * \version 2.3.0
 *
 * \brief   header file - wrapper for mbedtls SHA1 HW acceleration
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#if !defined(SHA1_ALT_H)
#define SHA1_ALT_H

#include "crypto_common.h"

#define SHA1_DCACHE_BUFFER_SIZE  (64)

#if defined(MBEDTLS_SHA1_ALT)
typedef struct mbedtls_sha1_context {
    cy_cmgr_crypto_hw_t MBEDTLS_PRIVATE(obj);
    uint8_t MBEDTLS_PRIVATE(hashState_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_sha_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE]);         /* Structure used by CY Crypto Driver   */
    cy_stc_crypto_sha_state_t* MBEDTLS_PRIVATE(hashState);
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    uint8_t MBEDTLS_PRIVATE(shaBuffers_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v1_sha1_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE]);         /* Structure used by CY Crypto Driver   */
    cy_stc_crypto_v1_sha1_buffers_t* MBEDTLS_PRIVATE(shaBuffers);
#else
    uint8_t MBEDTLS_PRIVATE(shaBuffers_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v2_sha1_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE]);         /* Structure used by CY Crypto Driver   */
    cy_stc_crypto_v2_sha1_buffers_t* MBEDTLS_PRIVATE(shaBuffers);
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t output_array[CY_CRYPTO_ALIGN_CACHE_LINE(32)+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    uint8_t* output_array_ptr;
#endif
}
mbedtls_sha1_context;

#endif /* MBEDTLS_SHA1_ALT */

#endif /* (SHA1_ALT_H) */

#endif /* CY_IP_MXCRYPTO */
