/***************************************************************************//**
* \file ifx_mxcrypto_common.h
*
* \brief
*  PSA crypto mxcrypto helper functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2022 Cypress Semiconductor Corporation
* SPDX-License-Identifier: Apache-2.0
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#if !defined(IFX_MXCRYPTO_COMMON_H)
#define IFX_MXCRYPTO_COMMON_H

#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "ifx_mxcrypto_config.h"

#include "cy_pdl.h"
#include <psa/crypto.h>

#if defined(__cplusplus)
extern "C" {
#endif


#if !defined(ifx_mxcrypto_memset)
#include <string.h>
#define ifx_mxcrypto_memset memset
#endif
#ifndef  ifx_mxcrypto_memcmp
#include <string.h>
#define  ifx_mxcrypto_memcmp      memcmp
#endif

#if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)

#ifndef ifx_mxcrypto_malloc
#include <stdlib.h>
#define ifx_mxcrypto_malloc malloc
#endif
#ifndef ifx_mxcrypto_free
#include <stdlib.h>
#define ifx_mxcrypto_free free
#endif
#ifndef  ifx_mxcrypto_memcpy
#include <string.h>
#define  ifx_mxcrypto_memcpy      memcpy
#endif
#ifndef  ifx_mxcrypto_memset
#include <string.h>
#define  ifx_mxcrypto_memset      memset
#endif
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
#define CY_PSA_DCACHE_LINE_ALIGNMENT_SIZE     (32u) // 32byte align
#define CY_PSA_IS_MEM_CACHABLE(x,y)           (Cy_Syslib_IsMemCacheable(MPU, (uint32_t)x, y))
#define CY_PSA_IS_MEM_CACHE_ALIGNED(x,y)      ((((uint32_t)x % CY_CRYPTO_DCAHCE_PADDING_SIZE) == 0u) && ((uint32_t)y % CY_CRYPTO_DCAHCE_PADDING_SIZE == 0u))
#define CY_PSA_IS_MEM_CACHABLE_ALIGNED(x,y)   (CY_PSA_IS_MEM_CACHABLE(x,y) && CY_PSA_IS_MEM_CACHE_ALIGNED(x,y))
#else
#define CY_PSA_DCACHE_LINE_ALIGNMENT_SIZE     (0u)
#define CY_PSA_IS_MEM_CACHABLE(x,y)           (false)
#define CY_PSA_IS_MEM_CACHE_ALIGNED(x,y)      (false)
#define CY_PSA_IS_MEM_CACHABLE_ALIGNED(x,y)   (CY_PSA_IS_MEM_CACHABLE(x,y) && CY_PSA_IS_MEM_CACHE_ALIGNED(x,y))
#endif


#if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521)
    #define IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTO_ECC_P521_BYTE_SIZE)
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)
    #define IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE  (2* CY_CRYPTO_ECC_P384_BYTE_SIZE)
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)
    #define IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE  (2* CY_CRYPTO_ECC_P256_BYTE_SIZE)
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)
    #define IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTO_ECC_P224_BYTE_SIZE)
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)
    #define IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTO_ECC_P192_BYTE_SIZE)
#endif

#if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521)
    #define IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTO_ECC_P521_BYTE_SIZE
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)
    #define IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTO_ECC_P384_BYTE_SIZE
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)
    #define IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTO_ECC_P256_BYTE_SIZE
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)
    #define IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTO_ECC_P224_BYTE_SIZE
#elif defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)
    #define IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTO_ECC_P192_BYTE_SIZE
#endif

#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
psa_status_t ifx_mxcrypto_get_rsa_public_key(psa_key_type_t key_type, unsigned char **p, 
                         const unsigned char *end, cy_stc_crypto_rsa_pub_key_t *rsa_pub_key);
#endif


#if defined(IFX_PSA_MXCRYPTO_RSA_SIGN)
psa_status_t ifx_mxcrypto_get_rsa_private_key(unsigned char **p, 
                         const unsigned char *end, cy_stc_crypto_rsa_pub_key_t *rsa_pub_key);                         
#endif

#define SIG_VALID 1

psa_status_t  ifx_mxcrypto_status_to_psa_status (cy_en_crypto_status_t mxcrypto_status);

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTO */

#endif /* #if !defined (IFX_MXCRYPTO_COMMON_H) */
