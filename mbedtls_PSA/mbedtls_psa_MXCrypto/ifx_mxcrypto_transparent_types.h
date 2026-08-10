
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_types.h
*
* \brief
*  PSA crypto transparent driver types.
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

#if !defined(IFX_MXCRYPTO_TRANSPARENT_TYPES_H)
#define IFX_MXCRYPTO_TRANSPARENT_TYPES_H


#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "cy_pdl.h"
#include "ifx_mxcrypto_config.h"
#include "ifx_mxcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_MXCRYPTO_SHA)
typedef struct
{
    cy_stc_crypto_sha_state_t* hash_state;
    uint8_t hash_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_sha_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    psa_algorithm_t hash_type;

#if (CY_IP_MXCRYPTO_VERSION == 1u) 
    cy_stc_crypto_v1_sha_buffers_t  *sha_buffer; //Allocating maximum size for the sha buffers
    uint8_t sha_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v1_sha_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
#elif (CY_IP_MXCRYPTO_VERSION == 2u)    
    cy_stc_crypto_v2_sha_buffers_t*  sha_buffer; //Allocating maximum size for the sha buffers
    uint8_t sha_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v2_sha_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint32_t hash_blk_size;
#endif
} ifx_mxcrypto_transparent_hash_operation_t;
#endif

#if defined(IFX_PSA_MXCRYPTO_MAC)
typedef struct
{
    psa_algorithm_t mac_type;
    struct
    {
        #if defined(IFX_PSA_MXCRYPTO_CMAC)
        #if (CY_IP_MXCRYPTO_VERSION == 1u) 
            cy_stc_crypto_v1_cmac_state_t *cmac_state;
            uint8_t cmac_state_t[sizeof(cy_stc_crypto_v1_cmac_state_t)];
        #elif (CY_IP_MXCRYPTO_VERSION == 2u)    
            uint8_t cmac_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v2_cmac_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
            cy_stc_crypto_v2_cmac_state_t *cmac_state;
        #endif
        #endif
        #if defined(IFX_PSA_MXCRYPTO_HMAC)
            cy_stc_crypto_hmac_state_t *hmac_state;
            uint8_t hmac_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_hmac_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
    }state;

    struct
    {
        #if defined(IFX_PSA_MXCRYPTO_CMAC)
        #if (CY_IP_MXCRYPTO_VERSION == 1u) 
            cy_stc_crypto_v1_cmac_buffers_t *cmac_buffer;
            uint8_t cmac_buffer_t[sizeof(cy_stc_crypto_v1_cmac_buffers_t)];
        #elif (CY_IP_MXCRYPTO_VERSION == 2u)    
            cy_stc_crypto_v2_cmac_buffers_t *cmac_buffer;
            uint8_t cmac_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v2_cmac_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #endif
        #if defined(IFX_PSA_MXCRYPTO_HMAC)
        #if (CY_IP_MXCRYPTO_VERSION == 1u) 
            uint8_t  hmac_buffer;   //Dummy buffer defined for the compilation    
        #elif (CY_IP_MXCRYPTO_VERSION == 2u)    
            cy_stc_crypto_v2_hmac_buffers_t *hmac_buffer;
            uint8_t hmac_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_v2_hmac_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif        
        #endif
    }buffer;

} ifx_mxcrypto_transparent_mac_operation_t;
#endif



#if defined(IFX_PSA_MXCRYPTO_CIPHER)
typedef struct
{
    psa_algorithm_t alg;
    size_t iv_length;
    cy_en_crypto_dir_mode_t mode;

    struct
    {
        #if !(CY_IP_MXCRYPTO_VERSION == 1u) 
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        cy_stc_crypto_aes_gcm_state_t *aes_gcm_state;
        uint8_t aes_gcm_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_gcm_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif

        #if defined(IFX_PSA_MXCRYPTO_CCM)
        cy_stc_crypto_aes_ccm_state_t *aes_ccm_state;
        uint8_t aes_ccm_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_ccm_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #endif

        #if defined(PSA_WANT_ALG_ECB_NO_PADDING) || defined(PSA_WANT_ALG_CBC_NO_PADDING)  || defined(PSA_WANT_ALG_CFB) \
        || defined(IFX_PSA_MXCRYPTO_CTR)
        cy_stc_crypto_aes_state_t *aes_state;
        uint8_t aes_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
    }state;

    struct
    {
        #if defined(PSA_WANT_ALG_ECB_NO_PADDING) || defined(PSA_WANT_ALG_CBC_NO_PADDING)  || defined(PSA_WANT_ALG_CFB) \
        || defined(IFX_PSA_MXCRYPTO_CTR)
        cy_stc_crypto_aes_buffers_t *aes_buffer;
        uint8_t aes_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #if !(CY_IP_MXCRYPTO_VERSION == 1u) 
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        cy_stc_crypto_aes_gcm_buffers_t *aes_gcm_buffer;
        uint8_t aes_gcm_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_gcm_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        cy_stc_crypto_aes_ccm_buffers_t *aes_ccm_buffer;
        uint8_t aes_ccm_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_ccm_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #endif     
    }buffer;
    

} ifx_mxcrypto_transparent_cipher_operation_t;
#endif


#if defined(IFX_PSA_MXCRYPTO_AEAD)
typedef struct
{
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    uint8_t is_encrypt;
    uint8_t tag_length;

    #if !(CY_IP_MXCRYPTO_VERSION == 1u) 
    struct
    {
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        cy_stc_crypto_aes_gcm_state_t *aes_gcm_state;
        uint8_t aes_gcm_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_gcm_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        cy_stc_crypto_aes_ccm_state_t *aes_ccm_state;
        uint8_t aes_ccm_state_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_ccm_state_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
    }state;

    struct
    {
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        cy_stc_crypto_aes_gcm_buffers_t *aes_gcm_buffer;
        uint8_t aes_gcm_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_gcm_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        cy_stc_crypto_aes_ccm_buffers_t *aes_ccm_buffer;
        uint8_t aes_ccm_buffer_t[CY_CRYPTO_ALIGN_CACHE_LINE(sizeof(cy_stc_crypto_aes_ccm_buffers_t))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
        #endif        
    }buffer;
    #endif
} ifx_mxcrypto_transparent_aead_operation_t;
#endif

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTO */

#endif /* #if !defined (IFX_MXCRYPTO_TRANSPARENT_TYPES_H) */
