
/***************************************************************************//**
* \file ifx_cryptolite_transparent_types.h
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_TYPES_H)
#define IFX_CRYPTOLITE_TRANSPARENT_TYPES_H

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_CRYPTOLITE_SHA)
typedef struct
{
    psa_algorithm_t hash_type;
    cy_stc_cryptolite_context_sha256_t sha_context;
} ifx_cryptolite_transparent_hash_operation_t;
#endif

#if defined(IFX_PSA_CRYPTOLITE_MAC)
typedef struct
{
    psa_algorithm_t mac_type;
    #if defined(IFX_PSA_CRYPTOLITE_CMAC)
    cy_stc_cryptolite_aes_state_t cmac_state;
    cy_stc_cryptolite_aes_buffers_t cmac_buffer;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_HMAC)
    cy_stc_cryptolite_context_hmac_sha256_t hmac_context;        
    #endif
} ifx_cryptolite_transparent_mac_operation_t;
#endif


#if defined(IFX_PSA_CRYPTOLITE_CIPHER)
typedef struct
{
    psa_algorithm_t alg;
    size_t iv_length;
    cy_en_cryptolite_dir_mode_t mode;

    union 
    {
         #if defined(PSA_WANT_ALG_ECB_NO_PADDING) || defined(PSA_WANT_ALG_CBC_NO_PADDING)  || defined(PSA_WANT_ALG_CFB) \
        || defined(PSA_WANT_ALG_CTR)
        cy_stc_cryptolite_aes_state_t aes_state;
        #endif
    }state;

    union 
    {
        #if defined(PSA_WANT_ALG_ECB_NO_PADDING) || defined(PSA_WANT_ALG_CBC_NO_PADDING)  || defined(PSA_WANT_ALG_CFB) \
        || defined(PSA_WANT_ALG_CTR)
        cy_stc_cryptolite_aes_buffers_t aes_buffer;
        #endif
    }buffer;
    

} ifx_cryptolite_transparent_cipher_operation_t;
#endif


#if defined(IFX_PSA_CRYPTOLITE_AEAD)
typedef struct
{
    cy_stc_cryptolite_aes_ccm_state_t aes_state;
    cy_stc_cryptolite_aes_ccm_buffers_t aes_buffers;
    psa_algorithm_t alg;
    psa_key_type_t key_type;
    bool is_encrypt;
    uint8_t tag_length;

} ifx_cryptolite_transparent_aead_operation_t;
#endif


#if defined(IFX_PSA_CRYPTOLITE_KEY_DERIVATION)

/**
 * State identifier for multi-part key derivation operations.
 */
typedef uint32_t ifx_cryptolite_key_derivation_state_t;

/// Newly initialized key derivation operation
#define IFX_CRYPTOLITE_KEY_DERIVATION_STATE_INIT ((ifx_cryptolite_key_derivation_state_t)0)
/// Setup done, waiting for key
#define IFX_CRYPTOLITE_KEY_DERIVATION_STATE_NEED_KEY ((ifx_cryptolite_key_derivation_state_t)1)
/// Active key derivation operation
#define IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE ((ifx_cryptolite_key_derivation_state_t)2)
/// Operating key derivation operation
#define IFX_CRYPTOLITE_KEY_DERIVATION_STATE_OPERATING ((ifx_cryptolite_key_derivation_state_t)3)
/// Finished key derivation operation
#define IFX_CRYPTOLITE_KEY_DERIVATION_STATE_FINISHED ((ifx_cryptolite_key_derivation_state_t)4)

/**
 * State object for multi-part key derivation operations.
 */
typedef struct
{
    ifx_cryptolite_key_derivation_state_t state; ///< Operation state
    size_t capacity; ///< Capacity of operation in bits
    size_t remaining_capacity; ///< Remaining capacity of operation in bits
    uint8_t key[16]; ///< Buffer for 128 bit shared key
    size_t key_size; ///< Size of key in bytes (16)
    uint32_t counter; ///< Iteration counter of KDF
    uint8_t * label; ///< Pointer to label (dynamically allocated)
    size_t label_size; ///< Actual size of label
    uint8_t * seed; ///< Pointer to seed (dynamically allocated)
    size_t seed_size; ///< Actual size of seed
    uint8_t * fixed_data; ///< Pointer to fixed_data (dynamically allocated)
    size_t fixed_data_size; ///< Actual size of fixed_data
    uint8_t block[16]; ///< Block cache
    uint8_t block_index; ///< Block cache
} ifx_cryptolite_key_derivation_operation_t;
#endif


#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_TYPES_H) */
