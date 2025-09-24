/***************************************************************************//**
* \file ifx_mxcrypto_transparent_aead.c
*
* \brief
*  PSA crypto transparent AEAD driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2023 Cypress Semiconductor Corporation
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

#include "ifx_mxcrypto_transparent_aead.h"

#if defined(IFX_PSA_MXCRYPTO_AEAD)

#if defined (CY_IP_MXCRYPTO)

static psa_status_t ifx_mxcrypto_transparent_psa_aead_setup(ifx_mxcrypto_transparent_aead_operation_t *operation,  const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer, size_t key_buffer_size,  psa_algorithm_t alg)
{


#if (CY_IP_MXCRYPTO_VERSION == 1u)
(void) operation;
(void) attributes;
(void) key_buffer;
(void) key_buffer_size;
(void) alg;

return PSA_ERROR_NOT_SUPPORTED;

#else
    cy_en_crypto_aes_key_length_t key_length;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t *aligned_key_buffer = (uint8_t *)key_buffer;
    size_t key_bits;
    psa_key_type_t key_type;

    if((NULL==operation) || (NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *in_key_buf = NULL;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)key_buffer, key_buffer_size) )
    {
        in_key_buf = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(key_buffer_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == in_key_buf)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        aligned_key_buffer = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)in_key_buf);
        ifx_mxcrypto_memcpy((void *)aligned_key_buffer, (void *)key_buffer, key_buffer_size);
    }
#endif

    key_bits = psa_get_key_bits(attributes);
    key_type = psa_get_key_type(attributes);

    operation->tag_length = 0;
    operation->alg = PSA_ALG_NONE;

    switch (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0))
    {

#if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0):

            if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) != 16)
            {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto cleanup;
            }

            switch( key_bits )
            {
                case 128: key_length = CY_CRYPTO_KEY_AES_128; break;
                case 192: key_length = CY_CRYPTO_KEY_AES_192; break;
                case 256: key_length = CY_CRYPTO_KEY_AES_256; break;
                default :
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto cleanup;
            }

            operation->state.aes_gcm_state = (cy_stc_crypto_aes_gcm_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_gcm_state_t);
            operation->buffer.aes_gcm_buffer = (cy_stc_crypto_aes_gcm_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_gcm_buffer_t);
            operation->alg = PSA_ALG_GCM;
            cy_status = Cy_Crypto_Core_Aes_GCM_Init(CRYPTO, operation->buffer.aes_gcm_buffer, operation->state.aes_gcm_state);

            if (CY_CRYPTO_SUCCESS == cy_status)
            {
                cy_status = Cy_Crypto_Core_Aes_GCM_SetKey(CRYPTO, aligned_key_buffer, key_length, operation->state.aes_gcm_state);
            }

            status = ifx_mxcrypto_status_to_psa_status(cy_status);

            if (status != PSA_SUCCESS)
            {
                goto cleanup;
            }
            break;
#endif /* IFX_PSA_MXCRYPTO_GCM */

#if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):

            if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) != 16)
            {
                status = PSA_ERROR_NOT_SUPPORTED;
                goto cleanup;
            }

            switch( key_bits )
            {
                case 128: key_length = CY_CRYPTO_KEY_AES_128; break;
                case 192: key_length = CY_CRYPTO_KEY_AES_192; break;
                case 256: key_length = CY_CRYPTO_KEY_AES_256; break;
                default :
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto cleanup;
            }
            operation->state.aes_ccm_state = (cy_stc_crypto_aes_ccm_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_ccm_state_t);
            operation->buffer.aes_ccm_buffer = (cy_stc_crypto_aes_ccm_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_ccm_buffer_t);
            operation->alg = PSA_ALG_CCM;
            cy_status = Cy_Crypto_Core_Aes_Ccm_Init(CRYPTO, operation->buffer.aes_ccm_buffer, operation->state.aes_ccm_state);

            if (CY_CRYPTO_SUCCESS == cy_status)
            {
                cy_status = Cy_Crypto_Core_Aes_Ccm_SetKey(CRYPTO, aligned_key_buffer, key_length, operation->state.aes_ccm_state);
            }

            status = ifx_mxcrypto_status_to_psa_status(cy_status);

            if (status != PSA_SUCCESS)
            {
                goto cleanup;
            }
            break;
#endif /* IFX_PSA_MXCRYPTO_CCM */

        default:
            {
                (void)key_length;
                (void)cy_status;
                (void)key_type;
                (void)key_bits;
                status = PSA_ALG_IS_AEAD ( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
                goto cleanup;
            }
    }

    operation->key_type = psa_get_key_type(attributes);
    operation->tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

cleanup:
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if (NULL != in_key_buf)
    {
        ifx_mxcrypto_free(in_key_buf);
    }
#endif
    return status;

#endif

}

#if !(CY_IP_MXCRYPTO_VERSION == 1u)
#if defined(IFX_PSA_MXCRYPTO_GCM)
static cy_en_crypto_status_t ifx_mxcrypto_transparent_psa_crypt_tag(ifx_mxcrypto_transparent_aead_operation_t *operation, cy_en_crypto_dir_mode_t mode,
                                            size_t input_length, const uint8_t *nonce, size_t nonce_length,
                                            const uint8_t *additional_data, size_t additional_data_length,
                                            const uint8_t *input, uint8_t *output, size_t tag_len, unsigned char *tag)

{
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *aligned_additional_data = (uint8_t *)additional_data;
    uint8_t *aligned_nonce = (uint8_t *)nonce;
    uint8_t *aligned_input = (uint8_t *)input;
    uint8_t *aligned_output = (uint8_t *)output;
    uint8_t *aligned_tag = (uint8_t *)tag;
    uint8_t *ptr_additional_data = NULL;
    uint8_t *ptr_nonce = NULL;
    uint8_t *ptr_input = NULL;
    uint8_t *ptr_output = NULL;
    uint8_t *ptr_tag = NULL;
#endif
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if (operation->alg == PSA_ALG_GCM)
    {
        if (nonce_length == 0 || (uint64_t) nonce_length >> 61 != 0)
        {
            return cy_status;
        }

        if ((uint64_t)additional_data_length >> 61 != 0)
        {
            return cy_status;
        }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)nonce, nonce_length) )
        {
            ptr_nonce = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(nonce_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_nonce)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_nonce = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_nonce);
            ifx_mxcrypto_memcpy((void *)aligned_nonce, (void *)nonce, nonce_length);
        }
        cy_status = Cy_Crypto_Core_Aes_GCM_Start(CRYPTO, mode, aligned_nonce, nonce_length, operation->state.aes_gcm_state);
#else
        cy_status = Cy_Crypto_Core_Aes_GCM_Start(CRYPTO, mode, nonce, nonce_length, operation->state.aes_gcm_state);
#endif

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)additional_data, additional_data_length) )
            {
                ptr_additional_data = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(additional_data_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
                if (NULL == ptr_additional_data)
                {
                    cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                    goto cleanup;
                }
                aligned_additional_data = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_additional_data);
                ifx_mxcrypto_memcpy((void *)aligned_additional_data, (void *)additional_data, additional_data_length);
            }
            cy_status = Cy_Crypto_Core_Aes_GCM_AAD_Update(CRYPTO, (uint8_t *)aligned_additional_data, additional_data_length, operation->state.aes_gcm_state);
        }
#else
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            cy_status = Cy_Crypto_Core_Aes_GCM_AAD_Update(CRYPTO, (uint8_t *)additional_data, additional_data_length, operation->state.aes_gcm_state);
        }
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
            {
                ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
                if (NULL == ptr_input)
                {
                    cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                    goto cleanup;
                }
                aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
                ifx_mxcrypto_memcpy((void *)aligned_input, (void *)input, input_length);
            }
            if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, (uint32_t)input_length) )
            {
                ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
                if (NULL == ptr_output)
                {
                    cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                    goto cleanup;
                }
                aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
            }

            cy_status = Cy_Crypto_Core_Aes_GCM_Update(CRYPTO, aligned_input,  input_length, aligned_output, operation->state.aes_gcm_state);
            if(output != aligned_output)
            {
                ifx_mxcrypto_memcpy((void *)output, (void *)aligned_output, input_length);
            }
        }
#else
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            cy_status = Cy_Crypto_Core_Aes_GCM_Update(CRYPTO, input,  input_length, output, operation->state.aes_gcm_state);
        }
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)tag, tag_len) )
            {
                ptr_tag = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(tag_len) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
                if (NULL == ptr_tag)
                {
                    cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                    goto cleanup;
                }
                aligned_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_tag);
            }
            cy_status = Cy_Crypto_Core_Aes_GCM_Finish(CRYPTO, (uint8_t *)aligned_tag, tag_len, operation->state.aes_gcm_state);
            if(tag != aligned_tag)
            {
                ifx_mxcrypto_memcpy((void *)tag, (void *)aligned_tag, tag_len);
            }
        }
#else
        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            cy_status = Cy_Crypto_Core_Aes_GCM_Finish(CRYPTO, tag, tag_len,  operation->state.aes_gcm_state);
        }
#endif
    }


#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
cleanup:
    if (NULL != ptr_additional_data)
    {
        ifx_mxcrypto_free(ptr_additional_data);
    }
    if (NULL != ptr_nonce)
    {
        ifx_mxcrypto_free(ptr_nonce);
    }
    if (NULL != ptr_input)
    {
        ifx_mxcrypto_free(ptr_input);
    }
    if (NULL != ptr_output)
    {
        ifx_mxcrypto_free(ptr_output);
    }
    if (NULL != ptr_tag)
    {
        ifx_mxcrypto_free(ptr_tag);
    }
#endif

    return cy_status;
}
#endif
#endif

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_encrypt
****************************************************************************//**
*
* Calculate a single part AEAD encrypt operation.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for encrypt operation
*
* \param key_buffer_size
* The length of the key.
*
* \param alg
* The AEAD algorithm to compute.
*
* \param nonce
* The pointer to nonce or IV.
*
* \param nonce_length
* The size of the nonce.
*
* \param additional_data
* The pointer to the additional data.
*
* \param additional_data_length
* The size of the additional data.
*
* \param plaintext
* The pointer to the plaintext.
*
* \param plaintext_length
* The size of the plaintext.
*
* \param ciphertext
* The pointer to store the ciphertext text and tag.
*
* \param ciphertext_size
* The buffer size of the ciphertext.
*
* \param ciphertext_length
* The Pointer to store the size of the encrypted text and tag.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_encrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size,
                                     psa_algorithm_t alg, const uint8_t *nonce, size_t nonce_length,
                                     const uint8_t *additional_data, size_t additional_data_length,
                                     const uint8_t *plaintext, size_t plaintext_length,
                                     uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{


#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;


    return PSA_ERROR_NOT_SUPPORTED;
#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint8_t *tag;
    #if defined (__ICCARM__)
    static ifx_mxcrypto_transparent_aead_operation_t operation ;
    #else
    ifx_mxcrypto_transparent_aead_operation_t operation ;
    #endif

    if((NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0))  || ((NULL==nonce) && (nonce_length > 0))
        || ((NULL==additional_data) && (additional_data_length > 0))   || ((NULL==plaintext) && (plaintext_length > 0))  || ((NULL==ciphertext) && (ciphertext_size > 0)) || (NULL==ciphertext_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_mxcrypto_transparent_psa_aead_setup(&operation, attributes, key_buffer, key_buffer_size, alg);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (ciphertext_size < (plaintext_length + operation.tag_length))
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    tag = ciphertext + plaintext_length;

#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation.alg == PSA_ALG_GCM)
    {
        cy_status =  ifx_mxcrypto_transparent_psa_crypt_tag(&operation, CY_CRYPTO_ENCRYPT,plaintext_length,
                                    nonce, nonce_length, additional_data, additional_data_length,
                                    plaintext, ciphertext, operation.tag_length, tag);

        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
        (void)Cy_Crypto_Core_Aes_GCM_Free(CRYPTO,  operation.state.aes_gcm_state);
    }else
#endif /* IFX_PSA_MXCRYPTO_GCM */
#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation.alg == PSA_ALG_CCM)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *aligned_additional_data = (uint8_t *)additional_data;
        uint8_t *aligned_nonce = (uint8_t *)nonce;
        uint8_t *aligned_input = (uint8_t *)plaintext;
        uint8_t *aligned_output = (uint8_t *)ciphertext;
        uint8_t *aligned_tag = (uint8_t *)tag;
        uint8_t *ptr_additional_data = NULL;
        uint8_t *ptr_nonce = NULL;
        uint8_t *ptr_input = NULL;
        uint8_t *ptr_output = NULL;
        uint8_t *ptr_tag = NULL;

        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)plaintext, plaintext_length) )
        {
            ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(plaintext_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_input)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
            ifx_mxcrypto_memcpy((void *)aligned_input, (void *)plaintext, plaintext_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)ciphertext, ciphertext_size ) )
        {
            ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(ciphertext_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_output)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)nonce, nonce_length) )
        {
            ptr_nonce = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(nonce_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_nonce)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_nonce = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_nonce);
            ifx_mxcrypto_memcpy((void *)aligned_nonce, (void *)nonce, nonce_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)additional_data, additional_data_length) )
        {
            ptr_additional_data = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(additional_data_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_additional_data)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_additional_data = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_additional_data);
            ifx_mxcrypto_memcpy((void *)aligned_additional_data, (void *)additional_data, additional_data_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)tag, operation.tag_length) )
        {
            ptr_tag = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(operation.tag_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_tag)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_tag);
        }
        cy_status = Cy_Crypto_Core_Aes_Ccm_Encrypt_Tag(CRYPTO, nonce_length, aligned_nonce,
                                                    additional_data_length, aligned_additional_data,
                                                    plaintext_length, aligned_output, aligned_input,
                                                    operation.tag_length, aligned_tag, operation.state.aes_ccm_state);
        if(ciphertext != aligned_output)
        {
            ifx_mxcrypto_memcpy((void *)ciphertext, (void *)aligned_output, ciphertext_size);
        }
        if(tag != aligned_tag)
        {
            ifx_mxcrypto_memcpy((void *)tag, (void *)aligned_tag, operation.tag_length);
        }
cleanup:
        if(ptr_input != NULL)
            ifx_mxcrypto_free(ptr_input);
        if(ptr_output != NULL)
            ifx_mxcrypto_free(ptr_output);
        if(ptr_tag != NULL)
            ifx_mxcrypto_free(ptr_tag);
        if(ptr_additional_data != NULL)
            ifx_mxcrypto_free(ptr_additional_data);
        if(ptr_nonce != NULL)
            ifx_mxcrypto_free(ptr_nonce);
#else
        cy_status = Cy_Crypto_Core_Aes_Ccm_Encrypt_Tag(CRYPTO, nonce_length, nonce,
                                                    additional_data_length, additional_data,
                                                    plaintext_length, ciphertext, plaintext,
                                                    operation.tag_length, tag, operation.state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
        (void)Cy_Crypto_Core_Aes_Ccm_Free(CRYPTO,  operation.state.aes_ccm_state);
    }
    else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void)cy_status;
        (void) tag;
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == PSA_SUCCESS)
    {
        *ciphertext_length = plaintext_length + operation.tag_length;
    }

    return status;
#endif
}

#if !(CY_IP_MXCRYPTO_VERSION == 1u)
static psa_status_t psa_aead_unpadded_locate_tag(size_t tag_length,
                                                 const uint8_t *ciphertext,
                                                 size_t ciphertext_length,
                                                 size_t plaintext_size,
                                                 const uint8_t **p_tag)
{
    size_t payload_length;
    if (tag_length > ciphertext_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    payload_length = ciphertext_length - tag_length;

    if (payload_length > plaintext_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    *p_tag = ciphertext + payload_length;
    return PSA_SUCCESS;
}
#endif


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_decrypt
****************************************************************************//**
*
* Calculate a single part AEAD decrypt operation.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for decrypt operation
*
* \param key_buffer_size
* The length of the key.
*
* \param alg
* The AEAD algorithm to compute.
*
* \param nonce
* The pointer to nonce or IV.
*
* \param nonce_length
* The size of the nonce.
*
* \param additional_data
* The pointer to the additional data.
*
* \param additional_data_length
* The size of the additional data.
*
* \param ciphertext
* The pointer to the ciphertext text and tag.
*
* \param ciphertext_length
* The buffer size of the ciphertext.
*
* \param plaintext
* The pointer to the store plaintext.
*
* \param plaintext_size
* The size of the plaintext.
*
* \param plaintext_length
* The Pointer to store the size of the decrypted text.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_decrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg,
                                      const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length,
                                      const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;


    return PSA_ERROR_NOT_SUPPORTED;
#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    const uint8_t *tag = NULL;
    #if defined (__ICCARM__)
    static ifx_mxcrypto_transparent_aead_operation_t operation ;
    #else
    ifx_mxcrypto_transparent_aead_operation_t operation ;
    #endif

    if((NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0))  || ((NULL==nonce) && (nonce_length > 0))
        || ((NULL==additional_data) && (additional_data_length > 0))   || ((NULL==ciphertext) && (ciphertext_length > 0))  || ((NULL==plaintext) && (plaintext_size > 0)) || (NULL==plaintext_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_mxcrypto_transparent_psa_aead_setup(&operation, attributes, key_buffer, key_buffer_size, alg);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

    status = psa_aead_unpadded_locate_tag(operation.tag_length, ciphertext, ciphertext_length, plaintext_size, &tag);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation.alg == PSA_ALG_GCM)
    {
        uint8_t check_tag_t[CY_CRYPTO_ALIGN_CACHE_LINE(16) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
        uint8_t *check_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)check_tag_t);

        cy_status =  ifx_mxcrypto_transparent_psa_crypt_tag(&operation, CY_CRYPTO_DECRYPT, ciphertext_length - operation.tag_length,
                            nonce, nonce_length, additional_data, additional_data_length,
                            ciphertext, plaintext, operation.tag_length, check_tag);

        status =  ifx_mxcrypto_status_to_psa_status(cy_status);

        (void)Cy_Crypto_Core_Aes_GCM_Free(CRYPTO,  operation.state.aes_gcm_state);

        if (status == PSA_SUCCESS)
        {
            if(ifx_mxcrypto_memcmp( tag, check_tag, operation.tag_length) != 0U)
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }else
#endif /* IFX_PSA_MXCRYPTO_GCM */

#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation.alg == PSA_ALG_CCM)
    {
        cy_en_crypto_aesccm_tag_verify_result_t isValid = CY_CRYPTO_CCM_TAG_INVALID;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *aligned_additional_data = (uint8_t *)additional_data;
        uint8_t *aligned_nonce = (uint8_t *)nonce;
        uint8_t *aligned_input = (uint8_t *)ciphertext;
        uint8_t *aligned_output = (uint8_t *)plaintext;
        uint8_t *aligned_tag = (uint8_t *)tag;
        uint8_t *ptr_additional_data = NULL;
        uint8_t *ptr_nonce = NULL;
        uint8_t *ptr_input = NULL;
        uint8_t *ptr_output = NULL;
        uint8_t *ptr_tag = NULL;

        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)plaintext, plaintext_size) )
        {
            ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(plaintext_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_output)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)ciphertext, ciphertext_length ))
        {
            ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(ciphertext_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_input)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
            ifx_mxcrypto_memcpy((void *)aligned_input, (void *)ciphertext, ciphertext_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)nonce, nonce_length) )
        {
            ptr_nonce = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(nonce_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_nonce)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_nonce = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_nonce);
            ifx_mxcrypto_memcpy((void *)aligned_nonce, (void *)nonce, nonce_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)additional_data, additional_data_length) )
        {
            ptr_additional_data = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(additional_data_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_additional_data)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_additional_data = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_additional_data);
            ifx_mxcrypto_memcpy((void *)aligned_additional_data, (void *)additional_data, additional_data_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)tag, operation.tag_length) )
        {
            ptr_tag = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(operation.tag_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_tag)
            {
                cy_status = CY_CRYPTO_MEMORY_ALLOC_FAIL;
                goto cleanup;
            }
            aligned_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_tag);
            ifx_mxcrypto_memcpy((void *)aligned_tag, (void *)tag, operation.tag_length);
        }
        cy_status = Cy_Crypto_Core_Aes_Ccm_Decrypt(CRYPTO,
                                            nonce_length, aligned_nonce,
                                            additional_data_length, aligned_additional_data,
                                            ciphertext_length - operation.tag_length, aligned_output, aligned_input,
                                            operation.tag_length, aligned_tag, &isValid,
                                            operation.state.aes_ccm_state);
        if(plaintext != aligned_output)
        {
            ifx_mxcrypto_memcpy((void *)plaintext, (void *)aligned_output, (ciphertext_length - operation.tag_length));
        }
cleanup:
        if(ptr_input != NULL)
            ifx_mxcrypto_free(ptr_input);
        if(ptr_output != NULL)
            ifx_mxcrypto_free(ptr_output);
        if(ptr_tag != NULL)
            ifx_mxcrypto_free(ptr_tag);
        if(ptr_additional_data != NULL)
            ifx_mxcrypto_free(ptr_additional_data);
        if(ptr_nonce != NULL)
            ifx_mxcrypto_free(ptr_nonce);
#else
        cy_status = Cy_Crypto_Core_Aes_Ccm_Decrypt(CRYPTO,
                                            nonce_length, nonce,
                                            additional_data_length, additional_data,
                                            ciphertext_length - operation.tag_length, plaintext, ciphertext,
                                            operation.tag_length, tag, &isValid,
                                            operation.state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);

        (void)Cy_Crypto_Core_Aes_Ccm_Free(CRYPTO, operation.state.aes_ccm_state);

        if (status == PSA_SUCCESS)
        {
            if(CY_CRYPTO_CCM_TAG_INVALID == isValid)
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void) cy_status;
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == PSA_SUCCESS)
    {
        *plaintext_length = ciphertext_length - operation.tag_length;
    }

    return status;

#endif
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_encrypt_setup
****************************************************************************//**
*
* Sets up a multi part AEAD encrypt Setup operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for encrypt operation
*
* \param key_buffer_size
* The length of the key.
*
* \param alg
* The AEAD algorithm to compute.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_encrypt_setup(ifx_mxcrypto_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = ifx_mxcrypto_transparent_psa_aead_setup(operation, attributes, key_buffer, key_buffer_size, alg);

    if (status == PSA_SUCCESS)
    {
        operation->is_encrypt = 1;
    }

    return status;
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_decrypt_setup
****************************************************************************//**
*
* Sets up a multi part AEAD Decrypt Setup operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for decrypt operation
*
* \param key_buffer_size
* The length of the key.
*
* \param alg
* The AEAD algorithm to compute.
*
* \return psa_status_t.
*
*******************************************************************************/

psa_status_t ifx_mxcrypto_transparent_aead_decrypt_setup(ifx_mxcrypto_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = ifx_mxcrypto_transparent_psa_aead_setup(operation, attributes, key_buffer, key_buffer_size, alg);

    if (status == PSA_SUCCESS)
    {
        operation->is_encrypt = 0;
    }

    return status;
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_set_nonce
****************************************************************************//**
*
*  Sets up nonce or iv for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param nonce
* The pointer to nonce or IV.
*
* \param nonce_length
* The size of the nonce.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_set_nonce(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) nonce;
    (void) nonce_length;

    return PSA_ERROR_NOT_SUPPORTED;

#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if((NULL==operation) || ((NULL==nonce) && (nonce_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(IFX_PSA_MXCRYPTO_GCM) || defined(IFX_PSA_MXCRYPTO_CCM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_nonce = NULL;
    uint8_t *aligned_nonce = (uint8_t *)nonce;
    if (operation->alg == PSA_ALG_GCM || operation->alg == PSA_ALG_CCM)
    {
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)nonce, nonce_length) )
        {
            ptr_nonce = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(nonce_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_nonce)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_nonce = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_nonce);
            ifx_mxcrypto_memcpy((void *)aligned_nonce, (void *)nonce, nonce_length);
        }
    }
#endif
#endif
#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation->alg == PSA_ALG_GCM)
    {
        if (nonce_length == 0 || (uint64_t) nonce_length >> 61 != 0)
        {
            cy_status =  CY_CRYPTO_BAD_PARAMS;
        }
        else
        {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
            cy_status = Cy_Crypto_Core_Aes_GCM_Start(CRYPTO, operation->is_encrypt ? CY_CRYPTO_ENCRYPT : CY_CRYPTO_DECRYPT , aligned_nonce, nonce_length, operation->state.aes_gcm_state);
#else
            cy_status = Cy_Crypto_Core_Aes_GCM_Start(CRYPTO, operation->is_encrypt ? CY_CRYPTO_ENCRYPT : CY_CRYPTO_DECRYPT , nonce, nonce_length, operation->state.aes_gcm_state);
#endif
        }
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_MXCRYPTO_GCM */
#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status =Cy_Crypto_Core_Aes_Ccm_Start(CRYPTO, operation->is_encrypt ? CY_CRYPTO_ENCRYPT : CY_CRYPTO_DECRYPT,
        nonce_length, aligned_nonce, operation->state.aes_ccm_state);
#else
        cy_status =Cy_Crypto_Core_Aes_Ccm_Start(CRYPTO, operation->is_encrypt ? CY_CRYPTO_ENCRYPT : CY_CRYPTO_DECRYPT,
        nonce_length, nonce, operation->state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void)cy_status;
        (void) operation;
        (void) nonce;
        (void) nonce_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(ptr_nonce != NULL)
        ifx_mxcrypto_free(ptr_nonce);
#endif
    return status;
#endif
}



/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_set_lengths
****************************************************************************//**
*
* Declare the lengths of the message and additional data for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param ad_length
* The size of the addtional authenticated data.
*
* \param plaintext_length
* The size of the plaintext.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_set_lengths(ifx_mxcrypto_transparent_aead_operation_t *operation, size_t ad_length, size_t plaintext_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) ad_length;
    (void) plaintext_length;

    return PSA_ERROR_NOT_SUPPORTED;
#else

#if defined(IFX_PSA_MXCRYPTO_CCM)
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if (operation->alg == PSA_ALG_CCM) {
        cy_status = Cy_Crypto_Core_Aes_Ccm_Set_Length(CRYPTO,
                                            ad_length,  plaintext_length,
                                            operation->tag_length,
                                            operation->state.aes_ccm_state);

        return ifx_mxcrypto_status_to_psa_status(cy_status);

    }
#else /* IFX_PSA_MXCRYPTO_CCM */
    (void) operation;
    (void) ad_length;
    (void) plaintext_length;
#endif

    return PSA_SUCCESS;
#endif
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_update_ad
****************************************************************************//**
*
*  AAD update function for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param input
* The pointer to aad.
*
* \param input_length
* The size of the aad.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_update_ad(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(IFX_PSA_MXCRYPTO_GCM) || defined(IFX_PSA_MXCRYPTO_CCM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_input = NULL;
    uint8_t *aligned_input = (uint8_t *)input;
    if (operation->alg == PSA_ALG_GCM || operation->alg == PSA_ALG_CCM)
    {
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
        {
            ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_input)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
            ifx_mxcrypto_memcpy((void *)aligned_input, (void *)input, input_length);
        }
    }
#endif
#endif
#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation->alg == PSA_ALG_GCM)
     {
        if ((uint64_t)input_length >> 61 != 0)
        {
            cy_status = CY_CRYPTO_BAD_PARAMS;
        }
        else
        {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
            cy_status = Cy_Crypto_Core_Aes_GCM_AAD_Update(CRYPTO, (uint8_t *)aligned_input, input_length, operation->state.aes_gcm_state);
#else
            cy_status = Cy_Crypto_Core_Aes_GCM_AAD_Update(CRYPTO, (uint8_t *)input, input_length, operation->state.aes_gcm_state);
#endif
        }
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_MXCRYPTO_GCM */
#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation->alg == PSA_ALG_CCM)
     {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status = Cy_Crypto_Core_Aes_Ccm_Update_Aad(CRYPTO, input_length, (uint8_t *)aligned_input, operation->state.aes_ccm_state);
#else
        cy_status = Cy_Crypto_Core_Aes_Ccm_Update_Aad(CRYPTO, input_length, (uint8_t *)input, operation->state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {   (void)cy_status;
        (void)operation;
        (void)input;
        (void)input_length;

        return PSA_ERROR_NOT_SUPPORTED;
    }

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(ptr_input != NULL)
        ifx_mxcrypto_free(ptr_input);
#endif
    return status;

#endif
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_update
****************************************************************************//**
*
*  update function for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param input
* The pointer to input data.
*
* \param input_length
* The size of the input data.
*
* \param output
* The pointer to the output buffer.
*
* \param output_size
* The size of the output buffer.
*
* \param output_length
* The pointer to store the length of the output.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_update(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length,
                                     uint8_t *output, size_t output_size, size_t *output_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    return PSA_ERROR_NOT_SUPPORTED;
#else
    size_t update_output_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    update_output_length = input_length;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)) || ((NULL==output) && (output_size > 0)) || (NULL == output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(output_size < input_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
#if defined(IFX_PSA_MXCRYPTO_GCM) || defined(IFX_PSA_MXCRYPTO_CCM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_input = NULL;
    uint8_t *aligned_input = (uint8_t *)input;
    uint8_t *ptr_output = NULL;
    uint8_t *aligned_output = output;
    if (operation->alg == PSA_ALG_GCM || operation->alg == PSA_ALG_CCM)
    {
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
        {
            ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_input)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
            ifx_mxcrypto_memcpy((void *)aligned_input, (void *)input, input_length);
        }
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, update_output_length) )
        {
            ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(update_output_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_output)
            {
                status = PSA_ERROR_INSUFFICIENT_MEMORY;
                goto cleanup;
            }
            aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
        }
    }
#endif
#endif
#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation->alg == PSA_ALG_GCM)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status = Cy_Crypto_Core_Aes_GCM_Update(CRYPTO, aligned_input,  input_length, aligned_output, operation->state.aes_gcm_state);
#else
        cy_status = Cy_Crypto_Core_Aes_GCM_Update(CRYPTO, input,  input_length, output, operation->state.aes_gcm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_MXCRYPTO_GCM */

#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status = Cy_Crypto_Core_Aes_Ccm_Update(CRYPTO,  input_length, aligned_output, aligned_input, operation->state.aes_ccm_state);
#else
        cy_status = Cy_Crypto_Core_Aes_Ccm_Update(CRYPTO,  input_length, output, input, operation->state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void)cy_status;
        (void) operation;
        (void) input;
        (void) output;
        (void) output_size;

        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == PSA_SUCCESS)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if (NULL != ptr_output)
        {
            ifx_mxcrypto_memcpy((void *)output, (void *)aligned_output, update_output_length);
        }
#endif
        *output_length = update_output_length;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
cleanup:
    if(ptr_input != NULL)
        ifx_mxcrypto_free(ptr_input);
    if(ptr_output != NULL)
        ifx_mxcrypto_free(ptr_output);
#endif
    return status;
#endif
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_finish
****************************************************************************//**
*
*  Finish the multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param ciphertext
* The pointer to store the cipher text.
*
* \param ciphertext_size
* The size of the ciphertext.
*
* \param ciphertext_length
* The pointer to store the size of ciphertext.
*
* \param tag
* The pointer to the store the tag.
*
* \param tag_size
* The size of the tag buffer .
*
* \param tag_length
* The pointer to store the length of the tag.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_finish(ifx_mxcrypto_transparent_aead_operation_t *operation, uint8_t *ciphertext, size_t ciphertext_size,
                                     size_t *ciphertext_length, uint8_t *tag, size_t tag_size, size_t *tag_length)
{
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    (void) tag;
    (void) tag_size;
    (void) tag_length;

    return PSA_ERROR_NOT_SUPPORTED;
#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    size_t finish_output_size = 0;

    if((NULL==operation) || (NULL==ciphertext_length) || ((NULL==tag) && (tag_size > 0)) || (NULL == tag_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (tag_size < operation->tag_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_tag = NULL;
    uint8_t *aligned_tag = tag;

    if (operation->alg == PSA_ALG_GCM || operation->alg == PSA_ALG_CCM)
    {
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)tag, operation->tag_length) )
        {
            ptr_tag = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(operation->tag_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_tag)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_tag);
        }
    }
#endif
#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation->alg == PSA_ALG_GCM)
    {
        (void) ciphertext;
        (void) ciphertext_size;
        *ciphertext_length = 0;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status = Cy_Crypto_Core_Aes_GCM_Finish(CRYPTO, aligned_tag,  operation->tag_length,  operation->state.aes_gcm_state);
        ifx_mxcrypto_memcpy((void *)tag, (void *)aligned_tag, operation->tag_length);
#else
        cy_status = Cy_Crypto_Core_Aes_GCM_Finish(CRYPTO, tag,  operation->tag_length,  operation->state.aes_gcm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_MXCRYPTO_GCM */
#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
        (void) ciphertext;
        (void) ciphertext_size;
        *ciphertext_length = 0;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        cy_status = Cy_Crypto_Core_Aes_Ccm_Finish(CRYPTO, aligned_tag, operation->state.aes_ccm_state);
        ifx_mxcrypto_memcpy((void *)tag, (void *)aligned_tag, operation->tag_length);
#else
        cy_status = Cy_Crypto_Core_Aes_Ccm_Finish(CRYPTO, tag, operation->state.aes_ccm_state);
#endif
        status =  ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void)cy_status;
        (void) ciphertext;
        (void) ciphertext_size;
        (void) ciphertext_length;
        (void) tag;
        (void) tag_size;
        (void) tag_length;

        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (status == PSA_SUCCESS)
    {
        *ciphertext_length = finish_output_size;
        *tag_length = operation->tag_length;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(ptr_tag != NULL)
        ifx_mxcrypto_free(ptr_tag);
#endif
    return status;

#endif
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_verify
****************************************************************************//**
*
*  Finish authenticating and decrypting a message in an AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \param plaintext
* Buffer where the last part of the plaintext is to be written.
* This is the remaining data from previous calls to psa_aead_update()
* that could not be processed until the end of the input.
*
* \param plaintext_size
* The size of the plaintext buffer in bytes.
*
* \param plaintext_length
* On success, the number of bytes of returned plaintext.
*
* \param tag
* The pointer to buffer containing authentication tag data.
*
* \param tag_length
* The length of the authentication tag in bytes.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_verify(ifx_mxcrypto_transparent_aead_operation_t *operation, uint8_t *plaintext, size_t plaintext_size,
                                     size_t *plaintext_length, const uint8_t *tag, size_t tag_length)
{


#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    (void) tag;
    (void) tag_length;

    return PSA_ERROR_NOT_SUPPORTED;
#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint8_t check_tag_t[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_AEAD_TAG_MAX_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    uint8_t *check_tag = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)check_tag_t);
    size_t check_tag_length = 0;

#if defined(IFX_PSA_MXCRYPTO_GCM)
    if (operation->alg == PSA_ALG_GCM)
    {
        status = ifx_mxcrypto_transparent_aead_finish(operation, plaintext, plaintext_size, plaintext_length, check_tag, PSA_AEAD_TAG_MAX_SIZE, &check_tag_length);
        if(PSA_SUCCESS == status)
        {
            /*compare auth tag*/
            if((check_tag_length != tag_length) || (ifx_mxcrypto_memcmp(tag, check_tag, check_tag_length) != 0U))
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }
    else
#endif /* IFX_PSA_MXCRYPTO_GCM */
#if defined(IFX_PSA_MXCRYPTO_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
        status = ifx_mxcrypto_transparent_aead_finish(operation, plaintext, plaintext_size, plaintext_length, check_tag, PSA_AEAD_TAG_MAX_SIZE, &check_tag_length);
        if(PSA_SUCCESS == status)
        {
            /*compare auth tag*/
            if((check_tag_length != tag_length) || (ifx_mxcrypto_memcmp(tag, check_tag, check_tag_length) != 0U))
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }
    else
#endif /* IFX_PSA_MXCRYPTO_CCM */
    {
        (void)cy_status;
        (void) plaintext;
        (void) plaintext_size;
        (void) plaintext_length;
        (void) tag;
        (void) tag_length;

        status = PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
#endif
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_aead_abort
****************************************************************************//**
*
*  Abort the multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_aead_abort(ifx_mxcrypto_transparent_aead_operation_t *operation)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u)
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
#else
    if(NULL==operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (operation->alg)
    {
#if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            (void)Cy_Crypto_Core_Aes_GCM_Free(CRYPTO,  operation->state.aes_gcm_state);
            break;
#endif /* IFX_PSA_MXCRYPTO_GCM */

#if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            (void)Cy_Crypto_Core_Aes_Ccm_Free(CRYPTO,  operation->state.aes_ccm_state);
            break;
#endif /* IFX_PSA_MXCRYPTO_CCM */
    }

    operation->is_encrypt = 0;

    return PSA_SUCCESS;
#endif
}

#endif /*(CY_IP_MXCRYPTO)*/
#endif /* IFX_PSA_MXCRYPTO_AEAD */
