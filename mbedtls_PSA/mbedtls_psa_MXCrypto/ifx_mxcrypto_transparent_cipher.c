
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_cipher.c
*
* \brief
*  PSA crypto transparent Cipher driver functions.
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

#include "ifx_mxcrypto_transparent_cipher.h"

#if defined(IFX_PSA_MXCRYPTO_CIPHER)

#if defined (CY_IP_MXCRYPTO)

static psa_status_t ifx_mxcrypto_transparent_cipher_aes_update(ifx_mxcrypto_transparent_cipher_operation_t *operation, uint8_t *input,
                                                    size_t input_length, uint8_t *output, size_t *output_length);

static psa_status_t ifx_mxcrypto_transparent_psa_cipher_setup(ifx_mxcrypto_transparent_cipher_operation_t *operation,
                                    const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer, size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    cy_en_crypto_dir_mode_t cipher_operation)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u) 
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void)cipher_operation;
    return PSA_ERROR_NOT_SUPPORTED; 
#else     
    psa_key_type_t key_type;
    size_t key_bits;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_en_crypto_aes_key_length_t key_length;
    uint8_t *aligned_key_buffer = (uint8_t *)key_buffer;;
    
    if((NULL==operation))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->alg = PSA_ALG_NONE;
    operation->mode = cipher_operation;
    
    if((NULL==attributes))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);
    operation->iv_length = PSA_CIPHER_IV_LENGTH(key_type, alg);

    if(key_type != PSA_KEY_TYPE_AES)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch( key_bits )
    {
        case 128:
            key_length = CY_CRYPTO_KEY_AES_128;
            break;
        case 192:
            key_length = CY_CRYPTO_KEY_AES_192;
            break;
        case 256:
            key_length = CY_CRYPTO_KEY_AES_256;
            break;
        default :
            return PSA_ERROR_INVALID_ARGUMENT ;
    }   

    if((NULL==key_buffer) && (key_buffer_size > 0))
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
    operation->alg = alg;
    switch (alg) {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            operation->state.aes_state = (cy_stc_crypto_aes_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_state_t);
            operation->buffer.aes_buffer = (cy_stc_crypto_aes_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, aligned_key_buffer, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);
            cy_status = Cy_Crypto_Core_Aes_Ecb_Setup(CRYPTO, cipher_operation, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            operation->state.aes_state = (cy_stc_crypto_aes_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_state_t);
            operation->buffer.aes_buffer = (cy_stc_crypto_aes_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, aligned_key_buffer, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);
            cy_status = Cy_Crypto_Core_Aes_Cbc_Setup(CRYPTO, cipher_operation, operation->state.aes_state);
            break;
        #endif

        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            operation->state.aes_state = (cy_stc_crypto_aes_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_state_t);
            operation->buffer.aes_buffer = (cy_stc_crypto_aes_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, aligned_key_buffer, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);
            cy_status = Cy_Crypto_Core_Aes_Ctr_Setup(CRYPTO, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            operation->state.aes_state = (cy_stc_crypto_aes_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_state_t);
            operation->buffer.aes_buffer = (cy_stc_crypto_aes_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, aligned_key_buffer, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);
            cy_status = Cy_Crypto_Core_Aes_Cfb_Setup(CRYPTO, cipher_operation, operation->state.aes_state);
            break;
        #endif        

        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            operation->state.aes_gcm_state = (cy_stc_crypto_aes_gcm_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_gcm_state_t);
            operation->buffer.aes_gcm_buffer = (cy_stc_crypto_aes_gcm_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_gcm_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_GCM_Init(CRYPTO, operation->buffer.aes_gcm_buffer,  operation->state.aes_gcm_state);
            if(CY_CRYPTO_SUCCESS ==cy_status)
            {
                cy_status = Cy_Crypto_Core_Aes_GCM_SetKey(CRYPTO, aligned_key_buffer, key_length,  operation->state.aes_gcm_state);
            }
            break;
        #endif

        #if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            operation->state.aes_ccm_state = (cy_stc_crypto_aes_ccm_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.aes_ccm_state_t);
            operation->buffer.aes_ccm_buffer = (cy_stc_crypto_aes_ccm_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.aes_ccm_buffer_t);
            cy_status = Cy_Crypto_Core_Aes_Ccm_Init(CRYPTO, operation->buffer.aes_ccm_buffer, operation->state.aes_ccm_state);
            if (CY_CRYPTO_SUCCESS == cy_status)
            {
                cy_status = Cy_Crypto_Core_Aes_Ccm_SetKey(CRYPTO, aligned_key_buffer, key_length, operation->state.aes_ccm_state);
            }
            break;
        #endif

        default:
            return( PSA_ALG_IS_CIPHER( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(in_key_buf != NULL)
    {
        ifx_mxcrypto_free(in_key_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status);
#endif
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_encrypt_setup
****************************************************************************//**
*
* Sets up a multi part Cipher encrypt operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
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
* The hash algorithm to compute.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_encrypt_setup(ifx_mxcrypto_transparent_cipher_operation_t *operation,
                                                           const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                                           size_t key_buffer_size, psa_algorithm_t alg)
{
    return ifx_mxcrypto_transparent_psa_cipher_setup(operation, attributes, key_buffer, key_buffer_size, alg, CY_CRYPTO_ENCRYPT);
}

 

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_decrypt_setup
****************************************************************************//**
*
* Sets up a multi part Cipher decrypt operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
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
* The hash algorithm to compute.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_decrypt_setup(ifx_mxcrypto_transparent_cipher_operation_t *operation,
                                                           const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                                           size_t key_buffer_size, psa_algorithm_t alg)
{
    return ifx_mxcrypto_transparent_psa_cipher_setup(operation, attributes,  key_buffer, key_buffer_size, alg, CY_CRYPTO_DECRYPT);
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_set_iv
****************************************************************************//**
*
* Sets up a IV for the Cipher operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
*
* The pointer to the iv.
*
* \param iv_length
* The size of the iv.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_set_iv(ifx_mxcrypto_transparent_cipher_operation_t *operation, 
                                                    const uint8_t *iv, size_t iv_length)
{

#if (CY_IP_MXCRYPTO_VERSION == 1u) 
    (void) operation;
    (void) iv;
    (void) iv_length;

    return PSA_ERROR_NOT_SUPPORTED; 
#else    
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint8_t *aligned_iv_buffer = (uint8_t *)iv;

    if((NULL==operation) || ((NULL==iv) && (iv_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (iv_length < PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, operation->alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *in_iv_buf = NULL;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)iv, iv_length) )
    {
        in_iv_buf = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(iv_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == in_iv_buf)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        aligned_iv_buffer = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)in_iv_buf);
        ifx_mxcrypto_memcpy((void *)aligned_iv_buffer, (void *)iv, iv_length);
    }
#endif
    switch (operation->alg)
    {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            cy_status = CY_CRYPTO_BAD_PARAMS;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            cy_status = Cy_Crypto_Core_Aes_Cbc_Set_IV(CRYPTO, aligned_iv_buffer, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            cy_status = Cy_Crypto_Core_Aes_Ctr_Set_IV(CRYPTO, aligned_iv_buffer, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            cy_status = Cy_Crypto_Core_Aes_Cfb_Set_IV(CRYPTO, aligned_iv_buffer, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            cy_status = Cy_Crypto_Core_Aes_GCM_Start(CRYPTO, operation->mode, aligned_iv_buffer, iv_length,  operation->state.aes_gcm_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            cy_status =Cy_Crypto_Core_Aes_Ccm_Start(CRYPTO, operation->mode, iv_length, aligned_iv_buffer, operation->state.aes_ccm_state);
            break;
        #endif        
        default:
            cy_status = CY_CRYPTO_BAD_PARAMS;
            break;
        }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(in_iv_buf != NULL)
    {
        ifx_mxcrypto_free(in_iv_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status);
#endif
}
static psa_status_t ifx_mxcrypto_transparent_cipher_aes_update(ifx_mxcrypto_transparent_cipher_operation_t *operation, uint8_t *input,
                                                    size_t input_length, uint8_t *output, size_t *output_length)
{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    *output_length = (size_t)0;
    switch (operation->alg)
    {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            *output_length = ((operation->state.aes_state->unProcessedBytes + input_length) / 16) * 16;
            cy_status = Cy_Crypto_Core_Aes_Ecb_Update(CRYPTO, input_length, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            *output_length = ((operation->state.aes_state->unProcessedBytes + input_length) / 16) * 16;
            cy_status = Cy_Crypto_Core_Aes_Cbc_Update(CRYPTO, input_length, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            cy_status = Cy_Crypto_Core_Aes_Ctr_Update(CRYPTO, input_length, output, input, operation->state.aes_state);
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            cy_status = Cy_Crypto_Core_Aes_Cfb_Update(CRYPTO, input_length, output, input, operation->state.aes_state);
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            cy_status = Cy_Crypto_Core_Aes_GCM_Update(CRYPTO, input, input_length,  output, operation->state.aes_gcm_state);
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            cy_status = Cy_Crypto_Core_Aes_Ccm_Update(CRYPTO,  input_length, output, input, operation->state.aes_ccm_state);
            *output_length = input_length;
            break;
        #endif
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }
    return ifx_mxcrypto_status_to_psa_status(cy_status);
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_update
****************************************************************************//**
*
* Update of the cipher message for multi stage operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param output
* The pointer to store the encrypted text.
*
* \param output_size
* The buffer size of the output.
*
* \param output_length
* The Pointer to store the size of the encrypted text.
*
* \return psa_status_t.
*
*******************************************************************************/ 

psa_status_t ifx_mxcrypto_transparent_cipher_update(ifx_mxcrypto_transparent_cipher_operation_t *operation, const uint8_t *input,
                                                    size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)
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
    psa_status_t cy_status = PSA_ERROR_INVALID_ARGUMENT;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)) || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(input_length == (size_t)0)
    {
        *output_length = (size_t)0;
        return PSA_SUCCESS;
    }
    switch (operation->alg)
    {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            *output_length = ((operation->state.aes_state->unProcessedBytes + input_length) / 16) * 16;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            *output_length = ((operation->state.aes_state->unProcessedBytes + input_length) / 16) * 16;
            break;  
        #endif      
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            *output_length = input_length;
            break;
        #endif       
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (output_size < *output_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(!(CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length)) || !(CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, output_size)) )
    {
        uint8_t *input_data = NULL;
        uint8_t *output_data = NULL;
        uint8_t *aligned_input_data = (uint8_t *)input;
        uint8_t *aligned_output_data = (uint8_t *)output;
        uint8_t *input_ptr = (uint8_t *)input;
        size_t out_size = 0;
        size_t in_size;

        if(!(CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length)))
        {
            input_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if(input_data == NULL)
            {
                cy_status = PSA_ERROR_INSUFFICIENT_MEMORY;
                goto cleanup;
            }
            aligned_input_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_data);
        }
        if( !(CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, output_size)))
        {
            output_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_AES_BLOCK_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if(output_data == NULL)
            {
                cy_status = PSA_ERROR_INSUFFICIENT_MEMORY;
                goto cleanup;
            }
            aligned_output_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)output_data);
        }
        in_size = CY_CRYPTO_AES_BLOCK_SIZE;
        while( input_length > 0 )
    {
            if(input_length < CY_CRYPTO_AES_BLOCK_SIZE)
            {
                in_size = input_length;
            }

            if(aligned_input_data != input_ptr)
            {
                ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, in_size);
            }

            cy_status = ifx_mxcrypto_transparent_cipher_aes_update(operation, aligned_input_data, in_size, aligned_output_data, &out_size);

            if (PSA_SUCCESS != cy_status)
            {
            break;
            }

            if(aligned_output_data != output)
            {
                ifx_mxcrypto_memcpy(output, aligned_output_data, (uint16_t)out_size);
            }
            else
            {
                aligned_output_data += in_size;
            }

            if(aligned_input_data == input_ptr)
            {
                aligned_input_data += in_size;
            }

            output += in_size;
            input_ptr += in_size;
            input_length -= in_size;
        }
cleanup:
        if(input_data != NULL)
        {
            ifx_mxcrypto_free(input_data);
    }
        if(output_data != NULL)
        {
            ifx_mxcrypto_free(output_data);
        }
        return cy_status;
    }
#endif
    cy_status = ifx_mxcrypto_transparent_cipher_aes_update(operation, (uint8_t *)input, input_length, output, output_length);
    return cy_status;
#endif    
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_finish
****************************************************************************//**
*
* Performs the cipher finish for the multi stage operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
*
* \param output
* The pointer to store the encrypted text.
*
* \param output_size
* The buffer size of the output.
*
* \param output_length
* The Pointer to store the size of the encrypted text.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_finish(ifx_mxcrypto_transparent_cipher_operation_t *operation, 
                                                    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void)output;
    (void)output_size;


#if (CY_IP_MXCRYPTO_VERSION == 1u) 
    (void) operation;
    (void) output_length;

    return PSA_ERROR_NOT_SUPPORTED; 
#else

    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if((NULL==operation) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *output_length=0;

    switch (operation->alg)
    {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
                cy_status = Cy_Crypto_Core_Aes_Ecb_Finish(CRYPTO, operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
                cy_status = Cy_Crypto_Core_Aes_Cbc_Finish(CRYPTO, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
                cy_status = Cy_Crypto_Core_Aes_Ctr_Finish(CRYPTO, operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
                cy_status = Cy_Crypto_Core_Aes_Cfb_Finish(CRYPTO, operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
        case PSA_ALG_CCM:
            break;
        #endif
        default:
            break;
    }

    return ifx_mxcrypto_status_to_psa_status(cy_status);

#endif
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_abort
****************************************************************************//**
*
* Aborts the multi stage cipher operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_cipher_operation_t structure that has the
*  cipher context of mxcrypto driver.
*
* \return psa_status_t.
*
*******************************************************************************/ 

psa_status_t ifx_mxcrypto_transparent_cipher_abort(ifx_mxcrypto_transparent_cipher_operation_t *operation)
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
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING) || defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING) || defined(IFX_PSA_MXCRYPTO_CTR) || defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_ECB_NO_PADDING:
        case PSA_ALG_CBC_NO_PADDING: 
        case PSA_ALG_CTR:
        case PSA_ALG_CFB:
            (void)Cy_Crypto_Core_Aes_Free(CRYPTO, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_GCM)
        case PSA_ALG_GCM:
            (void)Cy_Crypto_Core_Aes_GCM_Free(CRYPTO,  operation->state.aes_gcm_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CCM)
        case PSA_ALG_CCM:
            (void)Cy_Crypto_Core_Aes_Ccm_Free(CRYPTO,  operation->state.aes_ccm_state);
            break;
        #endif
    }
    
    return PSA_SUCCESS;

#endif
}

static inline unsigned char *get_buffer_offset(
    unsigned char *p, size_t n)
{
    return p == NULL ? NULL : p + n;
}

static inline const unsigned char *get_buffer_offset_const(
    const unsigned char *p, size_t n)
{
    return p == NULL ? NULL : p + n;
}

#if (CY_IP_MXCRYPTO_VERSION == 1u)

static inline cy_en_crypto_status_t ifx_mxcrypto_transparent_cipher_aes_ecb_v1(cy_en_crypto_dir_mode_t mode, size_t input_length, uint8_t *output,  const uint8_t *input, cy_stc_crypto_aes_state_t *aesState)

{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_SUCCESS ;
    uint8_t *src = (uint8_t *)input, *dst = output;

    while(input_length >= CY_CRYPTO_AES_BLOCK_SIZE)
    {

        cy_status = Cy_Crypto_Core_Aes_Ecb(CRYPTO, mode, dst, src, aesState);

        if(CY_CRYPTO_SUCCESS != cy_status)
        {
            return cy_status;
        }

        src += CY_CRYPTO_AES_BLOCK_SIZE;
        dst += CY_CRYPTO_AES_BLOCK_SIZE;
        input_length -= CY_CRYPTO_AES_BLOCK_SIZE;
    }

    return cy_status;
}

psa_status_t ifx_mxcrypto_transparent_cipher_encrypt_v1(ifx_mxcrypto_transparent_cipher_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *iv, size_t iv_length, const uint8_t *input,
    size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)

{
    psa_key_type_t key_type;
    size_t key_bits;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_en_crypto_aes_key_length_t key_length;
    (void) key_buffer_size;
    uint32_t srcOffset;
    uint8_t temp[CY_CRYPTO_AES_BLOCK_SIZE];

    
    if((NULL==attributes))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);

    if(key_type != PSA_KEY_TYPE_AES)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch( key_bits )
    {
        case 128:
            key_length = CY_CRYPTO_KEY_AES_128;
            break;
        case 192:
            key_length = CY_CRYPTO_KEY_AES_192;
            break;
        case 256:
            key_length = CY_CRYPTO_KEY_AES_256;
            break;
        default :
            return PSA_ERROR_INVALID_ARGUMENT ;
    }   

    switch (alg) {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            if(input_length % CY_CRYPTO_AES_BLOCK_SIZE != 0)
                return PSA_ERROR_INVALID_ARGUMENT;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            if(input_length % CY_CRYPTO_AES_BLOCK_SIZE != 0)
                return PSA_ERROR_INVALID_ARGUMENT;            
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            break;
        #endif        
        default:
            return( PSA_ALG_IS_CIPHER( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }

    *output_length = input_length;

    cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, key, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);

    if (output_size < *output_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }


    switch (alg) {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            (void)srcOffset;
            (void)temp;
            cy_status = ifx_mxcrypto_transparent_cipher_aes_ecb_v1(CY_CRYPTO_ENCRYPT, input_length, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            (void)srcOffset;
            Cy_Crypto_Core_MemCpy(CRYPTO, temp, iv, iv_length);
            cy_status =  Cy_Crypto_Core_Aes_Cbc(CRYPTO, CY_CRYPTO_ENCRYPT, input_length, temp, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            Cy_Crypto_Core_MemCpy(CRYPTO, temp, iv, iv_length);
            cy_status = Cy_Crypto_Core_Aes_Ctr(CRYPTO, input_length, &srcOffset, temp, NULL, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            (void)srcOffset;
            (void)temp;
            cy_status = Cy_Crypto_Core_Aes_Cfb(CRYPTO, CY_CRYPTO_ENCRYPT, input_length, (uint8_t *)iv, output, input, operation->state.aes_state);
            break;
        #endif        
    }

    if(cy_status != CY_CRYPTO_SUCCESS)
    {
        return ifx_mxcrypto_status_to_psa_status(cy_status);
    }

    cy_status = Cy_Crypto_Core_Aes_Free(CRYPTO, operation->state.aes_state);

    return ifx_mxcrypto_status_to_psa_status(cy_status);

}

psa_status_t ifx_mxcrypto_transparent_cipher_decrypt_v1(ifx_mxcrypto_transparent_cipher_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *input,
    size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)

{
    psa_key_type_t key_type;
    size_t key_bits;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_en_crypto_aes_key_length_t key_length;
    (void) key_buffer_size;
    uint32_t srcOffset;
    size_t iv_length=0;

    
    if((NULL==attributes))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);

    if(key_type != PSA_KEY_TYPE_AES)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch( key_bits )
    {
        case 128:
            key_length = CY_CRYPTO_KEY_AES_128;
            break;
        case 192:
            key_length = CY_CRYPTO_KEY_AES_192;
            break;
        case 256:
            key_length = CY_CRYPTO_KEY_AES_256;
            break;
        default :
            return PSA_ERROR_INVALID_ARGUMENT ;
    }   

    iv_length = PSA_CIPHER_IV_LENGTH(key_type, alg);
    switch (alg) {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            if(input_length % CY_CRYPTO_AES_BLOCK_SIZE != 0)
                return PSA_ERROR_INVALID_ARGUMENT;
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            if(input_length % CY_CRYPTO_AES_BLOCK_SIZE != 0)
                return PSA_ERROR_INVALID_ARGUMENT;            
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            break;
        #endif        
        default:
            return( PSA_ALG_IS_CIPHER( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }

    if(PSA_ALG_ECB_NO_PADDING == alg)
    {
        *output_length = input_length;
    }
    else
    {
        *output_length = input_length - iv_length;
    }

    cy_status = Cy_Crypto_Core_Aes_InitContext(CRYPTO, key, key_length,  operation->state.aes_state, operation->buffer.aes_buffer);

    if (output_size < *output_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }


    switch (alg) {
        #if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            (void)srcOffset;
            cy_status = ifx_mxcrypto_transparent_cipher_aes_ecb_v1(CY_CRYPTO_DECRYPT, input_length, output, input, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            (void)srcOffset;
            cy_status =  Cy_Crypto_Core_Aes_Cbc(CRYPTO, CY_CRYPTO_DECRYPT, *output_length, (uint8_t *)input, output, input + iv_length, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CTR)
        case PSA_ALG_CTR:
            cy_status = Cy_Crypto_Core_Aes_Ctr(CRYPTO, *output_length, &srcOffset, (uint8_t *)input, NULL, output, input + iv_length, operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_MXCRYPTO_CFB)
        case PSA_ALG_CFB:
            (void)srcOffset;
            cy_status = Cy_Crypto_Core_Aes_Cfb(CRYPTO, CY_CRYPTO_DECRYPT, *output_length, (uint8_t *)input, output, input + iv_length, operation->state.aes_state);
            break;
        #endif        
    }

    if(cy_status != CY_CRYPTO_SUCCESS)
    {
        return ifx_mxcrypto_status_to_psa_status(cy_status);
    }

    cy_status = Cy_Crypto_Core_Aes_Free(CRYPTO, operation->state.aes_state);

    return ifx_mxcrypto_status_to_psa_status(cy_status);

}
#endif
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_encrypt
****************************************************************************//**
*
* Calculate a single part Cipher encrypt operation.
*
* \param attributes
* The attributes for the key.
*
* \param key
* The pointer to the key buffer that has the key for encrypt operation
*
* \param key_length
* The length of the key.
*
* \param alg
* The hash algorithm to compute.
*
* \param iv
* The pointer to the iv.
*
* \param iv_length
* The size of the iv.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param output
* The pointer to store the encrypted text.
*
* \param output_size
* The buffer size of the output.
*
* \param output_length
* The Pointer to store the size of the encrypted text.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_encrypt(const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,
                                                     psa_algorithm_t alg, const uint8_t *iv, size_t iv_length, const uint8_t *input,
                                                     size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)
{
    #if !(CY_IP_MXCRYPTO_VERSION == 1u)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t update_output_length=0, finish_output_length=0;
    #endif
    #if defined (__ICCARM__)
    static ifx_mxcrypto_transparent_cipher_operation_t operation;
    #else
    ifx_mxcrypto_transparent_cipher_operation_t operation;
    #endif
    ifx_mxcrypto_memset(&operation,0,sizeof(ifx_mxcrypto_transparent_cipher_operation_t));
    
    if((NULL==attributes) || ((NULL==key) && (key_length > 0))  || ((NULL==iv) && (iv_length > 0))
           || ((NULL==input) && (input_length > 0))  || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if (CY_IP_MXCRYPTO_VERSION == 1u)

    return ifx_mxcrypto_transparent_cipher_encrypt_v1(&operation, attributes, key, key_length, alg, iv,  iv_length, input, input_length, output,  output_size, output_length);

#else 

    status = ifx_mxcrypto_transparent_cipher_encrypt_setup(&operation, attributes, key, key_length, alg);

    if (status == PSA_SUCCESS)
    {
        if (iv_length > 0)
        {
            status = ifx_mxcrypto_transparent_cipher_set_iv(&operation, iv, iv_length);
        }
    }

    if (status == PSA_SUCCESS)
    {
       status = ifx_mxcrypto_transparent_cipher_update(&operation, input, input_length, output, output_size, &update_output_length); 
    }

    if (status == PSA_SUCCESS)
    {
        status = ifx_mxcrypto_transparent_cipher_finish(&operation, get_buffer_offset(output, update_output_length),
                                                        output_size - update_output_length, &finish_output_length);
    }

    if (status == PSA_SUCCESS)
    {
        *output_length = update_output_length + finish_output_length;
    }

    (void)ifx_mxcrypto_transparent_cipher_abort(&operation);

    return status;
#endif
}
 

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_cipher_decrypt
****************************************************************************//**
*
* Calculate a single part Cipher decrypt operation.
*
* \param attributes
* The attributes for the key.
*
* \param key
* The pointer to the key buffer that has the key for decrypt operation
*
* \param key_length
* The length of the key.
*
* \param alg
* The hash algorithm to compute.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param output
* The pointer to store the decrypted text.
*
* \param output_size
* The buffer size of the output.
*
* \param output_length
* The Pointer to store the size of the decrypted text.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_mxcrypto_transparent_cipher_decrypt(const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,
                                                     psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                                     uint8_t *output, size_t output_size, size_t *output_length)
{

    #if !(CY_IP_MXCRYPTO_VERSION == 1u) 
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t olength, accumulated_length=0;
    #endif
    #if defined (__ICCARM__)
    static ifx_mxcrypto_transparent_cipher_operation_t operation;
    #else
    ifx_mxcrypto_transparent_cipher_operation_t operation;
    #endif

    if((NULL==attributes) || ((NULL==key) && (key_length > 0)) 
           || ((NULL==input) && (input_length > 0))  || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    #if (CY_IP_MXCRYPTO_VERSION == 1u) 
        return ifx_mxcrypto_transparent_cipher_decrypt_v1(&operation, attributes, key, key_length, alg, input, input_length, output,  output_size, output_length);
    #else 
    
    status = ifx_mxcrypto_transparent_cipher_decrypt_setup(&operation, attributes, key, key_length, alg);

    if(status == PSA_SUCCESS)
    {
        if (operation.iv_length > 0)
        {
            status = ifx_mxcrypto_transparent_cipher_set_iv(&operation, input, operation.iv_length);
        }
    }

    if(status == PSA_SUCCESS)
    {
        status = ifx_mxcrypto_transparent_cipher_update(&operation, get_buffer_offset_const(input, operation.iv_length),
                                                        input_length - operation.iv_length, output, output_size, &olength);
    }

    if(status == PSA_SUCCESS)
    {
        accumulated_length = olength;
        status = ifx_mxcrypto_transparent_cipher_finish(&operation, get_buffer_offset(output, accumulated_length),
                                                        output_size - accumulated_length, &olength);
    }

    if(status == PSA_SUCCESS)
    {
        *output_length = accumulated_length + olength;
    }

    ifx_mxcrypto_transparent_cipher_abort(&operation);
    return status;
    #endif
}

#endif /*(CY_IP_MXCRYPTO)*/
#endif /* IFX_PSA_MXCRYPTO_CIPHER */
