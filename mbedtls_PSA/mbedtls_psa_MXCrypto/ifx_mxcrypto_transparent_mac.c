
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_mac.c
*
* \brief
*  PSA crypto transparent MAC driver functions.
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

#include "ifx_mxcrypto_transparent_mac.h"

#if defined(IFX_PSA_MXCRYPTO_MAC)

#if defined (CY_IP_MXCRYPTO)

#include <string.h>



/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_compute
****************************************************************************//**
*
* Calculate a single part MAC operation.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for MAC operation
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param alg
* The algorithm to compute MAC.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param mac
* The pointer to store the calculated mac.
*
* \param mac_size
* The buffer size of the mac.
*
* \param mac_length
* The pointer to store the size of the calculated mac.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_compute(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                        uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    #if defined (__ICCARM__)
    static ifx_mxcrypto_transparent_mac_operation_t operation;
    #else
    ifx_mxcrypto_transparent_mac_operation_t operation;
    #endif
    ifx_mxcrypto_memset(&operation,0,sizeof(ifx_mxcrypto_transparent_mac_operation_t));

    if( (NULL==attributes) || ((NULL==key_buffer) && (0!=key_buffer_size)) || ((NULL == input) && (input_length > 0)) ||  (NULL==mac) || (NULL==mac_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_mxcrypto_transparent_mac_sign_setup(&operation, attributes, key_buffer, key_buffer_size, alg);

    if(status == PSA_SUCCESS)
    {
        status = ifx_mxcrypto_transparent_mac_update(&operation, input, input_length);
    }

    if(status == PSA_SUCCESS)
    {
        status = ifx_mxcrypto_transparent_mac_sign_finish(&operation, mac, mac_size, mac_length);
    }

    (void)ifx_mxcrypto_transparent_mac_abort(&operation);

    return status;
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_verify
****************************************************************************//**
*
* a single part Verification of MAC operation.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for MAC operation
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param alg
* The algorithm to compute verify MAC.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param mac
* The pointer to the buffer that has the calculated mac.
*
* \param mac_length
* The size of the mac buffer.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                       size_t key_buffer_size, psa_algorithm_t alg,
                                       const uint8_t *input, size_t input_length,
                                       const uint8_t *mac, size_t mac_length)
{

    uint8_t verify_mac_t[CY_CRYPTO_ALIGN_CACHE_LINE(64)+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    uint8_t *verify_mac = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)verify_mac_t);
    size_t verify_mac_size = (size_t)64;
    size_t verify_mac_length = 0;
    psa_status_t status = PSA_ERROR_BAD_STATE;

    status = ifx_mxcrypto_transparent_mac_compute(attributes, key_buffer, key_buffer_size, alg, input, input_length, verify_mac, verify_mac_size, &verify_mac_length);

    if(PSA_SUCCESS != status)
    {
        return status;
    }

    if(verify_mac_length != mac_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( 0 != ifx_mxcrypto_memcmp(mac, verify_mac, mac_length))
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

     return PSA_SUCCESS;
}



#if defined(IFX_PSA_MXCRYPTO_HMAC)
static psa_status_t  ifx_mxcrypto_transparent_hmac_setup(ifx_mxcrypto_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)

{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_en_crypto_sha_mode_t hash_mode;
    uint8_t *aligned_key_buffer;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *in_key_buf = NULL;
#endif

    if(PSA_KEY_TYPE_HMAC != psa_get_key_type(attributes))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch ( PSA_ALG_HMAC_GET_HASH(alg))
    {
    #if defined(IFX_PSA_MXCRYPTO_SHA_1)
        case PSA_ALG_SHA_1:
            hash_mode = CY_CRYPTO_MODE_SHA1;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_224)
        case PSA_ALG_SHA_224:
            hash_mode = CY_CRYPTO_MODE_SHA224;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_256)
        case PSA_ALG_SHA_256:
            hash_mode = CY_CRYPTO_MODE_SHA256;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_384)
        case PSA_ALG_SHA_384:
            hash_mode = CY_CRYPTO_MODE_SHA384;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_512)
        case PSA_ALG_SHA_512:
            hash_mode = CY_CRYPTO_MODE_SHA512;
            break;
    #endif
        default:
        return PSA_ERROR_NOT_SUPPORTED;
        }

    operation->mac_type = alg;
    aligned_key_buffer = (uint8_t *)key_buffer;
    operation->state.hmac_state = (cy_stc_crypto_hmac_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.hmac_state_t);
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    operation->buffer.hmac_buffer = (cy_stc_crypto_v1_hmac_buffers_t *)operation->buffer.hmac_buffer_t;
#elif (CY_IP_MXCRYPTO_VERSION == 2u)
    operation->buffer.hmac_buffer = (cy_stc_crypto_v2_hmac_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.hmac_buffer_t);
#endif

    cy_status  = Cy_Crypto_Core_Hmac_Init(CRYPTO, operation->state.hmac_state , hash_mode, operation->buffer.hmac_buffer);
    if (CY_CRYPTO_SUCCESS == cy_status)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
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
        cy_status  = Cy_Crypto_Core_Hmac_Start(CRYPTO, operation->state.hmac_state, aligned_key_buffer, key_buffer_size);
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(in_key_buf != NULL)
    {
        ifx_mxcrypto_free(in_key_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status);

}
#endif


#if defined(IFX_PSA_MXCRYPTO_CMAC)
static psa_status_t  ifx_mxcrypto_transparent_cmac_setup(ifx_mxcrypto_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)

{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    size_t key_bits = psa_get_key_bits(attributes);
    uint8_t *aligned_key_buffer;
    cy_en_crypto_aes_key_length_t key_length;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *in_key_buf = NULL;
#else
    (void) key_buffer_size;
#endif

    if(PSA_KEY_TYPE_AES != psa_get_key_type(attributes))
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

    operation->mac_type = alg;
    aligned_key_buffer = (uint8_t *)key_buffer;
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    operation->state.cmac_state = (cy_stc_crypto_v1_cmac_state_t *)operation->state.cmac_state_t;
    operation->buffer.cmac_buffer = (cy_stc_crypto_v1_cmac_buffers_t *)operation->buffer.cmac_buffer_t;
#elif (CY_IP_MXCRYPTO_VERSION == 2u)
    operation->state.cmac_state = (cy_stc_crypto_v2_cmac_state_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->state.cmac_state_t);
    operation->buffer.cmac_buffer = (cy_stc_crypto_v2_cmac_buffers_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->buffer.cmac_buffer_t);
#endif

    cy_status  = Cy_Crypto_Core_Cmac_Init(CRYPTO, operation->state.cmac_state, operation->buffer.cmac_buffer);

    if (CY_CRYPTO_SUCCESS == cy_status)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
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
        cy_status  = Cy_Crypto_Core_Cmac_Start(CRYPTO, operation->state.cmac_state, aligned_key_buffer, key_length);
    }

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(in_key_buf != NULL)
    {
        ifx_mxcrypto_free(in_key_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status);

}
#endif

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_sign_setup
****************************************************************************//**
*
* Mac sign setup for Multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context of mxcrypto driver.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for MAC operation
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param alg
* The algorithm to compute MAC.
*
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t  ifx_mxcrypto_transparent_mac_sign_setup(ifx_mxcrypto_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if((NULL==operation) || (NULL==attributes) || ((NULL==key_buffer) && (0 != key_buffer_size)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    #if defined(IFX_PSA_MXCRYPTO_HMAC)
    if (PSA_ALG_IS_HMAC(alg))
    {
        status = ifx_mxcrypto_transparent_hmac_setup(operation, attributes, key_buffer, key_buffer_size, alg);
    }else
    #endif

    #if defined(IFX_PSA_MXCRYPTO_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC)
    {
        status = ifx_mxcrypto_transparent_cmac_setup(operation, attributes, key_buffer, key_buffer_size, alg);
    }else
    #endif
    {
        (void) operation;
        (void) attributes;
        (void) key_buffer;
        (void) key_buffer_size;
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if(PSA_ERROR_NOT_SUPPORTED == status)
    {
        operation->mac_type = 0;
    }

    return status;
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_verify_setup
****************************************************************************//**
*
*  Mac verify setup for Multipart MAC verify operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context of mxcrypto driver.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for Verify MAC operation
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param alg
* The algorithm to perform MAC verification.
*
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t  ifx_mxcrypto_transparent_mac_verify_setup(ifx_mxcrypto_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{

    return  ifx_mxcrypto_transparent_mac_sign_setup(operation, attributes, key_buffer, key_buffer_size, alg);
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_update
****************************************************************************//**
*
*  To add multiple message fragment to a multipart MAC/MAC verify operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context for mxcrypto driver.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input messaage.
*
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_update(ifx_mxcrypto_transparent_mac_operation_t *operation, const uint8_t *input, size_t input_length)
{

    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if((NULL == operation) || ((NULL == input) && (input_length != 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == input_length)
    {
        return PSA_SUCCESS;
    }


    #if defined(IFX_PSA_MXCRYPTO_HMAC)
    if (PSA_ALG_IS_HMAC(operation->mac_type))
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *input_data = NULL;
        uint8_t *aligned_input_data = (uint8_t *)input;
        uint32_t blk_size = input_length;
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
        {
            uint8_t *input_ptr;
            uint32_t hash_blk_size = (uint32_t)PSA_HASH_BLOCK_LENGTH(operation->mac_type);
            input_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(hash_blk_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == input_data)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_input_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_data);
            input_ptr = (uint8_t *)input;
            while(blk_size >= hash_blk_size)
            {
                ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, hash_blk_size);
                cy_status = Cy_Crypto_Core_Hmac_Update(CRYPTO, operation->state.hmac_state, (uint8_t *)aligned_input_data, hash_blk_size);
                if(cy_status != CY_CRYPTO_SUCCESS)
                {
                    ifx_mxcrypto_free(input_data);
                    return ifx_mxcrypto_status_to_psa_status(cy_status);
                }
                input_ptr += hash_blk_size;
                blk_size -= hash_blk_size;
            }
            ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, blk_size);
        }
        cy_status = Cy_Crypto_Core_Hmac_Update(CRYPTO, operation->state.hmac_state, (uint8_t *)aligned_input_data, blk_size);
        if(input_data != NULL)
        {
            ifx_mxcrypto_free(input_data);
        }
#else
        cy_status = Cy_Crypto_Core_Hmac_Update(CRYPTO, operation->state.hmac_state, input, (uint32_t)input_length);
#endif
        status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
    #endif

    #if defined(IFX_PSA_MXCRYPTO_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->mac_type) == PSA_ALG_CMAC)
    {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        uint8_t *input_data = NULL;
        uint8_t *aligned_input_data = (uint8_t *)input;
        uint32_t blk_size = input_length;
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
        {
            uint8_t *input_ptr;
            uint32_t cmac_blk_size = (uint32_t)CY_CRYPTO_AES_BLOCK_SIZE;
            input_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(cmac_blk_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == input_data)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            aligned_input_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_data);
            input_ptr = (uint8_t *)input;
            while(blk_size >= cmac_blk_size)
            {
                ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, cmac_blk_size);
                cy_status = Cy_Crypto_Core_Cmac_Update(CRYPTO, operation->state.cmac_state, (uint8_t *)aligned_input_data, cmac_blk_size);
                if(cy_status != CY_CRYPTO_SUCCESS)
                {
                    ifx_mxcrypto_free(input_data);
                    return ifx_mxcrypto_status_to_psa_status(cy_status);
                }
                input_ptr += cmac_blk_size;
                blk_size -= cmac_blk_size;
            }
            ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, blk_size);
        }
        cy_status = Cy_Crypto_Core_Cmac_Update(CRYPTO, operation->state.cmac_state, (uint8_t *)aligned_input_data, blk_size);
        if(input_data != NULL)
        {
            ifx_mxcrypto_free(input_data);
        }
#else
        cy_status = Cy_Crypto_Core_Cmac_Update(CRYPTO, operation->state.cmac_state, input, (uint32_t)input_length);
#endif
        status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }else
    #endif

    {
        (void) operation;
        (void) input;
        (void) input_length;
        (void) cy_status;
        status = PSA_ERROR_NOT_SUPPORTED;
    }


    return status;

}

 __STATIC_INLINE psa_status_t mxcrypto_hmac_output_length(ifx_mxcrypto_transparent_mac_operation_t *operation, size_t* mac_tmp_length)
{

switch (PSA_ALG_HMAC_GET_HASH(operation->mac_type))
    {
#if defined(IFX_PSA_MXCRYPTO_SHA_1)
    case PSA_ALG_SHA_1:
        *mac_tmp_length = CY_CRYPTO_SHA1_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_224)
    case PSA_ALG_SHA_224:
        *mac_tmp_length = CY_CRYPTO_SHA224_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_256)
    case PSA_ALG_SHA_256:
        *mac_tmp_length = CY_CRYPTO_SHA256_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_384)
    case PSA_ALG_SHA_384:
        *mac_tmp_length = CY_CRYPTO_SHA384_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_512)
    case PSA_ALG_SHA_512:
        *mac_tmp_length = CY_CRYPTO_SHA512_DIGEST_SIZE;
        break;
#endif
    default:
    return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_sign_finish
****************************************************************************//**
*
*  Finish the MAC operation of a multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context of mxcrypto driver.
*
* \param mac
* The pointer to the buffer to store MAC.
*
* \param mac_size
* The size of the mac buffer.
*
* \param mac_length
* The pointer to the store MAC length.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_sign_finish(ifx_mxcrypto_transparent_mac_operation_t *operation, uint8_t *mac, size_t mac_size, size_t *mac_length)
{

    size_t mac_tmp_length = 0;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint8_t cal_mac[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_SHA512_DIGEST_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    uint8_t *mac_ptr = mac;
    bool is_mac_truncated = false;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if((NULL==operation) || (NULL==mac)  || (NULL==mac_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0 == mac_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *mac_buf = NULL;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)mac, mac_size) )
    {
        mac_buf = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(mac_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == mac_buf)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        mac_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)mac_buf);
    }
#endif

    #if defined(IFX_PSA_MXCRYPTO_HMAC)
    if (PSA_ALG_IS_HMAC(operation->mac_type))
    {
        status = mxcrypto_hmac_output_length(operation, &mac_tmp_length);
        if(status != PSA_SUCCESS)
        {
            return status;
        }
    }else
    #endif

    #if defined(IFX_PSA_MXCRYPTO_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->mac_type) == PSA_ALG_CMAC)
    {
        mac_tmp_length = CY_CRYPTO_AES_BLOCK_SIZE;
    }else
    #endif
    {
        (void) operation;
        (void) mac;
        (void) mac_size;
        (void) mac_length;
        (void) mac_tmp_length;
        (void) cy_status;
        (void) cal_mac;
        (void) mac_ptr;
        (void) is_mac_truncated;
        (void) status;

        return PSA_ERROR_NOT_SUPPORTED;
    }

    if((PSA_MAC_TRUNCATED_LENGTH(operation->mac_type) > 0) && (PSA_MAC_TRUNCATED_LENGTH(operation->mac_type) < mac_tmp_length))
    {
        mac_tmp_length = PSA_MAC_TRUNCATED_LENGTH(operation->mac_type);
        mac_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)cal_mac);
        is_mac_truncated = true;
    }

    if(mac_size < mac_tmp_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    #if defined(IFX_PSA_MXCRYPTO_HMAC)
    if (PSA_ALG_IS_HMAC(operation->mac_type))
    {
        cy_status = Cy_Crypto_Core_Hmac_Finish(CRYPTO, operation->state.hmac_state,  mac_ptr);
        status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    #endif

    #if defined(IFX_PSA_MXCRYPTO_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->mac_type) == PSA_ALG_CMAC)
    {
        cy_status = Cy_Crypto_Core_Cmac_Finish(CRYPTO, operation->state.cmac_state, mac_ptr);
        status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    #endif

    if(CY_CRYPTO_SUCCESS == cy_status)
    {
        if(is_mac_truncated)
        {
            ifx_mxcrypto_memcpy((void *)mac, (void *)mac_ptr, mac_tmp_length);

        }
        else
        {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
            /* Copy MAC data back to output buffer if we used internal aligned buffer */
            if(mac_buf != NULL)
            {
                ifx_mxcrypto_memcpy((void *)mac, (void *)mac_ptr, mac_tmp_length);
            }
#endif
        }
        *mac_length = mac_tmp_length;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(mac_buf != NULL)
    {
        ifx_mxcrypto_free(mac_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status);
}

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_verify_finish
****************************************************************************//**
*
*  Finish the MAC operation of a multipart MAC verify operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context for mxcrypto driver.
*
* \param mac
* The pointer to the buffer that has the calculated MAC.
*
* \param mac_size
* The size of the mac buffer.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_verify_finish(ifx_mxcrypto_transparent_mac_operation_t *operation, const uint8_t *mac, size_t mac_length)
{
    psa_status_t status = PSA_ERROR_BAD_STATE;
    uint8_t verify_mac[64];
    size_t verify_mac_size = sizeof(verify_mac)/sizeof(verify_mac[0]);
    size_t verify_mac_length = 0;

    status = ifx_mxcrypto_transparent_mac_sign_finish(operation, verify_mac, verify_mac_size, &verify_mac_length);

    if(PSA_SUCCESS != status)
    {
        return status;
    }

    if(verify_mac_length != mac_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( 0 != ifx_mxcrypto_memcmp( mac, verify_mac, mac_length))
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

     return PSA_SUCCESS;
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_mac_abort
****************************************************************************//**
*
*  Abort a multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_mac_operation_t structure that has the
*  mac context for mxcrypto driver.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_mac_abort(ifx_mxcrypto_transparent_mac_operation_t *operation)
{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;

    if(NULL == operation)
    {
       return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0 == operation->mac_type)
    {
        return PSA_ERROR_BAD_STATE;
    }

    #if defined(IFX_PSA_MXCRYPTO_HMAC)
    if (PSA_ALG_IS_HMAC(operation->mac_type))
    {
        cy_status = Cy_Crypto_Core_Hmac_Free(CRYPTO, operation->state.hmac_state);
    }else
    #endif

    #if defined(IFX_PSA_MXCRYPTO_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->mac_type) == PSA_ALG_CMAC)
    {
        cy_status = Cy_Crypto_Core_Cmac_Free(CRYPTO, operation->state.cmac_state);
    }else
    #endif
    {
        (void) cy_status;
        return PSA_ERROR_NOT_SUPPORTED;
    }


    return ifx_mxcrypto_status_to_psa_status(cy_status);
}

#endif /*(CY_IP_MXCRYPTO)*/
#endif /* IFX_PSA_MXCRYPTO_HMAC */
