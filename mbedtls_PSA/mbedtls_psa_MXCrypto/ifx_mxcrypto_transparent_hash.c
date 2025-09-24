
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_hash.c
*
* \brief
*  PSA crypto transparent Hash driver functions.
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


#include "ifx_mxcrypto_transparent_hash.h"

#if defined(IFX_PSA_MXCRYPTO_SHA)

#if defined(CY_IP_MXCRYPTO)


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_setup
****************************************************************************//**
*
* Set up a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure that stores the
*  hash context of mxcrypto driver.
*
* \param alg
* The hash algorithm to compute.
*
*
* \return psa_status_t.
*
*******************************************************************************/

psa_status_t ifx_mxcrypto_transparent_hash_setup(ifx_mxcrypto_transparent_hash_operation_t *operation, psa_algorithm_t alg)
{

    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_en_crypto_sha_mode_t hash_mode;

    if(NULL == operation) 
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (alg)
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
#if defined(IFX_PSA_MXCRYPTO_SHA3_224)
    case PSA_ALG_SHA3_224 :
        hash_mode = CY_CRYPTO_MODE_SHA3_224;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_256)
    case PSA_ALG_SHA3_256 :
        hash_mode = CY_CRYPTO_MODE_SHA3_256;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_384)
    case PSA_ALG_SHA3_384 :
        hash_mode = CY_CRYPTO_MODE_SHA3_384;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_512)
    case PSA_ALG_SHA3_512 :
        hash_mode = CY_CRYPTO_MODE_SHA3_512;
        break;
#endif
    default:
       return( PSA_ALG_IS_HASH( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }
        
    operation->hash_state = (cy_stc_crypto_sha_state_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->hash_state_t);
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    operation->sha_buffer = (cy_stc_crypto_v1_sha_buffers_t*)operation->sha_buffer_t;
#elif (CY_IP_MXCRYPTO_VERSION == 2u)
    operation->sha_buffer = (cy_stc_crypto_v2_sha_buffers_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)operation->sha_buffer_t);
    Cy_Crypto_Core_MemSet(CRYPTO, (uint8_t*)operation->sha_buffer, (uint8_t)0, (uint16_t)sizeof(cy_stc_crypto_v2_sha_buffers_t));
#endif
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    operation->hash_blk_size = (uint32_t)PSA_HASH_BLOCK_LENGTH(alg);
#endif
    operation->hash_type = alg;
    cy_status = Cy_Crypto_Core_Sha_Init(CRYPTO, operation->hash_state, hash_mode, operation->sha_buffer);
    if (CY_CRYPTO_SUCCESS == cy_status)
    {
        cy_status = Cy_Crypto_Core_Sha_Start(CRYPTO, operation->hash_state);

    }

    return ifx_mxcrypto_status_to_psa_status(cy_status);
}
  

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_update
****************************************************************************//**
*
* To add multiple message fragment to a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure that has the
*  hash context of Mxcrypto driver.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \return psa_status_t.
*
*******************************************************************************/  
psa_status_t ifx_mxcrypto_transparent_hash_update(ifx_mxcrypto_transparent_hash_operation_t *operation, const uint8_t *input, size_t input_length)
{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    
    if((NULL == operation) || ((NULL == input) && (input_length != 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == input_length)
    {
        return PSA_SUCCESS;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *input_data = NULL;
    uint8_t *aligned_input_data = (uint8_t *)input;
    uint32_t blk_size = input_length;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
    {
        uint8_t *input_ptr;
        input_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(operation->hash_blk_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == input_data)
        {
            return CY_CRYPTO_MEMORY_ALLOC_FAIL;
        }
        aligned_input_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_data);
    
        input_ptr = (uint8_t *)input;
        while(blk_size >= operation->hash_blk_size)
        {
            ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, operation->hash_blk_size);
            cy_status = Cy_Crypto_Core_Sha_Update(CRYPTO, operation->hash_state, (uint8_t *)aligned_input_data, operation->hash_blk_size);
            if(cy_status != CY_CRYPTO_SUCCESS)
            {
                ifx_mxcrypto_free(input_data);
                return ifx_mxcrypto_status_to_psa_status(cy_status);
            }
            input_ptr += operation->hash_blk_size;
            blk_size -= operation->hash_blk_size;
        }
        ifx_mxcrypto_memcpy((void *)aligned_input_data, (void *)input_ptr, blk_size);
    }
    cy_status = Cy_Crypto_Core_Sha_Update(CRYPTO, operation->hash_state, (uint8_t *)aligned_input_data, blk_size);
    if (NULL != input_data)
    {
        ifx_mxcrypto_free(input_data);
    }
    return ifx_mxcrypto_status_to_psa_status(cy_status);
#else
    cy_status = Cy_Crypto_Core_Sha_Update(CRYPTO, operation->hash_state, input, (uint32_t)input_length);
    return ifx_mxcrypto_status_to_psa_status(cy_status);
#endif
}
  

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_finish
****************************************************************************//**
*
* Finish the hash operation of a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure that has the
*  hash context of Mxcrypto driver.
*
* \param hash
* The pointer to store the calculated hash.
*
* \param hash_size
* The buffer size of the hash.
*
* \param hash_length
* The Pointer to store the size of the calculated hash.
*
* \return psa_status_t.
*
*******************************************************************************/  
psa_status_t  ifx_mxcrypto_transparent_hash_finish(ifx_mxcrypto_transparent_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    size_t hash_expected_size;

    if((NULL == operation)  || ((NULL == hash) && (hash_size > 0)) || (NULL == hash_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    switch (operation->hash_type)
    {
#if defined(IFX_PSA_MXCRYPTO_SHA_1)
    case PSA_ALG_SHA_1:
        hash_expected_size = CY_CRYPTO_SHA1_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_224)
    case PSA_ALG_SHA_224:
        hash_expected_size = CY_CRYPTO_SHA224_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_256)
    case PSA_ALG_SHA_256:
        hash_expected_size = CY_CRYPTO_SHA256_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_384)
    case PSA_ALG_SHA_384:
        hash_expected_size = CY_CRYPTO_SHA384_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_512)
    case PSA_ALG_SHA_512:
        hash_expected_size = CY_CRYPTO_SHA512_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_224)
    case PSA_ALG_SHA3_224 :
        hash_expected_size = CY_CRYPTO_SHA224_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_256)
    case PSA_ALG_SHA3_256 :
        hash_expected_size = CY_CRYPTO_SHA256_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_384)
    case PSA_ALG_SHA3_384 :
        hash_expected_size = CY_CRYPTO_SHA384_DIGEST_SIZE;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_512)
    case PSA_ALG_SHA3_512 :
        hash_expected_size = CY_CRYPTO_SHA512_DIGEST_SIZE;
        break;
#endif
    default:
      return PSA_ERROR_BAD_STATE;
    }

    if(hash_size < hash_expected_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
     
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
   if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)hash, hash_size))
    {
       uint8_t *hash_data = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(hash_expected_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
       if (NULL == hash_data)
       {
           return PSA_ERROR_INSUFFICIENT_MEMORY;
       }
       uint8_t *aligned_hash_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)hash_data);
       cy_status = Cy_Crypto_Core_Sha_Finish(CRYPTO, operation->hash_state, aligned_hash_data);
       if (CY_CRYPTO_SUCCESS == cy_status)
       {
            ifx_mxcrypto_memcpy( (void *)hash, (void *)aligned_hash_data, hash_expected_size);
           *hash_length = hash_expected_size;
       }
       ifx_mxcrypto_free(hash_data);
       return ifx_mxcrypto_status_to_psa_status(cy_status);
    }
#endif
    cy_status = Cy_Crypto_Core_Sha_Finish(CRYPTO, operation->hash_state, hash);
  
    if (CY_CRYPTO_SUCCESS == cy_status)
    {
        *hash_length = hash_expected_size;
    }   
    return ifx_mxcrypto_status_to_psa_status(cy_status);
}
  

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_abort
****************************************************************************//**
*
* Abort the multipart hash operation.
*
* \param operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure that has the
*  hash context of Mxcrypto driver.
*
* \return psa_status_t.
*
*******************************************************************************/   
psa_status_t ifx_mxcrypto_transparent_hash_abort(ifx_mxcrypto_transparent_hash_operation_t *operation)
{
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS; 

    if(NULL == operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
           
    cy_status = Cy_Crypto_Core_Sha_Free(CRYPTO, operation->hash_state);
    operation->hash_type = 0;
    return ifx_mxcrypto_status_to_psa_status(cy_status);
            
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_compute
****************************************************************************//**
*
* Calculate a single part hash operation.
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
* \param hash
* The pointer to store the calculated hash.
*
* \param hash_size
* The buffer size of the hash.
*
* \param hash_length
* The Pointer to store the size of the calculated hash.
*
* \return psa_status_t.
*
*******************************************************************************/ 

psa_status_t ifx_mxcrypto_transparent_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    ifx_mxcrypto_transparent_hash_operation_t operation;
    psa_status_t status;

    status = ifx_mxcrypto_transparent_hash_setup(&operation, alg);
    if(status == PSA_SUCCESS)
    {
        status = ifx_mxcrypto_transparent_hash_update(&operation, input, input_length);
        if(status == PSA_SUCCESS)
        {
            status = ifx_mxcrypto_transparent_hash_finish(&operation, hash, hash_size, hash_length);
        }
    }
    return status;
#else
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS; 
    size_t hash_expected_size;
    cy_en_crypto_sha_mode_t hash_mode;

    if( ((NULL == input) && (input_length > 0))  || ((NULL == hash) && (hash_size > 0)) || ((NULL == hash_length) && (hash_size > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (alg)
    {
#if defined(IFX_PSA_MXCRYPTO_SHA_1)
    case PSA_ALG_SHA_1:
        hash_expected_size = CY_CRYPTO_SHA1_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA1;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_224)
    case PSA_ALG_SHA_224:
        hash_expected_size = CY_CRYPTO_SHA224_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA224;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_256)
    case PSA_ALG_SHA_256:
        hash_expected_size = CY_CRYPTO_SHA256_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA256;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_384)
    case PSA_ALG_SHA_384:
        hash_expected_size = CY_CRYPTO_SHA384_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA384;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA_512)
    case PSA_ALG_SHA_512:
        hash_expected_size = CY_CRYPTO_SHA512_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA512;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_224)
    case PSA_ALG_SHA3_224:
        hash_expected_size = CY_CRYPTO_SHA224_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA3_224;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_256)
    case PSA_ALG_SHA3_256:
        hash_expected_size = CY_CRYPTO_SHA256_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA3_256;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_384)
    case PSA_ALG_SHA3_384:
        hash_expected_size = CY_CRYPTO_SHA384_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA3_384;
        break;
#endif
#if defined(IFX_PSA_MXCRYPTO_SHA3_512)
    case PSA_ALG_SHA3_512:
        hash_expected_size = CY_CRYPTO_SHA512_DIGEST_SIZE;
        hash_mode = CY_CRYPTO_MODE_SHA3_512;
        break;
#endif
    default:
      return PSA_ERROR_NOT_SUPPORTED;
    }


    if(hash_size < hash_expected_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
  
    cy_status = Cy_Crypto_Core_Sha(CRYPTO, input, (uint32_t)input_length, hash, hash_mode);
    
    if (CY_CRYPTO_SUCCESS == cy_status)
    {
        *hash_length = hash_expected_size;
    }  
    
    return ifx_mxcrypto_status_to_psa_status(cy_status);
#endif    /*#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)*/
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_hash_clone
****************************************************************************//**
*
* Clone the hash operation context for the multipart hash operation.
*
* \param source_operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure that needs to be
*  cloned.
*
* \param target_operation
*  The pointer to the ifx_mxcrypto_transparent_hash_operation_t structure to store the
*  cloned context.
*
* \return psa_status_t.
*
*******************************************************************************/

psa_status_t ifx_mxcrypto_transparent_hash_clone(const ifx_mxcrypto_transparent_hash_operation_t *source_operation, ifx_mxcrypto_transparent_hash_operation_t *target_operation)
{
 
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS; 

    if ((NULL == source_operation) || (NULL == target_operation))   
    {
        return PSA_ERROR_INVALID_ARGUMENT; 
    }

    target_operation->hash_state = (cy_stc_crypto_sha_state_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)target_operation->hash_state_t);
    Cy_Crypto_Core_MemCpy( CRYPTO, (void *)target_operation->hash_state, (void *)source_operation->hash_state, sizeof(cy_stc_crypto_sha_state_t));
#if (CY_IP_MXCRYPTO_VERSION == 1u)
    target_operation->sha_buffer = (cy_stc_crypto_v1_sha_buffers_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)target_operation->sha_buffer_t);
    Cy_Crypto_Core_MemCpy( CRYPTO, (void *)target_operation->sha_buffer, (void *)source_operation->sha_buffer, sizeof(cy_stc_crypto_v1_sha_buffers_t));
#elif (CY_IP_MXCRYPTO_VERSION == 2u)
    target_operation->sha_buffer = (cy_stc_crypto_v2_sha_buffers_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)target_operation->sha_buffer_t);
    Cy_Crypto_Core_MemCpy( CRYPTO, (void *)target_operation->sha_buffer, (void *)source_operation->sha_buffer, sizeof(cy_stc_crypto_v2_sha_buffers_t));
#endif
    target_operation->hash_type = source_operation->hash_type;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    target_operation->hash_blk_size = source_operation->hash_blk_size;
#endif
    cy_status = Cy_Crypto_Core_Sha_Init(CRYPTO, target_operation->hash_state, (cy_en_crypto_sha_mode_t)source_operation->hash_state->mode, target_operation->sha_buffer);


    return ifx_mxcrypto_status_to_psa_status(cy_status);
 
}
#endif /* CY_IP_MXCRYPTO */
#endif /* IFX_PSA_MXCRYPTO_SHA */

