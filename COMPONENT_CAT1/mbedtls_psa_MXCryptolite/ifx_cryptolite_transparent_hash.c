
/***************************************************************************//**
* \file ifx_cryptolite_transparent_hash.c
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


#include "ifx_cryptolite_transparent_hash.h"
#if defined(IFX_PSA_CRYPTOLITE_SHA)

#if defined (CY_IP_MXCRYPTOLITE)

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_setup
****************************************************************************//**
*
* Set up a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure that
*  stores the hash context of Cryptolite driver.
*
* \param alg
* The hash algorithm to compute.
*
*
* \return psa_status_t.
*
*******************************************************************************/

psa_status_t ifx_cryptolite_transparent_hash_setup(ifx_cryptolite_transparent_hash_operation_t *operation, psa_algorithm_t alg)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if(NULL == operation) 
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
        
    if(PSA_ALG_SHA_256 != alg)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    operation->hash_type = alg;        
    cy_status  = Cy_Cryptolite_Sha256_Init(CRYPTOLITE, &operation->sha_context);
    if (CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        cy_status  = Cy_Cryptolite_Sha256_Start(CRYPTOLITE, &operation->sha_context);
    }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}
  

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_update
****************************************************************************//**
*
* To add multiple message fragment to a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure that
*  has the hash context of Cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_hash_update(ifx_cryptolite_transparent_hash_operation_t *operation, const uint8_t *input, size_t input_length)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    
    if((NULL == operation) || ((NULL == input) && (input_length != 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == input_length)
    {
        return PSA_SUCCESS;
    }
    
    if(PSA_ALG_SHA_256 != operation->hash_type)
    {
        return PSA_ERROR_BAD_STATE;
    }
       
    cy_status = Cy_Cryptolite_Sha256_Update(CRYPTOLITE, input, (uint32_t)input_length,  &operation->sha_context);
    return ifx_cryptolite_status_to_psa_status(cy_status);
}
  

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_finish
****************************************************************************//**
*
* Finish the hash operation of a multipart hash operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure that
*  has the hash context of Cryptolite driver.
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
psa_status_t  ifx_cryptolite_transparent_hash_finish(ifx_cryptolite_transparent_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
  
    if((NULL == operation)  || ((NULL == hash) && (hash_size > 0)) || (NULL == hash_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if( hash_size < CY_CRYPTOLITE_SHA256_HASH_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    if(PSA_ALG_SHA_256 != operation->hash_type)
    {
        return PSA_ERROR_BAD_STATE;
    }
    
    cy_status =  Cy_Cryptolite_Sha256_Finish(CRYPTOLITE, hash, &operation->sha_context);
  
    if (CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        *hash_length = CY_CRYPTOLITE_SHA256_HASH_SIZE;
    }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}
  

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_abort
****************************************************************************//**
*
* Abort the multipart hash operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure that 
*  has the hash context of Cryptolite driver.
*
* \return psa_status_t.
*
*******************************************************************************/   
psa_status_t ifx_cryptolite_transparent_hash_abort(ifx_cryptolite_transparent_hash_operation_t *operation)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if(NULL == operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ALG_SHA_256 != operation->hash_type)    
    {
        return PSA_ERROR_BAD_STATE; 
    }
            
    cy_status = Cy_Cryptolite_Sha256_Free(CRYPTOLITE, &operation->sha_context);
    operation->hash_type = 0;
    
    return ifx_cryptolite_status_to_psa_status(cy_status);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_compute
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

psa_status_t ifx_cryptolite_transparent_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    cy_stc_cryptolite_context_sha256_t sha_context;

    if( ((NULL == input) && (input_length > 0))  || ((NULL == hash) && (hash_size > 0)) || ((NULL == hash_length) && (hash_size > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(PSA_ALG_SHA_256 != alg)
    {
        return PSA_ERROR_NOT_SUPPORTED;         
    }
    
    if(hash_size < CY_CRYPTOLITE_SHA256_HASH_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
  
    cy_status =  Cy_Cryptolite_Sha256_Run(CRYPTOLITE, input, (uint32_t)input_length, hash, &sha_context);
    
    if (CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        *hash_length = CY_CRYPTOLITE_SHA256_HASH_SIZE;
    }  
    
    return ifx_cryptolite_status_to_psa_status(cy_status);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_hash_clone
****************************************************************************//**
*
* Clone the hash operation context for the multipart hash operation.
*
* \param source_operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure that
*  needs to be cloned.
*
* \param target_operation
*  The pointer to the ifx_cryptolite_transparent_hash_operation_t structure
*  to store the cloned context.
*
* \return psa_status_t.
*
*******************************************************************************/

psa_status_t ifx_cryptolite_transparent_hash_clone(const ifx_cryptolite_transparent_hash_operation_t *source_operation, ifx_cryptolite_transparent_hash_operation_t *target_operation)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if ((NULL == source_operation) || (NULL == target_operation))   
    {
        return PSA_ERROR_INVALID_ARGUMENT; 
    }
        
    *target_operation = *source_operation;
    cy_status = Cy_Cryptolite_Sha256_Init(CRYPTOLITE, &target_operation->sha_context);

    return ifx_cryptolite_status_to_psa_status(cy_status);
}

#endif /* CY_IP_MXCRYPTOLITE */
#endif /* defined(IFX_PSA_CRYPTOLITE_SHA) */

