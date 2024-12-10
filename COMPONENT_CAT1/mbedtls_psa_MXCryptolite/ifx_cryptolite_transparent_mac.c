
/***************************************************************************//**
* \file ifx_cryptolite_transparent_mac.c
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

#include "ifx_cryptolite_transparent_mac.h"
#if defined(IFX_PSA_CRYPTOLITE_HMAC)

#if defined (CY_IP_MXCRYPTOLITE)

#include "cy_cryptolite_utils.h"

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_compute
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
psa_status_t ifx_cryptolite_transparent_mac_compute(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                        uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    size_t mac_tmp_length = CY_CRYPTOLITE_SHA256_HASH_SIZE;
    cy_stc_cryptolite_context_hmac_sha256_t hmac_ctx;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint8_t cal_mac[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    uint8_t *mac_ptr= mac;

    if( (NULL==attributes) || ((NULL == key_buffer) && (0 != key_buffer_size)) || ((NULL == input) && (input_length > 0)) ||  (NULL==mac) || (NULL==mac_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((0 == PSA_ALG_IS_HMAC(alg)) || (PSA_KEY_TYPE_HMAC != psa_get_key_type(attributes)))
    {	
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if(PSA_ALG_SHA_256 != PSA_ALG_HMAC_GET_HASH(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if((PSA_MAC_TRUNCATED_LENGTH(alg) > 0) && (PSA_MAC_TRUNCATED_LENGTH(alg) < mac_tmp_length))	
    {
        mac_tmp_length = PSA_MAC_TRUNCATED_LENGTH(alg);
        mac_ptr = cal_mac;
    }

    if(mac_size < mac_tmp_length)
    {
      return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    cy_status  = Cy_Cryptolite_Hmac_Sha256_Run(CRYPTOLITE, key_buffer, (uint32_t)key_buffer_size, input, (uint32_t)input_length,  mac_ptr, &hmac_ctx);

    if(CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        if(mac_tmp_length < CY_CRYPTOLITE_SHA256_HASH_SIZE)
        {
            Cy_Cryptolite_Setnumber(mac, (uint8_t *)mac_ptr, mac_tmp_length);

        }
        *mac_length = mac_tmp_length;
    }
    
    return ifx_cryptolite_status_to_psa_status(cy_status);
}
  
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_verify
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
psa_status_t ifx_cryptolite_transparent_mac_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                       size_t key_buffer_size, psa_algorithm_t alg,
                                       const uint8_t *input, size_t input_length,
                                       const uint8_t *mac, size_t mac_length)
{
    uint8_t verify_mac[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    size_t verify_mac_size = sizeof(verify_mac)/sizeof(verify_mac[0]);
    size_t verify_mac_length = 0;
    psa_status_t status = PSA_ERROR_BAD_STATE;
    
    status = ifx_cryptolite_transparent_mac_compute(attributes, key_buffer, key_buffer_size, alg, input, input_length, verify_mac, verify_mac_size, &verify_mac_length);
    
    if(PSA_SUCCESS != status)
    {
        return status;
    }

    if(verify_mac_length != mac_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if( 0 != ifx_psa_safer_memcmp(mac, verify_mac, mac_length))
    { 
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}
  
  
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_sign_setup
****************************************************************************//**
*
* Mac sign setup for Multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context of Cryptolite driver.
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
psa_status_t  ifx_cryptolite_transparent_mac_sign_setup(ifx_cryptolite_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
  
    if((NULL==operation) || (NULL==attributes) || ((NULL==key_buffer) && (0 !=key_buffer_size)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if((0 == PSA_ALG_IS_HMAC(alg)) || (PSA_KEY_TYPE_HMAC != psa_get_key_type(attributes)))
    {	
        return PSA_ERROR_INVALID_ARGUMENT;
    }
      
    if(PSA_ALG_SHA_256 != PSA_ALG_HMAC_GET_HASH(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    operation->mac_type = alg;
    
    cy_status  = Cy_Cryptolite_Hmac_Sha256_Init(CRYPTOLITE, &operation->hmac_context);
    if (CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        cy_status  = Cy_Cryptolite_Hmac_Sha256_Start(CRYPTOLITE, key_buffer, key_buffer_size, &operation->hmac_context);
    }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}
  
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_verify_setup
****************************************************************************//**
*
*  Mac verify setup for Multipart MAC verify operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context of Cryptolite driver.
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
psa_status_t  ifx_cryptolite_transparent_mac_verify_setup(ifx_cryptolite_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{    
    return  ifx_cryptolite_transparent_mac_sign_setup(operation, attributes, key_buffer, key_buffer_size, alg);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_update
****************************************************************************//**
*
*  To add multiple message fragment to a multipart MAC/MAC verify operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context for Cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_mac_update(ifx_cryptolite_transparent_mac_operation_t *operation, const uint8_t *input, size_t input_length)
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
    
    if(!PSA_ALG_IS_HMAC(operation->mac_type))
    {	
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    cy_status = Cy_Cryptolite_Hmac_Sha256_Update(CRYPTOLITE, input, (uint32_t)input_length,  &operation->hmac_context);
    
    return ifx_cryptolite_status_to_psa_status(cy_status);
}
 
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_sign_finish
****************************************************************************//**
*
*  Finish the MAC operation of a multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context of Cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_mac_sign_finish(ifx_cryptolite_transparent_mac_operation_t *operation, uint8_t *mac, size_t mac_size, size_t *mac_length)
{
 
    size_t mac_tmp_length = CY_CRYPTOLITE_SHA256_HASH_SIZE;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint8_t cal_mac[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    uint8_t *mac_ptr = mac;

    if((NULL==operation) || (NULL==mac)  || (NULL==mac_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (0 == mac_size)
    {
       return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if(!PSA_ALG_IS_HMAC(operation->mac_type))
    {	
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((PSA_MAC_TRUNCATED_LENGTH(operation->mac_type) > 0) && (PSA_MAC_TRUNCATED_LENGTH(operation->mac_type) < mac_tmp_length))	
    {
        mac_tmp_length = PSA_MAC_TRUNCATED_LENGTH(operation->mac_type);
        mac_ptr = cal_mac;
    }

    if(mac_size < mac_tmp_length)
    {
      return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    

    cy_status =  Cy_Cryptolite_Hmac_Sha256_Finish(CRYPTOLITE, mac_ptr, &operation->hmac_context);

    if(CY_CRYPTOLITE_SUCCESS == cy_status)
    {
        if(mac_tmp_length < CY_CRYPTOLITE_SHA256_HASH_SIZE)
        {
            Cy_Cryptolite_Setnumber(mac, (uint8_t *)mac_ptr, mac_tmp_length);

        }            
        
        *mac_length = mac_tmp_length;
    }
    return ifx_cryptolite_status_to_psa_status(cy_status); 
}
 
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_verify_finish
****************************************************************************//**
*
*  Finish the MAC operation of a multipart MAC verify operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context for Cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_mac_verify_finish(ifx_cryptolite_transparent_mac_operation_t *operation, const uint8_t *mac, size_t mac_length)
{
    psa_status_t status = PSA_ERROR_BAD_STATE;
    uint8_t verify_mac[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    size_t verify_mac_size = sizeof(verify_mac)/sizeof(verify_mac[0]);
    size_t verify_mac_length = 0;
    
    status = ifx_cryptolite_transparent_mac_sign_finish(operation, verify_mac, verify_mac_size, &verify_mac_length);
    
    if(PSA_SUCCESS != status)
    {
        return status;
    }

    if(verify_mac_length != mac_length)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if( 0 != ifx_psa_safer_memcmp(mac, verify_mac, mac_length))
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS; 
}
 

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_mac_abort
****************************************************************************//**
*
*  Abort a multipart MAC operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_mac_operation_t structure that has the
*  mac context for Cryptolite driver.
*
* \return psa_status_t.
*
*******************************************************************************/  
psa_status_t ifx_cryptolite_transparent_mac_abort(ifx_cryptolite_transparent_mac_operation_t *operation)
{

    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
  
    if(NULL == operation)
    {
       return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if ( (PSA_ALG_SHA_256 != PSA_ALG_HMAC_GET_HASH(operation->mac_type)) || (0 == operation->mac_type)) 
    {
        return PSA_ERROR_BAD_STATE; 
    }

    cy_status = Cy_Cryptolite_Hmac_Sha256_Free(CRYPTOLITE, &operation->hmac_context);
    return ifx_cryptolite_status_to_psa_status(cy_status);
}

#endif /* defined (CY_IP_MXCRYPTOLITE) */
#endif /* defined(IFX_PSA_CRYPTOLITE_HMAC)*/
