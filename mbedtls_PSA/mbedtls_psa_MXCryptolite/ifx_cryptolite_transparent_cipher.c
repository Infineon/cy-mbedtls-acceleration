
/***************************************************************************//**
* \file ifx_cryptolite_transparent_cipher.c
*
* \brief
*  PSA CRYPTOLITE transparent Cipher driver functions.
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

#include "ifx_cryptolite_transparent_cipher.h"

#if defined(IFX_PSA_CRYPTOLITE_CIPHER)

#if defined (CY_IP_MXCRYPTOLITE)

#define GET_BUFFER_PTR(x, y) (x == NULL ? NULL : x + y)

static psa_status_t ifx_mxcryptolite_transparent_psa_cipher_setup(ifx_cryptolite_transparent_cipher_operation_t *operation,
                                    const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer, size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    cy_en_cryptolite_dir_mode_t cipher_operation)
{
    psa_key_type_t key_type;
    size_t key_bits;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    (void) key_buffer_size;

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

    if(key_bits != 128)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if ((NULL==key_buffer) && (key_buffer_size > 0))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (alg) {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            if(cipher_operation == CY_CRYPTOLITE_DECRYPT)
            {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            cy_status =Cy_Cryptolite_Aes_Init(CRYPTOLITE, key_buffer, &operation->state.aes_state, &operation->buffer.aes_buffer);
            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {
                cy_status = Cy_Cryptolite_Aes_Ecb_Setup(CRYPTOLITE, &operation->state.aes_state);
            }
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            if(cipher_operation == CY_CRYPTOLITE_DECRYPT)
            {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            cy_status = Cy_Cryptolite_Aes_Init(CRYPTOLITE, key_buffer, &operation->state.aes_state, &operation->buffer.aes_buffer);
            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {
                cy_status = Cy_Cryptolite_Aes_Cbc_Setup(CRYPTOLITE, &operation->state.aes_state);
            }
            break;
        #endif

        #if defined(IFX_PSA_CRYPTOLITE_CTR)
        case PSA_ALG_CTR:
            cy_status =Cy_Cryptolite_Aes_Init(CRYPTOLITE, key_buffer, &operation->state.aes_state, &operation->buffer.aes_buffer);
            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {            
                cy_status = Cy_Cryptolite_Aes_Ctr_Setup(CRYPTOLITE, &operation->state.aes_state);
            }
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_CFB:
            cy_status =Cy_Cryptolite_Aes_Init(CRYPTOLITE, key_buffer, &operation->state.aes_state, &operation->buffer.aes_buffer);
            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {            
                cy_status = Cy_Cryptolite_Aes_Cfb_Setup(CRYPTOLITE, cipher_operation, &operation->state.aes_state);
            }
            break;
        #endif        
        default:
            return( PSA_ALG_IS_CIPHER( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }
    
    operation->alg = alg;

    return ifx_cryptolite_status_to_psa_status(cy_status);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_encrypt_setup
****************************************************************************//**
*
* Sets up a multi part Cipher encrypt operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_cipher_encrypt_setup(ifx_cryptolite_transparent_cipher_operation_t *operation,
                                                           const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                                           size_t key_buffer_size, psa_algorithm_t alg)
{
    return ifx_mxcryptolite_transparent_psa_cipher_setup(operation, attributes, key_buffer, key_buffer_size, alg, CY_CRYPTOLITE_ENCRYPT);
}

 

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_decrypt_setup
****************************************************************************//**
*
* Sets up a multi part Cipher decrypt operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_cipher_decrypt_setup(ifx_cryptolite_transparent_cipher_operation_t *operation,
                                                           const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                                           size_t key_buffer_size, psa_algorithm_t alg)
{
    return ifx_mxcryptolite_transparent_psa_cipher_setup(operation, attributes,  key_buffer, key_buffer_size, alg, CY_CRYPTOLITE_DECRYPT);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_set_iv
****************************************************************************//**
*
* Sets up a IV for the Cipher operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
*
* The pointer to the iv.
*
* \param iv_length
* The size of the iv.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t ifx_cryptolite_transparent_cipher_set_iv(ifx_cryptolite_transparent_cipher_operation_t *operation, 
                                                    const uint8_t *iv, size_t iv_length)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || ((NULL==iv) && (iv_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (iv_length < PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, operation->alg))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (operation->alg) {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            cy_status = CY_CRYPTOLITE_BAD_PARAMS;
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            cy_status = Cy_Cryptolite_Aes_Cbc_Set_IV(CRYPTOLITE, iv, &operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CTR)
        case PSA_ALG_CTR:
            cy_status = Cy_Cryptolite_Aes_Ctr_Set_IV(CRYPTOLITE, iv, &operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_CFB:
            cy_status = Cy_Cryptolite_Aes_Cfb_Set_IV(CRYPTOLITE, iv, &operation->state.aes_state);
            break;
        #endif
        default:
            cy_status = CY_CRYPTOLITE_BAD_PARAMS;
            break;
        }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_update
****************************************************************************//**
*
* Update of the cipher message for multi stage operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
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

psa_status_t ifx_cryptolite_transparent_cipher_update(ifx_cryptolite_transparent_cipher_operation_t *operation, const uint8_t *input,
                                                    size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)) || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (operation->alg)
    {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            *output_length = ((operation->state.aes_state.unProcessedBytes + input_length) / 16) * 16;
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            *output_length = ((operation->state.aes_state.unProcessedBytes + input_length) / 16) * 16;
            break;  
        #endif      
        #if defined(IFX_PSA_CRYPTOLITE_CTR)
        case PSA_ALG_CTR:
            *output_length = input_length;
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_CFB:
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

    switch (operation->alg)
    {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
            cy_status = Cy_Cryptolite_Aes_Ecb_Update(CRYPTOLITE, input_length, output, input, (uint32_t *)output_length, &operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
            cy_status = Cy_Cryptolite_Aes_Cbc_Update(CRYPTOLITE, input_length, output, input, (uint32_t *)output_length, &operation->state.aes_state);
            break;  
        #endif      
        #if defined(IFX_PSA_CRYPTOLITE_CTR)
        case PSA_ALG_CTR:
            cy_status = Cy_Cryptolite_Aes_Ctr_Update(CRYPTOLITE, input_length, output, input, &operation->state.aes_state);
            break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_CFB:
            cy_status = Cy_Cryptolite_Aes_Cfb_Update(CRYPTOLITE, input_length, output, input, &operation->state.aes_state);
            break;
        #endif
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
    }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_finish
****************************************************************************//**
*
* Performs the cipher finish for the multi stage operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
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
psa_status_t ifx_cryptolite_transparent_cipher_finish(ifx_cryptolite_transparent_cipher_operation_t *operation, 
                                                    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void)output;
    (void)output_size;

    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *output_length=0;

    switch (operation->alg)
    {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING)
        case PSA_ALG_ECB_NO_PADDING:
                cy_status = Cy_Cryptolite_Aes_Ecb_Finish(CRYPTOLITE, &operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)
        case PSA_ALG_CBC_NO_PADDING:
                cy_status = Cy_Cryptolite_Aes_Cbc_Finish(CRYPTOLITE, &operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CTR)
        case PSA_ALG_CTR:
                cy_status = Cy_Cryptolite_Aes_Ctr_Finish(CRYPTOLITE, &operation->state.aes_state);
                break;
        #endif
        #if defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_CFB:
                cy_status = Cy_Cryptolite_Aes_Cfb_Finish(CRYPTOLITE, &operation->state.aes_state);
                break;
        #endif
        default:
            cy_status = CY_CRYPTOLITE_BAD_PARAMS;
            break;
    }

    return ifx_cryptolite_status_to_psa_status(cy_status);
}



/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_abort
****************************************************************************//**
*
* Aborts the multi stage cipher operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_cipher_operation_t structure that has the
*  cipher context of cryptolite driver.
*
* \return psa_status_t.
*
*******************************************************************************/ 

psa_status_t ifx_cryptolite_transparent_cipher_abort(ifx_cryptolite_transparent_cipher_operation_t *operation)
{

    if(NULL==operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (operation->alg)
    {
        #if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING) || defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING) || defined(IFX_PSA_CRYPTOLITE_CTR) || defined(IFX_PSA_CRYPTOLITE_CFB)
        case PSA_ALG_ECB_NO_PADDING:
        case PSA_ALG_CBC_NO_PADDING: 
        case PSA_ALG_CTR:
        case PSA_ALG_CFB:
            (void)Cy_Cryptolite_Aes_Free(CRYPTOLITE, &operation->state.aes_state);
            break;
        #endif
    }
    
    return PSA_SUCCESS;
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_encrypt
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
psa_status_t ifx_cryptolite_transparent_cipher_encrypt(const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,
                                                     psa_algorithm_t alg, const uint8_t *iv, size_t iv_length, const uint8_t *input,
                                                     size_t input_length, uint8_t *output, size_t output_size, size_t *output_length)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    ifx_cryptolite_transparent_cipher_operation_t operation;
    size_t update_output_length=0, finish_output_length=0;
    ifx_mxcryptolite_memset(&operation,0,sizeof(ifx_cryptolite_transparent_cipher_operation_t));

    if((NULL==attributes) || ((NULL==key) && (key_length > 0))  || ((NULL==iv) && (iv_length > 0))
           || ((NULL==input) && (input_length > 0))  || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptolite_transparent_cipher_encrypt_setup(&operation, attributes, key, key_length, alg);

    if (status == PSA_SUCCESS)
    {
        if (iv_length > 0)
        {
            status = ifx_cryptolite_transparent_cipher_set_iv(&operation, iv, iv_length);
        }
    }

    if (status == PSA_SUCCESS)
    {
       status = ifx_cryptolite_transparent_cipher_update(&operation, input, input_length, output, output_size, &update_output_length); 
    }

    if (status == PSA_SUCCESS)
    {
        status = ifx_cryptolite_transparent_cipher_finish(&operation, GET_BUFFER_PTR(output, update_output_length),
                                                        output_size - update_output_length, &finish_output_length);
    }

    if (status == PSA_SUCCESS)
    {
        *output_length = update_output_length + finish_output_length;
    }

    (void)ifx_cryptolite_transparent_cipher_abort(&operation);

    return status;
}
 

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_cipher_decrypt
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
psa_status_t ifx_cryptolite_transparent_cipher_decrypt(const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,
                                                     psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                                     uint8_t *output, size_t output_size, size_t *output_length)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    ifx_cryptolite_transparent_cipher_operation_t operation;
    size_t olength, accumulated_length=0;
    ifx_mxcryptolite_memset(&operation,0,sizeof(ifx_cryptolite_transparent_cipher_operation_t));

    if((NULL==attributes) || ((NULL==key) && (key_length > 0)) 
           || ((NULL==input) && (input_length > 0))  || ((NULL==output) && (output_size > 0)) || (NULL==output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptolite_transparent_cipher_decrypt_setup(&operation, attributes, key, key_length, alg);

    if(status == PSA_SUCCESS)
    {
        if (operation.iv_length > 0)
        {
            status = ifx_cryptolite_transparent_cipher_set_iv(&operation, input, operation.iv_length);
        }
    }

    if(status == PSA_SUCCESS)
    {
        status = ifx_cryptolite_transparent_cipher_update(&operation, GET_BUFFER_PTR(input, operation.iv_length),
                                                        input_length - operation.iv_length, output, output_size, &olength);
    }

    if(status == PSA_SUCCESS)
    {
        accumulated_length = olength;
        status = ifx_cryptolite_transparent_cipher_finish(&operation, GET_BUFFER_PTR(output, accumulated_length),
                                                        output_size - accumulated_length, &olength);
    }

    if(status == PSA_SUCCESS)
    {
        *output_length = accumulated_length + olength;
    }

    if(status == PSA_SUCCESS)
    {
        ifx_cryptolite_transparent_cipher_abort(&operation);
    }

    return status;
}

#endif /*(CY_IP_MXCRYPTOLITE) */
#endif /* IFX_PSA_CRYPTOLITE_CIPHER */
