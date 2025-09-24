
/***************************************************************************//**
* \file ifx_cryptolite_transparent_aead.c
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

#include "ifx_cryptolite_transparent_aead.h"

#if defined(IFX_PSA_CRYPTOLITE_AEAD)

#if defined (CY_IP_MXCRYPTOLITE)

static psa_status_t ifx_cryptolite_transparent_psa_aead_setup(ifx_cryptolite_transparent_aead_operation_t *operation,  const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer, size_t key_buffer_size,  psa_algorithm_t alg)
{
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;
    psa_key_type_t key_type ;

    key_bits = psa_get_key_bits(attributes);
    key_type = psa_get_key_type(attributes);

    if(key_type != PSA_KEY_TYPE_AES)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if((NULL==operation) || (NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->tag_length = 0;
    operation->alg = PSA_ALG_NONE;

    switch (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0))
    {

#if defined(IFX_PSA_CRYPTOLITE_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):

            if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) != 16)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            switch( key_bits )
            {
                case 128:  break;
                default : return( PSA_ERROR_INVALID_ARGUMENT );
            }

            operation->alg = PSA_ALG_CCM;

            cy_status = Cy_Cryptolite_Aes_Ccm_Init(CRYPTOLITE, &operation->aes_buffers, &operation->aes_state);

            if (CY_CRYPTOLITE_SUCCESS == cy_status)
            {
                cy_status = Cy_Cryptolite_Aes_Ccm_SetKey(CRYPTOLITE, key_buffer, &operation->aes_state);
            }

            status = ifx_cryptolite_status_to_psa_status(cy_status);

            if (status != PSA_SUCCESS)
            {
                return status;
            }
            break;
#endif /* IFX_PSA_CRYPTOLITE_CCM */

        default:
            {
                (void)cy_status;
                (void)key_type;
                (void)key_bits;
                return( PSA_ALG_IS_AEAD ( alg ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
            }
    }

    operation->key_type = psa_get_key_type(attributes);
    operation->tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    return status;
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_encrypt
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
psa_status_t ifx_cryptolite_transparent_aead_encrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size,
                                     psa_algorithm_t alg, const uint8_t *nonce, size_t nonce_length,
                                     const uint8_t *additional_data, size_t additional_data_length,
                                     const uint8_t *plaintext, size_t plaintext_length,
                                     uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    ifx_cryptolite_transparent_aead_operation_t operation ;
    uint8_t *tag;

    if((NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0))  || ((NULL==nonce) && (nonce_length > 0))
        || ((NULL==additional_data) && (additional_data_length > 0))   || ((NULL==plaintext) && (plaintext_length > 0))  || ((NULL==ciphertext) && (ciphertext_size > 0)) || (NULL==ciphertext_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptolite_transparent_psa_aead_setup(&operation, attributes, key_buffer, key_buffer_size, alg);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

    if (ciphertext_size < (plaintext_length + operation.tag_length))
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    tag = ciphertext + plaintext_length;

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    if (operation.alg == PSA_ALG_CCM)
    {

        cy_status = Cy_Cryptolite_Aes_Ccm_Encrypt_Tag(CRYPTOLITE, nonce_length, nonce,
                                                    additional_data_length, additional_data,
                                                    plaintext_length, ciphertext, plaintext,
                                                    operation.tag_length, tag, &operation.aes_state);

        status =  ifx_cryptolite_status_to_psa_status(cy_status);
        (void)Cy_Cryptolite_Aes_Ccm_Free(CRYPTOLITE,  &operation.aes_state);
    }
    else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
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
}

static psa_status_t ifx_cryptolite_aead_unpadded_locate_tag(size_t tag_length,
                                                 const uint8_t *ciphertext,
                                                 size_t ciphertext_length,
                                                 size_t plaintext_size,
                                                 uint8_t **p_tag)
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

    *p_tag = (uint8_t *)ciphertext + payload_length;
    return PSA_SUCCESS;
}



/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_decrypt
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
psa_status_t ifx_cryptolite_transparent_aead_decrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg,
                                      const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length,
                                      const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    ifx_cryptolite_transparent_aead_operation_t operation ;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint8_t *tag = NULL;

    if((NULL==attributes) || ((NULL==key_buffer) && (key_buffer_size > 0))  || ((NULL==nonce) && (nonce_length > 0))
        || ((NULL==additional_data) && (additional_data_length > 0))   || ((NULL==ciphertext) && (ciphertext_length > 0))  || ((NULL==plaintext) && (plaintext_size > 0)) || (NULL==plaintext_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptolite_transparent_psa_aead_setup(&operation, attributes, key_buffer, key_buffer_size, alg);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

    status = ifx_cryptolite_aead_unpadded_locate_tag(operation.tag_length, ciphertext, ciphertext_length, plaintext_size, &tag);

    if (status != PSA_SUCCESS)
    {
        return status;
    }

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    if (operation.alg == PSA_ALG_CCM)
    {
        cy_en_cryptolite_ccm_auth_result_t isValid = CY_CRYPTOLITE_TAG_INVALID;

        cy_status = Cy_Cryptolite_Aes_Ccm_Decrypt(CRYPTOLITE,
                                            nonce_length, nonce,
                                            additional_data_length, additional_data,
                                            ciphertext_length - operation.tag_length, plaintext, ciphertext, 
                                            operation.tag_length, tag, &isValid,
                                            &operation.aes_state);

        status =  ifx_cryptolite_status_to_psa_status(cy_status);

        (void)Cy_Cryptolite_Aes_Ccm_Free(CRYPTOLITE,  &operation.aes_state);

        if (status == PSA_SUCCESS)
        {
            if(CY_CRYPTOLITE_TAG_INVALID == isValid)
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
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
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_encrypt_setup
****************************************************************************//**
*
* Sets up a multi part AEAD encrypt Setup operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_encrypt_setup(ifx_cryptolite_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = ifx_cryptolite_transparent_psa_aead_setup(operation, attributes, key_buffer, key_buffer_size, alg);

    if (status == PSA_SUCCESS)
    {
        operation->is_encrypt = true;
    }

    return status;
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_decrypt_setup
****************************************************************************//**
*
* Sets up a multi part AEAD Decrypt Setup operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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

psa_status_t ifx_cryptolite_transparent_aead_decrypt_setup(ifx_cryptolite_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = ifx_cryptolite_transparent_psa_aead_setup(operation, attributes, key_buffer, key_buffer_size, alg);

    if (status == PSA_SUCCESS)
    {
        operation->is_encrypt = false;
    }

    return status;
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_set_nonce
****************************************************************************//**
*
*  Sets up nonce or iv for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_set_nonce(ifx_cryptolite_transparent_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || ((NULL==nonce) && (nonce_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
        cy_status =Cy_Cryptolite_Aes_Ccm_Start(CRYPTOLITE, operation->is_encrypt ? CY_CRYPTOLITE_ENCRYPT : CY_CRYPTOLITE_DECRYPT, 
        nonce_length, nonce, &operation->aes_state);

        status =  ifx_cryptolite_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
    {
        (void)cy_status;
        (void) operation;
        (void) nonce;
        (void) nonce_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}



/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_set_lengths
****************************************************************************//**
*
* Declare the lengths of the message and additional data for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_set_lengths(ifx_cryptolite_transparent_aead_operation_t *operation, size_t ad_length, size_t plaintext_length)
{

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if (operation->alg == PSA_ALG_CCM) {
        cy_status = Cy_Cryptolite_Aes_Ccm_Set_Length(CRYPTOLITE,
                                            ad_length,  plaintext_length, 
                                            operation->tag_length,
                                            &operation->aes_state);
        
        return ifx_cryptolite_status_to_psa_status(cy_status);

    }
#else /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
    (void) operation;
    (void) ad_length;
    (void) plaintext_length;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */

    return PSA_SUCCESS;
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_update_ad
****************************************************************************//**
*
*  AAD update function for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_update_ad(ifx_cryptolite_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    if (operation->alg == PSA_ALG_CCM)
     {
        cy_status = Cy_Cryptolite_Aes_Ccm_Update_Aad(CRYPTOLITE, input_length, (uint8_t *)input, &operation->aes_state);

        status =  ifx_cryptolite_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
    {   (void)cy_status;
        (void)operation;
        (void)input;
        (void)input_length;

        return PSA_ERROR_NOT_SUPPORTED;
    }

    return status;
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_update
****************************************************************************//**
*
*  update function for multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_update(ifx_cryptolite_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length,
                                     uint8_t *output, size_t output_size, size_t *output_length)
{
    size_t update_output_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    update_output_length = input_length;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;

    if((NULL==operation) || ((NULL==input) && (input_length > 0)) || ((NULL==output) && (output_size > 0)) || (NULL == output_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(IFX_PSA_CRYPTOLITE_CCM)

    if(output_size < input_length)
    {
    	return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (operation->alg == PSA_ALG_CCM)
    {
        cy_status = Cy_Cryptolite_Aes_Ccm_Update(CRYPTOLITE,  input_length, output, input, &operation->aes_state);
        status =  ifx_cryptolite_status_to_psa_status(cy_status);
    } else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
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
        *output_length = update_output_length;
    }

    return status;
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_finish
****************************************************************************//**
*
*  Finish the multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_finish(ifx_cryptolite_transparent_aead_operation_t *operation, uint8_t *ciphertext, size_t ciphertext_size,
                                     size_t *ciphertext_length, uint8_t *tag, size_t tag_size, size_t *tag_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    size_t finish_output_size = 0;

    if((NULL==operation) || (NULL==ciphertext_length) || ((NULL==tag) && (tag_size > 0)) || (NULL == tag_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (tag_size < operation->tag_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    if (operation->alg == PSA_ALG_CCM)
    {
        /* mbedtls never pass any real ciphertext data in finish().
         * The ciphertext parameters exists only for the sake of alternative implementations. */
        (void) ciphertext;
        (void) ciphertext_size;
        *ciphertext_length = 0;

        cy_status = Cy_Cryptolite_Aes_Ccm_Finish(CRYPTOLITE, tag, &operation->aes_state);
        status =  ifx_cryptolite_status_to_psa_status(cy_status);
    }else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
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

    return status;
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_verify
****************************************************************************//**
*
*  Finish authenticating and decrypting a message in an AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
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
psa_status_t ifx_cryptolite_transparent_aead_verify(ifx_cryptolite_transparent_aead_operation_t *operation, uint8_t *plaintext, size_t plaintext_size,
                                     size_t *plaintext_length, const uint8_t *tag, size_t tag_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(IFX_PSA_CRYPTOLITE_CCM)
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint8_t check_tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t check_tag_length = 0;

    if (operation->alg == PSA_ALG_CCM)
    {
        status = ifx_cryptolite_transparent_aead_finish(operation, plaintext, plaintext_size, plaintext_length, check_tag, sizeof(check_tag), &check_tag_length);
        if(PSA_SUCCESS == status)
        {
            /*compare auth tag*/
            if((check_tag_length != tag_length) || (Cy_Cryptolite_Vu_memcmp(tag, check_tag, check_tag_length) != 0U))
            {
                status = PSA_ERROR_INVALID_SIGNATURE;
            }
        }
    }
    else
#endif /* IFX_PSA_CRYPTOLITE_CCM */
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
}

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_aead_abort
****************************************************************************//**
*
*  Abort the multi part AEAD operation.
*
* \param operation
*  The pointer to the ifx_cryptolite_transparent_aead_operation_t structure that has the
*  aead context of mxcrypto driver.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_cryptolite_transparent_aead_abort(ifx_cryptolite_transparent_aead_operation_t *operation)
{

    if(NULL==operation)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (operation->alg)
    {
#if defined(IFX_PSA_CRYPTOLITE_CCM)
        case PSA_ALG_CCM:
            (void)Cy_Cryptolite_Aes_Ccm_Free(CRYPTOLITE,  &operation->aes_state);
            break;
#endif /* IFX_PSA_CRYPTOLITE_CCM */
    }

    operation->is_encrypt = false;

    return PSA_SUCCESS;
}

#endif /*(CY_IP_MXCRYPTOLITE) && (CY_IP_cryptolite_VERSION == 2u)*/
#endif /* IFX_PSA_CRYPTOLITE_AEAD */
