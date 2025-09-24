/***************************************************************************//**
* \file ifx_mxcrypto_transparent_key_generation.c
*
* \brief
*  PSA crypto transparent Key Generation driver functions.
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

#include "ifx_mxcrypto_transparent_key_generation.h"
#if defined(IFX_PSA_MXCRYPTO_KEY_GENERATION) 
#if defined (CY_IP_MXCRYPTO)


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_generate_ecc_key
****************************************************************************//**
*
* Function to generate ECC key.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer.
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param key_buffer_length
* The size of the generated key.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_generate_ecc_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )

{

    size_t key_bits;
    psa_key_type_t key_type;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_stc_crypto_ecc_dp_type *dp;
    size_t bytesize;
    cy_en_crypto_ecc_curve_id_t curveID;
    uint8_t *aligned_key_buffer = (uint8_t *)key_buffer;

    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);

    if( PSA_KEY_TYPE_ECC_GET_FAMILY(key_type) != PSA_ECC_FAMILY_SECP_R1 )
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    switch(key_bits)
    {
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)
    case 192:
        curveID = CY_CRYPTO_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  
    case 224:
        curveID = CY_CRYPTO_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)
    case 256:
        curveID = CY_CRYPTO_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)
    case 384:  
        curveID = CY_CRYPTO_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521)
    case 521:  
        curveID = CY_CRYPTO_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Crypto_Core_ECC_GetCurveParams(curveID);
    bytesize   = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    if(key_buffer_size < bytesize)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
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
    }
#endif
    cy_status = Cy_Crypto_Core_ECC_MakePrivateKey(CRYPTO, curveID, (uint8_t *)aligned_key_buffer, NULL, NULL);

    if(CY_CRYPTO_SUCCESS == cy_status)
    {
        Cy_Crypto_Core_InvertEndianness(aligned_key_buffer, bytesize);
        *key_buffer_length = bytesize;
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(in_key_buf != NULL)
    {
        ifx_mxcrypto_memcpy((void *)key_buffer, (void *)aligned_key_buffer,  *key_buffer_length);
        ifx_mxcrypto_free(in_key_buf);
    }
#endif
    return ifx_mxcrypto_status_to_psa_status(cy_status); 
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_generate_key
****************************************************************************//**
*
* Function to generate key.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer.
*
* \param key_buffer_size
* The size of the key_buffer.
*
* \param key_buffer_length
* The size of the generated key.
* 
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)

{

    psa_key_type_t key_type;

    if ((NULL == attributes) || (NULL == key_buffer) || (NULL == key_buffer_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);

    if(PSA_KEY_TYPE_IS_UNSTRUCTURED( key_type ))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    else if ( key_type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type ) && PSA_KEY_TYPE_IS_KEY_PAIR(key_type) )
    {
        return ifx_mxcrypto_transparent_generate_ecc_key(attributes, key_buffer, key_buffer_size, key_buffer_length);
    }
    else
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

}

#endif  /* (CY_IP_MXCRYPTO) */
#endif /* defined(IFX_PSA_MXCRYPTO_KEY_GENERATION)*/
