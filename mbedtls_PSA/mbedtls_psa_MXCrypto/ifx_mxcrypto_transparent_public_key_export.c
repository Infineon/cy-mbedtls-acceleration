/***************************************************************************//**
* \file ifx_mxcrypto_transparent_public_key_export.c
*
* \brief
*  PSA crypto transparent Public key Export driver functions.
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


#include "ifx_mxcrypto_transparent_public_key_export.h"

#if defined(IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT) 
#if defined (CY_IP_MXCRYPTO)

#if defined(IFX_PSA_MXCRYPTO_ECC_PUBLIC_KEY_EXPORT)
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_ecc_load_key
****************************************************************************//**
*
* Function to Load the MXcrypto key from data buffer.
*
* \param attributes
* The attributes for the key.
*
* \param key
* The pointer to the key.
*
* \param data
* The pointer to data that contains the key.
*
* \param data_length
* The size of the data.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_ecc_load_key( const psa_key_attributes_t *attributes,
                                         cy_stc_crypto_ecc_key *key,
                                         const uint8_t *data, size_t data_length)
{
    size_t key_bits = psa_get_key_bits(attributes);
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t bytesize;
    cy_stc_crypto_ecc_dp_type *dp;

    switch(key_bits)
    {
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)
    case 192:
        key->curveID = CY_CRYPTO_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  
    case 224:
        key->curveID = CY_CRYPTO_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)
    case 256:
        key->curveID = CY_CRYPTO_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)
    case 384:  
        key->curveID = CY_CRYPTO_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521)
    case 521:  
    case 528:
        key->curveID = CY_CRYPTO_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Crypto_Core_ECC_GetCurveParams(key->curveID);
    bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);
    
    key->pubkey.y = (uint8_t *)key->pubkey.x + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize);

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( key_type ) )
    {
        if(data_length < 2*bytesize + 1)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        key->type = PK_PUBLIC;

        ifx_mxcrypto_memcpy(key->pubkey.x, &data[1], bytesize);
        Cy_Crypto_Core_InvertEndianness(key->pubkey.x, bytesize);

        ifx_mxcrypto_memcpy(key->pubkey.y, &data[1+bytesize], bytesize);
        Cy_Crypto_Core_InvertEndianness(key->pubkey.y, bytesize);
    }
    else
    {
        if(data_length < bytesize)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        key->type = PK_PRIVATE;
        ifx_mxcrypto_memcpy(key->k, data, bytesize);
        Cy_Crypto_Core_InvertEndianness(key->k, bytesize);
    }

    return PSA_SUCCESS;
}


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_ecc_export_key
****************************************************************************//**
*
* Function to export the MXcrypto key to data buffer.
*
* \param attributes
* The attributes for the key.
*
* \param key
* The pointer to the key.
*
* \param data
* The pointer to data that contains the key.
*
* \param data_size
* The size of the data buffer.
*
* \param data_length
* The size of the data buffer populated.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_ecc_export_key( psa_key_type_t type,
                                         cy_stc_crypto_ecc_key *key,
                                         uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint32_t bytesize;
    cy_stc_crypto_ecc_dp_type *dp;

    dp = Cy_Crypto_Core_ECC_GetCurveParams(key->curveID);
    bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        if( data_size < 2 * bytesize + 1)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        if( key->type == PK_PRIVATE )
        {
            cy_status = Cy_Crypto_Core_ECC_MakePublicKey(CRYPTO, key->curveID,  key->k,  key);
            psa_status = ifx_mxcrypto_status_to_psa_status(cy_status);

            if( psa_status != PSA_SUCCESS )
            {
                return psa_status;
            }
        }

        psa_status = PSA_SUCCESS;
        *data_length =  2 * bytesize + 1;
        data[0] = 0x04;

        ifx_mxcrypto_memcpy(&data[1], key->pubkey.x, bytesize);
        Cy_Crypto_Core_InvertEndianness(&data[1], bytesize);

        ifx_mxcrypto_memcpy(&data[1 + bytesize], key->pubkey.y, bytesize);
        Cy_Crypto_Core_InvertEndianness(&data[1 + bytesize], bytesize);

        return( psa_status );
    }
    else
    {
        if( data_size < bytesize)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        ifx_mxcrypto_memcpy(data, key->k, bytesize);
        Cy_Crypto_Core_InvertEndianness(data, bytesize);

        *data_length = bytesize;

        return PSA_SUCCESS;
    }
}



/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_ecc_export_public_key
****************************************************************************//**
*
* Function to export ECC key to data buffer.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that contains the key.
*
* \param key_buffer_size
* The size of the key buffer.
*
* \param data
* The pointer to data to export the key.
*
* \param data_size
* The size of the data buffer.
*
* \param data_length
* The size of the data buffer populated.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_ecc_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    cy_stc_crypto_ecc_key key;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    uint8_t *priv_ptr=NULL;
    uint8_t *pub_ptr=NULL;

#if defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    CY_ALIGN(32) static uint8_t ecc_priv_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE]);
    CY_ALIGN(32) static uint8_t ecc_pub_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE]);
#else
    CY_ALIGN(4) static uint8_t ecc_priv_key[IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE];
    CY_ALIGN(4) static uint8_t ecc_pub_key[IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE];
#endif
    priv_ptr = ecc_priv_key;
    pub_ptr = ecc_pub_key;
#elif defined (IFX_PSA_MXCRYPTO_USE_STACK_MEM)
    CY_ALIGN(4) uint8_t ecc_priv_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t ecc_pub_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE];

    priv_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_priv_key);
    pub_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_pub_key);
#else
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint32_t *ecc_pub_ptr = (uint32_t *)ifx_mxcrypto_malloc((2*CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_BYTE_SIZE))+CY_CRYPTO_DCAHCE_PADDING_SIZE);
#else
    uint32_t *ecc_pub_ptr = (uint32_t *)ifx_mxcrypto_malloc(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE);
#endif
    uint32_t *ecc_priv_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    priv_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_priv_ptr);
    pub_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_pub_ptr);
#endif

    if( (NULL != priv_ptr) && (NULL != pub_ptr) )
    {
        key.k = priv_ptr;
        key.pubkey.x = pub_ptr;

        psa_status = ifx_mxcrypto_transparent_ecc_load_key(attributes, &key, key_buffer, key_buffer_size);

        if(PSA_SUCCESS == psa_status)
        {
            psa_status = ifx_mxcrypto_transparent_ecc_export_key( PSA_KEY_TYPE_ECC_PUBLIC_KEY( PSA_KEY_TYPE_ECC_GET_FAMILY( key_type ) ),
                        &key, data, data_size, data_length );
        }
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_MXCRYPTO_USE_STACK_MEM)

    if(NULL != ecc_priv_ptr)
    {
        ifx_mxcrypto_free(ecc_priv_ptr);
    }

    if(NULL != ecc_pub_ptr)
    {
        ifx_mxcrypto_free(ecc_pub_ptr);
    }
    #endif

    return psa_status;
}
#endif /* IFX_PSA_MXCRYPTO_ECC_PUBLIC_KEY_EXPORT */

#if defined(IFX_PSA_MXCRYPTO_RSA_PUBLIC_KEY_EXPORT)
#include "psa_crypto_rsa.h"

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_rsa_export_public_key
****************************************************************************//**
*
* Function to export RSA key to data buffer.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that contains the key.
*
* \param key_buffer_size
* The size of the key buffer.
*
* \param data
* The pointer to data to export the key.
*
* \param data_size
* The size of the data buffer.
*
* \param data_length
* The size of the data buffer populated.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_rsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    return mbedtls_psa_rsa_export_public_key(
                             attributes,
                             key_buffer, key_buffer_size,
                             data, data_size, data_length);
}
#endif /* IFX_PSA_MXCRYPTO_RSA_PUBLIC_KEY_EXPORT */

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_export_public_key
****************************************************************************//**
*
* Function to export key to data buffer.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that contains the key.
*
* \param key_buffer_size
* The size of the key buffer.
*
* \param data
* The pointer to data to export the key.
*
* \param data_size
* The size of the data buffer.
*
* \param data_length
* The size of the data buffer populated.
* 
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length )
{
    psa_key_type_t key_type = psa_get_key_type(attributes);

    if((NULL == attributes) || ((NULL == key_buffer) && (key_buffer_size > 0))  || ((NULL == data) && (data_size > 0)) || (NULL == data_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( PSA_KEY_TYPE_IS_RSA( key_type ) || PSA_KEY_TYPE_IS_ECC( key_type ) )
    {
        if( PSA_KEY_TYPE_IS_PUBLIC_KEY( key_type ) )
        {
            if( key_buffer_size > data_size )
            {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            ifx_mxcrypto_memcpy(data, key_buffer, key_buffer_size);
            ifx_mxcrypto_memset(data + key_buffer_size, 0, data_size - key_buffer_size);
            *data_length = key_buffer_size;

            return PSA_SUCCESS;
        }

        if( PSA_KEY_TYPE_IS_RSA( key_type ) )
        {
#if defined(IFX_PSA_MXCRYPTO_RSA_PUBLIC_KEY_EXPORT)
            return ifx_mxcrypto_transparent_rsa_export_public_key( attributes, key_buffer, key_buffer_size,
                                                      data, data_size,data_length ) ;
#endif
        }
        else
        {
#if defined(IFX_PSA_MXCRYPTO_ECC_PUBLIC_KEY_EXPORT)
            return ifx_mxcrypto_transparent_ecc_export_public_key( attributes, key_buffer, key_buffer_size,
                                                                  data, data_size, data_length ) ;
#endif        
        }
    }

    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif  /* (CY_IP_MXCRYPTO) */
#endif /* defined(IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT)*/
