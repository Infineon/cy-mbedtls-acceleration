/***************************************************************************//**
* \file ifx_cryptolite_transparent_public_key_export.c
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


#include "ifx_cryptolite_transparent_public_key_export.h"

#if defined(IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT) 
#if defined (CY_IP_MXCRYPTOLITE) 

#include "cy_cryptolite_utils.h"

#if defined(IFX_PSA_CRYPTOLITE_RSA_PUBLIC_KEY_EXPORT)
#include "psa_crypto_rsa.h"
#endif

#if defined(IFX_PSA_CRYPTOLITE_ECC_PUBLIC_KEY_EXPORT)
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_ecc_load_key
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
static psa_status_t ifx_cryptolite_transparent_ecc_load_key( const psa_key_attributes_t *attributes,
                                         cy_stc_cryptolite_ecc_key *key,
                                         const uint8_t *data, size_t data_length)
{
    size_t key_bits = psa_get_key_bits(attributes);
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t bytesize;
    cy_stc_cryptolite_ecc_dp_type *dp;

    switch(key_bits)
    {
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)
    case 192:
        key->curveID = CY_CRYPTOLITE_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)  
    case 224:
        key->curveID = CY_CRYPTOLITE_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)
    case 256:
        key->curveID = CY_CRYPTOLITE_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)
    case 384:  
        key->curveID = CY_CRYPTOLITE_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521)
    case 521:  
    case 528:
        key->curveID = CY_CRYPTOLITE_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Cryptolite_ECC_GetCurveParams(key->curveID);
    bytesize = VU_BITS_TO_BYTES(dp->size);
    
    key->pubkey.y = (uint8_t *)(key->pubkey.x) + bytesize;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( key_type ) )
    {
        if(data_length < 2*bytesize + 1)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        key->type = PK_PUBLIC;

        Cy_Cryptolite_Vu_memcpy( key->pubkey.x, &data[1], bytesize);
        Cy_Cryptolite_InvertEndianness(key->pubkey.x, bytesize);

        Cy_Cryptolite_Vu_memcpy( key->pubkey.y, &data[1+bytesize], bytesize);
        Cy_Cryptolite_InvertEndianness(key->pubkey.y, bytesize);
    }
    else
    {
        if(data_length < bytesize)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        key->type = PK_PRIVATE;
        Cy_Cryptolite_Vu_memcpy( key->k, data, bytesize);
        Cy_Cryptolite_InvertEndianness(key->k, bytesize);
    }

    return PSA_SUCCESS;
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_ecc_export_key
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
static psa_status_t ifx_cryptolite_transparent_ecc_export_key( psa_key_type_t type,
                                         cy_stc_cryptolite_ecc_key *key,
                                         uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint32_t bytesize;
    cy_stc_cryptolite_ecc_dp_type *dp;
    cy_stc_cryptolite_context_ecdsa_t key_ctx;
    cy_stc_cryptolite_ecc_buffer_t* key_buf_ptr = NULL;

    dp = Cy_Cryptolite_ECC_GetCurveParams(key->curveID);
    bytesize = VU_BITS_TO_BYTES(dp->size);

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        if( data_size < 2 * bytesize + 1)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        if( key->type == PK_PRIVATE )
        {
            #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
                static cy_stc_cryptolite_ecc_buffer_t key_buf;
                key_buf_ptr = &key_buf;
            #elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
                cy_stc_cryptolite_ecc_buffer_t key_buf;
                key_buf_ptr = &key_buf;
            #else
                key_buf_ptr = (cy_stc_cryptolite_ecc_buffer_t *)ifx_mxcryptolite_malloc(sizeof(cy_stc_cryptolite_ecc_buffer_t));
            #endif

            if(NULL != key_buf_ptr)
            {
                cy_status = Cy_Cryptolite_ECC_Init(CRYPTOLITE, &key_ctx, key_buf_ptr);

                if(CY_CRYPTOLITE_SUCCESS == cy_status)
                {
                    cy_status = Cy_Cryptolite_ECC_MakePublicKey(CRYPTOLITE, &key_ctx, key->curveID,  key->k,  key);
                }

                psa_status = ifx_cryptolite_status_to_psa_status(cy_status);
            }
            else
            {
                psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;      
            }
        }

        if(psa_status == PSA_SUCCESS)
        {
            *data_length =  2 * bytesize + 1;
            data[0] = 0x04;

            Cy_Cryptolite_Vu_memcpy(&data[1], key->pubkey.x, bytesize);
            Cy_Cryptolite_InvertEndianness(&data[1], bytesize);

            Cy_Cryptolite_Vu_memcpy(&data[1 + bytesize], key->pubkey.y, bytesize);
            Cy_Cryptolite_InvertEndianness(&data[1 + bytesize], bytesize);
        }

        #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)  && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        if(NULL != key_buf_ptr)
        {
            ifx_mxcryptolite_free(key_buf_ptr);
        }
        #endif

        return( psa_status );
    }
    else
    {
        if( data_size < bytesize)
        {
            return PSA_ERROR_BUFFER_TOO_SMALL;   
        }

        Cy_Cryptolite_Vu_memcpy( data, key->k, bytesize);
        Cy_Cryptolite_InvertEndianness(data, bytesize);

        *data_length = bytesize;

        return PSA_SUCCESS;
    }
}


/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_ecc_export_public_key
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
static psa_status_t ifx_cryptolite_transparent_ecc_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    cy_stc_cryptolite_ecc_key key;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    uint8_t *priv_ptr=NULL;
    uint8_t *pub_ptr=NULL;

#if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
    CY_ALIGN(4) static uint8_t ecc_priv_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
    CY_ALIGN(4) static uint8_t ecc_pub_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];

    priv_ptr = ecc_priv_key;
    pub_ptr = ecc_pub_key;
#elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
    CY_ALIGN(4)  uint8_t ecc_priv_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
    CY_ALIGN(4)  uint8_t ecc_pub_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];

    priv_ptr = ecc_priv_key;
    pub_ptr = ecc_pub_key;
#else
    priv_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE);
    pub_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE);
#endif

    if( (NULL != priv_ptr) && (NULL != pub_ptr) )
    {
        key.k = priv_ptr;
        key.pubkey.x = pub_ptr;

        psa_status = ifx_cryptolite_transparent_ecc_load_key(attributes, &key, key_buffer, key_buffer_size);

        if(PSA_SUCCESS == psa_status)
        {
            psa_status = ifx_cryptolite_transparent_ecc_export_key( PSA_KEY_TYPE_ECC_PUBLIC_KEY( PSA_KEY_TYPE_ECC_GET_FAMILY( key_type ) ),
                        &key, data, data_size, data_length );
        }
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)  && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)

    if(NULL != priv_ptr)
    {
        ifx_mxcryptolite_free(priv_ptr);
    }

    if(NULL != pub_ptr)
    {
        ifx_mxcryptolite_free(pub_ptr);
    }
    #endif

    return psa_status;
}

#endif /*IFX_PSA_CRYPTOLITE_ECC_PUBLIC_KEY_EXPORT*/


#if defined(IFX_PSA_CRYPTOLITE_RSA_PUBLIC_KEY_EXPORT)

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_rsa_export_public_key
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
static psa_status_t ifx_cryptolite_transparent_rsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    return mbedtls_psa_rsa_export_public_key(
                             attributes,
                             key_buffer, key_buffer_size,
                             data, data_size, data_length);
}
#endif

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_export_public_key
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
psa_status_t ifx_cryptolite_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length )
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    
    if(PSA_KEY_TYPE_ECC_GET_FAMILY(key_type) != PSA_ECC_FAMILY_SECP_R1)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

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

            Cy_Cryptolite_Vu_memcpy( data, key_buffer, key_buffer_size);
            Cy_Cryptolite_Vu_memset(data + key_buffer_size, 0, data_size - key_buffer_size);
            *data_length = key_buffer_size;

            return PSA_SUCCESS;
        }

        if( PSA_KEY_TYPE_IS_RSA( key_type ) )
        {
#if defined(IFX_PSA_CRYPTOLITE_RSA_PUBLIC_KEY_EXPORT)            
            return ifx_cryptolite_transparent_rsa_export_public_key( attributes, key_buffer, key_buffer_size,
                                                      data, data_size,data_length ) ;
#endif                                                      
        }
        else
        {
#if defined (IFX_PSA_CRYPTOLITE_ECC_PUBLIC_KEY_EXPORT)            
            return ifx_cryptolite_transparent_ecc_export_public_key( attributes, key_buffer, key_buffer_size,
                                                                  data, data_size, data_length ) ;
#endif                                                                  
        }
    }

    return( PSA_ERROR_NOT_SUPPORTED );
    
}

#endif  /* (CY_IP_MXCRYPTOLITE)  */
#endif /* defined(IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT)*/
