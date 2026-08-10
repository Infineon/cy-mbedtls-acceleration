/***************************************************************************//**
* \file ifx_mxcrypto_common.c
*
* \brief
*  PSA crypto mxcrypto helper functions.
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



#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "ifx_mxcrypto_common.h"

#if (defined(IFX_PSA_MXCRYPTO_RSA_SIGN) || defined(IFX_PSA_MXCRYPTO_RSA_VERIFY))
#include "mbedtls/asn1.h"
#endif

/*******************************************************************************
* Function Name: ifx_mxcrypto_status_to_psa_status
****************************************************************************//**
*
* Function to convert the mxcrypto status code to PSA status code.
*
* \param mxcrypto_status
*  The status code of the mxcrypto pdl driver.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t  ifx_mxcrypto_status_to_psa_status (cy_en_crypto_status_t mxcrypto_status)
{
    
    switch (mxcrypto_status)
    {
    case CY_CRYPTO_SUCCESS:
        return PSA_SUCCESS;
    case CY_CRYPTO_NOT_SUPPORTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case CY_CRYPTO_SIZE_NOT_X16:
        return PSA_ERROR_INVALID_PADDING;
    case CY_CRYPTO_SERVER_BUSY:
    case CY_CRYPTO_HW_ERROR:
        return PSA_ERROR_HARDWARE_FAILURE;
    case CY_CRYPTO_BAD_PARAMS:
        return PSA_ERROR_INVALID_ARGUMENT;
    case CY_CRYPTO_MEMORY_ALLOC_FAIL:
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    default:
        return PSA_ERROR_GENERIC_ERROR;
    }
}



#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_mxcrypto_get_rsa_public_key
****************************************************************************//**
*
* Function to retrive the rsa public key component n and e from the asn1 der encoded rsa key.
*
* \param key_type
*  the encoded key type.
*
* \param p
*  Pointer to the rsa key buffer in asn1 format.
*
* \param end
* The pointer to the end of the rsa key buffer.
*
* \param rsa_pub_key
* The pointer to the cy_stc_crypto_rsa_pub_key_t.
* 
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_get_rsa_public_key(psa_key_type_t key_type, unsigned char **p, 
                         const unsigned char *end, cy_stc_crypto_rsa_pub_key_t *rsa_pub_key)
{

    size_t len;

    if( 0 !=  mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    
    if( *p + len != end )
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    if(PSA_KEY_TYPE_IS_KEY_PAIR(key_type))
    {

        /* Skip the revision */
        if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
        {
            return PSA_ERROR_GENERIC_ERROR;
        }

        *p += len;

    }

    /* Import N */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    rsa_pub_key->moduloPtr = *p;
    rsa_pub_key->moduloLength = len * 8;

    // Remove the positive integer encoded value
    if(*rsa_pub_key->moduloPtr == 0) 
    {
        ++(rsa_pub_key->moduloPtr);
        rsa_pub_key->moduloLength = (len -1) * 8;
    }

    *p += len;

    /* Import E */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
        
    rsa_pub_key->pubExpPtr= *p;
    rsa_pub_key->pubExpLength = len*8;

    return PSA_SUCCESS;
}
#endif


#if defined(IFX_PSA_MXCRYPTO_RSA_SIGN)

/*******************************************************************************
* Function Name: ifx_mxcrypto_get_rsa_private_key
****************************************************************************//**
*
* Function to retrive the rsa public key component n and e from the asn1 der encoded rsa key.
*
* \param p
*  Pointer to the rsa key buffer in asn1 format.
*
* \param end
* The pointer to the end of the rsa key buffer.
*
* \param rsa_pub_key
* The pointer to the cy_stc_crypto_rsa_pub_key_t.
* 
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_get_rsa_private_key(unsigned char **p, 
                         const unsigned char *end, cy_stc_crypto_rsa_pub_key_t *rsa_pub_key)
{

    size_t len;

    if( 0 !=  mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    
    if( *p + len != end )
    {
        return PSA_ERROR_GENERIC_ERROR;
    }


    /* Skip the revision */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *p += len;


    /* Import N */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    rsa_pub_key->moduloPtr = *p;
    rsa_pub_key->moduloLength = len * 8;

    // Remove the positive integer encoded value
    if(*rsa_pub_key->moduloPtr == 0) 
    {
        ++(rsa_pub_key->moduloPtr);
        rsa_pub_key->moduloLength = (len -1) * 8;
    }

    *p += len;

    /* Import E */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *p += len;

    /* Import D */
    if( 0 != mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
        
    rsa_pub_key->pubExpPtr= *p;
    rsa_pub_key->pubExpLength = len*8;

    // Remove the positive integer encoded value
    if(*rsa_pub_key->pubExpPtr == 0)
    {
        ++(rsa_pub_key->pubExpPtr);
        rsa_pub_key->pubExpLength = (len -1) * 8;
    }

    return PSA_SUCCESS;
}
#endif

#endif /* CY_IP_MXCRYPTO */
