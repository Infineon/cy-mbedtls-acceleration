/***************************************************************************//**
* \file ifx_cryptolite_transparent_key_agreement.c
*
* \brief
*  PSA crypto transparent Key Agreement driver functions.
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
#include "ifx_cryptolite_transparent_key_agreement.h"
#if defined(IFX_PSA_CRYPTOLITE_ECDH)
#if defined (CY_IP_MXCRYPTOLITE)
#include "ifx_cryptolite_transparent_key_agreement.h"
#include "mbedtls/private_access.h"
#include "cy_cryptolite_utils.h"

psa_status_t mbedtls_to_psa_error( int ret );

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_key_agreement
****************************************************************************//**
*
* Function to ECDH based key agreement.
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
* \param alg
* The algorithm used for signing & hashing the message.
*
* \param peer_key
* The pointer to the peer public key.
*
* \param peer_key_length
* The size of the peer_key.
*
* \param shared_secret
* The pointer to store the generated shared secret.
*
* \param shared_secret_size
* The size of the shared_secret buffer.
*
* \param shared_secret_length
* The size of the calculated shared secret.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_cryptolite_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length )
{
    psa_key_type_t key_type;
    size_t key_bits;
    cy_stc_cryptolite_ecc_dp_type *dp;
    size_t bytesize;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    uint8_t *pubkey_ptr=NULL;
    uint8_t *pkey_ptr=NULL;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    cy_en_cryptolite_ecc_curve_id_t curveID;
    cy_stc_cryptolite_context_ecdsa_t ecdh_ctx;
    cy_stc_cryptolite_ecc_buffer_t* ecdsa_buf_ptr;
    cy_stc_cryptolite_ecc_key  key;
    (void)peer_key_length;

    if ( (NULL == attributes) || (NULL == key_buffer) ||  (NULL == peer_key) || ((NULL == shared_secret) && (shared_secret_size >0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == key_buffer_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);

    if( !PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) || !PSA_ALG_IS_ECDH(alg) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( PSA_KEY_TYPE_ECC_GET_FAMILY(key_type) != PSA_ECC_FAMILY_SECP_R1 )
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /*validate our private Key attributes
     Private keys are represented in uncompressed private random integer
     format, meaning their curve_bytes is equal to the amount of input.
    */
    if (key_bits != 0)
    {
        /* With an explicit bit-size, the data must have the matching length. */
        if (key_buffer_size != PSA_BITS_TO_BYTES(key_bits))
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else
    {
        /* We need to infer the bit-size from the data. Since the only
         * information we have is the length in bytes, the value of curve_bits
         * at this stage is rounded up to the nearest multiple of 8. */
        key_bits = PSA_BYTES_TO_BITS(key_buffer_size);
    }

    /*validate peer public Key attributes*/
    /* A Weierstrass public key is represented as:
     * - The byte 0x04;
     * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
     * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
     * So its data length is 2m+1 where m is the curve size in bits.
     */
    if ((peer_key_length & 1) == 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((size_t)(peer_key_length / 2) != PSA_BITS_TO_BYTES(key_bits))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    
    switch(key_bits)
    {
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)
    case 192:
        curveID = CY_CRYPTOLITE_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)
    case 224:
        curveID = CY_CRYPTOLITE_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)
    case 256:
        curveID = CY_CRYPTOLITE_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)
    case 384:
        curveID = CY_CRYPTOLITE_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521)
    case 521:
        curveID = CY_CRYPTOLITE_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Cryptolite_ECC_GetCurveParams(curveID);
    bytesize   = VU_BITS_TO_BYTES(dp->size);

    if(shared_secret_size < bytesize)
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
        CY_ALIGN(4) static uint8_t public_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        CY_ALIGN(4) static uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        static cy_stc_cryptolite_ecc_buffer_t ecdsa_buf;

        ecdsa_buf_ptr = &ecdsa_buf;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
    #elif defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        CY_ALIGN(4)  uint8_t public_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        CY_ALIGN(4)  uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        cy_stc_cryptolite_ecc_buffer_t ecdsa_buf;

        ecdsa_buf_ptr = &ecdsa_buf;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
    #else
        ecdsa_buf_ptr = (cy_stc_cryptolite_ecc_buffer_t *)ifx_mxcryptolite_malloc(sizeof(cy_stc_cryptolite_ecc_buffer_t));
        pubkey_ptr = (uint8_t *)(uint32_t *)ifx_mxcryptolite_malloc(2 * bytesize);
        pkey_ptr = (uint8_t *)(uint32_t *)ifx_mxcryptolite_malloc(bytesize);
    #endif

    if( (NULL != ecdsa_buf_ptr) && (NULL != pubkey_ptr) && (NULL != pkey_ptr) )
    {
        cy_status = Cy_Cryptolite_ECC_Init(CRYPTOLITE, &ecdh_ctx, ecdsa_buf_ptr);

        if(CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            Cy_Cryptolite_Setnumber(pubkey_ptr, (uint8_t *)++peer_key , 2 * bytesize); // peer_key[0] holds the uncompressed byte value
            key.type = PK_PUBLIC;
            key.pubkey.x = pubkey_ptr;
            key.pubkey.y = pubkey_ptr + bytesize;
            Cy_Cryptolite_InvertEndianness(key.pubkey.x, bytesize);
            Cy_Cryptolite_InvertEndianness(key.pubkey.y, bytesize);

            Cy_Cryptolite_Setnumber(pkey_ptr,(uint8_t *) key_buffer , bytesize);
            Cy_Cryptolite_InvertEndianness(pkey_ptr, bytesize);
            /* Validate public key first*/
            if( Cy_Cryptolite_ECC_CheckPublicKey(CRYPTOLITE, &ecdh_ctx, curveID, &key) != CY_CRYPTOLITE_SUCCESS)
            {
                psa_status = PSA_ERROR_INVALID_ARGUMENT;
                goto cleanup;
            }

            cy_status = Cy_Cryptolite_ECC_SharedSecret(CRYPTOLITE, &ecdh_ctx, curveID, pkey_ptr, &key, shared_secret);

            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {
                Cy_Cryptolite_InvertEndianness(shared_secret, bytesize);
                *shared_secret_length = bytesize;
            }
        }
        psa_status = ifx_cryptolite_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    cleanup:
    #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)  && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)

  
        if(NULL != ecdsa_buf_ptr)
        {
            ifx_mxcryptolite_free(ecdsa_buf_ptr);
        }
        
        if(NULL != pubkey_ptr)
        {
            ifx_mxcryptolite_free(pubkey_ptr);
        }
        
        if(NULL != pkey_ptr)
        {
            ifx_mxcryptolite_free(pkey_ptr);
        }
	#endif
    
    return psa_status;
}

#endif  /* (CY_IP_MXCRYPTOLITE)  */
#endif /* defined(IFX_PSA_CRYPTOLITE_ECDH)*/
