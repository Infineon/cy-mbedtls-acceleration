/***************************************************************************//**
* \file ifx_mxcrypto_transparent_key_agreement.c
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

#include "ifx_mxcrypto_transparent_key_agreement.h"
#if defined(IFX_PSA_MXCRYPTO_ECDH)
#if defined (CY_IP_MXCRYPTO)
#include "mbedtls/ecp.h"
#include "mbedtls/private_access.h"


/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_key_agreement
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
psa_status_t ifx_mxcrypto_transparent_key_agreement(
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
    cy_stc_crypto_ecc_dp_type *dp;
    size_t bytesize;
    cy_en_crypto_ecc_curve_id_t curveID;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    uint8_t *shared_y=NULL;
    uint8_t *pubkey_ptr=NULL;
    uint8_t *pkey_ptr=NULL;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    uint8_t* aligned_shared = shared_secret;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_shared = NULL;
#endif

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
    case 528:
        curveID = CY_CRYPTO_ECC_ECP_SECP521R1;
        break;

    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Crypto_Core_ECC_GetCurveParams(curveID);
    bytesize   = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    if(shared_secret_size < bytesize)
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    CY_ALIGN(32) static uint8_t ecpQY1[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_SIZE)];
    CY_ALIGN(32) static uint8_t public_key[2*CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_BYTE_SIZE)];
    CY_ALIGN(32) static uint8_t private_key[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_BYTE_SIZE)];
#else
        CY_ALIGN(4) static uint8_t ecpQY1[CY_CRYPTO_ECC_MAX_SIZE];
        CY_ALIGN(4) static uint8_t public_key[CY_CRYPTO_ECC_MAX_BYTE_SIZE*2];
        CY_ALIGN(4) static uint8_t private_key[CY_CRYPTO_ECC_MAX_BYTE_SIZE];
#endif

        shared_y = ecpQY1;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
    #elif defined (IFX_PSA_MXCRYPTO_USE_STACK_MEM)
    CY_ALIGN(4) uint8_t ecpQY1[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t public_key[2*CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_BYTE_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t private_key[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_ECC_MAX_BYTE_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];


    shared_y = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecpQY1);
    pubkey_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)public_key);
    pkey_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)private_key);
    #else
    uint8_t *ptr_shared_y = NULL;
    uint8_t *ptr_pubkey_ptr = NULL;
    uint8_t *ptr_pkey_ptr = NULL;
    ptr_shared_y = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
    ptr_pubkey_ptr = (uint8_t *)ifx_mxcrypto_malloc((2*CY_CRYPTO_ALIGN_CACHE_LINE(bytesize)) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
    ptr_pkey_ptr = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
    if((ptr_shared_y == NULL) || (ptr_pubkey_ptr == NULL) || (ptr_pkey_ptr == NULL))
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    shared_y = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_shared_y);
    pubkey_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_pubkey_ptr);
    pkey_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_pkey_ptr);
    #endif

    if( (NULL != shared_y) && (NULL != pubkey_ptr) && (NULL != pkey_ptr) )
    {
        cy_stc_crypto_ecc_key pubKey;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)shared_secret, bytesize) )
        {
            ptr_shared = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            if (NULL == ptr_shared)
            {
                psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
                goto cleanup;
            }
            aligned_shared = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_shared);
        }
        ifx_mxcrypto_memcpy( pubkey_ptr, ++peer_key, bytesize);
        ifx_mxcrypto_memcpy( pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize), peer_key + bytesize, bytesize);
#else
        ifx_mxcrypto_memcpy( pubkey_ptr, ++peer_key, bytesize * 2);
#endif
        Cy_Crypto_Core_InvertEndianness(pubkey_ptr, bytesize);
        Cy_Crypto_Core_InvertEndianness(pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize), bytesize);

        /* Validate peer public key */
        pubKey.curveID = curveID;
        pubKey.pubkey.x = pubkey_ptr;
        pubKey.pubkey.y = pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize);
        pubKey.k = NULL;
        if( Cy_Crypto_Core_ECC_CheckPublicKey(CRYPTO,  curveID, &pubKey) != CY_CRYPTO_SUCCESS)
        {
            psa_status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        ifx_mxcrypto_memcpy( pkey_ptr, key_buffer, bytesize);
        Cy_Crypto_Core_InvertEndianness(pkey_ptr, bytesize);

        cy_status = Cy_Crypto_Core_EC_NistP_PointMultiplication (CRYPTO,  curveID,  pubkey_ptr,
                                                                pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize), (uint8_t *)pkey_ptr, aligned_shared, shared_y);

        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            Cy_Crypto_Core_InvertEndianness(aligned_shared, bytesize);
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
            if(ptr_shared != NULL)
            {
                ifx_mxcrypto_memcpy((void *)shared_secret, (void *)aligned_shared, bytesize);
            }
#endif
            *shared_secret_length = bytesize;
        }

        psa_status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

cleanup:
    #if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_MXCRYPTO_USE_STACK_MEM)
    if(NULL != ptr_shared_y)
        {
        ifx_mxcrypto_free(ptr_shared_y);
        }

    if(NULL != ptr_pubkey_ptr)
        {
        ifx_mxcrypto_free(ptr_pubkey_ptr);
        }

    if(NULL != ptr_pkey_ptr)
        {
        ifx_mxcrypto_free(ptr_pkey_ptr);
        }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if(NULL != ptr_shared)
    {
        ifx_mxcrypto_free(ptr_shared);
    }
#endif
    #endif

    return psa_status;
}

#endif  /* (CY_IP_MXCRYPTO)*/
#endif /* defined(IFX_PSA_MXCRYPTO_ECDH)*/