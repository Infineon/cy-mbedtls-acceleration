/***************************************************************************//**
* \file ifx_mxcrypto_transparent_signature_verify.c
*
* \brief
*  PSA crypto transparent signature verify driver functions.
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

#include "ifx_mxcrypto_transparent_signature_verify.h"
#if (defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY) || defined(IFX_PSA_MXCRYPTO_RSA_VERIFY))

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#include "ifx_mxcrypto_transparent_hash.h"


#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)
static psa_status_t ifx_mxcrypto_transparent_ecdsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length);
#endif

#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
static psa_status_t ifx_mxcrypto_transparent_rsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length);
#endif

#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_ecdsa_verify
****************************************************************************//**
*
* Function to verify the ecdsa signature with precalculated hash.
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
* The algorithm used for signing & hashing the message.
*
* \param hash
* The pointer to the hash.
*
* \param hash_length
* The size of the hash.
*
* \param signature
* The pointer to the buffer containing the signature.
*
* \param signature_length
* The size of the signature.
*
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_ecdsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)
{

    (void)alg;

    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits = psa_get_key_bits(attributes);
    cy_stc_crypto_ecc_key  key;
    uint8_t stat = 0;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    cy_stc_crypto_ecc_dp_type *dp;
    size_t bytesize;
    uint8_t *sig_ptr=NULL;
    uint8_t *pubkey_ptr=NULL;
    uint8_t *pkey_ptr=NULL;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;


    if(key_buffer_size < PSA_BITS_TO_BYTES(key_bits))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ( !PSA_ALG_IS_ECDSA( alg ) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0 == signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (PSA_ECDSA_SIGNATURE_SIZE(key_bits) != signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    switch(key_bits)
    {
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)
    case 192:
        key.curveID = CY_CRYPTO_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)
    case 224:
        key.curveID = CY_CRYPTO_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)
    case 256:
        key.curveID = CY_CRYPTO_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)
    case 384:
        key.curveID = CY_CRYPTO_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521)
    case 521:
        key.curveID = CY_CRYPTO_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Crypto_Core_ECC_GetCurveParams(key.curveID);
    bytesize   = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    #if defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    CY_ALIGN(32) static uint8_t public_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE + 1)];
    CY_ALIGN(32) static uint8_t private_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE)];
    CY_ALIGN(32) static uint8_t signature_buf[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE)];
#else
        CY_ALIGN(4) static uint8_t public_key[IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE + 1];
        CY_ALIGN(4) static uint8_t private_key[IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE];
        CY_ALIGN(4) static uint8_t signature_buf[IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE];
#endif
        sig_ptr = signature_buf;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
    #elif defined (IFX_PSA_MXCRYPTO_USE_STACK_MEM)
    CY_ALIGN(4) uint8_t public_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE + 1)+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t private_key[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PRIV_KEY_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t signature_buf[CY_CRYPTO_ALIGN_CACHE_LINE(IFX_MXCRYPTO_ECC_MAX_PUB_KEY_SIZE)+CY_CRYPTO_DCAHCE_PADDING_SIZE];

    sig_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)signature_buf);
    pubkey_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)public_key);
    pkey_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)private_key);
    #else
    uint32_t *ecc_sig_ptr = (uint32_t *)ifx_mxcrypto_malloc((2*CY_CRYPTO_ALIGN_CACHE_LINE(bytesize))+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    uint32_t *ecc_pkey_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    uint32_t *ecc_pubkey_ptr = (uint32_t *)ifx_mxcrypto_malloc((2*CY_CRYPTO_ALIGN_CACHE_LINE(bytesize)+1)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    if( (NULL == ecc_sig_ptr) || (NULL == ecc_pkey_ptr) || (NULL == ecc_pubkey_ptr))
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    sig_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_sig_ptr);
    pkey_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_pkey_ptr);
    pubkey_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ecc_pubkey_ptr);
    #endif

    if( (NULL != sig_ptr) && (NULL != pubkey_ptr) && (NULL != pkey_ptr) )
    {
        ifx_mxcrypto_memcpy(sig_ptr, signature, 2 * bytesize);
        Cy_Crypto_InvertEndianness(sig_ptr, bytesize);
        Cy_Crypto_InvertEndianness(sig_ptr + bytesize, bytesize);

        if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type))
        {
#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY_USE_PK)
            ifx_mxcrypto_memcpy(pkey_ptr, key_buffer, bytesize);
            Cy_Crypto_Core_InvertEndianness(pkey_ptr, bytesize);

            key.type = PK_PRIVATE;
            key.k = pkey_ptr;
            key.pubkey.x = pubkey_ptr;
            key.pubkey.y = pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize);

            cy_status = Cy_Crypto_Core_ECC_MakePublicKey(CRYPTO, key.curveID, key.k, &key);
#else
            cy_status = CY_CRYPTO_NOT_SUPPORTED;
#endif /* IFX_PSA_MXCRYPTO_ECDSA_VERIFY_USE_PK */
        }
        else
        {
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
            ifx_mxcrypto_memcpy(pubkey_ptr, &key_buffer[1], bytesize);
            ifx_mxcrypto_memcpy(pubkey_ptr+CY_CRYPTO_ALIGN_CACHE_LINE(bytesize), &key_buffer[1+bytesize], bytesize);
#else
            ifx_mxcrypto_memcpy(pubkey_ptr, &key_buffer[1], (2 * bytesize));
#endif
            key.type = PK_PUBLIC;
            key.pubkey.x = pubkey_ptr;
            key.pubkey.y = pubkey_ptr + CY_CRYPTO_ALIGN_CACHE_LINE(bytesize);

            Cy_Crypto_InvertEndianness(key.pubkey.x, bytesize);
            Cy_Crypto_InvertEndianness(key.pubkey.y, bytesize);

            cy_status = CY_CRYPTO_SUCCESS;
        }

        if(CY_CRYPTO_SUCCESS == cy_status)
        {
            cy_status = Cy_Crypto_Core_ECC_VerifyHash(CRYPTO, sig_ptr, hash, (uint32_t)hash_length, &stat, &key);
        }

        psa_status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_MXCRYPTO_USE_STACK_MEM)
cleanup:
    if(NULL != ecc_sig_ptr)
    {
        ifx_mxcrypto_free(ecc_sig_ptr);
    }

    if(NULL != ecc_pubkey_ptr)
    {
        ifx_mxcrypto_free(ecc_pubkey_ptr);
    }

    if(NULL != ecc_pkey_ptr)
    {
        ifx_mxcrypto_free(ecc_pkey_ptr);
    }

    #endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if(SIG_VALID != stat)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}
#endif /*defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)*/

#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_rsa_verify
****************************************************************************//**
*
* Function to verify the rsa signature with precalculated hash.
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
* The algorithm used for signing & hashing the message.
*
* \param hash
* The pointer to the hash.
*
* \param hash_length
* The size of the hash.
*
* \param signature
* The pointer to the buffer containing the signature.
*
* \param signature_length
* The size of the signature.
*
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_transparent_rsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)
{

    cy_en_crypto_rsa_ver_result_t verResult = CY_CRYPTO_RSA_VERIFY_FAIL;
    cy_stc_crypto_rsa_pub_key_t pub_key;
    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    unsigned char *p;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    uint8_t *sig_ptr = NULL;
    uint8_t *dec_sig_ptr = NULL;
    uint8_t *modulus_ptr = NULL;
    uint8_t *pub_ptr = NULL;
    cy_en_crypto_sha_mode_t hash_mode;
    uint32_t pubkey_mod_len;
    uint32_t pubkey_exp_len;

    if ( (PSA_ALG_SIGN_GET_HASH(alg) != 0) && (hash_length != PSA_HASH_LENGTH(alg)) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0 == signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    switch ( PSA_ALG_SIGN_GET_HASH(alg))
    {
    #if defined(IFX_PSA_MXCRYPTO_SHA_1)
        case PSA_ALG_SHA_1:
            hash_mode = CY_CRYPTO_MODE_SHA1;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_224)
        case PSA_ALG_SHA_224:
            hash_mode = CY_CRYPTO_MODE_SHA224;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_256)
        case PSA_ALG_SHA_256:
            hash_mode = CY_CRYPTO_MODE_SHA256;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_384)
        case PSA_ALG_SHA_384:
            hash_mode = CY_CRYPTO_MODE_SHA384;
            break;
    #endif
    #if defined(IFX_PSA_MXCRYPTO_SHA_512)
        case PSA_ALG_SHA_512:
            hash_mode = CY_CRYPTO_MODE_SHA512;
            break;
    #endif
         case PSA_ALG_NONE:
             hash_mode = CY_CRYPTO_MODE_SHA_NONE;
             break;
        default:
        return PSA_ERROR_NOT_SUPPORTED;
        }

    ifx_mxcrypto_memset((void *)&pub_key, 0, sizeof(pub_key));
    p = (unsigned char *)key_buffer;

    psa_status = ifx_mxcrypto_get_rsa_public_key(key_type, &p, p + key_buffer_size, &pub_key);

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;

    }

    if((Cy_Crypto_Core_GetVuMemorySize(CRYPTO) <= 4096u) && (pub_key.moduloLength > 2048u))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    pubkey_mod_len = PSA_BITS_TO_BYTES(pub_key.moduloLength);
    pubkey_exp_len = PSA_BITS_TO_BYTES(pub_key.pubExpLength);

    if(pubkey_mod_len != signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    #if defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    CY_ALIGN(32) static uint8_t signature_buf[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
    CY_ALIGN(32) static uint8_t modulus[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
    CY_ALIGN(32) static uint8_t public_key[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_PUB_EXP_SIZE))];
    CY_ALIGN(32) static uint8_t dec_signature[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
#else
        CY_ALIGN(4) static uint8_t signature_buf[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t public_key[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_PUB_EXP_SIZE)];
        CY_ALIGN(4) static uint8_t dec_signature[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
#endif
        sig_ptr =  signature_buf;
        modulus_ptr = modulus;
        pub_ptr = public_key;
        dec_sig_ptr = dec_signature;
    #elif defined (IFX_PSA_MXCRYPTO_USE_STACK_MEM)
    CY_ALIGN(4) uint8_t signature_buf[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t modulus[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t public_key[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_PUB_EXP_SIZE))+CY_CRYPTO_DCAHCE_PADDING_SIZE];
    CY_ALIGN(4) uint8_t dec_signature[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))+CY_CRYPTO_DCAHCE_PADDING_SIZE];

    sig_ptr =  (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)signature_buf);
    modulus_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)modulus);
    pub_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)public_key);
    dec_sig_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)dec_signature);
    #else
    uint32_t *rsa_sig_ptr = NULL;
    uint32_t *rsa_modulus_ptr = NULL;
    uint32_t *rsa_pub_ptr = NULL;
    uint32_t *rsa_dec_sig_ptr = NULL;
    rsa_sig_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(signature_length)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    rsa_modulus_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(pubkey_mod_len)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    rsa_pub_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(pubkey_exp_len)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    rsa_dec_sig_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(signature_length)+CY_CRYPTO_DCAHCE_PADDING_SIZE);
    if( (NULL == rsa_sig_ptr) || (NULL == rsa_modulus_ptr) || (NULL == rsa_pub_ptr) || (NULL == rsa_dec_sig_ptr))
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto cleanup;
    }
    sig_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)rsa_sig_ptr);
    modulus_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)rsa_modulus_ptr);
    pub_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)rsa_pub_ptr);
    dec_sig_ptr = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)rsa_dec_sig_ptr);
    #endif

    if( (NULL != sig_ptr) && (NULL != modulus_ptr) && (NULL != pub_ptr) && (NULL != dec_sig_ptr) )
    {
        ifx_mxcrypto_memcpy(sig_ptr, signature, signature_length);
        Cy_Crypto_InvertEndianness(sig_ptr, signature_length);

        ifx_mxcrypto_memcpy(modulus_ptr, pub_key.moduloPtr, pubkey_mod_len);
        Cy_Crypto_InvertEndianness(modulus_ptr, pubkey_mod_len);
        pub_key.moduloPtr = modulus_ptr;

        ifx_mxcrypto_memcpy(pub_ptr, pub_key.pubExpPtr, pubkey_exp_len);
        Cy_Crypto_InvertEndianness(pub_ptr, pubkey_exp_len);
        pub_key.pubExpPtr = pub_ptr;

        cy_status = Cy_Crypto_Core_Rsa_Proc(CRYPTO, &pub_key, sig_ptr, signature_length, dec_sig_ptr);

        if (CY_CRYPTO_SUCCESS == cy_status)
        {

            Cy_Crypto_InvertEndianness(dec_sig_ptr, signature_length);
            cy_status = Cy_Crypto_Core_Rsa_Verify_Ext(CRYPTO, &verResult, hash_mode, hash, (uint32_t)hash_length, dec_sig_ptr, signature_length);

        }

        psa_status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    else
    {

        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;

    }

    #if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_MXCRYPTO_USE_STACK_MEM)
cleanup:
    if(NULL != rsa_sig_ptr)
    {
        ifx_mxcrypto_free(rsa_sig_ptr);
    }

    if(NULL != rsa_modulus_ptr)
    {
        ifx_mxcrypto_free(rsa_modulus_ptr);
    }

    if(NULL != rsa_pub_ptr)
    {
        ifx_mxcrypto_free(rsa_pub_ptr);
    }

    if(NULL != rsa_dec_sig_ptr)
    {
        ifx_mxcrypto_free(rsa_dec_sig_ptr);
    }

    #endif

    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if(CY_CRYPTO_RSA_VERIFY_SUCCESS  != verResult)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;

}
#endif /*defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)*/

/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_verify_message
****************************************************************************//**
*
* Function to calculate the hash of the message and verify the signature.
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
* The algorithm used for signing & hashing the message.
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param signature
* The pointer to the buffer containing the signature.
*
* \param signature_length
* The size of the signature.
*
* \return psa_status_t.
*
*******************************************************************************/
#if defined(IFX_PSA_MXCRYPTO_SHA) && (defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY) || defined(IFX_PSA_MXCRYPTO_RSA_VERIFY))
psa_status_t ifx_mxcrypto_transparent_verify_message(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length)
{
    uint8_t hash_t[CY_CRYPTO_ALIGN_CACHE_LINE(CY_CRYPTO_SHA512_DIGEST_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    uint8_t *hash = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)hash_t);
    size_t hash_size = CY_CRYPTO_SHA512_DIGEST_SIZE;
    size_t hash_length;
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    psa_key_type_t key_type;

    if ( (NULL == attributes) || (NULL == key_buffer) ||  ((NULL == input) && (input_length > 0)) || ((NULL == signature) && (signature_length >0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == key_buffer_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);

#if defined(IFX_PSA_MXCRYPTO_SHA)
    if((PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg )) || PSA_KEY_TYPE_IS_ECC( key_type) )
    {
        psa_status = ifx_mxcrypto_transparent_hash_compute(PSA_ALG_SIGN_GET_HASH( alg ), input, input_length, hash, hash_size, &hash_length);
    }
#endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;

    }

    if( PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ))
    {
#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
        return ifx_mxcrypto_transparent_rsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature,signature_length);
#endif
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type))
    {
#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)
        return  ifx_mxcrypto_transparent_ecdsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature,signature_length);
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

 /*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_verify_hash
****************************************************************************//**
*
* Function to verify the signature with already calculated hash.
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
* The algorithm was used for signing the hash.
*
* \param hash
* The pointer to the hash.
*
* \param hash_length
* The size of the hash.
*
* \param signature
* The pointer to the buffer containing the signature.
*
* \param signature_length
* The size of the signature.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_verify_hash(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,  const uint8_t *signature, size_t signature_length)
{

    psa_key_type_t key_type;
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    uint8_t *aligned_hash = (uint8_t *)hash;

    if((NULL == attributes) || (NULL == key_buffer) || ((NULL == hash) && (hash_length > 0))  || ((NULL == signature) && (signature_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((0 == key_buffer_size) || (0 == hash_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (0 == signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    key_type = psa_get_key_type(attributes);

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *hash_ptr = NULL;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)hash, hash_length))
    {
        hash_ptr = (uint8_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(hash_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == hash_ptr)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        aligned_hash = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)hash_ptr);
        ifx_mxcrypto_memcpy(aligned_hash, hash, hash_length);
    }
#endif
    if( PSA_KEY_TYPE_IS_RSA( key_type ) && PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY)
        psa_status = ifx_mxcrypto_transparent_rsa_verify(attributes, key_buffer, key_buffer_size, alg, aligned_hash, hash_length, signature,signature_length);
#endif
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type ))
    {
#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)
        psa_status = ifx_mxcrypto_transparent_ecdsa_verify(attributes, key_buffer, key_buffer_size, alg, aligned_hash, hash_length, signature,signature_length);
#endif
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if (NULL != hash_ptr)
    {
        ifx_mxcrypto_free(hash_ptr);
    }
#endif
    return psa_status;
}
#endif

#endif  /* (CY_IP_MXCRYPTO) */
#endif /*#if (defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY) || defined(IFX_PSA_MXCRYPTO_RSA))*/
