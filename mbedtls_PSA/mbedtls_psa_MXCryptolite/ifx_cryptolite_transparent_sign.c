/***************************************************************************//**
* \file ifx_cryptolite_transparent_sig.c
*
* \brief
*  PSA crypto transparent signature driver functions.
*
********************************************************************************
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

#include "ifx_cryptolite_transparent_sign.h"
#include "ifx_cryptolite_transparent_hash.h"

#if (defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN) || defined(IFX_PSA_CRYPTOLITE_RSA_SIGN))

#if defined (CY_IP_MXCRYPTOLITE)

#include "cy_cryptolite_utils.h"

#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
#include "mbedtls/asn1.h"
#endif

#if defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN)
static psa_status_t ifx_cryptolite_transparent_ecdsa_sign(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_size, size_t *signature_length);
#endif

#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
static psa_status_t ifx_cryptolite_transparent_rsa_sign(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_size, size_t *signature_length);
#endif


#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)

/*******************************************************************************
* Function Name: ifx_cryptolite_get_rsa_private_key
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
static psa_status_t ifx_cryptolite_get_rsa_private_key(unsigned char **p,
                         const unsigned char *end, cy_stc_cryptolite_rsa_pub_key_t *rsa_pub_key)
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

#if defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN)

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_ecdsa_sign
****************************************************************************//**
*
* Function to perform ECDSA Sign on the precalculated hash.
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
* \param hash
* The pointer to the hash.
*
* \param hash_length
* The size of the hash.
*
* \param signature
* The pointer to store the signature.
*
* \param signature_size
* The size of the signature buffer.
*
* \param signature_length
* The size of the calculated signature.
*
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_cryptolite_transparent_ecdsa_sign(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_size, size_t *signature_length)
{

    size_t key_bits = psa_get_key_bits(attributes);
    cy_stc_cryptolite_ecc_key  key;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    cy_stc_cryptolite_ecc_dp_type *dp;
    size_t bytesize;
    uint8_t *sig_ptr=NULL;
    uint8_t *pkey_ptr=NULL;
    uint8_t *msgkey_ptr=NULL;
    uint8_t *hash_ptr=NULL;

    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    cy_stc_cryptolite_context_ecdsa_t key_ctx;
    cy_stc_cryptolite_ecc_buffer_t* key_buf_ptr=NULL;

    if( !PSA_ALG_IS_ECDSA(alg) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ALG_ECDSA_IS_DETERMINISTIC(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if(key_buffer_size < PSA_BITS_TO_BYTES(key_bits))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch(key_bits)
    {
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)
    case 192:
        key.curveID = CY_CRYPTOLITE_ECC_ECP_SECP192R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)
    case 224:
        key.curveID = CY_CRYPTOLITE_ECC_ECP_SECP224R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)
    case 256:
        key.curveID = CY_CRYPTOLITE_ECC_ECP_SECP256R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)
    case 384:
        key.curveID = CY_CRYPTOLITE_ECC_ECP_SECP384R1;
        break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521)
    case 521:
        key.curveID = CY_CRYPTOLITE_ECC_ECP_SECP521R1;
        break;
    #endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    dp = Cy_Cryptolite_ECC_GetCurveParams(key.curveID);
    bytesize   = CY_CRYPTOLITE_BYTE_SIZE_OF_BITS(dp->size);

    if (signature_size <  2*bytesize)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
        CY_ALIGN(4) static uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        CY_ALIGN(4) static uint8_t signature_buf[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        CY_ALIGN(4) static uint8_t msg_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        CY_ALIGN(4) static uint8_t hash_buf[IFX_PSA_CRYPTOLITE_MAX_SHA_HASH_SIZE];
        static cy_stc_cryptolite_ecc_buffer_t key_buf;
        sig_ptr = signature_buf;
        pkey_ptr = private_key;
        msgkey_ptr = msg_key;
        hash_ptr = hash_buf;
        key_buf_ptr = &key_buf;
    #elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        CY_ALIGN(4) uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        CY_ALIGN(4) uint8_t signature_buf[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        CY_ALIGN(4) uint8_t msg_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        CY_ALIGN(4) uint8_t hash_buf[IFX_PSA_CRYPTOLITE_MAX_SHA_HASH_SIZE];
        cy_stc_cryptolite_ecc_buffer_t key_buf;
        sig_ptr = signature_buf;
        pkey_ptr = private_key;
        msgkey_ptr = msg_key;
        hash_ptr = hash_buf;
        key_buf_ptr = &key_buf;

    #else
        sig_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(2 * bytesize);
        pkey_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(bytesize);
        msgkey_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(bytesize);
        hash_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(IFX_PSA_CRYPTOLITE_MAX_SHA_HASH_SIZE);
        key_buf_ptr = (cy_stc_cryptolite_ecc_buffer_t *)ifx_mxcryptolite_malloc(sizeof(cy_stc_cryptolite_ecc_buffer_t));

    #endif


    if((NULL != sig_ptr) && (NULL != pkey_ptr) && (NULL != msgkey_ptr) && (NULL != hash_ptr) && (NULL != key_buf_ptr))
    {
        Cy_Cryptolite_Vu_memcpy(pkey_ptr, key_buffer, bytesize);
        Cy_Cryptolite_InvertEndianness(pkey_ptr, bytesize);

        Cy_Cryptolite_Vu_memcpy(hash_ptr, hash, hash_length);
        Cy_Cryptolite_InvertEndianness(hash_ptr, hash_length);

        key.type = PK_PRIVATE;
        key.k = pkey_ptr;

        cy_status = Cy_Cryptolite_ECC_Init(CRYPTOLITE, &key_ctx, key_buf_ptr);

        if(CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            cy_status = Cy_Cryptolite_ECC_MakePrivateKey(CRYPTOLITE, &key_ctx, key.curveID, (uint8_t *)msgkey_ptr, NULL, NULL);
        }

        if(CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            cy_status = Cy_Cryptolite_ECC_SignHash(CRYPTOLITE, &key_ctx, hash_ptr, hash_length, sig_ptr, &key, msgkey_ptr);
        }

        if(CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            Cy_Cryptolite_InvertEndianness(sig_ptr, bytesize);
            Cy_Cryptolite_InvertEndianness(sig_ptr + bytesize, bytesize);
            Cy_Cryptolite_Vu_memcpy(signature , sig_ptr,  2 * bytesize);
            *signature_length = 2 * bytesize;
        }

        psa_status = ifx_cryptolite_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)  && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)

    if(NULL != sig_ptr)
    {
        ifx_mxcryptolite_free(sig_ptr);
    }

    if(NULL != pkey_ptr)
    {
        ifx_mxcryptolite_free(pkey_ptr);
    }

    if(NULL != msgkey_ptr)
    {
        ifx_mxcryptolite_free(msgkey_ptr);
    }

    if(NULL != hash_ptr)
    {
        ifx_mxcryptolite_free(hash_ptr);
    }

    if(NULL != key_buf_ptr)
    {
        ifx_mxcryptolite_free(key_buf_ptr);
    }
    #endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    return PSA_SUCCESS;
}
#endif /*defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN)*/



#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_rsa_sign
****************************************************************************//**
*
* Function to generate rsa signature with precalculated hash.
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
* \param hash
* The pointer to the hash.
*
* \param hash_length
* The size of the hash.
*
* \param signature
* The pointer to buffer for storing the calculated signature.
*
* \param signature_length
* The size of the signature buffer.
*
* \param signature_length
* The pointer to store the size of the calculated signature.
*
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_cryptolite_transparent_rsa_sign(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, uint8_t *signature, size_t signature_size, size_t *signature_length)
{

    cy_stc_cryptolite_rsa_pub_key_t priv_key;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    unsigned char *p;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    uint8_t *sig_ptr = NULL;
    uint8_t *modulus_ptr = NULL;
    uint8_t *pub_ptr = NULL;
    cy_en_cryptolite_sha_mode_t hash_mode;
    uint32_t pubkey_mod_len;
    uint32_t pubkey_exp_len;
    uint8_t *barretCoef_ptr = NULL;
    uint8_t *inverseModulo_ptr = NULL;
    uint8_t *rBar_ptr = NULL;

    switch ( PSA_ALG_SIGN_GET_HASH(alg))
    {
    #if defined(IFX_PSA_CRYPTOLITE_SHA_1)
        case PSA_ALG_SHA_1:
            hash_mode = CY_CRYPTOLITE_MODE_SHA1;
            break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_SHA_224)
        case PSA_ALG_SHA_224:
            hash_mode = CY_CRYPTOLITE_MODE_SHA224;
            break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_SHA_256)
        case PSA_ALG_SHA_256:
            hash_mode = CY_CRYPTOLITE_MODE_SHA256;
            break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_SHA_384)
        case PSA_ALG_SHA_384:
            hash_mode = CY_CRYPTOLITE_MODE_SHA384;
            break;
    #endif
    #if defined(IFX_PSA_CRYPTOLITE_SHA_512)
        case PSA_ALG_SHA_512:
            hash_mode = CY_CRYPTOLITE_MODE_SHA512;
            break;
    #endif
         case PSA_ALG_NONE:
             hash_mode = CY_CRYPTOLITE_MODE_SHA_NONE;
             break;
        default:
        return PSA_ERROR_NOT_SUPPORTED;
        }


    Cy_Cryptolite_Vu_memset((void *)&priv_key, 0, sizeof(priv_key));
    p = (unsigned char *)key_buffer;

    if (PSA_KEY_TYPE_IS_KEY_PAIR(key_type))
    {
        psa_status = ifx_cryptolite_get_rsa_private_key(&p, p + key_buffer_size, &priv_key);
    }
    else
    {
        psa_status = PSA_ERROR_NOT_SUPPORTED;
    }

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    pubkey_mod_len = PSA_BITS_TO_BYTES(priv_key.moduloLength);
    pubkey_exp_len = PSA_BITS_TO_BYTES(priv_key.pubExpLength);

    psa_status = ifx_psa_rsa_keylen_supported(pubkey_mod_len);
    
    if(psa_status != PSA_SUCCESS)
    {
        return psa_status;
    }

    if(signature_size < pubkey_mod_len)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }


    #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
        CY_ALIGN(4) static uint8_t signature_buf[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t public_key[IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE];

        CY_ALIGN(4) static uint8_t barretCoef[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};
        CY_ALIGN(4) static uint8_t inverseModulo[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};
        CY_ALIGN(4) static uint8_t rBar[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};

        sig_ptr =  signature_buf;
        modulus_ptr = modulus;
        pub_ptr = public_key;
        barretCoef_ptr = barretCoef;
        inverseModulo_ptr = inverseModulo;
        rBar_ptr = rBar;
    #elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        CY_ALIGN(4) uint8_t signature_buf[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) uint8_t public_key[IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE];

        CY_ALIGN(4) uint8_t barretCoef[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};
        CY_ALIGN(4) uint8_t inverseModulo[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};
        CY_ALIGN(4) uint8_t rBar[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};

        sig_ptr =  signature_buf;
        modulus_ptr = modulus;
        pub_ptr = public_key;
        barretCoef_ptr = barretCoef;
        inverseModulo_ptr = inverseModulo;
        rBar_ptr = rBar;
    #else
        sig_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(pubkey_mod_len);
        modulus_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(pubkey_mod_len);
        pub_ptr = (uint8_t*)(uint32_t *)ifx_mxcryptolite_malloc(pubkey_exp_len);
        barretCoef_ptr = ifx_mxcryptolite_malloc(4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1));
        inverseModulo_ptr = ifx_mxcryptolite_malloc(4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1));
        rBar_ptr = ifx_mxcryptolite_malloc(4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1));
    #endif


        priv_key.barretCoefPtr = barretCoef_ptr;
        priv_key.inverseModuloPtr = inverseModulo_ptr;
        priv_key.rBarPtr  = rBar_ptr;


    if( (NULL != sig_ptr) && (NULL != modulus_ptr) && (NULL != pub_ptr) && (NULL != barretCoef_ptr) && (NULL != inverseModulo_ptr) && (NULL != rBar_ptr))
    {
        Cy_Cryptolite_Vu_memcpy(modulus_ptr, priv_key.moduloPtr, pubkey_mod_len);
        Cy_Cryptolite_InvertEndianness(modulus_ptr, pubkey_mod_len);
        priv_key.moduloPtr = modulus_ptr;

        Cy_Cryptolite_Vu_memcpy(pub_ptr, priv_key.pubExpPtr, pubkey_exp_len);
        Cy_Cryptolite_InvertEndianness(pub_ptr, pubkey_exp_len);
        priv_key.pubExpPtr = pub_ptr;

        static cy_stc_cryptolite_context_rsa_t rsa_ctx;
        static cy_stc_cryptolite_rsa_buffer_t rsa_buffer;

        cy_status = Cy_Cryptolite_Rsa_Init(CRYPTOLITE, &rsa_ctx, &rsa_buffer);

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            cy_status = Cy_Cryptolite_Rsa_Sign(CRYPTOLITE, hash_mode, hash, (uint32_t)hash_length, sig_ptr, pubkey_mod_len);
        }

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            Cy_Cryptolite_InvertEndianness(sig_ptr, pubkey_mod_len);
            cy_status = Cy_Cryptolite_Rsa_Proc(CRYPTOLITE, &rsa_ctx, &priv_key, sig_ptr, pubkey_mod_len, signature);
        }

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            Cy_Cryptolite_InvertEndianness(signature, pubkey_mod_len);
            *signature_length = pubkey_mod_len;
        }

        psa_status = ifx_cryptolite_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)  && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)

    if(NULL != sig_ptr)
    {
        ifx_mxcryptolite_free(sig_ptr);
    }

    if(NULL != modulus_ptr)
    {
        ifx_mxcryptolite_free(modulus_ptr);
    }

    if(NULL != pub_ptr)
    {
        ifx_mxcryptolite_free(pub_ptr);
    }

    if(NULL != barretCoef_ptr)
    {
        ifx_mxcryptolite_free(barretCoef_ptr);
    }

    if(NULL != inverseModulo_ptr)
    {
        ifx_mxcryptolite_free(inverseModulo_ptr);
    }

    if(NULL != rBar_ptr)
    {
        ifx_mxcryptolite_free(rBar_ptr);
    }
    #endif

    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    return PSA_SUCCESS;

}
#endif /*defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)*/

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_sign_message
****************************************************************************//**
*
* Function to calculate the signature by hashing the message.
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
* \param input
* The pointer to the input message.
*
* \param input_length
* The size of the input message.
*
* \param signature
* The pointer to buffer for storing the calculated signature.
*
* \param signature_length
* The size of the signature buffer.
*
* \param signature_length
* The pointer to store the size of the calculated signature.
*
* \return psa_status_t.
*
*******************************************************************************/
#if defined(IFX_PSA_CRYPTOLITE_SHA) && (defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN) || defined(IFX_PSA_CRYPTOLITE_RSA_SIGN))
psa_status_t ifx_cryptolite_transparent_sign_message(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    uint8_t hash[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    size_t hash_size = sizeof(hash);
    size_t hash_length;
    psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
    psa_key_type_t key_type;

    if ( (NULL == attributes) || (NULL == key_buffer) ||  ((NULL == input) && (input_length > 0)) || (NULL == signature)  || (NULL == signature_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if(0 == key_buffer_size  || 0 == signature_size)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);

#if defined(IFX_PSA_CRYPTOLITE_SHA)
    if((PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg )) || (PSA_KEY_TYPE_IS_ECC( key_type) && !PSA_ALG_ECDSA_IS_DETERMINISTIC( alg )))
    {
        psa_status = ifx_cryptolite_transparent_hash_compute(PSA_ALG_SIGN_GET_HASH( alg ), input, input_length, hash, hash_size, &hash_length);
    }
#endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if( PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ))
    {
#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
        return ifx_cryptolite_transparent_rsa_sign(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_size, signature_length);
#endif
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type ) )
    {
#if defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN)
        return  ifx_cryptolite_transparent_ecdsa_sign(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_size, signature_length);
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

 /*******************************************************************************
* Function Name: ifx_cryptolite_transparent_sign_hash
****************************************************************************//**
*
* Function to calculate the signature with already calculated hash.
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
* The pointer to buffer for storing the calculated signature.
*
* \param signature_length
* The size of the signature buffer.
*
* \param signature_length
* The pointer to store the size of the calculated signature.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_cryptolite_transparent_sign_hash(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,  uint8_t *signature, size_t signature_size, size_t *signature_length )
{

     psa_key_type_t key_type;

    if((NULL == attributes) || (NULL == key_buffer) || ((NULL == hash) && (hash_length > 0))  || (NULL == signature) || (NULL == signature_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((0 == key_buffer_size) || (0 == signature_size))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);

    if( PSA_KEY_TYPE_IS_RSA( key_type ) && PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
        return  ifx_cryptolite_transparent_rsa_sign(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_size, signature_length);
#endif
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type ))
    {
#if defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN)
        return  ifx_cryptolite_transparent_ecdsa_sign(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_size, signature_length);
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}
#endif

#endif  /* (CY_IP_MXCRYPTOLITE)*/
#endif /*#if (defined(IFX_PSA_CRYPTOLITE_ECDSA_SIGN) || defined(IFX_PSA_CRYPTOLITE_RSA))*/
