/***************************************************************************//**
* \file ifx_cryptolite_transparent_signature_verify.c
*
* \brief
*  PSA crypto transparent Signature verify driver functions.
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

#include "ifx_cryptolite_transparent_signature_verify.h"

#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY) || defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)

#if defined (CY_IP_MXCRYPTOLITE)

#include "ifx_cryptolite_common.h"
#include "ifx_cryptolite_transparent_hash.h"
#include "cy_cryptolite_utils.h"


#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)
static psa_status_t ifx_cryptolite_transparent_ecdsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length);
#endif

#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)
#include "mbedtls/asn1.h"
static psa_status_t ifx_cryptolite_get_rsa_public_key( bool is_private, unsigned char **p, const unsigned char *end, cy_stc_cryptolite_rsa_pub_key_t *rsa_pub_key);
#endif


#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_ecdsa_verify
****************************************************************************//**
*
* Function to verify the ecdsa signature with precalculated hash.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for verify operation
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
* The pointer to the buffer containing the signature.
*
* \param signature_length
* The size of the signature.
*
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_cryptolite_transparent_ecdsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_ecc_family_t curve_type = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
    size_t key_bits = psa_get_key_bits(attributes);
    cy_stc_cryptolite_context_ecdsa_t sig_ctx;
    cy_stc_cryptolite_ecc_buffer_t* ecdsa_buf_ptr;
    cy_stc_cryptolite_ecc_key  key;
    cy_en_cryptolite_sig_verify_result_t ver_result = CY_CRYPTOLITE_SIG_INVALID;
    size_t bytesize;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    uint8_t *sig_ptr=NULL;
    uint8_t *pubkey_ptr=NULL;
    uint8_t *hash_ptr=NULL;
    uint8_t *pkey_ptr=NULL;

    psa_status_t psa_status = PSA_ERROR_BAD_STATE;

    if(PSA_ECC_FAMILY_SECP_R1 != curve_type)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if(key_buffer_size < PSA_BITS_TO_BYTES(key_bits))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ( !PSA_ALG_IS_ECDSA( alg ) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_ECDSA_SIGNATURE_SIZE(key_bits) != signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
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

    bytesize   = CY_CRYPTOLITE_BYTE_SIZE_OF_BITS(key_bits);

    #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
        static uint8_t public_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        static uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        static uint8_t signature_buf[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        static uint8_t hash_buf[IFX_PSA_CRYPTOLITE_MAX_SHA_HASH_SIZE];
        static cy_stc_cryptolite_ecc_buffer_t ecdsa_buf;

        ecdsa_buf_ptr = &ecdsa_buf;
        sig_ptr = signature_buf;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
        hash_ptr = hash_buf;
    #elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        uint8_t public_key[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        uint8_t private_key[IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE];
        uint8_t signature_buf[IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE];
        uint8_t hash_buf[IFX_PSA_CRYPTOLITE_MAX_SHA_HASH_SIZE];
        cy_stc_cryptolite_ecc_buffer_t ecdsa_buf;

        ecdsa_buf_ptr = &ecdsa_buf;
        sig_ptr = signature_buf;
        pubkey_ptr = public_key;
        pkey_ptr = private_key;
        hash_ptr = hash_buf;
    #else
        sig_ptr = ifx_mxcryptolite_malloc(2 * bytesize);
        pubkey_ptr = ifx_mxcryptolite_malloc(2 * bytesize + 1u);
        pkey_ptr = ifx_mxcryptolite_malloc(bytesize);
        hash_ptr =  ifx_mxcryptolite_malloc(hash_length);
        ecdsa_buf_ptr = (cy_stc_cryptolite_ecc_buffer_t *)ifx_mxcryptolite_malloc(sizeof(cy_stc_cryptolite_ecc_buffer_t));

    #endif /* IFX_PSA_CRYPTOLITE_USE_STATIC_MEM */

    if( (NULL != sig_ptr) && (NULL != pubkey_ptr) && (NULL != hash_ptr) && (NULL != ecdsa_buf_ptr) && (NULL != pkey_ptr))
    {
        Cy_Cryptolite_Setnumber(sig_ptr, (uint8_t *)signature, 2 * bytesize);
        Cy_Cryptolite_InvertEndianness(sig_ptr, bytesize);
        Cy_Cryptolite_InvertEndianness(sig_ptr+bytesize, bytesize);

        Cy_Cryptolite_Setnumber(hash_ptr, (uint8_t *)hash, hash_length);
        Cy_Cryptolite_InvertEndianness(hash_ptr, hash_length);

        cy_status = Cy_Cryptolite_ECC_Init(CRYPTOLITE,&sig_ctx, ecdsa_buf_ptr);

        if(CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type))
            {
#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY_USE_PK)
                Cy_Cryptolite_Setnumber(pkey_ptr, (uint8_t *)key_buffer, bytesize);
                Cy_Cryptolite_InvertEndianness(pkey_ptr, bytesize);

                key.type = PK_PRIVATE;
                key.k = (void*)pkey_ptr;
                key.pubkey.x =(void *)pubkey_ptr;
                key.pubkey.y = (void *)(pubkey_ptr + bytesize);

                cy_status = Cy_Cryptolite_ECC_MakePublicKey(CRYPTOLITE,  &sig_ctx, key.curveID , key.k, &key);
#else
                return PSA_ERROR_NOT_SUPPORTED;
#endif /* IFX_PSA_CRYPTOLITE_ECDSA_VERIFY_USE_PK */
            }
            else
            {
                Cy_Cryptolite_Setnumber(pubkey_ptr, (uint8_t *)key_buffer + 1 , 2 * bytesize); // key_buffer[0] holds the uncompressed byte value

                key.type = PK_PUBLIC;
                key.pubkey.x = pubkey_ptr;
                key.pubkey.y = pubkey_ptr + bytesize;

                Cy_Cryptolite_InvertEndianness(key.pubkey.x, bytesize);
                Cy_Cryptolite_InvertEndianness(key.pubkey.y, bytesize);

                cy_status = CY_CRYPTOLITE_SUCCESS;
            }

            if(CY_CRYPTOLITE_SUCCESS == cy_status)
            {
                cy_status  = Cy_Cryptolite_ECC_VerifyHash ( CRYPTOLITE, &sig_ctx, sig_ptr, (uint32_t)signature_length, hash_ptr, (uint32_t)hash_length, &ver_result, &key);
            }
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

    if(NULL != pubkey_ptr)
    {
        ifx_mxcryptolite_free(pubkey_ptr);
    }

    if(NULL != pkey_ptr)
    {
        ifx_mxcryptolite_free(pkey_ptr);
    }

    if(NULL != hash_ptr)
    {
        ifx_mxcryptolite_free(hash_ptr);
    }

    if(NULL != ecdsa_buf_ptr)
    {
        ifx_mxcryptolite_free(ecdsa_buf_ptr);
    }
    #endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if(CY_CRYPTOLITE_SIG_VALID != ver_result)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}
#endif



#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_cryptolite_get_rsa_public_key
****************************************************************************//**
*
* Function to retrive the rsa public key component n and e from the asn1 der encoded rsa key.
*
* \param is_private
* To indicate whether the key is  rsa private/public key.
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

static psa_status_t ifx_cryptolite_get_rsa_public_key( bool is_private, unsigned char **p, const unsigned char *end, cy_stc_cryptolite_rsa_pub_key_t *rsa_pub_key)
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

    if(is_private)
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
    rsa_pub_key->moduloLength = len  * 8;

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

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_rsa_verify
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
static psa_status_t ifx_cryptolite_transparent_rsa_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)
{
    (void)hash_length;

    cy_stc_cryptolite_context_rsa_t rsa_ctx;
    cy_en_cryptolite_sig_verify_result_t ver_result = CY_CRYPTOLITE_SIG_INVALID;
    cy_stc_cryptolite_rsa_pub_key_t pub_key;
    cy_en_cryptolite_status_t cy_status = CY_CRYPTOLITE_BAD_PARAMS;
    unsigned char *p;
    psa_status_t psa_status = PSA_ERROR_BAD_STATE;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    cy_stc_cryptolite_rsa_buffer_t *rsa_buffer_ptr = NULL;
    uint8_t *sig_ptr = NULL;
    uint8_t *dec_sig_ptr = NULL;
    uint8_t *modulus_ptr = NULL;
    uint8_t *pub_ptr = NULL;
    uint8_t *barret_ptr = NULL;
    uint8_t *invmodulus_ptr = NULL;
    uint8_t *rbar_ptr = NULL;

    cy_en_cryptolite_sha_mode_t hash_mode;
    uint32_t pubkey_mod_len;
    uint32_t pubkey_exp_len;

    p = (unsigned char *)key_buffer;

    if ( (PSA_ALG_SIGN_GET_HASH(alg) != 0) && (hash_length != PSA_HASH_LENGTH(alg)) )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (PSA_KEY_TYPE_IS_KEY_PAIR(key_type))
    {
        psa_status = ifx_cryptolite_get_rsa_public_key(true, &p, p + key_buffer_size, &pub_key);
    }

    else
    {
        psa_status = ifx_cryptolite_get_rsa_public_key(false, &p, p + key_buffer_size, &pub_key);
    }

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    pubkey_mod_len = PSA_BITS_TO_BYTES(pub_key.moduloLength);
    pubkey_exp_len = PSA_BITS_TO_BYTES(pub_key.pubExpLength);

    if(pubkey_mod_len != signature_length)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    switch(PSA_ALG_SIGN_GET_HASH( alg ))
    {
        #ifdef CY_CRYPTOLITE_CFG_RSA_VERIFY_SHA1
        case PSA_ALG_SHA_1:
            hash_mode = CY_CRYPTOLITE_MODE_SHA1;
            break;
        #endif

        #ifdef CY_CRYPTOLITE_CFG_RSA_VERIFY_SHA256
        case PSA_ALG_SHA_224:
            hash_mode = CY_CRYPTOLITE_MODE_SHA224;
            break;

        case PSA_ALG_SHA_256:
            hash_mode = CY_CRYPTOLITE_MODE_SHA256;
            break;
        #endif

        #ifdef CY_CRYPTOLITE_CFG_RSA_VERIFY_SHA512
        case PSA_ALG_SHA_384:
            hash_mode = CY_CRYPTOLITE_MODE_SHA384;
            break;

        case PSA_ALG_SHA_512:
            hash_mode = CY_CRYPTOLITE_MODE_SHA512;
            break;

        case PSA_ALG_SHA_512_224:
            hash_mode = CY_CRYPTOLITE_MODE_SHA512_224;
            break;

        case PSA_ALG_SHA_512_256:
            hash_mode = CY_CRYPTOLITE_MODE_SHA512_256;
            break;
        #endif
        case PSA_ALG_NONE:
            hash_mode = CY_CRYPTOLITE_MODE_SHA_NONE;
            break;
        default:
            return( PSA_ALG_IS_HASH( PSA_ALG_SIGN_GET_HASH( alg ) ) ? PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT);
    }

    #if defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)
        CY_ALIGN(4) static cy_stc_cryptolite_rsa_buffer_t rsa_buffer;
        rsa_buffer_ptr = &rsa_buffer;
        CY_ALIGN(4) static uint8_t signature_buf[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t public_key[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE)];
        CY_ALIGN(4) static uint8_t dec_signature[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t barret_coef[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};  /* Must be modulo length + 1 BITS */
        CY_ALIGN(4) static uint8_t inverse_modulo[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};    /* Must be modulo length + 1 BITS */
        CY_ALIGN(4) static uint8_t rbar[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE)]={0};             /* Must be same as modulo length */

        sig_ptr =  signature_buf;
        modulus_ptr = modulus;
        pub_ptr = public_key;
        dec_sig_ptr = dec_signature;

        barret_ptr = barret_coef;
        invmodulus_ptr = inverse_modulo;
        rbar_ptr = rbar;
    #elif defined (IFX_PSA_CRYPTOLITE_USE_STACK_MEM)
        CY_ALIGN(4) cy_stc_cryptolite_rsa_buffer_t rsa_buffer;
        rsa_buffer_ptr = &rsa_buffer;
        CY_ALIGN(4) uint8_t signature_buf[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) uint8_t public_key[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE)];
        CY_ALIGN(4) uint8_t dec_signature[PSA_BITS_TO_BYTES(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) uint8_t barret_coef[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};  /* Must be modulo length + 1 BITS */
        CY_ALIGN(4) uint8_t inverse_modulo[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE+1)]={0};    /* Must be modulo length + 1 BITS */
        CY_ALIGN(4) uint8_t rbar[4*VU_BITS_TO_WORDS(CY_CRYPTOLITE_RSA_BITSIZE)]={0};             /* Must be same as modulo length */

        sig_ptr =  signature_buf;
        modulus_ptr = modulus;
        pub_ptr = public_key;
        dec_sig_ptr = dec_signature;

        barret_ptr = barret_coef;
        invmodulus_ptr = inverse_modulo;
        rbar_ptr = rbar;

    #else
        uint32_t total_mem_req = 2 * signature_length + pubkey_mod_len + pubkey_exp_len +  (4*VU_BITS_TO_WORDS(pub_key.moduloLength + 1))*2 + 4 * VU_BITS_TO_WORDS(pub_key.moduloLength) ;
        uint32_t *temp_ptr = NULL;
        uint32_t address_offset=0u;

        temp_ptr = (uint32_t *)ifx_mxcryptolite_malloc(total_mem_req + 3);

        if(NULL != temp_ptr)
        {
            /*Aligning the buffer address by 4 bytes*/
            if(((uint32_t)temp_ptr & 0x03U) != 0u)
            {
                address_offset = 4u - ((uint32_t)temp_ptr & 0x03U);
            }

            sig_ptr = (uint8_t *)temp_ptr + address_offset;
            modulus_ptr = sig_ptr +  VU_BITS_TO_BYTES(signature_length*8);
            pub_ptr = modulus_ptr + VU_BITS_TO_BYTES(pubkey_mod_len*8);
            dec_sig_ptr = pub_ptr + VU_BITS_TO_BYTES(pubkey_exp_len*8);

            barret_ptr = dec_sig_ptr + VU_BITS_TO_BYTES(signature_length*8);
            invmodulus_ptr = barret_ptr + 4*VU_BITS_TO_WORDS(pub_key.moduloLength + 1);
            rbar_ptr = invmodulus_ptr + 4*VU_BITS_TO_WORDS(pub_key.moduloLength + 1);

            rsa_buffer_ptr = (cy_stc_cryptolite_rsa_buffer_t *)ifx_mxcryptolite_malloc(sizeof(cy_stc_cryptolite_rsa_buffer_t));
        }

    #endif /* IFX_PSA_CRYPTOLITE_USE_STATIC_MEM */


    pub_key.barretCoefPtr       = barret_ptr;
    pub_key.inverseModuloPtr    = invmodulus_ptr;
    pub_key.rBarPtr             = rbar_ptr;
    pub_key.preCalculatedCoeff  = false;

    if(NULL !=rsa_buffer_ptr)
    {
        cy_status = Cy_Cryptolite_Rsa_Init(CRYPTOLITE, &rsa_ctx, rsa_buffer_ptr);

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {

            Cy_Cryptolite_Setnumber(sig_ptr, (uint8_t *)signature, signature_length);
            Cy_Cryptolite_InvertEndianness(sig_ptr, signature_length);

            Cy_Cryptolite_Setnumber(modulus_ptr, pub_key.moduloPtr, pubkey_mod_len);
            Cy_Cryptolite_InvertEndianness(modulus_ptr, pubkey_mod_len);
            pub_key.moduloPtr = modulus_ptr;

            Cy_Cryptolite_Setnumber(pub_ptr, pub_key.pubExpPtr, pubkey_exp_len);
            Cy_Cryptolite_InvertEndianness(pub_ptr, pubkey_exp_len);
            pub_key.pubExpPtr = pub_ptr;

            cy_status = Cy_Cryptolite_Rsa_Proc(CRYPTOLITE, &rsa_ctx, &pub_key, sig_ptr, signature_length, dec_sig_ptr);
        }

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            Cy_Cryptolite_InvertEndianness(dec_sig_ptr, signature_length);
            cy_status = Cy_Cryptolite_Rsa_Verify(CRYPTOLITE, NULL, &ver_result, hash_mode, hash, (uint32_t)hash_length, dec_sig_ptr, signature_length);
        }

        if (CY_CRYPTOLITE_SUCCESS == cy_status)
        {
            cy_status = Cy_Cryptolite_Rsa_Free(CRYPTOLITE, &rsa_ctx);
        }

        psa_status = ifx_cryptolite_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM) && !defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM)

    if(NULL != temp_ptr)
    {
        ifx_mxcryptolite_free(temp_ptr);
    }

    if(NULL != rsa_buffer_ptr)
    {
        ifx_mxcryptolite_free(rsa_buffer_ptr);
    }
    #endif

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if(CY_CRYPTOLITE_SIG_VALID != ver_result)
    {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}
#endif

/*******************************************************************************
* Function Name: ifx_cryptolite_transparent_verify_message
****************************************************************************//**
*
* Function to calculate the hash of the message and verify the signature.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for Verify operation
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
psa_status_t ifx_cryptolite_transparent_verify_message(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length)
{
    uint8_t hash[CY_CRYPTOLITE_SHA256_HASH_SIZE];
    size_t hash_size = sizeof(hash);
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

    if((PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg )) || PSA_KEY_TYPE_IS_ECC( key_type) )
    {
        psa_status = ifx_cryptolite_transparent_hash_compute(PSA_ALG_SIGN_GET_HASH( alg ), input, input_length, hash, hash_size, &hash_length);
    }

    if(PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    if( PSA_KEY_TYPE_IS_RSA( key_type ) &&  PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ))
    {
#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)
        return  ifx_cryptolite_transparent_rsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_length);
#endif
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type))
    {
#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)
        return  ifx_cryptolite_transparent_ecdsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_length);
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

 /*******************************************************************************
* Function Name: ifx_cryptolite_transparent_verify_hash
****************************************************************************//**
*
* Function to verify the signature with already calculated hash.
*
* \param attributes
* The attributes for the key.
*
* \param key_buffer
* The pointer to the key buffer that has the key for Verify operation
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
psa_status_t ifx_cryptolite_transparent_verify_hash(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,  const uint8_t *signature, size_t signature_length)
{
    psa_key_type_t key_type;

    if((NULL == attributes) || (NULL == key_buffer) || ((NULL == hash) && (hash_length > 0))  || ((NULL == signature) && (signature_length > 0)))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((0 == key_buffer_size) || (0 == hash_length))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_type = psa_get_key_type(attributes);

    if( PSA_KEY_TYPE_IS_RSA( key_type))
    {
        if(PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ))
        {
#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)
        return  ifx_cryptolite_transparent_rsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_length);
#endif
        }
    }
    else if ( PSA_KEY_TYPE_IS_ECC( key_type ))
    {

#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)
        return  ifx_cryptolite_transparent_ecdsa_verify(attributes, key_buffer, key_buffer_size, alg, hash, hash_length, signature, signature_length);
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}
#endif

#endif
