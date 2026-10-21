/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_public_key_export.c
*
* \brief
*   PSA crypto transparent public key export (ML-DSA / ML-KEM) driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors
*
* Copyright (C) 2026 Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.
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

#include "ifx_wolfcrypto_transparent_public_key_export.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && defined(IFX_PSA_WOLFCRYPTO_PUBLIC_KEY_EXPORT)

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT)
#include <wolfssl/wolfcrypt/dilithium.h>

/* Derives the public key of an ML-DSA key pair from its private seed. */
static psa_status_t ifx_wolfcrypto_mldsa_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t status;
    int ret;
    byte level;
    int pub_size;
    word32 out_len;
    dilithium_key *key;
    int key_initialized = 0;

    if (key_buffer_size != IFX_WOLFCRYPTO_MLDSA_SEED_SIZE)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_wolfcrypto_mldsa_level_from_bits(
                 psa_get_key_bits(attributes), &level);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    /* wolfCrypt already sizes dilithium_key for the largest ML-DSA parameter
     * set enabled in the build, so one instance works for 44/65/87 alike. */
#if defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM)
    static dilithium_key key_static;
    key = &key_static;
#elif defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    dilithium_key key_stack;
    key = &key_stack;
#else
    key = (dilithium_key *)ifx_wolfcrypto_malloc(sizeof(*key));
    if (key == NULL)
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif

    ret = wc_dilithium_init(key);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    key_initialized = 1;

    ret = wc_dilithium_set_level(key, level);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_dilithium_make_key_from_seed(key, key_buffer);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    pub_size = wc_dilithium_pub_size(key);
    if (pub_size <= 0)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }
    if (data_size < (size_t)pub_size)
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    out_len = (word32)data_size;
    ret = wc_dilithium_export_public(key, data, &out_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *data_length = (size_t)out_len;
    status = PSA_SUCCESS;

cleanup:
    if (key_initialized)
    {
        wc_dilithium_free(key);
    }
#if !defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    ifx_wolfcrypto_free(key);
#endif
    return status;
}
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT */

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT)
/* wc_mlkem.h (not mlkem.h) is required for the full MlKemKey struct definition. */
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* Derives the public (encapsulation) key of an ML-KEM key pair from its seed. */
static psa_status_t ifx_wolfcrypto_mlkem_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_status_t status;
    int ret;
    int type;
    word32 pub_len = 0;
    MlKemKey *key;
    int key_initialized = 0;

    if (key_buffer_size != IFX_WOLFCRYPTO_MLKEM_SEED_SIZE)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_wolfcrypto_mlkem_type_from_bits(
                 psa_get_key_bits(attributes), &type);
    if (status != PSA_SUCCESS)
    {
        return status;
    }

    /* wolfCrypt already sizes MlKemKey for the largest ML-KEM parameter set
     * enabled in the build, so one instance works for 512/768/1024 alike. */
#if defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM)
    static MlKemKey key_static;
    key = &key_static;
#elif defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    MlKemKey key_stack;
    key = &key_stack;
#else
    key = (MlKemKey *)ifx_wolfcrypto_malloc(sizeof(*key));
    if (key == NULL)
    {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif

    ret = wc_MlKemKey_Init(key, type, NULL, INVALID_DEVID);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    key_initialized = 1;

    ret = wc_MlKemKey_MakeKeyWithRandom(key, key_buffer,
                                        (int)key_buffer_size);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_MlKemKey_PublicKeySize(key, &pub_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    if (data_size < (size_t)pub_len)
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ret = wc_MlKemKey_EncodePublicKey(key, data, pub_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *data_length = (size_t)pub_len;
    status = PSA_SUCCESS;

cleanup:
    if (key_initialized)
    {
        (void)wc_MlKemKey_Free(key);
    }
#if !defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    ifx_wolfcrypto_free(key);
#endif
    return status;
}
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT */

/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_export_public_key
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT)
    if (key_type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR)
    {
        return ifx_wolfcrypto_mldsa_export_public_key(
                   attributes, key_buffer, key_buffer_size,
                   data, data_size, data_length);
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT */

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT)
    if (key_type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR)
    {
        return ifx_wolfcrypto_mlkem_export_public_key(
                   attributes, key_buffer, key_buffer_size,
                   data, data_size, data_length);
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT */

    (void)key_buffer;
    (void)key_buffer_size;
    (void)data;
    (void)data_size;
    (void)data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* IFX_PSA_WOLFCRYPTO_PUBLIC_KEY_EXPORT */
