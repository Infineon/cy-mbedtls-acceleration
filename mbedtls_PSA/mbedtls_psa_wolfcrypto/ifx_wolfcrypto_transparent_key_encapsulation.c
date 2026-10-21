/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_key_encapsulation.c
*
* \brief
*   PSA crypto transparent key encapsulation (ML-KEM) driver functions.
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

#include "ifx_wolfcrypto_transparent_key_encapsulation.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && \
    (defined(IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE) || \
     defined(IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE))

/* wc_mlkem.h (not mlkem.h) is required for the full MlKemKey struct definition. */
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_encapsulate
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_status_t status;
    int ret;
    int type;
    word32 ct_len = 0;
    word32 ss_len = 0;
    MlKemKey *key;
    int key_initialized = 0;
    WC_RNG rng;
    int rng_initialized = 0;

    if (alg != PSA_ALG_ML_KEM || !PSA_KEY_TYPE_IS_ML_KEM(key_type))
    {
        return PSA_ERROR_NOT_SUPPORTED;
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

    /* Load the public (encapsulation) key: either directly from the encoded
     * public key, or by re-deriving it from a key pair seed. */
    if (key_type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY)
    {
        ret = wc_MlKemKey_DecodePublicKey(key, key_buffer,
                                          (word32)key_buffer_size);
    }
    else
    {
        if (key_buffer_size != IFX_WOLFCRYPTO_MLKEM_SEED_SIZE)
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        ret = wc_MlKemKey_MakeKeyWithRandom(key, key_buffer,
                                            (int)key_buffer_size);
    }
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_MlKemKey_CipherTextSize(key, &ct_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    ret = wc_MlKemKey_SharedSecretSize(key, &ss_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    if (ciphertext_size < (size_t)ct_len ||
        shared_secret_size < (size_t)ss_len)
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    rng_initialized = 1;

    ret = wc_MlKemKey_Encapsulate(key, ciphertext, shared_secret, &rng);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *ciphertext_length = (size_t)ct_len;
    *shared_secret_length = (size_t)ss_len;
    status = PSA_SUCCESS;

cleanup:
    if (rng_initialized)
    {
        wc_FreeRng(&rng);
    }
    if (key_initialized)
    {
        (void)wc_MlKemKey_Free(key);
    }
#if !defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    ifx_wolfcrypto_free(key);
#endif
    return status;
}
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE */

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_decapsulate
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    psa_status_t status;
    int ret;
    int type;
    word32 ss_len = 0;
    MlKemKey *key;
    int key_initialized = 0;

    if (alg != PSA_ALG_ML_KEM ||
        key_type != PSA_KEY_TYPE_ML_KEM_KEY_PAIR)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

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

    /* Re-derive the full private key from the stored key pair seed. */
    ret = wc_MlKemKey_MakeKeyWithRandom(key, key_buffer,
                                        (int)key_buffer_size);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_MlKemKey_SharedSecretSize(key, &ss_len);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }
    if (shared_secret_size < (size_t)ss_len)
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ret = wc_MlKemKey_Decapsulate(key, shared_secret, ciphertext,
                                  (word32)ciphertext_length);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *shared_secret_length = (size_t)ss_len;
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
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE */

#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE ||
          IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE */
