/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_sign.c
*
* \brief
*   PSA crypto transparent signature (ML-DSA) driver functions.
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

#include "ifx_wolfcrypto_transparent_sign.h"

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN) || defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN_CONTEXT)

#include <wolfssl/wolfcrypt/dilithium.h>

/* FIPS 204 caps the context string at 255 bytes (ctxLen is encoded as a
 * single byte in wc_dilithium_sign_ctx_msg()). */
#define IFX_WOLFCRYPTO_MLDSA_CONTEXT_MAX_SIZE (255u)

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_sign_message
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_status_t status;
    int ret;
    byte level;
    int sig_size;
    word32 sig_len;
    dilithium_key *key;
    int key_initialized = 0;
    WC_RNG rng;
    int rng_initialized = 0;

    /* This driver only handles ML-DSA private keys with an ML-DSA algorithm. */
    if (!PSA_KEY_TYPE_IS_ML_DSA(psa_get_key_type(attributes)) ||
        !PSA_ALG_IS_ML_DSA(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* The PSA export representation of an ML-DSA key pair is the private seed. */
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

    /* Expand the full private key from the stored seed. */
    ret = wc_dilithium_make_key_from_seed(key, key_buffer);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    /* Verify the output buffer is large enough for the signature. */
    sig_size = wc_dilithium_sig_size(key);
    if (sig_size <= 0)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }
    if (signature_size < (size_t)sig_size)
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

    sig_len = (word32)signature_size;
    ret = wc_dilithium_sign_msg(input, (word32)input_length,
                                signature, &sig_len, key, &rng);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *signature_length = (size_t)sig_len;
    status = PSA_SUCCESS;

cleanup:
    if (rng_initialized)
    {
        wc_FreeRng(&rng);
    }
    if (key_initialized)
    {
        wc_dilithium_free(key);
    }
#if !defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    ifx_wolfcrypto_free(key);
#endif
    return status;
}
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_SIGN */

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN_CONTEXT)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_sign_message_with_context
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_status_t status;
    int ret;
    byte level;
    int sig_size;
    word32 sig_len;
    dilithium_key *key;
    int key_initialized = 0;
    WC_RNG rng;
    int rng_initialized = 0;

    /* This driver only handles ML-DSA private keys with an ML-DSA algorithm. */
    if (!PSA_KEY_TYPE_IS_ML_DSA(psa_get_key_type(attributes)) ||
        !PSA_ALG_IS_ML_DSA(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (context_length > IFX_WOLFCRYPTO_MLDSA_CONTEXT_MAX_SIZE)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* The PSA export representation of an ML-DSA key pair is the private seed. */
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

    /* Expand the full private key from the stored seed. */
    ret = wc_dilithium_make_key_from_seed(key, key_buffer);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    /* Verify the output buffer is large enough for the signature. */
    sig_size = wc_dilithium_sig_size(key);
    if (sig_size <= 0)
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }
    if (signature_size < (size_t)sig_size)
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

    sig_len = (word32)signature_size;
    ret = wc_dilithium_sign_ctx_msg(context, (byte)context_length,
                                    input, (word32)input_length,
                                    signature, &sig_len, key, &rng);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    *signature_length = (size_t)sig_len;
    status = PSA_SUCCESS;

cleanup:
    if (rng_initialized)
    {
        wc_FreeRng(&rng);
    }
    if (key_initialized)
    {
        wc_dilithium_free(key);
    }
#if !defined(IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_WOLFCRYPTO_USE_STACK_MEM)
    ifx_wolfcrypto_free(key);
#endif
    return status;
}
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_SIGN_CONTEXT */

#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_SIGN || IFX_PSA_WOLFCRYPTO_MLDSA_SIGN_CONTEXT */
