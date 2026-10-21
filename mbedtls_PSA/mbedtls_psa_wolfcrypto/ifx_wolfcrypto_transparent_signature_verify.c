/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_signature_verify.c
*
* \brief
*   PSA crypto transparent signature verification (ML-DSA) driver functions.
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

#include "ifx_wolfcrypto_transparent_signature_verify.h"

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY) || defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT)

#include <wolfssl/wolfcrypt/dilithium.h>

/* FIPS 204 caps the context string at 255 bytes. */
#define IFX_WOLFCRYPTO_MLDSA_CONTEXT_MAX_SIZE (255u)

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_verify_message
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_status_t status;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    int ret;
    byte level;
    int res = 0;
    dilithium_key *key;
    int key_initialized = 0;

    if (!PSA_KEY_TYPE_IS_ML_DSA(key_type) || !PSA_ALG_IS_ML_DSA(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
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

    if (key_type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY)
    {
        ret = wc_dilithium_import_public(key_buffer, (word32)key_buffer_size,
                                         key);
    }
#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN) || \
    defined(IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION)
    else
    {
        /* Key pair: re-derive the public key from the private seed. This needs
         * the wolfCrypt make-key capability, which is compiled out of
         * verify-only builds. */
        if (key_buffer_size != IFX_WOLFCRYPTO_MLDSA_SEED_SIZE)
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        ret = wc_dilithium_make_key_from_seed(key, key_buffer);
    }
#else
    else
    {
        /* Verify-only wolfCrypt build: a public key must be supplied because
         * the public key cannot be re-derived from a private seed. */
        status = PSA_ERROR_NOT_SUPPORTED;
        goto cleanup;
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_SIGN || IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION */
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_dilithium_verify_msg(signature, (word32)signature_length,
                                  input, (word32)input_length, &res, key);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    status = (res == 1) ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;

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
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY */

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_verify_message_with_context
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_status_t status;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    int ret;
    byte level;
    int res = 0;
    dilithium_key *key;
    int key_initialized = 0;

    if (!PSA_KEY_TYPE_IS_ML_DSA(key_type) || !PSA_ALG_IS_ML_DSA(alg))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (context_length > IFX_WOLFCRYPTO_MLDSA_CONTEXT_MAX_SIZE)
    {
        return PSA_ERROR_NOT_SUPPORTED;
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

    if (key_type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY)
    {
        ret = wc_dilithium_import_public(key_buffer, (word32)key_buffer_size,
                                         key);
    }
#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_SIGN) || \
    defined(IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION)
    else
    {
        /* Key pair: re-derive the public key from the private seed. This needs
         * the wolfCrypt make-key capability, which is compiled out of
         * verify-only builds. */
        if (key_buffer_size != IFX_WOLFCRYPTO_MLDSA_SEED_SIZE)
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        ret = wc_dilithium_make_key_from_seed(key, key_buffer);
    }
#else
    else
    {
        /* Verify-only wolfCrypt build: a public key must be supplied because
         * the public key cannot be re-derived from a private seed. */
        status = PSA_ERROR_NOT_SUPPORTED;
        goto cleanup;
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_SIGN || IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION */
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    ret = wc_dilithium_verify_ctx_msg(signature, (word32)signature_length,
                                      context, (word32)context_length,
                                      input, (word32)input_length, &res, key);
    if (ret != 0)
    {
        status = ifx_wolfcrypto_status_to_psa_status(ret);
        goto cleanup;
    }

    status = (res == 1) ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;

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
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT */

#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY || IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT */
