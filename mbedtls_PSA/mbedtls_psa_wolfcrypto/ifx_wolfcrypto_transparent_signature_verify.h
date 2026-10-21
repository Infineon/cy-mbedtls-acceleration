/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_signature_verify.h
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

#if !defined(IFX_WOLFCRYPTO_TRANSPARENT_SIGNATURE_VERIFY_H)
#define IFX_WOLFCRYPTO_TRANSPARENT_SIGNATURE_VERIFY_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && \
    (defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY) || \
     defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT))

#include "ifx_wolfcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_verify_message
****************************************************************************//**
*
* Verifies a message signature with an ML-DSA (FIPS 204) key using wolfCrypt.
*
* When \p key_buffer holds an ML-DSA public key it is the encoded public key.
* When it holds an ML-DSA key pair it is the 32-byte private seed, from which
* the public key is re-derived.
*
* \param[in]  attributes        Attributes of the key to use.
* \param[in]  key_buffer        ML-DSA public key or private seed.
* \param[in]  key_buffer_size   Size of \p key_buffer in bytes.
* \param[in]  alg               The ML-DSA signature algorithm.
* \param[in]  input             The signed message.
* \param[in]  input_length      Size of \p input in bytes.
* \param[in]  signature         The signature to verify.
* \param[in]  signature_length  Size of \p signature in bytes.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length);
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY */

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_verify_message_with_context
****************************************************************************//**
*
* Verifies a message signature with an ML-DSA (FIPS 204) key and an
* application supplied context string, using wolfCrypt.
*
* When \p key_buffer holds an ML-DSA public key it is the encoded public key.
* When it holds an ML-DSA key pair it is the 32-byte private seed, from which
* the public key is re-derived. The FIPS 204 context string is at most 255
* bytes.
*
* \param[in]  attributes        Attributes of the key to use.
* \param[in]  key_buffer        ML-DSA public key or private seed.
* \param[in]  key_buffer_size   Size of \p key_buffer in bytes.
* \param[in]  alg               The ML-DSA signature algorithm.
* \param[in]  input             The signed message.
* \param[in]  input_length      Size of \p input in bytes.
* \param[in]  context           The context string.
* \param[in]  context_length    Size of \p context in bytes (at most 255).
* \param[in]  signature         The signature to verify.
* \param[in]  signature_length  Size of \p signature in bytes.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT */

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY || IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT */

#endif /* #if !defined (IFX_WOLFCRYPTO_TRANSPARENT_SIGNATURE_VERIFY_H) */
