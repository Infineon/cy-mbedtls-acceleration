/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_key_encapsulation.h
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

#if !defined(IFX_WOLFCRYPTO_TRANSPARENT_KEY_ENCAPSULATION_H)
#define IFX_WOLFCRYPTO_TRANSPARENT_KEY_ENCAPSULATION_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && \
    (defined(IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE) || \
     defined(IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE))

#include "ifx_wolfcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_encapsulate
****************************************************************************//**
*
* Performs ML-KEM (FIPS 203) encapsulation using wolfCrypt.
*
* The key material in \p key_buffer is the encoded ML-KEM public
* (encapsulation) key, or the 64-byte key pair seed. The parameter set is
* taken from the key size (bits) in \p attributes.
*
* \param[in]  attributes             Attributes of the key to use.
* \param[in]  key_buffer             Encoded public key or key pair seed.
* \param[in]  key_buffer_size        Size of \p key_buffer in bytes.
* \param[in]  alg                    The ML-KEM algorithm.
* \param[out] ciphertext             Buffer to hold the ciphertext.
* \param[in]  ciphertext_size        Size of \p ciphertext in bytes.
* \param[out] ciphertext_length      On success, ciphertext bytes written.
* \param[out] shared_secret          Buffer to hold the shared secret.
* \param[in]  shared_secret_size     Size of \p shared_secret in bytes.
* \param[out] shared_secret_length   On success, shared secret bytes written.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length);
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE */

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_decapsulate
****************************************************************************//**
*
* Performs ML-KEM (FIPS 203) decapsulation using wolfCrypt.
*
* The key material in \p key_buffer is the 64-byte ML-KEM key pair seed. The
* parameter set is taken from the key size (bits) in \p attributes.
*
* \param[in]  attributes             Attributes of the key to use.
* \param[in]  key_buffer             ML-KEM key pair seed (64 bytes).
* \param[in]  key_buffer_size        Size of \p key_buffer in bytes.
* \param[in]  alg                    The ML-KEM algorithm.
* \param[in]  ciphertext             The ciphertext to decapsulate.
* \param[in]  ciphertext_length      Size of \p ciphertext in bytes.
* \param[out] shared_secret          Buffer to hold the shared secret.
* \param[in]  shared_secret_size     Size of \p shared_secret in bytes.
* \param[out] shared_secret_length   On success, shared secret bytes written.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length);
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE */

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE ||
          IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE */

#endif /* #if !defined (IFX_WOLFCRYPTO_TRANSPARENT_KEY_ENCAPSULATION_H) */
