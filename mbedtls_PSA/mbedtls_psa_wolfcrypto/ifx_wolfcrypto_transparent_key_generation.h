/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_key_generation.h
*
* \brief
*   PSA crypto transparent key generation (ML-DSA / ML-KEM) driver functions.
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

#if !defined(IFX_WOLFCRYPTO_TRANSPARENT_KEY_GENERATION_H)
#define IFX_WOLFCRYPTO_TRANSPARENT_KEY_GENERATION_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && defined(IFX_PSA_WOLFCRYPTO_KEY_GENERATION)

#include "ifx_wolfcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_generate_key
****************************************************************************//**
*
* Generates an ML-DSA or ML-KEM key pair using wolfCrypt.
*
* The generated key material stored in \p key_buffer is the key pair seed:
* 32 bytes for ML-DSA (FIPS 204) and 64 bytes for ML-KEM (FIPS 203). The
* parameter set is taken from the key size (bits) in \p attributes.
*
* \param[in]  attributes         Attributes of the key to generate.
* \param[out] key_buffer         Buffer to hold the generated key seed.
* \param[in]  key_buffer_size    Size of \p key_buffer in bytes.
* \param[out] key_buffer_length  On success, the number of bytes written.
*
* \return psa_status_t. Returns #PSA_ERROR_NOT_SUPPORTED for key types not
*         handled by this driver so that the dispatch layer can fall through.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_KEY_GENERATION */

#endif /* #if !defined (IFX_WOLFCRYPTO_TRANSPARENT_KEY_GENERATION_H) */
