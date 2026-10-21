/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_import.h
*
* \brief
*   PSA crypto transparent key import (ML-DSA / ML-KEM) driver functions.
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

#if !defined(IFX_WOLFCRYPTO_TRANSPARENT_IMPORT_H)
#define IFX_WOLFCRYPTO_TRANSPARENT_IMPORT_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && defined(IFX_PSA_WOLFCRYPTO_IMPORT)

#include "ifx_wolfcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_import_key
****************************************************************************//**
*
* Imports an ML-DSA or ML-KEM key into its PSA export representation.
*
* Key pairs are represented by their generation seed (32 bytes for ML-DSA,
* 64 bytes for ML-KEM); public keys by their FIPS encoded form. The parameter
* set (key size in bits) is validated against / inferred from the input, and
* the validated key material is copied into \p key_buffer unchanged.
*
* \param[in]  attributes         Attributes of the key to import.
* \param[in]  data               The key data to import.
* \param[in]  data_length        Size of \p data in bytes.
* \param[out] key_buffer         Buffer to hold the key in export form.
* \param[in]  key_buffer_size    Size of \p key_buffer in bytes.
* \param[out] key_buffer_length  On success, the number of bytes written.
* \param[out] bits               On success, the key size in bits.
*
* \return psa_status_t. Returns #PSA_ERROR_NOT_SUPPORTED for key types not
*         handled by this driver so that the dispatch layer can fall through.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length,
    size_t *bits);

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_IMPORT */

#endif /* #if !defined (IFX_WOLFCRYPTO_TRANSPARENT_IMPORT_H) */
