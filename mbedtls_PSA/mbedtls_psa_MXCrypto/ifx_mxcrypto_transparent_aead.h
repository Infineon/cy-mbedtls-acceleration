
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_aead.h
*
* \brief
*  PSA crypto transparent AEAD driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2023 Cypress Semiconductor Corporation
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

#if !defined(IFX_MXCRYPTO_TRANSPARENT_AEAD_H)
#define IFX_MXCRYPTO_TRANSPARENT_AEAD_H

#include "ifx_mxcrypto_config.h"

#if defined(IFX_PSA_MXCRYPTO_AEAD)
#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "psa/crypto_driver_common.h"
#include "ifx_mxcrypto_common.h"
#include "ifx_mxcrypto_transparent_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

psa_status_t ifx_mxcrypto_transparent_aead_encrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size,
                                     psa_algorithm_t alg, const uint8_t *nonce, size_t nonce_length,
                                     const uint8_t *additional_data, size_t additional_data_length,
                                     const uint8_t *plaintext, size_t plaintext_length,
                                     uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);
psa_status_t ifx_mxcrypto_transparent_aead_decrypt(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg,
                                      const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length,
                                      const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);
psa_status_t ifx_mxcrypto_transparent_aead_encrypt_setup(ifx_mxcrypto_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg);
psa_status_t ifx_mxcrypto_transparent_aead_decrypt_setup(ifx_mxcrypto_transparent_aead_operation_t *operation, const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg);
psa_status_t ifx_mxcrypto_transparent_aead_set_nonce(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length);
psa_status_t ifx_mxcrypto_transparent_aead_set_lengths(ifx_mxcrypto_transparent_aead_operation_t *operation, size_t ad_length, size_t plaintext_length);
psa_status_t ifx_mxcrypto_transparent_aead_update_ad(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length);
psa_status_t ifx_mxcrypto_transparent_aead_update(ifx_mxcrypto_transparent_aead_operation_t *operation, const uint8_t *input, size_t input_length,
                                     uint8_t *output, size_t output_size, size_t *output_length);
psa_status_t ifx_mxcrypto_transparent_aead_verify(ifx_mxcrypto_transparent_aead_operation_t *operation, uint8_t *plaintext, size_t plaintext_size,
                                     size_t *plaintext_length, const uint8_t *tag, size_t tag_length);
psa_status_t ifx_mxcrypto_transparent_aead_finish(ifx_mxcrypto_transparent_aead_operation_t *operation, uint8_t *ciphertext, size_t ciphertext_size,
                                     size_t *ciphertext_length, uint8_t *tag, size_t tag_size, size_t *tag_length);
psa_status_t ifx_mxcrypto_transparent_aead_abort(ifx_mxcrypto_transparent_aead_operation_t *operation);

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTO */
#endif /*IFX_PSA_MXCRYPTO_AEAD*/

#endif /* #if !defined (IFX_MXCRYPTO_TRANSPARENT_AEAD_H) */
