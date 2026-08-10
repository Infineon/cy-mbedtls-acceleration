
/***************************************************************************//**
* \file ifx_cryptolite_transparent_cipher.h
*
* \brief
*  PSA crypto transparent Cipher driver functions.
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_CIPHER_H)
#define IFX_CRYPTOLITE_TRANSPARENT_CIPHER_H

#include "ifx_cryptolite_config.h"
#if defined(IFX_PSA_CRYPTOLITE_CIPHER)

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "psa/crypto_driver_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "ifx_cryptolite_transparent_types.h"

psa_status_t ifx_cryptolite_transparent_cipher_encrypt( const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,  psa_algorithm_t alg,
                                                    const uint8_t *iv, size_t iv_length, const uint8_t *input, size_t input_length,
                                                    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t ifx_cryptolite_transparent_cipher_decrypt( const psa_key_attributes_t *attributes,  const uint8_t *key, size_t key_length, psa_algorithm_t alg,
                                                    const uint8_t *input, size_t input_length, uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t ifx_cryptolite_transparent_cipher_encrypt_setup( ifx_cryptolite_transparent_cipher_operation_t *operation, const psa_key_attributes_t *attributes,
                                                            const uint8_t *key, size_t key_length, psa_algorithm_t alg);

psa_status_t ifx_cryptolite_transparent_cipher_decrypt_setup(  ifx_cryptolite_transparent_cipher_operation_t *operation,  const psa_key_attributes_t *attributes,
                                                            const uint8_t *key, size_t key_length, psa_algorithm_t alg);

psa_status_t ifx_cryptolite_transparent_cipher_abort(ifx_cryptolite_transparent_cipher_operation_t *operation );

psa_status_t ifx_cryptolite_transparent_cipher_set_iv(ifx_cryptolite_transparent_cipher_operation_t *operation, const uint8_t *iv, size_t iv_length);

psa_status_t ifx_cryptolite_transparent_cipher_update( ifx_cryptolite_transparent_cipher_operation_t *operation,  const uint8_t *input, size_t input_length,
                                                    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t ifx_cryptolite_transparent_cipher_finish(  ifx_cryptolite_transparent_cipher_operation_t *operation,  uint8_t *output, size_t output_size, size_t *output_length);

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */
#endif /*IFX_PSA_CRYPTOLITE_CIPHER*/

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_CIPHER_H) */
