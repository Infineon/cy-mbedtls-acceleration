
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_asymmetric.h
*
* \brief
*   PSA crypto transparent asymmetric encrypt/decrypt driver functions.
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

#if !defined(IFX_MXCRYPTO_TRANSPARENT_ASYMMETRIC_H)
#define IFX_MXCRYPTO_TRANSPARENT_ASYMMETRIC_H

#include "ifx_mxcrypto_config.h"

#if (defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT) || defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT))
#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "psa/crypto_driver_common.h"
#include "ifx_mxcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif


psa_status_t ifx_mxcrypto_transparent_asymmetric_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length);

psa_status_t ifx_mxcrypto_transparent_asymmetric_decrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length);
#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTO */
#endif /* defined(IFX_PSA_MXCRYPTO_ECDSA_SIGN) || defined(IFX_PSA_MXCRYPTO_RSA_SIGN) */

#endif /* #if !defined (IFX_MXCRYPTO_TRANSPARENT_ASYMMETRIC_H) */
