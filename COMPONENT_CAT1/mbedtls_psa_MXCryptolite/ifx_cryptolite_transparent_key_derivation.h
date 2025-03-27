
/***************************************************************************//**
* \file ifx_cryptolite_transparent_key_derivation.h
*
* \brief
*  PSA crypto transparent Key Derivation driver functions.
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
#ifndef IFX_CRYPTOLITE_TRANSPARENT_KEY_DERIVATION_H
#define IFX_CRYPTOLITE_TRANSPARENT_KEY_DERIVATION_H

#include "ifx_cryptolite_config.h"

#if defined(IFX_PSA_CRYPTOLITE_KEY_DERIVATION)
#include "cy_device.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "psa/crypto_driver_common.h"
#include "ifx_cryptolite_common.h"
#include "ifx_cryptolite_transparent_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define PSA_CRYPTOLITE_ALG_SP800_108_COUNTER_CMAC ((psa_algorithm_t)0x08000600)

/**
 * Fixed size of counter's binary representation in bytes.
 */
#define IFX_CRYPTOLITE_KEY_DERIVATION_COUNTER_LENGTH sizeof(uint32_t)

/**
 * Fixed size of capacity's binary representation in bytes.
 */
#define IFX_CRYPTOLITE_KEY_DERIVATION_CAPACITY_LENGTH sizeof(uint32_t)

/**
 * Maximum possible number of bytes a key derivation operation can output.
 *
 * This number is derived from the maximum number of bits which can be represented within
 * \p IFX_CRYPTOLITE_KEY_DERIVATION_CAPACITY_LENGTH bytes.
 */
#define IFX_CRYPTOLITE_KEY_DERIVATION_MAXIMUM_CAPACITY ((size_t)0x0FFFFFFF)

/**
 * Fixed data for the key derivation.
 *
 * This should be a direct input.
 */
#define PSA_KEY_DERIVATION_INPUT_FIXED_DATA ((psa_key_derivation_step_t)0x0206)


psa_status_t ifx_cryptolite_key_derivation_setup(ifx_cryptolite_key_derivation_operation_t *operation, psa_algorithm_t alg);

psa_status_t ifx_cryptolite_key_derivation_get_capacity(const ifx_cryptolite_key_derivation_operation_t *operation, size_t *capacity);

psa_status_t ifx_cryptolite_key_derivation_set_capacity(ifx_cryptolite_key_derivation_operation_t *operation, size_t capacity);


psa_status_t ifx_cryptolite_key_derivation_input_bytes(ifx_cryptolite_key_derivation_operation_t *operation,  psa_key_derivation_step_t step,
                                                        const uint8_t *data, size_t data_length);

psa_status_t ifx_cryptolite_key_derivation_output_bytes(ifx_cryptolite_key_derivation_operation_t *operation, uint8_t *output, size_t output_length);

psa_status_t ifx_cryptolite_key_derivation_abort(ifx_cryptolite_key_derivation_operation_t *operation);

#if defined(__cplusplus)
}
#endif

#endif //CY_IP_MXCRYPTOLITE
#endif //IFX_PSA_CRYPTOLITE_KEY_DERIVATION
#endif