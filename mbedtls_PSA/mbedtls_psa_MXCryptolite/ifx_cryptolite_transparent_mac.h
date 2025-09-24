
/***************************************************************************//**
* \file ifx_cryptolite_transparent_mac.h
*
* \brief
*  PSA crypto transparent MAC driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2022 Cypress Semiconductor Corporation
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_MAC_H)
#define IFX_CRYPTOLITE_TRANSPARENT_MAC_H

#include "ifx_cryptolite_config.h"
#if defined(IFX_PSA_CRYPTOLITE_MAC)

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "psa/crypto_driver_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "ifx_cryptolite_transparent_types.h"


#if defined(IFX_PSA_CRYPTOLITE_HMAC)
    #define IFX_PSA_CRYPTOLITE_MAC_SIZE CY_CRYPTOLITE_SHA256_HASH_SIZE
#elif defined(IFX_PSA_CRYPTOLITE_CMAC)
    #define IFX_PSA_CRYPTOLITE_MAC_SIZE CY_CRYPTOLITE_AES_BLOCK_SIZE
#else
    #define IFX_PSA_CRYPTOLITE_MAC_SIZE 16u
#endif

psa_status_t ifx_cryptolite_transparent_mac_compute(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                                        uint8_t *mac, size_t mac_size, size_t *mac_length);
                                        
psa_status_t ifx_cryptolite_transparent_mac_verify(const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
                                       size_t key_buffer_size, psa_algorithm_t alg,
                                       const uint8_t *input, size_t input_length,
                                       const uint8_t *mac, size_t mac_length);
                                       
psa_status_t  ifx_cryptolite_transparent_mac_sign_setup(ifx_cryptolite_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg);
psa_status_t  ifx_cryptolite_transparent_mac_verify_setup(ifx_cryptolite_transparent_mac_operation_t *operation, const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg);
psa_status_t ifx_cryptolite_transparent_mac_update(ifx_cryptolite_transparent_mac_operation_t *operation, const uint8_t *input, size_t input_length);
psa_status_t ifx_cryptolite_transparent_mac_sign_finish(ifx_cryptolite_transparent_mac_operation_t *operation, uint8_t *mac, size_t mac_size, size_t *mac_length);
psa_status_t ifx_cryptolite_transparent_mac_verify_finish(ifx_cryptolite_transparent_mac_operation_t *operation, const uint8_t *mac, size_t mac_length);
psa_status_t ifx_cryptolite_transparent_mac_abort(ifx_cryptolite_transparent_mac_operation_t *operation);

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */

#endif /* IFX_PSA_CRYPTOLITE_MAC */

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_MAC_H) */
