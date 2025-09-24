
/***************************************************************************//**
* \file ifx_cryptolite_transparent_hash.h
*
* \brief
*  PSA crypto transparent Hash driver functions.
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_HASH_H)
#define IFX_CRYPTOLITE_TRANSPARENT_HASH_H

#include "ifx_cryptolite_config.h"

#if defined(IFX_PSA_CRYPTOLITE_SHA)

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "psa/crypto_driver_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "ifx_cryptolite_transparent_types.h"

psa_status_t ifx_cryptolite_transparent_hash_setup(ifx_cryptolite_transparent_hash_operation_t *operation, psa_algorithm_t alg);
psa_status_t ifx_cryptolite_transparent_hash_update(ifx_cryptolite_transparent_hash_operation_t *operation, const uint8_t *input, size_t input_length);
psa_status_t ifx_cryptolite_transparent_hash_finish(ifx_cryptolite_transparent_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length);
psa_status_t ifx_cryptolite_transparent_hash_abort(ifx_cryptolite_transparent_hash_operation_t *operation);
psa_status_t ifx_cryptolite_transparent_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length);
psa_status_t ifx_cryptolite_transparent_hash_clone(const ifx_cryptolite_transparent_hash_operation_t *source_operation, ifx_cryptolite_transparent_hash_operation_t *target_operation);


#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */

#endif /* IFX_PSA_CRYPTOLITE_SHA */

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_HASH_H) */
