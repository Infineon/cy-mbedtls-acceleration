
/***************************************************************************//**
* \file ifx_cryptolite_transparent_signature_verify.h
*
* \brief
*   PSA crypto transparent Signature verify driver functions.
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_SIGNATURE_VERIFY_H)
#define IFX_CRYPTOLITE_TRANSPARENT_SIGNATURE_VERIFY_H

#include "ifx_cryptolite_config.h"

#if defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY) || defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY)

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "psa/crypto_driver_common.h"

#if defined(__cplusplus)
extern "C" {
#endif


psa_status_t ifx_cryptolite_transparent_verify_hash(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,  const uint8_t *signature, size_t signature_length);
psa_status_t ifx_cryptolite_transparent_verify_message(const psa_key_attributes_t *attributes, const uint8_t *key_buffer, size_t key_buffer_size, psa_algorithm_t alg, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length);

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */
#endif /* defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY) || defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY) */
#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_SIGNATURE_VERIFY_H) */
