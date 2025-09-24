
/***************************************************************************//**
* \file ifx_mxcrypto_transparent_key_agreement.h
*
* \brief
*   PSA crypto transparent Key Agreement driver functions.
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

#if !defined(IFX_MXCRYPTO_TRANSPARENT_KEY_AGREEMENT_H)
#define IFX_MXCRYPTO_TRANSPARENT_KEY_AGREEMENT_H

#include "ifx_mxcrypto_config.h"
#if defined(IFX_PSA_MXCRYPTO_ECDH)
#include "cy_device.h"

#if defined(CY_IP_MXCRYPTO)

#include "cy_pdl.h"
#include "psa/crypto_driver_common.h"
#include "ifx_mxcrypto_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

psa_status_t ifx_mxcrypto_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length );

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTO */
#endif /* defined(IFX_PSA_MXCRYPTO_ECDH) */
#endif /* #if !defined (IFX_MXCRYPTO_TRANSPARENT_KEY_AGREEMENT_H) */
