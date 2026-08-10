/***************************************************************************//**
* \file ifx_cryptolite_transparent_public_key_export.h
*
* \brief
*  PSA crypto transparent Public Key export driver functions.
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_PUBLIC_KEY_EXPORT_H)
#define IFX_CRYPTOLITE_TRANSPARENT_PUBLIC_KEY_EXPORT_H

#include "ifx_cryptolite_config.h"

#if defined(IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT)

#include "ifx_cryptolite_common.h"

#if defined(CY_IP_MXCRYPTOLITE)

#if defined(__cplusplus)
extern "C" {
#endif

psa_status_t ifx_cryptolite_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length );

#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */
#endif /*IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT*/

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_PUBLIC_KEY_EXPORT_H) */
