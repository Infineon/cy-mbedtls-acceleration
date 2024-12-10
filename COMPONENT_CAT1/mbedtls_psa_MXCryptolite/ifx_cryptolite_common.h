/***************************************************************************//**
* \file ifx_cryptolite_common.h
*
* \brief
*  PSA crypto cryptolite helper functions.
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

#if !defined(IFX_CRYPTOLITE_COMMON_H)
#define IFX_CRYPTOLITE_COMMON_H

#include "mbedtls/build_info.h"

#include "cy_device.h"

#if defined(CY_IP_MXCRYPTOLITE)

#include "ifx_cryptolite_config.h"

#include "cy_cryptolite.h"
#include <psa/crypto.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM)

#include <stdlib.h>
#if !defined(ifx_mxcryptolite_malloc)
#define ifx_mxcryptolite_malloc malloc
#endif

#if !defined(ifx_mxcryptolite_free)
#define ifx_mxcryptolite_free free
#endif

#endif /* IFX_PSA_CRYPTOLITE_USE_STATIC_MEM */

#if defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521)
    #define IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTOLITE_ECC_P521_BYTE_SIZE
    #define IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTOLITE_ECC_P521_BYTE_SIZE)
#elif defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)
    #define IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTOLITE_ECC_P384_BYTE_SIZE
    #define IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTOLITE_ECC_P384_BYTE_SIZE)
#elif defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)
    #define IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTOLITE_ECC_P256_BYTE_SIZE
    #define IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTOLITE_ECC_P256_BYTE_SIZE)
#elif defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)
    #define IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTOLITE_ECC_P224_BYTE_SIZE
    #define IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTOLITE_ECC_P224_BYTE_SIZE)
#elif defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)
    #define IFX_CRYPTOLITE_ECC_MAX_PRIV_KEY_SIZE  CY_CRYPTOLITE_ECC_P192_BYTE_SIZE
    #define IFX_CRYPTOLITE_ECC_MAX_PUB_KEY_SIZE  (2 * CY_CRYPTOLITE_ECC_P192_BYTE_SIZE)
#endif

psa_status_t  ifx_cryptolite_status_to_psa_status (cy_en_cryptolite_status_t cryptolite_status);
uint8_t ifx_psa_safer_memcmp(const uint8_t *a, const uint8_t *b, size_t n);



#if defined(__cplusplus)
}
#endif

#endif /* CY_IP_MXCRYPTOLITE */

#endif /* #if !defined (IFX_CRYPTOLITE_COMMON_H) */
