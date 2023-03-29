/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (c) (2019-2023), Cypress Semiconductor Corporation (an Infineon company) or
 *  an affiliate of Cypress Semiconductor Corporation.
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * \file    aes_gcm_alt_mxcrypto.h
 * \version 2.1
 *
 * \brief This file contains GCM definitions and functions.
 *
 * The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
 * in D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 * (GCM), Natl. Inst. Stand. Technol.
 *
 * For more information on GCM, see NIST SP 800-38D: Recommendation for
 * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#ifndef AES_GCM_ALT_H
#define AES_GCM_ALT_H

#if defined(MBEDTLS_GCM_ALT)

#include <cy_crypto_common.h>
#include <cy_crypto_core_aes.h>
#include "cy_syslib.h"

#include "crypto_common.h"

/**
 * \brief The AES context-type definition.
 */
typedef struct mbedtls_gcm_context
{
    cy_cmgr_crypto_hw_t MBEDTLS_PRIVATE(obj);
    cy_stc_crypto_aes_gcm_state_t MBEDTLS_PRIVATE(aes_state);
    cy_stc_crypto_aes_gcm_buffers_t MBEDTLS_PRIVATE(aes_buffers);
}
mbedtls_gcm_context;

#endif /* MBEDTLS_GCM_ALT */
#endif /* AES_GCM_ALT_H */
#endif /* CY_IP_MXCRYPTO */
