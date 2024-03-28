/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2019-2024 Cypress Semiconductor Corporation
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

/**
 * \file    aes_alt_mxcryptolite.h
 * \version 2.3.0
 *
 * \brief   This file contains AES definitions and functions.
 *
 *          The Advanced Encryption Standard (AES) specifies a FIPS-approved
 *          cryptographic algorithm that can be used to protect electronic
 *          data.
 *
 *          The AES algorithm is a symmetric block cipher that can
 *          encrypt and decrypt information. For more information, see
 *          <em>FIPS Publication 197: Advanced Encryption Standard</em> and
 *          <em>ISO/IEC 18033-2:2006: Information technology -- Security
 *          techniques -- Encryption algorithms -- Part 2: Asymmetric
 *          ciphers</em>.
 *
 *          The AES-XTS block mode is standardized by NIST SP 800-38E
 *          <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
 *          and described in detail by IEEE P1619
 *          <https://ieeexplore.ieee.org/servlet/opac?punumber=4375278>.
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#ifndef AES_ALT_H
#define AES_ALT_H

#if defined(MBEDTLS_AES_ALT)

#include "mbedtls/build_info.h"


#include "cy_cryptolite_common.h"
#include "cy_cryptolite.h"

#include "cryptolite_common.h"


/**
 * \brief The AES context-type definition.
 */
typedef struct mbedtls_aes_context
{
    cy_stc_cryptolite_aes_state_t MBEDTLS_PRIVATE(aes_state);
    cy_stc_cryptolite_aes_buffers_t MBEDTLS_PRIVATE(aes_buffers);
}
mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)

/**
 * \brief The AES XTS context-type definition.
 */
typedef struct mbedtls_aes_xts_context
{
    mbedtls_aes_context MBEDTLS_PRIVATE(crypt); /*!< The AES context to use for AES block
                                        encryption or decryption. */
    mbedtls_aes_context MBEDTLS_PRIVATE(tweak); /*!< The AES context used for tweak
                                        computation. */
} mbedtls_aes_xts_context;

#endif /* MBEDTLS_CIPHER_MODE_XTS */

#endif /* MBEDTLS_AES_ALT */

#endif /* aes_alt.h */

#endif /* CY_IP_MXCRYPTOLITE */