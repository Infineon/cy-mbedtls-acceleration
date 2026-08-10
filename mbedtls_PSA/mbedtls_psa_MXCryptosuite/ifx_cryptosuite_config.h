/***************************************************************************//**
* \file ifx_cryptosuite_config.h
*
* \brief
*  PSA CryptoSuite driver configuration file.
*
********************************************************************************
* Copyright (C) 2026 Cypress Semiconductor Corporation
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
#if !defined(IFX_CRYPTOSUITE_CONFIG_H)
#define IFX_CRYPTOSUITE_CONFIG_H

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_CRYPTOSUITE_USER_CONFIG_FILE)
#include IFX_PSA_CRYPTOSUITE_USER_CONFIG_FILE
#else

#include "mbedtls/build_info.h"
#include "psa/crypto_driver_common.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)
/**
 * \brief Default configuration of PSA CryptoSuite Driver
 *
 * \details
 *  The CryptoSuite driver supports the following cryptographic operations:
 *  - AES block cipher modes: ECB, CBC, CTR
 *  - CCM authenticated encryption with associated data (AEAD)
 *  - CMAC message authentication code
 *
 *  Configuration is automatically derived from PSA_WANT_* macros defined
 *  in the mbedTLS build configuration.
 */

/*******************************************************************************
 * AES Cipher Mode Configuration
 ******************************************************************************/

/** Enable AES-ECB (Electronic Code book) mode */
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
#define IFX_PSA_CRYPTOSUITE_AES_ECB
#endif

/** Enable AES-CBC (Cipher Block Chaining) mode */
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#define IFX_PSA_CRYPTOSUITE_AES_CBC
#endif

/** Enable AES-CTR (Counter) mode */
#if defined(PSA_WANT_ALG_CTR)
#define IFX_PSA_CRYPTOSUITE_AES_CTR
#endif

/**
 * \brief Master AES enable
 * 
 * \details
 *  Enabled if any AES cipher mode is configured. This controls the
 *  availability of AES cipher operations in the transparent driver.
 */
#if defined(IFX_PSA_CRYPTOSUITE_AES_ECB) || defined(IFX_PSA_CRYPTOSUITE_AES_CBC) \
  || defined(IFX_PSA_CRYPTOSUITE_AES_CTR)
#define IFX_PSA_CRYPTOSUITE_AES
#endif

/*******************************************************************************
 * AEAD Configuration
 ******************************************************************************/

/**
 * \brief Enable CCM (Counter with CBC-MAC) AEAD mode
 *
 * \details
 *  CCM provides authenticated encryption with associated data using AES.
 *  Requires IFX_PSA_CRYPTOSUITE_AES to be enabled.
 */
#if defined(PSA_WANT_ALG_CCM)
#define IFX_PSA_CRYPTOSUITE_CCM
#endif

/*******************************************************************************
 * MAC Configuration
 ******************************************************************************/

/**
 * \brief Enable CMAC (Cipher-based MAC) algorithm
 *
 * \details
 *  CMAC provides message authentication using AES.
 *  Requires IFX_PSA_CRYPTOSUITE_AES to be enabled.
 */
#if defined(PSA_WANT_ALG_CMAC)
#define IFX_PSA_CRYPTOSUITE_CMAC
#endif

/*******************************************************************************
 * Grouped Configuration Macros
 ******************************************************************************/
/** Enable cipher operation support (set if AES is enabled) */
#if defined(IFX_PSA_CRYPTOSUITE_AES)
#define IFX_PSA_CRYPTOSUITE_CIPHER
#endif

/** Enable MAC operation support (set if CMAC is enabled) */
#if defined(IFX_PSA_CRYPTOSUITE_CMAC)
#define IFX_PSA_CRYPTOSUITE_MAC
#endif

/** Enable AEAD operation support (set if CCM is enabled) */
#if defined(IFX_PSA_CRYPTOSUITE_CCM)
#define IFX_PSA_CRYPTOSUITE_AEAD
#endif


/*******************************************************************************
 * Configuration Validation
 ******************************************************************************/
/** Verify that at least one AES mode is selected when AES is enabled */
#if defined(IFX_PSA_CRYPTOSUITE_AES) && (!defined(IFX_PSA_CRYPTOSUITE_AES_ECB) \
  && !defined(IFX_PSA_CRYPTOSUITE_AES_CBC) \
  && !defined(IFX_PSA_CRYPTOSUITE_AES_CTR))
#error "IFX_PSA_CRYPTOSUITE_AES is defined but no AES mode is selected"
#endif

/** Verify that AES is enabled when CCM is requested */
#if defined(IFX_PSA_CRYPTOSUITE_CCM) && !defined(IFX_PSA_CRYPTOSUITE_AES)
#error "IFX_PSA_CRYPTOSUITE_AES is required for CCM operation"
#endif

/** Verify that AES is enabled when CMAC is requested */
#if defined(IFX_PSA_CRYPTOSUITE_CMAC) && !defined(IFX_PSA_CRYPTOSUITE_AES)
#error "IFX_PSA_CRYPTOSUITE_AES is required for CMAC operation"
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_PSA_CRYPTOSUITE_USER_CONFIG_FILE */

#if defined(__cplusplus)
}
#endif

#endif /* #if !defined (IFX_CRYPTOSUITE_CONFIG_H) */
