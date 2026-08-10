/***************************************************************************//**
* \file ifx_cryptolite_config.h
*
* \brief
*  PSA cryptolite driver configuration file.
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
#if !defined(IFX_CRYPTOLITE_CONFIG_H)
#define IFX_CRYPTOLITE_CONFIG_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "cy_device.h"

#if defined(CY_IP_MXCRYPTOLITE)

#if defined(IFX_PSA_CRYPTOLITE_USER_CONFIG_FILE)
#include IFX_PSA_CRYPTOLITE_USER_CONFIG_FILE
#else

#include "mbedtls/build_info.h"
#include "psa/crypto_driver_common.h"

/* Default configuration of PSA CRYPTOLITE Driver:
 *
 * - SHA256
 * - HMAC-SHA256
 * - RSA PKCS#1.l5 verification
 * - ECDSA verification
 */

#if defined(PSA_WANT_KEY_TYPE_DERIVE)
#define IFX_PSA_CRYPTOLITE_KEY_DERIVATION
#endif

#if defined(PSA_WANT_ALG_HMAC)
#define IFX_PSA_CRYPTOLITE_HMAC
#endif

#if defined(PSA_WANT_ALG_CMAC)
#define IFX_PSA_CRYPTOLITE_CMAC
#endif

#if defined(PSA_WANT_ALG_SHA_256)
#define IFX_PSA_CRYPTOLITE_SHA_256
#endif

#if defined(PSA_WANT_ALG_SHA_384)
#define IFX_PSA_CRYPTOLITE_SHA_384
#endif

#if defined(PSA_WANT_ALG_SHA_512)
#define IFX_PSA_CRYPTOLITE_SHA_512
#endif
#if (defined(PSA_WANT_ALG_SHA_256) ||  defined(PSA_WANT_ALG_SHA_384) ||  defined(PSA_WANT_ALG_SHA_512) )
#define IFX_PSA_CRYPTOLITE_SHA
#endif

/*  AES configuration */

#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
#define IFX_PSA_CRYPTOLITE_ECB_NO_PADDING
#endif

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#define IFX_PSA_CRYPTOLITE_CBC_NO_PADDING
#endif

#if defined(PSA_WANT_ALG_CFB)
#define IFX_PSA_CRYPTOLITE_CFB
#endif

#if defined(PSA_WANT_ALG_CTR)
#define IFX_PSA_CRYPTOLITE_CTR
#endif

#if defined(PSA_WANT_ALG_CCM)
#define IFX_PSA_CRYPTOLITE_CCM
#endif

/*  ECDSA configuration */

#if defined(PSA_WANT_ECC_SECP_R1_192)
#define IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192
#endif

#if defined(PSA_WANT_ECC_SECP_R1_224)
#define IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224
#endif

#if defined(PSA_WANT_ECC_SECP_R1_256)
#define IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256
#endif

#if defined(PSA_WANT_ECC_SECP_R1_384)
#define IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384
#endif

#if defined(PSA_WANT_ECC_SECP_R1_521)
#define IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521
#endif


/*  ECDH configuration */
#if (defined(PSA_WANT_ALG_ECDH) &&  (defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR) || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)))        \
  && (defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)                                      \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384))     
#define IFX_PSA_CRYPTOLITE_ECDH
#endif

/*  RSA configuration */
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#define IFX_PSA_CRYPTOLITE_RSA_PUBLIC_KEY_EXPORT
#endif

#if (defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY))        \
  && (defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)                                      \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384))     
#define IFX_PSA_CRYPTOLITE_ECC_PUBLIC_KEY_EXPORT
#endif

#if defined(IFX_PSA_CRYPTOLITE_RSA_PUBLIC_KEY_EXPORT) \
  || defined(IFX_PSA_CRYPTOLITE_ECC_PUBLIC_KEY_EXPORT)
#define IFX_PSA_CRYPTOLITE_PUBLIC_KEY_EXPORT
#endif

#if defined(PSA_WANT_ALG_ECDSA)
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define IFX_PSA_CRYPTOLITE_ECDSA_SIGN
#else
  #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR) \
  && (defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)                                      \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)                                        \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521))     
#define IFX_PSA_CRYPTOLITE_ECDSA_VERIFY
#define IFX_PSA_CRYPTOLITE_ECDSA_VERIFY_USE_PK
  #endif
#endif /*PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC*/

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) // Defined to be compatible with mbedtls 3.6
#if !defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)
  #define IFX_PSA_CRYPTOLITE_ECDSA_VERIFY
#endif
#if !defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY_USE_PK)
  #define IFX_PSA_CRYPTOLITE_ECDSA_VERIFY_USE_PK
#endif
#endif /*PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY*/

#endif /*PSA_WANT_ALG_ECDSA*/

#if  (defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)  || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE))     \
  && (defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)                                                         \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)                                                          \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256)                                                          \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384))     
#define IFX_PSA_CRYPTOLITE_KEY_GENERATION
#endif


/*  RSA configuration */
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && \
     (defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) || \
     defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR))
#define IFX_PSA_CRYPTOLITE_RSA
/* RSA PKCS 1.5 verification */
#define IFX_PSA_CRYPTOLITE_RSA_VERIFY
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
//#define IFX_PSA_CRYPTOLITE_RSA_SIGN
#endif
/* Use Static mem allocation */
//#define IFX_PSA_CRYPTOLITE_USE_STATIC_MEM
/* Use Stack mem allocation */
// #define IFX_PSA_CRYPTOLITE_USE_STACK_MEM

#endif

#if defined(IFX_PSA_CRYPTOLITE_RSA_SIGN)
#error "IFX_PSA_CRYPTOLITE_RSA_SIGN is not supported"
#endif

#if !defined(IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE)
#define IFX_PSA_CRYPTOLITE_RSA_MODULUS_SIZE (2048)
#endif

#if !defined(IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE)
#define IFX_PSA_CRYPTOLITE_RSA_PUB_EXP_SIZE (256)
#endif


#if defined(IFX_PSA_CRYPTOLITE_ECB_NO_PADDING) || defined(IFX_PSA_CRYPTOLITE_CBC_NO_PADDING)  || defined(IFX_PSA_CRYPTOLITE_CFB) \
  || defined(IFX_PSA_CRYPTOLITE_CTR)           
#define IFX_PSA_CRYPTOLITE_CIPHER
#endif

#if defined(IFX_PSA_CRYPTOLITE_HMAC) || defined(IFX_PSA_CRYPTOLITE_CMAC)           
#define IFX_PSA_CRYPTOLITE_MAC
#endif

#if defined(IFX_PSA_CRYPTOLITE_CCM)
#define IFX_PSA_CRYPTOLITE_AEAD
#endif

/* Check Key derivation configuration */
#if defined(IFX_PSA_CRYPTOLITE_KEY_DERIVATION) && (defined(IFX_PSA_CRYPTOLITE_USE_STATIC_MEM) || defined(IFX_PSA_CRYPTOLITE_USE_STACK_MEM))
#include <stdlib.h>
#if !defined(ifx_mxcryptolite_malloc)
#define ifx_mxcryptolite_malloc malloc
#endif
#if !defined(ifx_mxcryptolite_free)
#define ifx_mxcryptolite_free free
#endif
#endif

/* Check SHA configuration */
#if defined(IFX_PSA_CRYPTOLITE_SHA_256) && !defined(IFX_PSA_CRYPTOLITE_SHA)
#error "IFX_PSA_CRYPTOLITE_SHA is not defined to use SHA digests"
#endif

#if defined(IFX_PSA_CRYPTOLITE_SHA) && (!defined(IFX_PSA_CRYPTOLITE_SHA_256) && !defined(IFX_PSA_CRYPTOLITE_SHA_384) && !defined(IFX_PSA_CRYPTOLITE_SHA_512))
#error "IFX_PSA_CRYPTOLITE_SHA is defined but no SHA mode is selected"
#endif

/* Check HMAC configuration */
#if defined(IFX_PSA_CRYPTOLITE_HMAC) && !defined(IFX_PSA_CRYPTOLITE_SHA)
#error "IFX_PSA_CRYPTOLITE_SHA is not defined to use HMAC calculation"
#endif /* defined(IFX_PSA_CRYPTOLITE_HMAC) && !defined(IFX_PSA_CRYPTOLITE_SHA) */

/* Check RSA verify configuration */
#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY) && !defined(IFX_PSA_CRYPTOLITE_RSA)
#error "IFX_PSA_CRYPTOLITE_RSA is not defined to use RSA verification functionality"
#endif

#if defined(IFX_PSA_CRYPTOLITE_RSA_VERIFY) && !defined(IFX_PSA_CRYPTOLITE_SHA)
#error "IFX_PSA_CRYPTOLITE_SHA is not defined to use RSA verification functionality"
#endif

/* Check ECDSA configuration */
#if (defined(IFX_PSA_CRYPTOLITE_ECDSA_VERIFY)) && !(defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256) \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384)  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_521))     
#error "IFX_PSA_CRYPTOLITE_ECC_SECP_R1_xxx curve not defined for ECDSA functionality"
#endif


#if (defined(IFX_PSA_CRYPTOLITE_ECDH)) && !(defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_224)  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_256) \
  || defined(IFX_PSA_CRYPTOLITE_ECC_SECP_R1_384))     
#error "IFX_PSA_CRYPTOLITE_ECC_SECP_R1_xxx curve not defined for ECDH functionality"
#endif

#endif /* CY_IP_MXCRYPTOLITE */

#if defined(__cplusplus)
}
#endif

#endif /* #if !defined (IFX_CRYPTOLITE_CONFIG_H) */
