/***************************************************************************//**
* \file ifx_mxcrypto_config.h
*
* \brief
*  PSA mxcrypto driver configuration file.
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
#if !defined(IFX_MXCRYPTO_CONFIG_H)
#define IFX_MXCRYPTO_CONFIG_H

#include "cy_device.h"
#include "cy_device_headers.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(CY_IP_MXCRYPTO)

#if defined(IFX_PSA_MXCRYPTO_USER_CONFIG_FILE)
#include IFX_PSA_MXCRYPTO_USER_CONFIG_FILE
#else

/* Default configuration of PSA MXCRYPTO Driver:
 *
 * - SHA1
 * - SHA256
 * - SHA512
 * - HMAC
 * - RSA PKCS#1.l5 verification
 * - ECP multiplication
 * - ECDSA key generation
 * - ECDSA sign
 * - ECDSA verification
 */

#include "mbedtls/build_info.h"

/*  HMAC configuration */
#if defined(PSA_WANT_ALG_HMAC)
#define IFX_PSA_MXCRYPTO_HMAC
#endif

#if defined(PSA_WANT_ALG_CMAC)
#define IFX_PSA_MXCRYPTO_CMAC
#endif

/*  SHA configuration */
#if defined(PSA_WANT_ALG_SHA_1)
#define IFX_PSA_MXCRYPTO_SHA_1
#endif

#if defined(PSA_WANT_ALG_SHA_224)
#define IFX_PSA_MXCRYPTO_SHA_224
#endif

#if defined(PSA_WANT_ALG_SHA_256)
#define IFX_PSA_MXCRYPTO_SHA_256
#endif

#if defined(PSA_WANT_ALG_SHA_384)
#define IFX_PSA_MXCRYPTO_SHA_384
#endif

#if defined(PSA_WANT_ALG_SHA_512)
#define IFX_PSA_MXCRYPTO_SHA_512
#endif

#if defined(PSA_WANT_ALG_SHA3_224)
#define IFX_PSA_MXCRYPTO_SHA3_224
#endif

#if defined(PSA_WANT_ALG_SHA3_256)
#define IFX_PSA_MXCRYPTO_SHA3_256
#endif

#if defined(PSA_WANT_ALG_SHA3_384)
#define IFX_PSA_MXCRYPTO_SHA3_384
#endif

#if defined(PSA_WANT_ALG_SHA3_512)
#define IFX_PSA_MXCRYPTO_SHA3_512
#endif



/*  AES configuration */

#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
#define IFX_PSA_MXCRYPTO_ECB_NO_PADDING
#endif

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#define IFX_PSA_MXCRYPTO_CBC_NO_PADDING
#endif

#if defined(PSA_WANT_ALG_CFB)
#define IFX_PSA_MXCRYPTO_CFB
#endif

#if defined(PSA_WANT_ALG_CTR)
#define IFX_PSA_MXCRYPTO_CTR
#endif

#if defined(PSA_WANT_ALG_GCM)
#define IFX_PSA_MXCRYPTO_GCM
#endif

#if defined(PSA_WANT_ALG_CCM)
#define IFX_PSA_MXCRYPTO_CCM
#endif

/*  RSA configuration */
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#define IFX_PSA_MXCRYPTO_RSA_PUBLIC_KEY_EXPORT
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && \
     (defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) || \
     defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR))
  #define IFX_PSA_MXCRYPTO_RSA_VERIFY
  #define IFX_PSA_MXCRYPTO_RSA_SIGN
#endif

/*  ECDSA configuration */

#if defined(PSA_WANT_ECC_SECP_R1_192)
#define IFX_PSA_MXCRYPTO_ECC_SECP_R1_192
#endif

#if defined(PSA_WANT_ECC_SECP_R1_224)
#define IFX_PSA_MXCRYPTO_ECC_SECP_R1_224
#endif

#if defined(PSA_WANT_ECC_SECP_R1_256)
#define IFX_PSA_MXCRYPTO_ECC_SECP_R1_256
#endif

#if defined(PSA_WANT_ECC_SECP_R1_384)
#define IFX_PSA_MXCRYPTO_ECC_SECP_R1_384
#endif

#if defined(PSA_WANT_ECC_SECP_R1_521)
#define IFX_PSA_MXCRYPTO_ECC_SECP_R1_521
#endif

#if defined(PSA_WANT_ALG_ECDSA)
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define IFX_PSA_MXCRYPTO_ECDSA_SIGN
#else
  #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR) \
  && (defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)                                      \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)                                        \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)                                        \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)                                        \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
  #define IFX_PSA_MXCRYPTO_ECDSA_VERIFY
  #define IFX_PSA_MXCRYPTO_ECDSA_SIGN
  #define IFX_PSA_MXCRYPTO_ECDSA_VERIFY_USE_PK
  #endif
#endif /*PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC*/

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) // Defined to be compatible with mbedtls 3.6
#if !defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY)
  #define IFX_PSA_MXCRYPTO_ECDSA_VERIFY
#endif
#if !defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY_USE_PK)
  #define IFX_PSA_MXCRYPTO_ECDSA_VERIFY_USE_PK
#endif
#endif /*PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY*/

#endif /*PSA_WANT_ALG_ECDSA*/

#if  defined(PSA_WANT_ALG_ECDH)
#if  (defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR) || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC))         \
  && (defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)                                                         \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#define IFX_PSA_MXCRYPTO_ECDH
#endif
#endif

#if  (defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)  || defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE))     \
  && (defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)                                                         \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)                                                          \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#define IFX_PSA_MXCRYPTO_KEY_GENERATION
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)                                        \
  && (defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)                                      \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)                                       \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256)                                       \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)                                       \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#define IFX_PSA_MXCRYPTO_ECC_PUBLIC_KEY_EXPORT
#endif

#if defined(IFX_PSA_MXCRYPTO_RSA_PUBLIC_KEY_EXPORT) \
  || defined(IFX_PSA_MXCRYPTO_ECC_PUBLIC_KEY_EXPORT)
#define IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT
#endif

/* Use Static mem allocation */
//#define IFX_PSA_MXCRYPTO_USE_STATIC_MEM
/* Use Stack mem allocation */
//#define IFX_PSA_MXCRYPTO_USE_STACK_MEM

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
#define IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT
#endif
#if defined(PSA_WANT_ALG_RSA_OAEP)
#define IFX_PSA_MXCRYPTO_RSA_OEAP
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) || defined(PSA_WANT_ALG_RSA_OAEP)
#define IFX_PSA_MXCRYPTO_RSA_ENCRYPT
#define IFX_PSA_MXCRYPTO_RSA_DECRYPT
#endif



/* RSA Key size*/
//#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (4096)
//#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (3072)
//#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (2048)
//#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (1024)
//#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (512)

//#if (CY_IP_MXCRYPTO_VERSION == 2u)
/* Disabled chacha20 functionality */
//#define IFX_PSA_MXCRYPTO_CHACHA
//#endif

#endif

#if !defined(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)
#define IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE (2048)
#endif

#if !defined(IFX_PSA_MXCRYPTO_RSA_PUB_EXP_SIZE)
#define IFX_PSA_MXCRYPTO_RSA_PUB_EXP_SIZE (256)
#endif

#if defined(IFX_PSA_MXCRYPTO_SHA_1) || \
     defined(IFX_PSA_MXCRYPTO_SHA_224) || \
     defined(IFX_PSA_MXCRYPTO_SHA_256) || \
     defined(IFX_PSA_MXCRYPTO_SHA_384) || \
     defined(IFX_PSA_MXCRYPTO_SHA_512) 
#define IFX_PSA_MXCRYPTO_SHA
#endif

#if defined(IFX_PSA_MXCRYPTO_HMAC) || defined(IFX_PSA_MXCRYPTO_CMAC)
#define IFX_PSA_MXCRYPTO_MAC
#endif

#if defined(IFX_PSA_MXCRYPTO_ECB_NO_PADDING) || defined(IFX_PSA_MXCRYPTO_CBC_NO_PADDING)  || defined(IFX_PSA_MXCRYPTO_CFB) \
  || defined(IFX_PSA_MXCRYPTO_CTR) || defined(IFX_PSA_MXCRYPTO_GCM)           
#define IFX_PSA_MXCRYPTO_CIPHER
#endif

#if defined(IFX_PSA_MXCRYPTO_GCM) || defined(IFX_PSA_MXCRYPTO_CCM)
#define IFX_PSA_MXCRYPTO_AEAD
#endif

/* Check HMAC configuration */
#if defined(IFX_PSA_MXCRYPTO_HMAC) && !defined(IFX_PSA_MXCRYPTO_SHA)
#error "IFX_PSA_MXCRYPTO_SHA is not defined to use HMAC calculation"
#endif /* defined(IFX_PSA_MXCRYPTO_HMAC) && !defined(IFX_PSA_MXCRYPTO_SHA) */

/* Check RSA verify configuration */
#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY) && !defined(IFX_PSA_MXCRYPTO_SHA)
#error "IFX_PSA_MXCRYPTO_SHA is not defined to use RSA verification functionality"
#endif

/* Check RSA OAEP configuration */
#if defined(IFX_PSA_MXCRYPTO_RSA_OEAP) && !defined(IFX_PSA_MXCRYPTO_SHA)
#error "IFX_PSA_MXCRYPTO_SHA is not defined to use RSA OAEP functionality"
#endif

#if defined(IFX_PSA_MXCRYPTO_RSA_VERIFY) && !defined(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)
#error "IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE is not defined to use RSA verification functionality"
#endif

/* Check ECDSA configuration */
#if defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY) && !defined(IFX_PSA_MXCRYPTO_SHA)
#error "IFX_PSA_MXCRYPTO_SHA is not defined to use ECDSA functionalities"
#endif

#if (defined(IFX_PSA_MXCRYPTO_ECDSA_VERIFY) || defined(IFX_PSA_MXCRYPTO_ECDSA_SIGN)) && !(defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256) \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)   || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#error "IFX_PSA_MXCRYPTO_ECC_SECP_R1_xxx curve not defined for ECDSA sign/verify functionality"
#endif


#if (defined(IFX_PSA_MXCRYPTO_ECDH)) && !(defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256) \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)   || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#error "IFX_PSA_MXCRYPTO_ECC_SECP_R1_xxx curve not defined for ECDH functionality"
#endif

#if (defined(IFX_PSA_MXCRYPTO_KEY_GENERATION)) && !(defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256) \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)   || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#error "IFX_PSA_MXCRYPTO_ECC_SECP_R1_xxx curve not defined for key generation functionality"
#endif

#if (defined(IFX_PSA_MXCRYPTO_PUBLIC_KEY_EXPORT)) && !(defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_192)   \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_224)  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_256) \
  || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_384)   || defined(IFX_PSA_MXCRYPTO_ECC_SECP_R1_521))     
#error "IFX_PSA_MXCRYPTO_ECC_SECP_R1_xxx curve not defined for public key export functionality"
#endif

#endif /* CY_IP_MXCRYPTO */

#if defined(__cplusplus)
}
#endif

#endif /* #if !defined (IFX_MXCRYPTO_CONFIG_H) */
