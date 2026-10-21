/***************************************************************************//**
* \file ifx_wolfcrypto_common.h
*
* \brief
*  PSA crypto wolfcrypto helper functions and shared definitions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors
*
* Copyright (C) 2026 Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.
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

#if !defined(IFX_WOLFCRYPTO_COMMON_H)
#define IFX_WOLFCRYPTO_COMMON_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT)

#include <psa/crypto.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
/* wc_mlkem.h provides the full MlKemKey struct definition and the
 * WC_ML_KEM_MAKEKEY_RAND_SZ macro */
#if defined(WOLFSSL_HAVE_MLKEM)
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/* Memory / string helpers (overridable). */
#if !defined(ifx_wolfcrypto_malloc)
#include <stdlib.h>
#define ifx_wolfcrypto_malloc   malloc
#endif
#if !defined(ifx_wolfcrypto_free)
#include <stdlib.h>
#define ifx_wolfcrypto_free     free
#endif
#if !defined(ifx_wolfcrypto_memcpy)
#include <string.h>
#define ifx_wolfcrypto_memcpy   memcpy
#endif
#if !defined(ifx_wolfcrypto_memset)
#include <string.h>
#define ifx_wolfcrypto_memset   memset
#endif

/* Size, in bytes, of the ML-DSA (FIPS 204) private key seed (xi). This is the
 * PSA export representation of an ML-DSA key pair and is identical for every
 * parameter set. */
#define IFX_WOLFCRYPTO_MLDSA_SEED_SIZE      (32u)

/* Size, in bytes, of the ML-KEM (FIPS 203) key generation seed (d || z). This
 * is the PSA export representation of an ML-KEM key pair and is identical for
 * every parameter set. */
#if defined(WOLFSSL_HAVE_MLKEM)
#define IFX_WOLFCRYPTO_MLKEM_SEED_SIZE      (WC_ML_KEM_MAKEKEY_RAND_SZ)
#endif

/*******************************************************************************
* Function Name: ifx_wolfcrypto_status_to_psa_status
****************************************************************************//**
*
* Converts a wolfCrypt return code (0 on success, negative wolfSSL error code
* otherwise) into the corresponding PSA status code.
*
* \param wc_status  The wolfCrypt return code.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_status_to_psa_status(int wc_status);

#if defined(HAVE_DILITHIUM)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_mldsa_level_from_bits
****************************************************************************//**
*
* Maps the PSA key size (in bits) of an ML-DSA key to the wolfCrypt security
* level identifier (WC_ML_DSA_44 / _65 / _87).
*
* \param bits   PSA key size in bits (44, 65 or 87).
* \param level  Output wolfCrypt level identifier.
*
* \return PSA_SUCCESS or PSA_ERROR_NOT_SUPPORTED for an unknown size.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_mldsa_level_from_bits(size_t bits, byte *level);
#endif /* HAVE_DILITHIUM */

#if defined(WOLFSSL_HAVE_MLKEM)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_mlkem_type_from_bits
****************************************************************************//**
*
* Maps the PSA key size (in bits) of an ML-KEM key to the wolfCrypt key type
* identifier (WC_ML_KEM_512 / _768 / _1024).
*
* \param bits  PSA key size in bits (512, 768 or 1024).
* \param type  Output wolfCrypt key type identifier.
*
* \return PSA_SUCCESS or PSA_ERROR_NOT_SUPPORTED for an unknown size.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_mlkem_type_from_bits(size_t bits, int *type);
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_PRESENT */

#endif /* #if !defined (IFX_WOLFCRYPTO_COMMON_H) */
