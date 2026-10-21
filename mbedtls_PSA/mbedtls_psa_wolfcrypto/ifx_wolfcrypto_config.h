/***************************************************************************//**
* \file ifx_wolfcrypto_config.h
*
* \brief
*  PSA wolfcrypto driver configuration file.
*
*  This header translates the PSA capability macros (PSA_WANT_*) and the
*  underlying wolfCrypt capability macros (HAVE_DILITHIUM, WOLFSSL_HAVE_MLKEM)
*  into the IFX_PSA_WOLFCRYPTO_* feature macros that gate the transparent
*  driver entry points. The PSA driver dispatch layer (in TF-PSA-Crypto)
*  references these IFX_PSA_WOLFCRYPTO_* macros directly.
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
#if !defined(IFX_WOLFCRYPTO_CONFIG_H)
#define IFX_WOLFCRYPTO_CONFIG_H

/* Everything in this header (and therefore every IFX_PSA_WOLFCRYPTO_* feature
 * macro it defines) only exists when the wolfcrypto transparent driver has
 * been selected for this build via IFX_PSA_WOLFCRYPTO_PRESENT. This keeps
 * builds that don't use this backend from pulling in any wolfSSL headers. */
#if defined(IFX_PSA_WOLFCRYPTO_PRESENT)

/* Pull in the wolfCrypt build configuration (user_settings.h / settings.h)
 * so that the HAVE_DILITHIUM / WOLFSSL_HAVE_MLKEM capability macros and the
 * per-parameter-set exclusions are visible here. */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(IFX_PSA_WOLFCRYPTO_USER_CONFIG_FILE)
#include IFX_PSA_WOLFCRYPTO_USER_CONFIG_FILE
#else

/* Default configuration of the PSA WOLFCRYPTO Driver:
 *
 * - ML-DSA (Dilithium) sign / verify / key generation / public key export
 * - ML-KEM (Kyber) encapsulate / decapsulate / key generation /
 *   public key export
 *
 * The individual mechanisms are only enabled when the corresponding wolfCrypt
 * feature has been compiled in.
 */

/*
 * ML-DSA (FIPS 204) configuration.
 */
#if defined(HAVE_DILITHIUM)

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN)
#define IFX_PSA_WOLFCRYPTO_MLDSA_SIGN
#endif

/* wc_dilithium_sign_ctx_msg() shares the same underlying signing capability
 * as wc_dilithium_sign_msg() (both are gated by WOLFSSL_DILITHIUM_NO_SIGN in
 * wolfCrypt), so PSA's context-carrying psa_sign_message_with_context() is
 * supported whenever plain message signing is. */
#if !defined(WOLFSSL_DILITHIUM_NO_SIGN)
#define IFX_PSA_WOLFCRYPTO_MLDSA_SIGN_CONTEXT
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
#define IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY
#endif

/* wc_dilithium_verify_ctx_msg() shares the same underlying verification
 * capability as wc_dilithium_verify_msg(). */
#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
#define IFX_PSA_WOLFCRYPTO_MLDSA_VERIFY_CONTEXT
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
#define IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION
#endif

/* Public key derivation from the private seed and key import both require the
 * ability to expand a key from its seed (make key) as well as the public-key
 * encode path. */
#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
#define IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT
#endif

#define IFX_PSA_WOLFCRYPTO_MLDSA_IMPORT

#endif /* HAVE_DILITHIUM */

/*
 * ML-KEM (FIPS 203) configuration.
 */
#if defined(WOLFSSL_HAVE_MLKEM)

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE)
#define IFX_PSA_WOLFCRYPTO_MLKEM_ENCAPSULATE
#endif

#if !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#define IFX_PSA_WOLFCRYPTO_MLKEM_DECAPSULATE
#endif

#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY)
#define IFX_PSA_WOLFCRYPTO_MLKEM_KEY_GENERATION
#define IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT
#endif

#define IFX_PSA_WOLFCRYPTO_MLKEM_IMPORT

#endif /* WOLFSSL_HAVE_MLKEM */

/* Memory allocation strategy for the wolfCrypt key context objects
 * (dilithium_key / MlKemKey) used internally by this driver.
 *
 * By default these are heap-allocated via ifx_wolfcrypto_malloc() /
 * ifx_wolfcrypto_free(). Uncomment one of the following to use a
 * statically-allocated or stack-allocated instance instead, for targets
 * that want to avoid heap usage.
 *
 * wolfCrypt already sizes dilithium_key / MlKemKey for the largest
 * parameter set enabled in the build (see DILITHIUM_MAX_PUB_KEY_SIZE /
 * DILITHIUM_MAX_KEY_SIZE and WC_ML_KEM_MAX_K in the wolfCrypt headers), so a
 * single instance safely accommodates ML-DSA-44/65/87 and
 * ML-KEM-512/768/1024 within the same build; no per-level sizing is needed.
 *
 * Note: IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM uses one static (not reentrant,
 * not thread-safe) instance per driver function. */

/* Use Static mem allocation */
//#define IFX_PSA_WOLFCRYPTO_USE_STATIC_MEM
/* Use Stack mem allocation */
//#define IFX_PSA_WOLFCRYPTO_USE_STACK_MEM

#endif /* IFX_PSA_WOLFCRYPTO_USER_CONFIG_FILE */

/*
 * Aggregate (umbrella) gates used by the PSA driver dispatch layer. The
 * dispatch checks a single macro per PSA entry point; the per-mechanism gates
 * above are used to select the algorithm branch inside each entry point.
 */
#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION) || \
    defined(IFX_PSA_WOLFCRYPTO_MLKEM_KEY_GENERATION)
#define IFX_PSA_WOLFCRYPTO_KEY_GENERATION
#endif

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_PUBLIC_KEY_EXPORT) || \
    defined(IFX_PSA_WOLFCRYPTO_MLKEM_PUBLIC_KEY_EXPORT)
#define IFX_PSA_WOLFCRYPTO_PUBLIC_KEY_EXPORT
#endif

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_IMPORT) || \
    defined(IFX_PSA_WOLFCRYPTO_MLKEM_IMPORT)
#define IFX_PSA_WOLFCRYPTO_IMPORT
#endif

#if defined(__cplusplus)
}
#endif

#endif /* IFX_PSA_WOLFCRYPTO_PRESENT */

#endif /* #if !defined (IFX_WOLFCRYPTO_CONFIG_H) */
