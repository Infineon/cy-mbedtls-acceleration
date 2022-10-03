/*
 *  mbed Microcontroller Library
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2019-2022 Cypress Semiconductor Corporation
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
 * \file    ecp_alt_mxcrypto.h
 * \version 2.0
 *
 * \brief   This file provides an API for Elliptic Curves over GF(P) (ECP).
 *
 *          The use of ECP in cryptography and TLS is defined in
 *          <em>Standards for Efficient Cryptography Group (SECG): SEC1
 *          Elliptic Curve Cryptography</em> and
 *          <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 *          for Transport Layer Security (TLS)</em>.
 *
 *          <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
 *          group types.
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#ifndef ECP_ALT_H
#define ECP_ALT_H

#include "mbedtls/bignum.h"
#include "mbedtls/compat-2.x.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_ECP_ALT)

#if defined(MBEDTLS_ECP_RESTARTABLE)
#error MBEDTLS_ECP_RESTARTABLE is not supported by Cypress implementation
#endif

#include "cy_crypto_core_ecc.h"

/*
 * default mbed TLS elliptic curve arithmetic implementation
 *
 * (in case MBEDTLS_ECP_ALT is defined then the developer has to provide an
 * alternative implementation for the whole module and it will replace this
 * one.)
 */

/**
 * \brief           The ECP group structure.
 *
 * We consider two types of curve equations:
 * <ul><li>Short Weierstrass: <code>y^2 = x^3 + A x + B mod P</code>
 * (SEC1 + RFC-4492)</li>
 * <li>Montgomery: <code>y^2 = x^3 + A x^2 + x mod P</code> (Curve25519,
 * Curve448)</li></ul>
 * In both cases, the generator (\p G) for a prime-order subgroup is fixed.
 *
 * For Short Weierstrass, this subgroup is the whole curve, and its
 * cardinality is denoted by \p N. Our code requires that \p N is an
 * odd prime as mbedtls_ecp_mul() requires an odd number, and
 * mbedtls_ecdsa_sign() requires that it is prime for blinding purposes.
 *
 * For Montgomery curves, we do not store \p A, but <code>(A + 2) / 4</code>,
 * which is the quantity used in the formulas. Additionally, \p nbits is
 * not the size of \p N but the required size for private keys.
 *
 * If \p modp is NULL, reduction modulo \p P is done using a generic algorithm.
 * Otherwise, \p modp must point to a function that takes an \p mbedtls_mpi in the
 * range of <code>0..2^(2*pbits)-1</code>, and transforms it in-place to an integer
 * which is congruent mod \p P to the given MPI, and is close enough to \p pbits
 * in size, so that it may be efficiently brought in the 0..P-1 range by a few
 * additions or subtractions. Therefore, it is only an approximative modular
 * reduction. It must return 0 on success and non-zero on failure.
 *
 * \note        Alternative implementations of the ECP module must obey the
 *              following constraints.
 *              * Group IDs must be distinct: if two group structures have
 *                the same ID, then they must be identical.
 *              * The fields \c id, \c P, \c A, \c B, \c G, \c N,
 *                \c pbits and \c nbits must have the same type and semantics
 *                as in the built-in implementation.
 *                They must be available for reading, but direct modification
 *                of these fields does not need to be supported.
 *                They do not need to be at the same offset in the structure.
 */
typedef struct mbedtls_ecp_group
{
    mbedtls_ecp_group_id MBEDTLS_PRIVATE(id);    /*!< An internal group identifier. */
    mbedtls_mpi MBEDTLS_PRIVATE(P);              /*!< The prime modulus of the base field. */
    mbedtls_mpi MBEDTLS_PRIVATE(A);              /*!< For Short Weierstrass: \p A in the equation. For
                                     Montgomery curves: <code>(A + 2) / 4</code>. */
    mbedtls_mpi MBEDTLS_PRIVATE(B);              /*!< For Short Weierstrass: \p B in the equation.
                                     For Montgomery curves: unused. */
    mbedtls_ecp_point MBEDTLS_PRIVATE(G);        /*!< The generator of the subgroup used. */
    mbedtls_mpi MBEDTLS_PRIVATE(N);              /*!< The order of \p G. */
    size_t MBEDTLS_PRIVATE(pbits);               /*!< The number of bits in \p P.*/
    size_t MBEDTLS_PRIVATE(nbits);               /*!< For Short Weierstrass: The number of bits in \p P.
                                     For Montgomery curves: the number of bits in the
                                     private keys. */
    /* End of public fields */

    unsigned int MBEDTLS_PRIVATE(h);             /*!< \internal 1 if the constants are static. */
    int (*MBEDTLS_PRIVATE(modp))(mbedtls_mpi *); /*!< The function for fast pseudo-reduction
                                     mod \p P (see above).*/
    int (*MBEDTLS_PRIVATE(t_pre))(mbedtls_ecp_point *, void *);  /*!< Unused. */
    int (*MBEDTLS_PRIVATE(t_post))(mbedtls_ecp_point *, void *); /*!< Unused. */
    void *MBEDTLS_PRIVATE(t_data);               /*!< Unused. */
    mbedtls_ecp_point *MBEDTLS_PRIVATE(T);       /*!< Pre-computed points for ecp_mul_comb(). */
    size_t MBEDTLS_PRIVATE(T_size);              /*!< The number of dynamic allocated pre-computed points. */
}
mbedtls_ecp_group;

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in mbedtls_config.h, or define them using the compiler command line.
 * \{
 */

#define MBEDTLS_ECP_MAX_BYTES    ( ( MBEDTLS_ECP_MAX_BITS + 7 ) / 8 )
#define MBEDTLS_ECP_MAX_PT_LEN   ( 2 * MBEDTLS_ECP_MAX_BYTES + 1 )

#if !defined(MBEDTLS_ECP_WINDOW_SIZE)
/*
 * Maximum "window" size used for point multiplication.
 * Default: a point where higher memory usage yields disminishing performance
 *          returns.
 * Minimum value: 2. Maximum value: 7.
 *
 * Result is an array of at most ( 1 << ( MBEDTLS_ECP_WINDOW_SIZE - 1 ) )
 * points used for point multiplication. This value is directly tied to EC
 * peak memory usage, so decreasing it by one should roughly cut memory usage
 * by two (if large curves are in use).
 *
 * Reduction in size may reduce speed, but larger curves are impacted first.
 * Sample performances (in ECDHE handshakes/s, with FIXED_POINT_OPTIM = 1):
 *      w-size:     6       5       4       3       2
 *      521       145     141     135     120      97
 *      384       214     209     198     177     146
 *      256       320     320     303     262     226
 *      224       475     475     453     398     342
 *      192       640     640     633     587     476
 */
#define MBEDTLS_ECP_WINDOW_SIZE    4   /**< The maximum window size used. */
#endif /* MBEDTLS_ECP_WINDOW_SIZE */

#if !defined(MBEDTLS_ECP_FIXED_POINT_OPTIM)
/*
 * Trade code size for speed on fixed-point multiplication.
 *
 * This speeds up repeated multiplication of the generator (that is, the
 * multiplication in ECDSA signatures, and half of the multiplications in
 * ECDSA verification and ECDHE) by a factor roughly 3 to 4.
 *
 * For each n-bit Short Weierstrass curve that is enabled, this adds 4n bytes
 * of code size if n < 384 and 8n otherwise.
 *
 * Change this value to 0 to reduce code size.
 */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0   /**< Enable fixed-point speed-up. */
#endif /* MBEDTLS_ECP_FIXED_POINT_OPTIM */

/* \} name SECTION: Module settings */

cy_en_crypto_ecc_curve_id_t cy_get_dp_idx(mbedtls_ecp_group_id gid);

#endif /* MBEDTLS_ECP_ALT */

#ifdef __cplusplus
}
#endif

#endif /* ecp_alt.h */

#endif /* CY_IP_MXCRYPTO */
