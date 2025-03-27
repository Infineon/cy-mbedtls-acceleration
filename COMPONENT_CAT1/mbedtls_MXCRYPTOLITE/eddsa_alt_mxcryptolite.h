/*
 *  Copyright The Mbed TLS Contributors
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
 * \file    eddsa_alt_mxcryptolite.h
 * \version 2.3.0
 *
 * \brief   This file provides an API for Edward's Elliptic Curves over GF(P) (ECP).
 *          contains EDDSA definitions and functions.
 *
 * The Edwards-curve Digital Signature Algorithm (EdDSA) is defined in
 * <em>Standards for Efficient Cryptography Group (SECG):
 * SEC1 Elliptic Curve Cryptography</em>.
 * The use of EdDSA for TLS is defined in <em>RFC-8422: Elliptic Curve
 * Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
 * Versions 1.2 and Earlier</em>.
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#ifndef _EDDSA_ALT_CRYPTOLITE_H
#define _EDDSA_ALT_CRYPTOLITE_H

#include "mbedtls/bignum.h"
#include "mbedtls/compat-2.x.h"
#include "mbedtls/ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_EDDSA_ALT)

#include "cy_cryptolite.h"

#if defined(MBEDTLS_EDDSA_RESTARTABLE)
#error MBEDTLS_EDDSA_RESTARTABLE is not supported by Infineon implementation
#endif
/* Cryptolite does not support SHA512 HW acceleration, To be full filled by thirdparty implementations */
extern void *Cy_ed25519_sha512_ctx;
extern cy_en_cryptolite_status_t Cy_ed25519_sha512_init(void *context);
extern cy_en_cryptolite_status_t Cy_ed25519_sha512_start(void *context);
extern cy_en_cryptolite_status_t Cy_ed25519_sha512_update(void *context, const uint8_t *input, uint32_t length);
extern cy_en_cryptolite_status_t Cy_ed25519_sha512_finish(void *context, uint8_t *digest);
extern cy_en_cryptolite_status_t Cy_ed25519_sha512_free(void *context);


/* ED25519 Group ID */
#define MBEDTLS_ECP_DP_ED25519 (14u)

/*
 * mbed TLS eddsa implementation. There is no official eddsa support from the mbedTLS public library yet
 * and it is still work in progress.This iplementation follows the same interface signatures as proposed by mbedTLS
 * for future release.
 */
/**
 * EdDSA signature operation type.
 *
 * It identifies the signature operation type (pure, ctx or prehash).
 */

typedef enum
{
    MBEDTLS_EDDSA_NONE = 0, /*!< Operation not defined. */
    MBEDTLS_EDDSA_PURE,     /*!< Pure operation (the usual). It uses the entire message, without hashing it previously. */
    MBEDTLS_EDDSA_CTX,      /*!< Operation with a deterministic context. It uses the entire message, without hashing it previously. */
    MBEDTLS_EDDSA_PREHASH,  /*!< Operation with a pre-hashed message. It uses the hashed message instead of full message like pure or ctx. */
} mbedtls_eddsa_id;

/**
 * \brief           This function computes the EdDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated
 *                  as defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param grp       The context for the elliptic curve to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 * \param r         The MPI context in which to store the first part
 *                  the signature. This must be initialized.
 * \param s         The MPI context in which to store the second part
 *                  the signature. This must be initialized.
 * \param d         The private signing key. This must be initialized.
 * \param buf       The content to be signed. This is usually the hash of
 *                  the original data to be signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_eddsa_sign( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                mbedtls_eddsa_id eddsa_id,
                const unsigned char *ed_ctx, size_t ed_ctx_len,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           This function verifies the EdDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 * \param buf       The hashed content that was signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param Q         The public key to use for verification. This must be
 *                  initialized and setup.
 * \param r         The first integer of the signature.
 *                  This must be initialized.
 * \param s         The second integer of the signature.
 *                  This must be initialized.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_eddsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                          const mbedtls_mpi *s,
                          mbedtls_eddsa_id eddsa_id,
                          const unsigned char *ed_ctx, size_t ed_ctx_len );

#endif /* MBEDTLS_EDDSA_ALT */

#ifdef __cplusplus
}
#endif

#endif /* eddsa_alt.h */

#endif /* CY_IP_MXCRYPTO */
