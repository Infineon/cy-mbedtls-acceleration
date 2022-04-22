/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (c) (2019-2022), Cypress Semiconductor Corporation (an Infineon company) or
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * \file    ecdh_alt_mxcrypto.c
 * \version 1.4
 *
 * \brief   This file provides an API for ECDH algorithm acceleration.
 *
 */
 /*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "cy_crypto_core_ecc.h"
#include "crypto_common.h"

/* Parameter validation macros based on platform_util.h */
#define ECDH_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDH_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/**
 * \brief           This function generates an ECDH keypair on an elliptic
 *                  curve.
 *
 *                  This function performs the first of two core computations
 *                  implemented during the ECDH key exchange. The second core
 *                  computation is performed by mbedtls_ecdh_compute_shared().
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param d         The destination MPI (private key).
 *                  This must be initialized.
 * \param Q         The destination point (public key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;
    size_t bytesize;
    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;
    cy_stc_crypto_ecc_key key;
    cy_stc_crypto_ecc_dp_type *dp;
    cy_en_crypto_status_t ecdh_status;

    ECDH_VALIDATE_RET( grp != NULL );
    ECDH_VALIDATE_RET( d != NULL );
    ECDH_VALIDATE_RET( Q != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

    if( mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        return( ret );
    }

    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Reserve the crypto hardware for the operation */
    cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_VU);

    key.curveID = cy_get_dp_idx(grp->id);
    ECDH_VALIDATE_RET( key.curveID != CY_CRYPTO_ECC_ECP_NONE);

    dp = Cy_Crypto_Core_ECC_GetCurveParams(key.curveID);
    bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    MBEDTLS_MPI_CHK( mbedtls_mpi_grow(d, bytesize) );
    key.k = (uint8_t *)d->p;

    /* Q.Z coordinate should be 1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &Q->Z, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &Q->X, bytesize ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &Q->Y, bytesize ) );
    key.pubkey.x = (uint8_t *)Q->X.p;
    key.pubkey.y = (uint8_t *)Q->Y.p;

    ecdh_status = Cy_Crypto_Core_ECC_MakeKeyPair(crypto_obj.base, key.curveID, &key, f_rng, p_rng);
    MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_ECP_HW_ACCEL_FAILED : 0);

cleanup:
    /* Realease the crypto hardware */
    cy_hw_crypto_release(&crypto_obj);

    return( ret );
}    
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#endif /* MBEDTLS_ECDH_C */

#endif /* CY_IP_MXCRYPTO */
