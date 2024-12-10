/*
 *  Edwards-curve Digital Signature Algorithm
 *
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

/*
 * \file    ed25519_alt_mxcrypto.c
 * \version 2.3.0
 *
 * \brief   This file provides an API for Elliptic Curves sign and verifications.
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#include "common.h"

#if defined(MBEDTLS_EDDSA_ALT)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"

#include "cy_crypto_core.h"
#include "cy_crypto_core_ecc.h"
#include "cy_crypto_core_vu.h"
#include "crypto_common.h"


#include "eddsa_alt.h"
#include <string.h>

/* Parameter validation macros based on platform_util.h */
#define EDDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define EDDSA_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Compute EdDSA signature of a message.
 * For PREHASH operation, the message is already previously hashed.
 * For PREHASH, we skip hash message step.
 */
int mbedtls_eddsa_sign( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                mbedtls_eddsa_id eddsa_id,
                const unsigned char *ed_ctx, size_t ed_ctx_len,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    size_t bytesize;
    uint8_t *sig = NULL;
    (void)p_rng;
    (void)f_rng;

    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;
    cy_stc_crypto_ecc_key key;
    cy_stc_crypto_edw_dp_type edwDp_t;
    cy_stc_crypto_edw_dp_type *dp = &edwDp_t;
    cy_en_crypto_status_t eddsa_status;
    cy_en_eddsa_sig_type_t sig_type = CY_CRYPTO_EDDSA_PURE;

    EDDSA_VALIDATE_RET( grp   != NULL );
    EDDSA_VALIDATE_RET( r     != NULL );
    EDDSA_VALIDATE_RET( s     != NULL );
    EDDSA_VALIDATE_RET( d     != NULL );
    EDDSA_VALIDATE_RET( eddsa_id != 0 );
    EDDSA_VALIDATE_RET( f_rng != NULL );
    EDDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    if(eddsa_id != MBEDTLS_EDDSA_PURE)
    {
        if(eddsa_id == MBEDTLS_EDDSA_CTX)
        {
            if( ed_ctx == NULL  || ed_ctx_len ==0 || ed_ctx_len > 255)
            {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            sig_type = CY_CRYPTO_EDDSA_CTX;
        }
        else if (eddsa_id == MBEDTLS_EDDSA_PREHASH)
        {
            sig_type = CY_CRYPTO_EDDSA_PREHASH;
        }
        else
        {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }
    if (grp->id == MBEDTLS_ECP_DP_ED25519)
    {
        key.curveID = CY_CRYPTO_ECC_ECP_ED25519;
    }
    else
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Make sure d is in range 1..n-1 */
    if( mbedtls_mpi_size( d ) != 32)
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    /* Reserve the crypto hardware for the operation */
    cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_VU);

    if(CY_CRYPTO_SUCCESS != Cy_Crypto_Core_EDW_GetCurveParams(dp, key.curveID))
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    key.k = mbedtls_malloc(bytesize);
    MBEDTLS_MPI_CHK((key.k == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( d, key.k, bytesize ) );
    Cy_Crypto_Core_InvertEndianness(key.k, bytesize);

    sig = mbedtls_malloc(2 * bytesize);
    MBEDTLS_MPI_CHK((sig == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

    eddsa_status = Cy_Crypto_Core_ED25519_Sign(crypto_obj.base, buf, blen, sig, &key, sig_type,
                                                ed_ctx, ed_ctx_len);
    MBEDTLS_MPI_CHK((eddsa_status == CY_CRYPTO_SUCCESS) ? 0 : MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);

    /* Prepare a signature to load into an mpi format */
    Cy_Crypto_Core_InvertEndianness(sig, bytesize);
    Cy_Crypto_Core_InvertEndianness(sig + bytesize, bytesize);

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( r, sig, bytesize ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( s, sig + bytesize, bytesize ) );

cleanup:
    /* Realease the crypto hardware */
    cy_hw_crypto_release(&crypto_obj);

    if (key.k != NULL)
    {
        mbedtls_platform_zeroize(key.k, bytesize);
        mbedtls_free(key.k);
    }
    if (sig != NULL)
    {
        mbedtls_platform_zeroize(sig, 2 * bytesize);
        mbedtls_free(sig);
    }

    return( ret );
}

/*
 * Verify EDDSA (ED25519) signature of message
 */
 int mbedtls_eddsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                          const mbedtls_mpi *s,
                          mbedtls_eddsa_id eddsa_id,
                          const unsigned char *ed_ctx, size_t ed_ctx_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    uint32_t stat;
    size_t bytesize;
    uint8_t *sig = NULL;
    uint8_t *point_arr = NULL;
    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;
    cy_stc_crypto_ecc_key key;
    cy_stc_crypto_edw_dp_type edwDp_t;
    cy_stc_crypto_edw_dp_type *dp = &edwDp_t;
    cy_en_crypto_status_t eddsa_ver_status;
    cy_en_eddsa_sig_type_t sig_type = CY_CRYPTO_EDDSA_PURE;

    EDDSA_VALIDATE_RET( grp != NULL );
    EDDSA_VALIDATE_RET( Q   != NULL );
    EDDSA_VALIDATE_RET( r   != NULL );
    EDDSA_VALIDATE_RET( s   != NULL );
    EDDSA_VALIDATE_RET( buf != NULL || blen == 0 );

    if(eddsa_id != MBEDTLS_EDDSA_PURE)
    {
        if(eddsa_id == MBEDTLS_EDDSA_CTX)
        {
            if( ed_ctx == NULL  || ed_ctx_len ==0 || ed_ctx_len > 255)
            {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            sig_type = CY_CRYPTO_EDDSA_CTX;
        }
        else if (eddsa_id == MBEDTLS_EDDSA_PREHASH)
        {
            sig_type = CY_CRYPTO_EDDSA_PREHASH;
        }
        else
        {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if (grp->id == MBEDTLS_ECP_DP_ED25519)
    {
        key.curveID = CY_CRYPTO_ECC_ECP_ED25519;
    }
    else
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK( (key.curveID == CY_CRYPTO_ECC_ECP_NONE) ? MBEDTLS_ERR_ECP_BAD_INPUT_DATA : 0);

    /* Reserve the crypto hardware for the operation */
    cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_VU);

    if(CY_CRYPTO_SUCCESS != Cy_Crypto_Core_EDW_GetCurveParams(dp, key.curveID))
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    bytesize   = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);

    point_arr = mbedtls_malloc(2 * bytesize);
    MBEDTLS_MPI_CHK((point_arr == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
    key.pubkey.x  = point_arr;
    key.pubkey.y  = point_arr + bytesize;

    sig = mbedtls_malloc(2 * bytesize);
    MBEDTLS_MPI_CHK((sig == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( r, sig, bytesize ) );
    Cy_Crypto_Core_InvertEndianness(sig, bytesize);

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( s, sig + bytesize, bytesize ) );
    Cy_Crypto_Core_InvertEndianness(sig + bytesize, bytesize);

    /* Export a pubKey from an mpi format to verify */
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Q->X, key.pubkey.x, bytesize ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Q->Y, key.pubkey.y, bytesize ) );
    Cy_Crypto_Core_InvertEndianness(key.pubkey.x, bytesize);
    Cy_Crypto_Core_InvertEndianness(key.pubkey.y, bytesize);

    eddsa_ver_status = Cy_Crypto_Core_ED25519_Verify(crypto_obj.base, sig, buf, blen,
         &key, &stat, sig_type, ed_ctx, ed_ctx_len);

    MBEDTLS_MPI_CHK((eddsa_ver_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);

    MBEDTLS_MPI_CHK((stat == 0xA1A1A1A1) ? 0 : MBEDTLS_ERR_ECP_VERIFY_FAILED);

cleanup:
    /* Realease the crypto hardware */
    cy_hw_crypto_release(&crypto_obj);

    if (point_arr != NULL)
    {
        mbedtls_platform_zeroize(point_arr, 2 * bytesize);
        mbedtls_free(point_arr);
    }
    if (sig != NULL)
    {
        mbedtls_platform_zeroize(sig, 2 * bytesize);
        mbedtls_free(sig);
    }

    return( ret );
}

#endif //#if defined(MBEDTLS_EDDSA_ALT)
