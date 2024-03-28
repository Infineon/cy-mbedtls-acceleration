/*
 *  ECDSA sign functions
 *
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

/*
 * \file    ecdsa_alt_mxcryptolite.c
 * \version 2.3.0
 *
 * \brief   This file provides an API for Elliptic Curves verifications.
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ECDSA_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/compat-2.x.h"

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)

#include "cy_cryptolite_common.h"
#include "cy_cryptolite.h"
#include "cy_cryptolite_utils.h"
#include "cryptolite_common.h"


cy_en_cryptolite_ecc_curve_id_t cy_get_dp_idx(mbedtls_ecp_group_id gid)
{
    cy_en_cryptolite_ecc_curve_id_t dp_idx;

    switch( gid )
    {
    #if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192R1:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_SECP192R1;
            break;
    #endif /* defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) */
    #if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224R1:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_SECP224R1;
            break;
    #endif /* defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) */
    #if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256R1:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_SECP256R1;
            break;
    #endif /* defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) */
    #if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP384R1:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_SECP384R1;
            break;
    #endif /* defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) */
    #if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP521R1:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_SECP521R1;
            break;
    #endif /* defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) */

        default:
            dp_idx = CY_CRYPTOLITE_ECC_ECP_NONE;
            break;
    }

    return dp_idx;
}

/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    cy_en_cryptolite_sig_verify_result_t ver_result = CY_CRYPTOLITE_SIG_INVALID;
    size_t bytesize;
    size_t olen;
    uint8_t *sig = NULL;
    uint8_t *point_arr = NULL;
    cy_stc_cryptolite_ecc_key  key;
    cy_stc_cryptolite_ecc_dp_type *eccDp;
    cy_stc_cryptolite_context_ecdsa_t sig_ctx;
    cy_stc_cryptolite_ecc_buffer_t *ecdsa_buf_ptr = NULL;
    uint8_t *buf_ptr = NULL;

    cy_en_cryptolite_status_t  cy_status  = CY_CRYPTOLITE_BAD_PARAMS;;

    ECDSA_VALIDATE_RET( grp != NULL );
    ECDSA_VALIDATE_RET( Q   != NULL );
    ECDSA_VALIDATE_RET( r   != NULL );
    ECDSA_VALIDATE_RET( s   != NULL );
    ECDSA_VALIDATE_RET( buf != NULL || blen == 0 );

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    key.curveID = cy_get_dp_idx(grp->id);
    MBEDTLS_MPI_CHK( (key.curveID == CY_CRYPTOLITE_ECC_ECP_NONE) ? MBEDTLS_ERR_ECP_BAD_INPUT_DATA : 0);

    eccDp = Cy_Cryptolite_ECC_GetCurveParams(key.curveID );

    bytesize   = CY_CRYPTOLITE_BYTE_SIZE_OF_BITS(eccDp->size);

    ecdsa_buf_ptr = (cy_stc_cryptolite_ecc_buffer_t *)mbedtls_malloc(sizeof(cy_stc_cryptolite_ecc_buffer_t));
    
    cy_status = Cy_Cryptolite_ECC_Init(CRYPTOLITE, &sig_ctx, ecdsa_buf_ptr);
    MBEDTLS_MPI_CHK((cy_status != CY_CRYPTOLITE_SUCCESS ) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);


    point_arr = mbedtls_malloc(2 * bytesize + 1u);
    MBEDTLS_MPI_CHK((point_arr == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
    key.pubkey.x  = point_arr + 1u;
    key.pubkey.y  = point_arr + bytesize + 1u;

    buf_ptr = mbedtls_malloc(blen);
    MBEDTLS_MPI_CHK((buf_ptr == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

    mbedtls_memcpy(buf_ptr, buf, blen);
    Cy_Cryptolite_InvertEndianness(buf_ptr, blen);

    sig = mbedtls_malloc(2 * bytesize);
    MBEDTLS_MPI_CHK((sig == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( r, sig, bytesize ) );
    Cy_Cryptolite_InvertEndianness(sig, bytesize);

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( s, sig + bytesize, bytesize ) );
    Cy_Cryptolite_InvertEndianness(sig + bytesize, bytesize);

    /* Export a signature from an mpi format to verify */
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_write_binary( grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, point_arr, 2 * bytesize + 1) );
    Cy_Cryptolite_InvertEndianness(key.pubkey.x, bytesize);
    Cy_Cryptolite_InvertEndianness(key.pubkey.y, bytesize);

    cy_status = Cy_Cryptolite_ECC_VerifyHash (CRYPTOLITE, &sig_ctx, sig, bytesize * 2, buf_ptr, blen, &ver_result, &key);
    MBEDTLS_MPI_CHK((cy_status != CY_CRYPTOLITE_SUCCESS ) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);

    MBEDTLS_MPI_CHK((ver_result == CY_CRYPTOLITE_SIG_VALID ) ? 0 : MBEDTLS_ERR_ECP_VERIFY_FAILED);

cleanup:

    if(buf_ptr != NULL)
    {
        mbedtls_free(buf_ptr);        
    }

    if(ecdsa_buf_ptr != NULL)
    {
        mbedtls_free(ecdsa_buf_ptr);        
    }

    if (point_arr != NULL)
    {
        mbedtls_platform_zeroize(point_arr, 2 * bytesize + 1u);
        mbedtls_free(point_arr);
    }
    if (sig != NULL)
    {
        mbedtls_platform_zeroize(sig, 2 * bytesize);
        mbedtls_free(sig);
    }

    return( ret );
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

#endif /* MBEDTLS_ECDSA_C */

#endif /* CY_IP_MXCRYPTOLITE */