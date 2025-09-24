/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright (C) 2019-2024 Cypress Semiconductor Corporation
 *
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
 * \version 2.3.0
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

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ECDH_C)

/* Allow only *_alt implementations to access private members of structures*/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/compat-2.x.h"

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
    cy_en_crypto_status_t ecdh_status;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *key_x_data = NULL;
    uint8_t *key_y_data = NULL;
    uint8_t *key_k_data = NULL;
#endif

    ECDH_VALIDATE_RET( grp != NULL );
    ECDH_VALIDATE_RET( d != NULL );
    ECDH_VALIDATE_RET( Q != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

    if( mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS && mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        return( ret );
    }

    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Reserve the crypto hardware for the operation */
    cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_VU);

    key.curveID = cy_get_dp_idx(grp->id);

    if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
    {
        bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(grp->nbits);
    }
    else
    {
        cy_stc_crypto_ecc_dp_type *dp;
        dp = Cy_Crypto_Core_ECC_GetCurveParams(key.curveID);
        if(dp == NULL)
        {
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_grow(d, bytesize) );
    key.k = (uint8_t *)d->p;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.k, bytesize) )
    {
        key_k_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_k_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
        key.k = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_k_data);
        ifx_mbedtls_memcpy(key.k,d->p, bytesize);
        //MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( d, key.k, bytesize ) );
    }
#endif
    /* Q.Z coordinate should be 1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &Q->Z, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &Q->X, bytesize ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &Q->Y, bytesize ) );
    key.pubkey.x = (uint8_t *)Q->X.p;
    key.pubkey.y = (uint8_t *)Q->Y.p;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.pubkey.x, bytesize)
        || !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.pubkey.y, bytesize) )
    {
        key_x_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_x_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
        key_y_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_y_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

        key.pubkey.x = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_x_data);
        key.pubkey.y = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_y_data);

        ifx_mbedtls_memcpy(key.pubkey.x, Q->X.p, bytesize);
        ifx_mbedtls_memcpy(key.pubkey.y, Q->Y.p, bytesize);
        //MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &Q->X, key.pubkey.x, bytesize ) );
        //MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &Q->Y, key.pubkey.y, bytesize ) );

        ecdh_status = Cy_Crypto_Core_ECC_MakeKeyPair(crypto_obj.base, key.curveID, &key, f_rng, p_rng);
        MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);

        if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
        {
            Cy_Crypto_Core_InvertEndianness(key.k, bytesize);
        }

        ifx_mbedtls_memcpy(Q->X.p, key.pubkey.x,bytesize);
        ifx_mbedtls_memcpy(Q->Y.p, key.pubkey.y,bytesize);
        ifx_mbedtls_memcpy(d->p, key.k, bytesize);
        //MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( &Q->X, key.pubkey.x, bytesize ) );
        //MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( &Q->Y, key.pubkey.y, bytesize ) );
        //MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( d, key.k, bytesize ) );

        goto cleanup;
    }
#endif

    ecdh_status = Cy_Crypto_Core_ECC_MakeKeyPair(crypto_obj.base, key.curveID, &key, f_rng, p_rng);
    MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);

    if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
    {
        Cy_Crypto_Core_InvertEndianness(key.k, bytesize);
    }

cleanup:
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if (key_k_data != NULL) ifx_mbedtls_free(key_k_data);
    if (key_x_data != NULL) ifx_mbedtls_free(key_x_data);
    if (key_y_data != NULL) ifx_mbedtls_free(key_y_data);
#endif

    /* Realease the crypto hardware */
    cy_hw_crypto_release(&crypto_obj);

    return( ret );
}
#endif /* MBEDTLS_ECDH_GEN_PUBLIC_ALT */
#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by mbedtls_ecdh_gen_public().
 *
 * \see             ecp.h
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see mbedtls_ecp_mul().
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group().
 * \param z         The destination MPI (shared secret).
 *                  This must be initialized.
 * \param Q         The public key from another party.
 *                  This must be initialized.
 * \param d         Our secret exponent (private key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't need a
 *                  context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c MBEDTLS_ERR_ECP_XXX or
 *                  \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    size_t bytesize;
    cy_cmgr_crypto_hw_t crypto_obj = CY_CMGR_CRYPTO_OBJ_INIT;
    cy_stc_crypto_ecc_key key;
    cy_en_crypto_status_t ecdh_status;

    (void)f_rng;
    (void)p_rng;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *key_x_data = NULL;
    uint8_t *key_y_data = NULL;
    uint8_t *key_k_data = NULL;
    uint8_t *zp_data = NULL;
#endif

    ECDH_VALIDATE_RET( grp != NULL );
    ECDH_VALIDATE_RET( Q != NULL );
    ECDH_VALIDATE_RET( d != NULL );
    ECDH_VALIDATE_RET( z != NULL );

    if( mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS
        && mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        return( ret );
    }

    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Reserve the crypto hardware for the operation */
    cy_hw_crypto_reserve(&crypto_obj, CY_CMGR_CRYPTO_VU);

    key.curveID = cy_get_dp_idx(grp->id);
    if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
    {
        bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(grp->nbits);
    }
    else
    {
        cy_stc_crypto_ecc_dp_type *dp;
        dp = Cy_Crypto_Core_ECC_GetCurveParams(key.curveID);
        if(dp == NULL)
        {
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        }
        bytesize = CY_CRYPTO_BYTE_SIZE_OF_BITS(dp->size);
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( z, bytesize ) );
    key.k = (uint8_t *)d->p;
    key.pubkey.x = (uint8_t *)Q->X.p;
    key.pubkey.y = (uint8_t *)Q->Y.p;

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if( !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.pubkey.x, bytesize)
        ||  !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.pubkey.y, bytesize)
        ||  !CY_MBTLS_IS_MEM_CACHABLE_ALIGNED((uint32_t)key.k, bytesize) )
    {
        key_k_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_k_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
        key.k = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_k_data);
        //ifx_mbedtls_memcpy(key.k,d->p, bytesize);
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( d, key.k, bytesize ) );

        key_x_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_x_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
        key_y_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((key_y_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
        zp_data = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        MBEDTLS_MPI_CHK((zp_data == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);

        key.pubkey.x = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_x_data);
        key.pubkey.y = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)key_y_data);
        uint8_t *aligned_zp_data = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)zp_data);

        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &Q->X, key.pubkey.x, bytesize ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( &Q->Y, key.pubkey.y, bytesize ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary_le( z, aligned_zp_data, bytesize ) );
        //ifx_mbedtls_memcpy(key.pubkey.x, Q->X.p, bytesize);
        //ifx_mbedtls_memcpy(key.pubkey.y, Q->Y.p, bytesize);
        //ifx_mbedtls_memcpy(aligned_zp_data, z->p, bytesize);

        if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
        {

            Cy_Crypto_Core_InvertEndianness(key.k, bytesize);
            ecdh_status = Cy_Crypto_Core_EC25519_PointMultiplication(crypto_obj.base, aligned_zp_data, (const uint8_t *)key.pubkey.x, (const uint8_t*)key.k);
            MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);
        }
        else
        {
            uint8_t *Z_y = (uint8_t *)ifx_mbedtls_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(bytesize) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
            MBEDTLS_MPI_CHK((Z_y == NULL) ? MBEDTLS_ERR_ECP_ALLOC_FAILED : 0);
            uint8_t *Z_y_aligned = (uint8_t*)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)Z_y);

            ecdh_status = Cy_Crypto_Core_EC_NistP_PointMultiplication(crypto_obj.base, key.curveID, (const uint8_t *)key.pubkey.x,(const uint8_t *)key.pubkey.y,
            (const uint8_t *)key.k, aligned_zp_data, Z_y_aligned);

            mbedtls_platform_zeroize(Z_y_aligned, bytesize);
            ifx_mbedtls_free(Z_y);
            MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);
        }
        //ifx_mbedtls_memcpy(z->p, aligned_zp_data, bytesize);
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary_le( z, aligned_zp_data, bytesize ) );
        goto cleanup;
    }
#endif

    if(key.curveID == CY_CRYPTO_ECC_ECP_EC25519)
    {

        Cy_Crypto_Core_InvertEndianness(key.k, bytesize);
        ecdh_status = Cy_Crypto_Core_EC25519_PointMultiplication(crypto_obj.base, (uint8_t *)z->p, (const uint8_t *)key.pubkey.x, (const uint8_t*)key.k);
        MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);
    }
    else
    {
        uint8_t *Z_y = (uint8_t *)ifx_mbedtls_malloc(bytesize);
        if(Z_y == NULL)
        {
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
            goto cleanup;
        }
        ecdh_status = Cy_Crypto_Core_EC_NistP_PointMultiplication(crypto_obj.base, key.curveID, (const uint8_t *)key.pubkey.x,(const uint8_t *)key.pubkey.y,
        (const uint8_t *)key.k, (uint8_t *)z->p, Z_y);

        mbedtls_platform_zeroize(Z_y, bytesize);
        ifx_mbedtls_free(Z_y);
    }

    MBEDTLS_MPI_CHK((ecdh_status != CY_CRYPTO_SUCCESS) ? MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED : 0);

cleanup:
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if (key_k_data != NULL) ifx_mbedtls_free(key_k_data);
    if (key_x_data != NULL) ifx_mbedtls_free(key_x_data);
    if (key_y_data != NULL) ifx_mbedtls_free(key_y_data);
    if (zp_data!= NULL) ifx_mbedtls_free(zp_data);
#endif
    /* Realease the crypto hardware */
    cy_hw_crypto_release(&crypto_obj);

    return( ret );
}
#endif /* #if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT) */
#endif /* MBEDTLS_ECDH_C */

#endif /* CY_IP_MXCRYPTO */
