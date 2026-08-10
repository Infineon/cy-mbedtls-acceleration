/***************************************************************************//**
* \file ifx_cryptosuite_common.h
*
* \brief
*  PSA CryptoSuite common types and utilities.
*
********************************************************************************
* Copyright (C) 2026 Cypress Semiconductor Corporation
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

#ifndef IFX_CRYPTOSUITE_COMMON_H
#define IFX_CRYPTOSUITE_COMMON_H

#define USE_FUNC_ID 1
#include "psa/crypto.h"
#include "ifx_cryptosuite_config.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

/* CryptoSuite API includes */
#include "Cs_StdApi.h"
#include "Cs_XBlob_Api.h"
#include "Cs_Sym_Cipher.h"
#include "Cs_Sym_Ae.h"
#include "Cs_Sym_Cipher_Aes.h"
#include "Cs_Sym_Mac_Ciphermac_Cmac.h"
#include "Cs_Sym_Ae_Ccm.h"
#include "cy_cryptolite_trng_config.h"
#include "cy_cryptolite_trng.h"
#include "stdbool.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ifx_mxcryptosuite_memset
#define ifx_mxcryptosuite_memset memset
#endif

#ifndef ifx_mxcryptosuite_memcpy
#define ifx_mxcryptosuite_memcpy memcpy
#endif

#ifndef ifx_mxcryptosuite_malloc
#define ifx_mxcryptosuite_malloc malloc
#endif

#ifndef ifx_mxcryptosuite_free
#define ifx_mxcryptosuite_free free
#endif

/* AES key size definitions in bits */
#define IFX_CS_AES_KEY_BITS_128     128U
#define IFX_CS_AES_KEY_BITS_256     256U


#define IFX_CS_BITS_TO_BYTES(bits) ((bits+7U) / 8U)

/**
 * \brief Get AES entity function pointer based on key size
 *
 * \param key_bits      Key size in bits (128 or 256)
 * \return              Entity function pointer or NULL
 */
static inline Cs_StdApi_EntityFnPtrType ifx_cryptosuite_get_aes_entity(size_t key_bits)
{
    switch (key_bits) {
        case IFX_CS_AES_KEY_BITS_128:
            return Cs_Entity_Aes128_Sec;
        case IFX_CS_AES_KEY_BITS_256:
            return Cs_Entity_Aes256_Sec;
        default:
            return NULL;
    }
}

/**
 * \brief Get AES OID based on key size
 *
 * \param key_bits      Key size in bits (128 or 256)
 * \return              OID value
 */
static inline uint32_t ifx_cryptosuite_get_aes_oid(size_t key_bits)
{
    switch (key_bits) {
        case IFX_CS_AES_KEY_BITS_128:
            return CS_ENTITY_AES128_SEC_OID;
        case IFX_CS_AES_KEY_BITS_256:
            return CS_ENTITY_AES256_SEC_OID;
        default:
            return 0;
    }
}

/**
 * \brief Get AES heap size based on key size
 *
 * \param key_bits      Key size in bits (128 or 256)
 * \return              Heap size in bytes
 */
static inline size_t ifx_cryptosuite_get_aes_heap_size(size_t key_bits)
{
    switch (key_bits) {
        case IFX_CS_AES_KEY_BITS_128:
            return CS_ENTITY_AES128_SEC_HEAPSIZE;
        case IFX_CS_AES_KEY_BITS_256:
            return CS_ENTITY_AES256_SEC_HEAPSIZE;
        default:
            return 0;
    }
}

/**
 * \brief Get RNG seed enable constant
 *
 * \return              RNG seed enable value
 */
static inline uint8_t ifx_cryptosuite_get_rng_seed_enable(void)
{
    return CS_STDAPI_CFG_RNG_SEED_ENABLE;
}

/**
 * \brief Get Cipher configuration input function ID
 *
 * \return              Cipher configuration function ID
 */
static inline uint32_t ifx_cryptosuite_get_cipher_cfg_func_id(void)
{
    return CS_CIPHER_CFG_INPUT_FUNC_ID;
}

/**
 * \brief Get Cipher configuration key enable constant
 *
 * \return              Cipher configuration key enable value
 */
static inline uint8_t ifx_cryptosuite_get_cipher_cfg_key_enable(void)
{
    return CS_CIPHER_CFG_KEY_ENABLE;
}

/**
 * \brief Get Cipher configuration IV enable constant
 *
 * \return              Cipher configuration IV enable value
 */
static inline uint8_t ifx_cryptosuite_get_cipher_cfg_iv_enable(void)
{
    return CS_CIPHER_CFG_IV_ENABLE;
}

/**
 * \brief Convert CryptoSuite status to PSA status
 *
 * \param cs_status     CryptoSuite status code
 * \return              Corresponding PSA status code
 */
psa_status_t ifx_cryptosuite_to_psa_status(Cs_StdApi_StatusType cs_status);

/**
 * \brief Build a CryptoSuite INPUT XBlob (masked) from a source buffer.
 *
 * \details
 *  Sets byte-array + standard-integrity properties, TRNG-initialises the share
 *  seeds, then calls Cs_XBlob_Import to write the masked share into \p dst_buf.
 *  \p dst_buf must be writable, at least \p length bytes, and distinct from
 *  \p src (import is not performed in place). \p src may be read-only/const.
 *  If \p src is NULL or \p length is 0, only the checksum is computed.
 *
 * \param xblob         Pointer to XBlob structure
 * \param dst_buf       Writable destination buffer (becomes Data1Ptr)
 * \param src           Source data to import (may be const); distinct from dst_buf
 * \param length        Length of data in bytes
 */
void ifx_cryptosuite_init_xblob(Cs_XBlobType *xblob, uint8_t *dst_buf,
                                const uint8_t *src, size_t length);

/**
 * \brief Build a valid CryptoSuite OUTPUT XBlob (data written by CryptoSuite).
 *
 * \details
 *  Sets byte-array + standard-integrity properties, TRNG-initialises the share seeds,
 *  then sets a short-integrity checksum via Cs_XBlob_CalculateChecksum (required for
 *  output XBlobs; CryptoSuite updates it to the Properties checksum type on return).
 *  \p out_buf may be NULL with \p length 0 for intermediate/no-output control calls.
 *
 * \param xblob    Pointer to XBlob structure to initialise
 * \param out_buf  Writable output buffer (becomes Data1Ptr), or NULL
 * \param length   Length of the output buffer in bytes (0 if none)
 * \return         PSA_SUCCESS
 */
psa_status_t ifx_cryptosuite_prepare_output_xblob(Cs_XBlobType *xblob, uint8_t *out_buf,
                                                  size_t length);

/**
 * \brief Generate a random seed using the hardware TRNG
 *
 * \param rng_seed      Output buffer for random seed bytes
 * \param rng_seed_inv  Output buffer for bitwise-inverted seed bytes (may be NULL)
 * \param size          Number of bytes to generate
 * \return              PSA_SUCCESS or PSA_ERROR_HARDWARE_FAILURE
 */
psa_status_t ifx_cryptosuite_generate_rng_seed(uint8_t *rng_seed, uint8_t *rng_seed_inv, size_t size);

/**
 * \brief Generate a single random 32-bit word using the hardware TRNG
 *
 * \details
 *  Used to pre-initialise redundant status words (e.g. Cs_Ae_CtrlType::RedStatusWord)
 *  before CryptoSuite decrypt/verify operations.
 *
 * \param out           Output pointer for the random word (must not be NULL)
 * \return              PSA_SUCCESS or PSA_ERROR_HARDWARE_FAILURE
 */
psa_status_t ifx_cryptosuite_generate_random_u32(uint32_t *out);

/**
 * \brief Verify the checksum of an output XBlob returned by CryptoSuite.
 *
 * \details
 *  After CryptoSuite writes to an output XBlob,
 *  the caller shall check that the XBlob checksum matches the value calculated by
 *  Cs_XBlob_CalculateChecksum. A mismatch indicates the XBlob was compromised
 *  (e.g. by fault injection) between the HW engine writing it and the caller reading it.
 *
 *  The integrity algorithm is read directly from the XBlob Properties field, which
 *  CryptoSuite updates to the configured type before returning.
 *
 * \param xblob   Output XBlob whose checksum is to be verified (must not be NULL)
 * \return        PSA_SUCCESS if checksum matches, PSA_ERROR_CORRUPTION_DETECTED otherwise
 */
static inline psa_status_t ifx_cryptosuite_verify_output_xblob(Cs_XBlobType *xblob)
{
    uint16_t algo = (uint16_t)((xblob->Properties & CS_XBLOB_INTEGRITY_Msk) >> CS_XBLOB_INTEGRITY_Pos);
    uint32_t expected = Cs_XBlob_CalculateChecksum(xblob, CS_XBLOB_ID_DEFAULT, algo, NULL);
    return (xblob->Checksum == expected) ? PSA_SUCCESS : PSA_ERROR_CORRUPTION_DETECTED;
}

#ifdef __cplusplus
}
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_CRYPTOSUITE_COMMON_H */
