/***************************************************************************//**
* \file ifx_cryptosuite_transparent_aead.h
*
* \brief
*  PSA CryptoSuite transparent AEAD driver interface.
*
********************************************************************************
* Copyright (C) 2026 Infineon Technologies AG
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

#ifndef IFX_CRYPTOSUITE_TRANSPARENT_AEAD_H
#define IFX_CRYPTOSUITE_TRANSPARENT_AEAD_H

#include "ifx_cryptosuite_transparent_types.h"
#include "ifx_cryptosuite_common.h"
#include <string.h>
#include <stdio.h>

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get CCM OID
 *
 * \return              CCM entity OID
 */
static inline uint32_t ifx_cryptosuite_get_ccm_oid(void)
{
    return CS_ENTITY_CCM_SEC_OID;
}

/**
 * \brief Get CCM entity function pointer
 *
 * \return              CCM entity function pointer
 */
static inline Cs_StdApi_EntityFnPtrType ifx_cryptosuite_get_ccm_entity(void)
{
    return Cs_Entity_Ccm_Sec;
}

/**
 * \brief Get CCM heap size
 *
 * \return              Heap size in bytes
 */
static inline size_t ifx_cryptosuite_get_ccm_heap_size(void)
{
    return CS_ENTITY_CCM_SEC_HEAPSIZE;
}

/**
 * \brief Get CCM configuration input function ID
 *
 * \return              CCM configuration function ID
 */
static inline uint32_t ifx_cryptosuite_get_ccm_cfg_func_id(void)
{
    return CS_AE_CFG_INPUT_FUNC_ID;
}

/**
 * \brief Get CCM consume-AD input function ID (first / chained call to ConsumeAD)
 */
static inline uint32_t ifx_cryptosuite_get_ccm_consume_ad_input_func_id(void)
{
    return CS_AE_CONSUME_AD_INPUT_FUNC_ID;
}

/**
 * \brief Get CCM encrypt input function ID (first / chained call to Ae_Enc)
 */
static inline uint32_t ifx_cryptosuite_get_ccm_encrypt_input_func_id(void)
{
    return CS_AE_ENCRYPT_INPUT_FUNC_ID;
}

/**
 * \brief Get CCM decrypt input function ID (first / chained call to Ae_Dec)
 */
static inline uint32_t ifx_cryptosuite_get_ccm_decrypt_input_func_id(void)
{
    return CS_AE_DECRYPT_INPUT_FUNC_ID;
}
/**
 * \brief Get CCM consume AD callback function
 *
 * \return              CCM consume AD function pointer
 */
static inline Cs_StdApi_CtrlCodeFnPtrType ifx_cryptosuite_get_ccm_consume_ad_fn(void)
{
    return Cs_Ccc_Ae_ConsumeAD;
}

/**
 * \brief Get CCM encryption callback function
 *
 * \return              CCM encryption function pointer
 */
static inline Cs_StdApi_CtrlCodeFnPtrType ifx_cryptosuite_get_ccm_encrypt_fn(void)
{
    return Cs_Ccc_Ae_Enc;
}

/**
 * \brief Get CCM decryption callback function
 *
 * \return              CCM decryption function pointer
 */
static inline Cs_StdApi_CtrlCodeFnPtrType ifx_cryptosuite_get_ccm_decrypt_fn(void)
{
    return Cs_Ccc_Ae_Dec;
}

/* Single-shot operations */
psa_status_t ifx_cryptosuite_transparent_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length);

psa_status_t ifx_cryptosuite_transparent_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length);

/* Multi-part operations */
psa_status_t ifx_cryptosuite_transparent_aead_encrypt_setup(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

psa_status_t ifx_cryptosuite_transparent_aead_decrypt_setup(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

psa_status_t ifx_cryptosuite_transparent_aead_set_nonce(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length);

psa_status_t ifx_cryptosuite_transparent_aead_set_lengths(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length);

psa_status_t ifx_cryptosuite_transparent_aead_update_ad(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

psa_status_t ifx_cryptosuite_transparent_aead_update(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t ifx_cryptosuite_transparent_aead_finish(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length);

psa_status_t ifx_cryptosuite_transparent_aead_verify(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length,
    const uint8_t *tag,
    size_t tag_length);

psa_status_t ifx_cryptosuite_transparent_aead_abort(
    ifx_cryptosuite_transparent_aead_operation_t *operation);

#ifdef __cplusplus
}
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_CRYPTOSUITE_TRANSPARENT_AEAD_H */
