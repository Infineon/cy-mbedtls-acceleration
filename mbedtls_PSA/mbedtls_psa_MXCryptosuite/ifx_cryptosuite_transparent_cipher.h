/***************************************************************************//**
* \file ifx_cryptosuite_transparent_cipher.h
*
* \brief
*  PSA CryptoSuite transparent cipher driver interface.
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

#ifndef IFX_CRYPTOSUITE_TRANSPARENT_CIPHER_H
#define IFX_CRYPTOSUITE_TRANSPARENT_CIPHER_H

#include "ifx_cryptosuite_transparent_types.h"
#include "ifx_cryptosuite_common.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#ifdef __cplusplus
extern "C" {
#endif

/* Cipher setup operations */
psa_status_t ifx_cryptosuite_transparent_cipher_encrypt_setup(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

psa_status_t ifx_cryptosuite_transparent_cipher_decrypt_setup(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

/* Cipher operations */
psa_status_t ifx_cryptosuite_transparent_cipher_set_iv(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length);

psa_status_t ifx_cryptosuite_transparent_cipher_update(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t ifx_cryptosuite_transparent_cipher_finish(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t ifx_cryptosuite_transparent_cipher_abort(
    ifx_cryptosuite_transparent_cipher_operation_t *operation);

/* Single-shot operations */
psa_status_t ifx_cryptosuite_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t ifx_cryptosuite_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);


/**
 * \brief Get cipher CCC function pointer based on algorithm and direction
 *
 * \param alg           PSA algorithm
 * \param is_encrypt    true for encryption, false for decryption
 * \return              CCC function pointer or NULL
 */
static inline Cs_StdApi_CtrlCodeFnPtrType ifx_cryptosuite_get_cipher_ccc_fn(psa_algorithm_t alg, bool is_encrypt)
{
    psa_algorithm_t base_alg = PSA_ALG_FULL_LENGTH_MAC(alg);
    
    if (PSA_ALG_ECB_NO_PADDING == base_alg) {
        return is_encrypt ? Cs_Ccc_Cipher_ECB_Encrypt : Cs_Ccc_Cipher_ECB_Decrypt;
    } else if (PSA_ALG_CBC_NO_PADDING == base_alg) {
        return is_encrypt ? Cs_Ccc_Cipher_CBC_Encrypt : Cs_Ccc_Cipher_CBC_Decrypt;
    } else if (PSA_ALG_CTR == base_alg) {
        return is_encrypt ? Cs_Ccc_Cipher_CTR_Encrypt : Cs_Ccc_Cipher_CTR_Decrypt;
    }
    return NULL;
}

/**
 * \brief Get cipher function ID based on algorithm and direction
 *
 * \param alg           PSA algorithm
 * \param is_encrypt    true for encryption, false for decryption
 * \return              Function ID
 */
static inline uint32_t ifx_cryptosuite_get_cipher_func_id(psa_algorithm_t alg, bool is_encrypt)
{
    psa_algorithm_t base_alg = PSA_ALG_FULL_LENGTH_MAC(alg);
    
    if (PSA_ALG_ECB_NO_PADDING == base_alg) {
        return is_encrypt ? CS_CCC_CIPHER_ECB_ENCRYPT_INPUT_FUNC_ID : CS_CCC_CIPHER_ECB_DECRYPT_INPUT_FUNC_ID;
    } else if (PSA_ALG_CBC_NO_PADDING == base_alg) {
        return is_encrypt ? CS_CCC_CIPHER_CBC_ENCRYPT_INPUT_FUNC_ID : CS_CCC_CIPHER_CBC_DECRYPT_INPUT_FUNC_ID;
    } else if (PSA_ALG_CTR == base_alg) {
        return is_encrypt ? CS_CCC_CIPHER_CTR_ENCRYPT_INPUT_FUNC_ID : CS_CCC_CIPHER_CTR_DECRYPT_INPUT_FUNC_ID;
    }

    return 0;
}


#ifdef __cplusplus
}
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_CRYPTOSUITE_TRANSPARENT_CIPHER_H */
