/***************************************************************************//**
* \file ifx_cryptosuite_transparent_mac.h
*
* \brief
*  PSA CryptoSuite transparent MAC driver interface.
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

#ifndef IFX_CRYPTOSUITE_TRANSPARENT_MAC_H
#define IFX_CRYPTOSUITE_TRANSPARENT_MAC_H

#include "ifx_cryptosuite_transparent_types.h"
#include "ifx_cryptosuite_common.h"
#include <string.h>
#include <stdio.h>

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#include "Cs_StdApi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get CMAC OID
 *
 * \return              CMAC entity OID
 */
static inline uint32_t ifx_cryptosuite_get_cmac_oid(void)
{
    return CS_ENTITY_CMAC_SEC_OID;
}

/**
 * \brief Get CMAC entity function pointer
 *
 * \return              CMAC entity function pointer
 */
static inline Cs_StdApi_EntityFnPtrType ifx_cryptosuite_get_cmac_entity(void)
{
    return Cs_Entity_Cmac_Sec;
}

/**
 * \brief Get CMAC heap size
 *
 * \return              Heap size in bytes
 */
static inline size_t ifx_cryptosuite_get_cmac_heap_size(void)
{
    return CS_ENTITY_CMAC_SEC_HEAPSIZE;
}

/**
 * \brief Get CMAC configuration input function ID
 *
 * \return              CMAC configuration function ID (always 0)
 */
static inline uint32_t ifx_cryptosuite_get_cmac_cfg_func_id(void)
{
    return CS_MAC_CFG_INPUT_FUNC_ID;
}

/**
 * \brief Get MAC configuration key enable constant
 *
 * \return              MAC configuration key enable value
 */
static inline uint8_t ifx_cryptosuite_get_mac_cfg_key_enable(void)
{
    return CS_MAC_CFG_KEY_ENABLE;
}

/**
 * \brief Get MAC configuration crypto handle enable constant
 *
 * \return              MAC configuration crypto handle enable value
 */
static inline uint8_t ifx_cryptosuite_get_mac_cfg_crypto_hdl_enable(void)
{
    return CS_MAC_CFG_CRYPTO_HDL_ENABLE;
}

/**
 * \brief Get CMAC generate callback function
 *
 * \return              CMAC generate function pointer
 */
static inline Cs_StdApi_CtrlCodeFnPtrType ifx_cryptosuite_get_cmac_generate_fn(void)
{
    return Cs_Ccc_Mac_Generate;
}

/**
 * \brief Get CMAC generate input function ID
 *
 * \return              CMAC generate function ID
 */
static inline uint32_t ifx_cryptosuite_get_cmac_generate_func_id(void)
{
    return CS_CCC_MAC_GENERATE_INPUT_FUNC_ID;
}

/* Single-shot operations */
psa_status_t ifx_cryptosuite_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length);

psa_status_t ifx_cryptosuite_transparent_mac_verify(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *mac,
    size_t mac_length);

/* Multi-part operations */
psa_status_t ifx_cryptosuite_transparent_mac_sign_setup(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

psa_status_t ifx_cryptosuite_transparent_mac_verify_setup(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg);

psa_status_t ifx_cryptosuite_transparent_mac_update(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

psa_status_t ifx_cryptosuite_transparent_mac_sign_finish(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length);

psa_status_t ifx_cryptosuite_transparent_mac_verify_finish(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length);

psa_status_t ifx_cryptosuite_transparent_mac_abort(
    ifx_cryptosuite_transparent_mac_operation_t *operation);

#ifdef __cplusplus
}
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_CRYPTOSUITE_TRANSPARENT_MAC_H */
