/***************************************************************************//**
* \file ifx_cryptosuite_transparent_mac.c
*
* \brief
*  PSA CryptoSuite transparent MAC driver implementation.
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

#include "ifx_cryptosuite_transparent_mac.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#if defined(IFX_PSA_CRYPTOSUITE_CMAC)

/* Common setup function */
static psa_status_t ifx_cryptosuite_mac_setup_common(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    bool is_sign)
{
    psa_key_type_t key_type;
    size_t key_bits;
    Cs_StdApi_OpenType aes_open_params, cmac_open_params;
    Cs_Cmac_CfgType cmac_cfg_params;
    Cs_XBlobType key_xblob;
    uint8_t key_buf[IFX_CS_MAX_KEY_SIZE_BYTES];
    uint8_t rng_seed[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint8_t rng_seed_inv[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint32_t func_id;
    psa_status_t status;

    if (operation == NULL || attributes == NULL || key_buffer == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Clear operation structure */
    ifx_mxcryptosuite_memset(operation, 0, sizeof(*operation));

    /* Get key attributes */
    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);

    /* Validate key type and size */
    if (key_type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_bits != IFX_CS_AES_KEY_BITS_128 && key_bits != IFX_CS_AES_KEY_BITS_256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size != IFX_CS_BITS_TO_BYTES(key_bits)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Only CMAC supported */
    if (PSA_ALG_FULL_LENGTH_MAC(alg) != PSA_ALG_CMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Store operation parameters */
    operation->alg 		= alg;
    operation->key_bits = key_bits;
    operation->is_sign 	= is_sign;
    ifx_mxcryptosuite_memcpy(operation->key, key_buffer, key_buffer_size);

    /* Allocate heap memory for AES entity */
    size_t aes_heap_size = ifx_cryptosuite_get_aes_heap_size(key_bits);
    #if defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
        static uint8_t static_aes_heap[IFX_CS_HEAP_SIZE];
        operation->aes_heap = static_aes_heap;
        ifx_mxcryptosuite_memset(operation->aes_heap, 0, aes_heap_size);
    #else
        operation->aes_heap = (uint8_t *)ifx_mxcryptosuite_malloc(aes_heap_size);
        if (operation->aes_heap == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ifx_mxcryptosuite_memset(operation->aes_heap, 0, aes_heap_size);
    #endif

    /* Allocate heap memory for CMAC entity */
    #if defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
        static uint8_t static_cmac_heap[IFX_CS_CMAC_HEAP_SIZE];
        operation->cmac_heap = static_cmac_heap;
        ifx_mxcryptosuite_memset(operation->cmac_heap, 0, ifx_cryptosuite_get_cmac_heap_size());
    #else
        operation->cmac_heap = (uint8_t *)ifx_mxcryptosuite_malloc(ifx_cryptosuite_get_cmac_heap_size());
        if (operation->cmac_heap == NULL) {
            ifx_mxcryptosuite_free(operation->aes_heap);
            operation->aes_heap = NULL;
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ifx_mxcryptosuite_memset(operation->cmac_heap, 0, ifx_cryptosuite_get_cmac_heap_size());
    #endif

    /* Open AES entity */
    ifx_mxcryptosuite_memset(&aes_open_params, 0, sizeof(aes_open_params));
    aes_open_params.Super.OID 				= ifx_cryptosuite_get_aes_oid(key_bits);
    aes_open_params.EntityFnPtr 			= ifx_cryptosuite_get_aes_entity(key_bits);
    aes_open_params.HeapMemPtr 				= operation->aes_heap;
    aes_open_params.HeapMemSize 			= aes_heap_size;
    aes_open_params.OsHwEntryCallbackFnPtr 	= NULL;
    aes_open_params.OsHwExitCallbackFnPtr 	= NULL;

    operation->aes_handle = Cs_Open(&aes_open_params);
    if (operation->aes_handle.FirstPtr == NULL) {
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->cmac_heap);
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->cmac_heap = NULL;
        operation->aes_heap = NULL;
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    /* Configure the AES entity with its own RNG seed before it is used as a CryptoHdl
     * inside CMAC. Key and IV are managed by CMAC, so they are disabled here. */
    {
        uint8_t aes_rng_seed[IFX_CS_RNG_SEED_SIZE_BYTES];
        uint8_t aes_rng_seed_inv[IFX_CS_RNG_SEED_SIZE_BYTES];
        Cs_Aes_CfgType aes_cfg_params;

        ifx_cryptosuite_generate_rng_seed(aes_rng_seed, aes_rng_seed_inv, sizeof(aes_rng_seed));

        ifx_mxcryptosuite_memset(&aes_cfg_params, 0, sizeof(aes_cfg_params));
        aes_cfg_params.Super.Super.Super.OID                        = ifx_cryptosuite_get_aes_oid(key_bits);
        aes_cfg_params.Super.Super.TempMemPtr                       = NULL;
        aes_cfg_params.Super.Super.TempMemSize                      = 0;
        aes_cfg_params.Super.Super.ClearTempMemOnExit               = 0;
        aes_cfg_params.Super.Super.CfgSelector.CfgSelRfu1           = CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
        aes_cfg_params.Super.Super.CfgSelector.Repetitions          = CS_STDAPI_CFG_REPETITIONS_DISABLE;
        aes_cfg_params.Super.Super.CfgSelector.UnprivilegedCallback = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
        aes_cfg_params.Super.Super.CfgSelector.RngSeed              = CS_STDAPI_CFG_RNG_SEED_ENABLE;
        aes_cfg_params.Super.Super.RngSeedPtr                       = aes_rng_seed;
        aes_cfg_params.Super.Super.RngSeedInvPtr                    = aes_rng_seed_inv;
        aes_cfg_params.Super.Super.FuncIDPtr                        = &func_id;
        aes_cfg_params.Super.Super.FuncIDPtr[0]                     = CS_CIPHER_CFG_INPUT_FUNC_ID;
        aes_cfg_params.Super.CipherCfgSelector.Rfu1                 = CS_CIPHER_CFG_SEL_RFU_1_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.Rfu2                 = CS_CIPHER_CFG_SEL_RFU_2_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.Rfu3                 = CS_CIPHER_CFG_SEL_RFU_3_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.IV                   = CS_CIPHER_CFG_IV_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.Key                  = CS_CIPHER_CFG_KEY_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.UseIKS               = CS_CIPHER_CFG_USE_IKS_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.SecControl           = CS_CIPHER_CFG_SEC_CONTROL_DISABLE;
        aes_cfg_params.Super.CipherCfgSelector.BlockRepetition      = CS_CIPHER_CFG_BLOCK_REPETITION_DISABLE;

        status = ifx_cryptosuite_to_psa_status(Cs_Cfg(operation->aes_handle, (Cs_StdApi_CfgType *)&aes_cfg_params));
        if (status != PSA_SUCCESS) {
            Cs_Close(operation->aes_handle, NULL);
            #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
                ifx_mxcryptosuite_free(operation->cmac_heap);
                ifx_mxcryptosuite_free(operation->aes_heap);
            #endif
            operation->cmac_heap = NULL;
            operation->aes_heap  = NULL;
            return status;
        }
    }

    /* Open CMAC entity */
    ifx_mxcryptosuite_memset(&cmac_open_params, 0, sizeof(cmac_open_params));
    cmac_open_params.Super.OID 				= ifx_cryptosuite_get_cmac_oid();
    cmac_open_params.EntityFnPtr 			= ifx_cryptosuite_get_cmac_entity();
    cmac_open_params.HeapMemPtr 			= operation->cmac_heap;
    cmac_open_params.HeapMemSize 			= ifx_cryptosuite_get_cmac_heap_size();
    cmac_open_params.OsHwEntryCallbackFnPtr = NULL;
    cmac_open_params.OsHwExitCallbackFnPtr 	= NULL;

    operation->cmac_handle = Cs_Open(&cmac_open_params);
    if (operation->cmac_handle.FirstPtr == NULL) {
        Cs_Close(operation->aes_handle, NULL);
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->cmac_heap);
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->cmac_heap    = NULL;
        operation->aes_heap     = NULL;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Generate RNG seed */
    ifx_cryptosuite_generate_rng_seed(rng_seed, rng_seed_inv, sizeof(rng_seed));

    /* Prepare key XBlob: copy key into stack buffer, then init xblob from it */
    ifx_mxcryptosuite_memcpy(key_buf, key_buffer, key_buffer_size);
    ifx_cryptosuite_init_xblob(&key_xblob, key_buf, key_buffer, key_buffer_size);

    /* Configure CMAC entity */
    ifx_mxcryptosuite_memset(&cmac_cfg_params, 0, sizeof(cmac_cfg_params));
    cmac_cfg_params.Super.Super.Super.Super.OID                             = ifx_cryptosuite_get_cmac_oid();
    cmac_cfg_params.Super.Super.Super.TempMemPtr                            = NULL;
    cmac_cfg_params.Super.Super.Super.TempMemSize                           = 0;
    cmac_cfg_params.Super.Super.Super.ClearTempMemOnExit                    = 0;
    cmac_cfg_params.Super.Super.Super.CfgSelector.CfgSelRfu1                = CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
    cmac_cfg_params.Super.Super.Super.CfgSelector.Repetitions               = CS_STDAPI_CFG_REPETITIONS_DISABLE;
    cmac_cfg_params.Super.Super.Super.CfgSelector.UnprivilegedCallback      = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
    cmac_cfg_params.Super.Super.Super.CfgSelector.RngSeed                   = CS_STDAPI_CFG_RNG_SEED_ENABLE;
    cmac_cfg_params.Super.Super.Super.RngSeedPtr                            = rng_seed;
    cmac_cfg_params.Super.Super.Super.RngSeedInvPtr                         = rng_seed_inv;
	cmac_cfg_params.Super.Super.Super.FuncIDPtr                             = &func_id;
    cmac_cfg_params.Super.Super.Super.FuncIDPtr[0]                          = CS_MAC_CFG_INPUT_FUNC_ID;
    cmac_cfg_params.Super.Super.MacCfgSelector.Key                          = CS_MAC_CFG_KEY_ENABLE;
    cmac_cfg_params.Super.Super.MacCfgSelector.MacCfgSelRfu2                = CS_MAC_CFG_SEL_RFU_2_DISABLE;
    cmac_cfg_params.Super.Super.MacCfgSelector.CryptoHdl                    = CS_MAC_CFG_CRYPTO_HDL_ENABLE;
    cmac_cfg_params.Super.Super.MacCfgSelector.MacCfgSelRfu4                = CS_MAC_CFG_SEL_RFU_4_DISABLE;
    cmac_cfg_params.Super.Super.KeyPtr                                      = &key_xblob;
    cmac_cfg_params.Super.Super.CryptoHdl                                   = operation->aes_handle;

    status = ifx_cryptosuite_to_psa_status(Cs_Cfg(operation->cmac_handle, (Cs_StdApi_CfgType *)&cmac_cfg_params));
    if (status != PSA_SUCCESS) {
        Cs_Close(operation->cmac_handle, NULL);
        Cs_Close(operation->aes_handle, NULL);
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->cmac_heap);
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->cmac_heap    = NULL;
        operation->aes_heap     = NULL;
        ifx_mxcryptosuite_memset(operation, 0, sizeof(*operation));
        return status;
    }

    operation->initialized = true;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_mac_sign_setup(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_mac_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, true);
}

psa_status_t ifx_cryptosuite_transparent_mac_verify_setup(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_mac_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, false);
}

psa_status_t ifx_cryptosuite_transparent_mac_update(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    Cs_Cmac_CtrlType cmac_ctrl_params;
    Cs_XBlobType in_xblob;
    Cs_XBlobType out_xblob;
    uint32_t func_id;
    psa_status_t status;
    const uint8_t *p = input;
    size_t remaining = input_length;
    size_t to_copy;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (input == NULL && input_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    /* Step 1: Fill pending[] to 16 bytes from the new input */
    to_copy = 16U - operation->pending_len;
    if (to_copy > remaining) { to_copy = remaining; }
    ifx_mxcryptosuite_memcpy(operation->pending + operation->pending_len, p, to_copy);
    operation->pending_len += to_copy;
    p         += to_copy;
    remaining -= to_copy;

    /* If pending is still not a full block, or no more input: done */
    if (remaining == 0U || operation->pending_len < 16U) {
        return PSA_SUCCESS;
    }

    /* Step 2: pending is full (16 bytes) AND more input exists.
     * Build ctrl params template once, reused for every intermediate call. */
    ifx_mxcryptosuite_memset(&cmac_ctrl_params, 0, sizeof(cmac_ctrl_params));
    cmac_ctrl_params.Super.Super.Super.Super.OID            = ifx_cryptosuite_get_cmac_oid();
    cmac_ctrl_params.Super.Super.Super.TempMemPtr           = operation->temp_mem;
    cmac_ctrl_params.Super.Super.Super.TempMemSize          = sizeof(operation->temp_mem);
    cmac_ctrl_params.Super.Super.Super.ClearTempMemOnExit   = 0xFF;
    cmac_ctrl_params.Super.Super.Super.CccFnPtr             = ifx_cryptosuite_get_cmac_generate_fn();
    cmac_ctrl_params.Super.Super.Super.FuncIDPtr            = &func_id;
    cmac_ctrl_params.Super.Super.Super.FuncIDPtr[0]         = ifx_cryptosuite_get_cmac_generate_func_id();
    cmac_ctrl_params.Super.Super.InDataPtr                  = &in_xblob;
    cmac_ctrl_params.Super.Super.OutDataPtr                 = &out_xblob;

    /* Flush pending (16 B), then pass remaining full blocks via direct pointer.
     * Last <=16 bytes are always held in pending for sign_finish. */
    while (remaining > 0U) {
        /* Flush current 16-byte pending block as intermediate */
        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = operation->pending;      /* writable struct field */
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = 16U;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, NULL, 0);
        cmac_ctrl_params.Super.Super.Super.FuncIDPtr[0] = ifx_cryptosuite_get_cmac_generate_func_id();

        status = ifx_cryptosuite_to_psa_status(
            Cs_Ctrl(operation->cmac_handle, (Cs_StdApi_CtrlType *)&cmac_ctrl_params));
        if (status != PSA_SUCCESS) { return status; }

        /* Refill pending with next <=16 bytes from the direct input pointer */
        to_copy = (remaining > 16U) ? 16U : remaining;
        ifx_mxcryptosuite_memcpy(operation->pending, p, to_copy);
        operation->pending_len = to_copy;
        p         += to_copy;
        remaining -= to_copy;
    }

    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_mac_sign_finish(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length)
{
    Cs_Cmac_CtrlType cmac_ctrl_params;
    Cs_XBlobType in_xblob;
    Cs_XBlobType out_xblob;
    uint32_t func_id;
    psa_status_t status;
    uint8_t full_mac[16]; /* CMAC output is always 16 bytes */
    size_t mac_len = PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, operation->key_bits, operation->alg);

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!operation->is_sign) {
        return PSA_ERROR_BAD_STATE;
    }

    if (mac == NULL || mac_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (mac_size < mac_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* sign_finish */
    if (operation->pending_len > 0U) {
        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = operation->pending;
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)operation->pending_len;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
    } else {
        ifx_cryptosuite_init_xblob(&in_xblob, NULL, NULL, 0);
    }
    ifx_cryptosuite_prepare_output_xblob(&out_xblob, full_mac, sizeof(full_mac));

    /* Execute final MAC generation */
    ifx_mxcryptosuite_memset(&cmac_ctrl_params, 0, sizeof(cmac_ctrl_params));
    cmac_ctrl_params.Super.Super.Super.Super.OID 			= ifx_cryptosuite_get_cmac_oid();
    cmac_ctrl_params.Super.Super.Super.TempMemPtr 			= operation->temp_mem;
    cmac_ctrl_params.Super.Super.Super.TempMemSize 			= sizeof(operation->temp_mem);
    cmac_ctrl_params.Super.Super.Super.ClearTempMemOnExit 	= 0xFF;
    cmac_ctrl_params.Super.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_cmac_generate_fn();
    cmac_ctrl_params.Super.Super.Super.FuncIDPtr 			= &func_id;
    cmac_ctrl_params.Super.Super.Super.FuncIDPtr[0] 		= ifx_cryptosuite_get_cmac_generate_func_id();
    cmac_ctrl_params.Super.Super.InDataPtr = &in_xblob;
    cmac_ctrl_params.Super.Super.OutDataPtr = &out_xblob;

    status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation->cmac_handle, (Cs_StdApi_CtrlType *)&cmac_ctrl_params));
    
    if (status == PSA_SUCCESS) {
        /* Output XBlob uses random seeds, so full_mac holds masked data.
         * Export unmasks it into the caller's buffer. */
        (void)Cs_XBlob_Export(&out_xblob, full_mac, NULL, NULL, NULL);
        ifx_mxcryptosuite_memcpy(mac, full_mac, mac_len);
        *mac_length = mac_len;
    } else {
        *mac_length = 0;
    }

    return status;
}

psa_status_t ifx_cryptosuite_transparent_mac_verify_finish(
    ifx_cryptosuite_transparent_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length)
{
    uint8_t computed_mac[16];
    size_t computed_mac_length;
    psa_status_t status;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->is_sign) {
        return PSA_ERROR_BAD_STATE;
    }

    if (mac == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Temporarily set operation to sign mode to compute MAC */
    operation->is_sign = true;
    
    /* Compute MAC */
    status = ifx_cryptosuite_transparent_mac_sign_finish(operation, computed_mac, 
                                                         sizeof(computed_mac), &computed_mac_length);
    
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Compare MACs */
    if (mac_length != computed_mac_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (size_t i = 0; i < mac_length; i++) {
        diff |= (mac[i] ^ computed_mac[i]);
    }

    return (diff == 0) ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

psa_status_t ifx_cryptosuite_transparent_mac_abort(
    ifx_cryptosuite_transparent_mac_operation_t *operation)
{
    uint32_t func_id;
    
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Safely abort even if operation is in an inconsistent state */
    if (operation->initialized) {
        
        /* Close AES handle first (cipher before mode) */
        if (operation->aes_handle.FirstPtr != NULL) {
			Cs_StdApi_CloseType aes_closeparams;
			ifx_mxcryptosuite_memset(&aes_closeparams, 0, sizeof(aes_closeparams));
			aes_closeparams.Super.OID    = ifx_cryptosuite_get_aes_oid(operation->key_bits);
			aes_closeparams.FuncIDPtr    = &func_id;
			aes_closeparams.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
			
            (void)Cs_Close(operation->aes_handle, &aes_closeparams);
            /* Ignore return - abort must always succeed per PSA spec */
        }
        
        /* Close CMAC handle second */
        if (operation->cmac_handle.FirstPtr != NULL) {
			Cs_StdApi_CloseType cmac_closeparams;
			ifx_mxcryptosuite_memset(&cmac_closeparams, 0, sizeof(cmac_closeparams));
			cmac_closeparams.Super.OID    = ifx_cryptosuite_get_cmac_oid();
			cmac_closeparams.FuncIDPtr    = &func_id;
			cmac_closeparams.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
			
            (void)Cs_Close(operation->cmac_handle, &cmac_closeparams);
            /* Ignore return - abort must always succeed per PSA spec */
        }
        
    }
	
  	ifx_mxcryptosuite_memset(&operation->aes_handle, 0, sizeof(operation->aes_handle));
	ifx_mxcryptosuite_memset(&operation->cmac_handle, 0, sizeof(operation->cmac_handle));
	ifx_mxcryptosuite_memset(&operation->key, 0, sizeof(operation->key));
	ifx_mxcryptosuite_memset(operation->pending, 0, sizeof(operation->pending));
	operation->pending_len = 0;
	ifx_mxcryptosuite_memset(operation->temp_mem, 0, sizeof(operation->temp_mem));

	/* Free dynamically allocated heap memory */
	if (operation->aes_heap != NULL) {
		ifx_mxcryptosuite_memset(operation->aes_heap, 0, ifx_cryptosuite_get_aes_heap_size(operation->key_bits));
		#if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
			ifx_mxcryptosuite_free(operation->aes_heap);
		#endif
		operation->aes_heap = NULL;
	}
	
	if (operation->cmac_heap != NULL) {
		ifx_mxcryptosuite_memset(operation->cmac_heap, 0, ifx_cryptosuite_get_cmac_heap_size());
		#if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
			ifx_mxcryptosuite_free(operation->cmac_heap);
		#endif
		operation->cmac_heap = NULL;
	}
	    
    /* Abort must always succeed per PSA spec - ignore any CryptoSuite errors */
    return PSA_SUCCESS; 
}

psa_status_t ifx_cryptosuite_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length)
{
    ifx_cryptosuite_transparent_mac_operation_t operation = {0};
    psa_status_t status;
    
    if (attributes == NULL || key_buffer == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Setup */
    status = ifx_cryptosuite_transparent_mac_sign_setup(&operation, attributes, 
                                                        key_buffer, key_buffer_size, alg);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Update */
    if (input_length > 0) {
        status = ifx_cryptosuite_transparent_mac_update(&operation, input, input_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    /* Finish */
    status = ifx_cryptosuite_transparent_mac_sign_finish(&operation, mac, mac_size, mac_length);

cleanup:
    ifx_cryptosuite_transparent_mac_abort(&operation);
    return status;
}

psa_status_t ifx_cryptosuite_transparent_mac_verify(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *mac,
    size_t mac_length)
{
    ifx_cryptosuite_transparent_mac_operation_t operation = {0};
    psa_status_t status;

    /* Setup */
    status = ifx_cryptosuite_transparent_mac_verify_setup(&operation, attributes, 
                                                          key_buffer, key_buffer_size, alg);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Update */
    if (input_length > 0) {
        status = ifx_cryptosuite_transparent_mac_update(&operation, input, input_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    /* Finish */
    status = ifx_cryptosuite_transparent_mac_verify_finish(&operation, mac, mac_length);

cleanup:
    ifx_cryptosuite_transparent_mac_abort(&operation);
    return status;
}

#endif /* IFX_PSA_CRYPTOSUITE_CMAC */

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */
