/***************************************************************************//**
* \file ifx_cryptosuite_transparent_aead.c
*
* \brief
*  PSA CryptoSuite transparent AEAD driver implementation.
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

#include "ifx_cryptosuite_transparent_aead.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#if defined(IFX_PSA_CRYPTOSUITE_CCM)

/* Validate CCM tag length encoded in algorithm */
static psa_status_t ifx_cryptosuite_validate_ccm_tag_length(psa_algorithm_t alg)
{
    size_t tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16 */
    if (tag_length < 4 || tag_length > 16 || (tag_length % 2) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

/* Common setup function */
static psa_status_t ifx_cryptosuite_aead_setup_common(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    bool is_encrypt)
{
    psa_key_type_t key_type;
    size_t key_bits;
    psa_status_t status;
    Cs_StdApi_OpenType aes_open_params, ccm_open_params;

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

    /* Only CCM supported */
    if (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0) != PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = ifx_cryptosuite_validate_ccm_tag_length(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Store operation parameters */
    operation->alg 			= alg;
    operation->key_bits 	= key_bits;
    operation->is_encrypt 	= is_encrypt;
    operation->tag_length 	= PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);
    ifx_mxcryptosuite_memcpy(operation->key, key_buffer, key_buffer_size);

    /* Allocate heap memory for AES entity */
    size_t aes_heap_size = ifx_cryptosuite_get_aes_heap_size(key_bits);
    
    #if defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
        /* Use static memory allocation */
        static uint8_t static_aes_heap[CS_ENTITY_AES256_SEC_HEAPSIZE];
        static uint8_t static_ccm_heap[IFX_CS_CCM_HEAP_SIZE];
        
        operation->aes_heap = static_aes_heap;
        operation->ccm_heap = static_ccm_heap;
        
        ifx_mxcryptosuite_memset(operation->aes_heap, 0, aes_heap_size);
        ifx_mxcryptosuite_memset(operation->ccm_heap, 0, ifx_cryptosuite_get_ccm_heap_size());
    #else
        /* Use dynamic memory allocation */
        operation->aes_heap = (uint8_t *)ifx_mxcryptosuite_malloc(aes_heap_size);
        if (operation->aes_heap == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ifx_mxcryptosuite_memset(operation->aes_heap, 0, aes_heap_size);

        /* Allocate heap memory for CCM entity */
        operation->ccm_heap = (uint8_t *)ifx_mxcryptosuite_malloc(ifx_cryptosuite_get_ccm_heap_size());
        if (operation->ccm_heap == NULL) {
            ifx_mxcryptosuite_free(operation->aes_heap);
            operation->aes_heap = NULL;
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ifx_mxcryptosuite_memset(operation->ccm_heap, 0, ifx_cryptosuite_get_ccm_heap_size());
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
            ifx_mxcryptosuite_free(operation->ccm_heap);
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->ccm_heap = NULL;
        operation->aes_heap = NULL;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Open CCM entity */
    ifx_mxcryptosuite_memset(&ccm_open_params, 0, sizeof(ccm_open_params));
    ccm_open_params.Super.OID 				= ifx_cryptosuite_get_ccm_oid();
    ccm_open_params.EntityFnPtr	 			= ifx_cryptosuite_get_ccm_entity();
    ccm_open_params.HeapMemPtr 				= operation->ccm_heap;
    ccm_open_params.HeapMemSize 			= ifx_cryptosuite_get_ccm_heap_size();
    ccm_open_params.OsHwEntryCallbackFnPtr 	= NULL;
    ccm_open_params.OsHwExitCallbackFnPtr 	= NULL;

    operation->ccm_handle = Cs_Open(&ccm_open_params);
    if (operation->ccm_handle.FirstPtr == NULL) {
        Cs_StdApi_CloseType aes_close_params;
        uint32_t close_func_id;
        ifx_mxcryptosuite_memset(&aes_close_params, 0, sizeof(aes_close_params));
        aes_close_params.Super.OID    = ifx_cryptosuite_get_aes_oid(key_bits);
        aes_close_params.FuncIDPtr    = &close_func_id;
        aes_close_params.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
        (void)Cs_Close(operation->aes_handle, &aes_close_params);
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->ccm_heap);
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->ccm_heap = NULL;
        operation->aes_heap = NULL;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    operation->initialized = true;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_aead_encrypt_setup(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_aead_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, true);
}

psa_status_t ifx_cryptosuite_transparent_aead_decrypt_setup(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_aead_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, false);
}

/* Configure the CCM entity once both nonce and lengths are available */
static psa_status_t ifx_cryptosuite_ccm_try_configure(
    ifx_cryptosuite_transparent_aead_operation_t *operation)
{
    Cs_Aes_CfgType aes_cfg_params;
    Cs_Ccm_CfgType ccm_cfg_params;
    Cs_XBlobType key_xblob;
    Cs_XBlobType nonce_xblob;
    uint8_t key_dst[IFX_CS_MAX_KEY_SIZE_BYTES];
    uint8_t nonce_dst[IFX_CS_MAX_NONCE_SIZE_BYTES];
    uint8_t rng_seed[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint8_t rng_seed_inv[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint32_t func_id;
    psa_status_t status;

    if (!operation->nonce_set || !operation->lengths_set) {
        return PSA_SUCCESS; /* Wait until both are available */
    }

    if (operation->ccm_configured) {
        return PSA_SUCCESS; /* Already configured */
    }

    /* Generate RNG seed */
    ifx_cryptosuite_generate_rng_seed(rng_seed, rng_seed_inv, sizeof(rng_seed));

    /* Configure the AES entity (key disabled) before using it as the CCM CipherHdl. */
    ifx_mxcryptosuite_memset(&aes_cfg_params, 0, sizeof(aes_cfg_params));
    aes_cfg_params.Super.Super.Super.OID                        = ifx_cryptosuite_get_aes_oid(operation->key_bits);
    aes_cfg_params.Super.Super.TempMemPtr                       = NULL;
    aes_cfg_params.Super.Super.TempMemSize                      = 0;
    aes_cfg_params.Super.Super.ClearTempMemOnExit               = 0;
    aes_cfg_params.Super.Super.CfgSelector.CfgSelRfu1           = CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
    aes_cfg_params.Super.Super.CfgSelector.Repetitions          = CS_STDAPI_CFG_REPETITIONS_DISABLE;
    aes_cfg_params.Super.Super.CfgSelector.UnprivilegedCallback = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
    aes_cfg_params.Super.Super.CfgSelector.RngSeed              = CS_STDAPI_CFG_RNG_SEED_ENABLE;
    aes_cfg_params.Super.Super.RngSeedPtr                       = rng_seed;
    aes_cfg_params.Super.Super.RngSeedInvPtr                    = rng_seed_inv;
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

    status = ifx_cryptosuite_to_psa_status(
        Cs_Cfg(operation->aes_handle, (Cs_StdApi_CfgType *)&aes_cfg_params));
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Build the key and nonce input XBlobs from the operation store. */
    ifx_cryptosuite_init_xblob(&key_xblob, key_dst, operation->key, IFX_CS_BITS_TO_BYTES(operation->key_bits));
    ifx_cryptosuite_init_xblob(&nonce_xblob, nonce_dst, operation->nonce, operation->nonce_length);

    /* Fresh RNG seed for the CCM config. */
    ifx_cryptosuite_generate_rng_seed(rng_seed, rng_seed_inv, sizeof(rng_seed));

    ifx_mxcryptosuite_memset(&ccm_cfg_params, 0, sizeof(ccm_cfg_params));
    ccm_cfg_params.Super.Super.Super.OID             = ifx_cryptosuite_get_ccm_oid();
    ccm_cfg_params.Super.Super.TempMemPtr            = NULL;
    ccm_cfg_params.Super.Super.TempMemSize           = 0;
    ccm_cfg_params.Super.Super.ClearTempMemOnExit    = 0;
    ccm_cfg_params.Super.Super.CfgSelector.RngSeed   = ifx_cryptosuite_get_rng_seed_enable();
    ccm_cfg_params.Super.Super.CfgSelector.CfgSelRfu1 = CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
    ccm_cfg_params.Super.Super.CfgSelector.Repetitions = CS_STDAPI_CFG_REPETITIONS_DISABLE;
    ccm_cfg_params.Super.Super.CfgSelector.UnprivilegedCallback = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
    ccm_cfg_params.Super.Super.RngSeedPtr            = rng_seed;
    ccm_cfg_params.Super.Super.RngSeedInvPtr         = rng_seed_inv;
    ccm_cfg_params.Super.Super.FuncIDPtr             = &func_id;
    ccm_cfg_params.Super.Super.FuncIDPtr[0]          = ifx_cryptosuite_get_ccm_cfg_func_id();
    ccm_cfg_params.Super.AeCfgSelector.CipherHdl     = CS_AE_CFG_CRYPTO_HDL_ENABLE;
    ccm_cfg_params.Super.AeCfgSelector.Key           = CS_AE_CFG_KEY_ENABLE;
    ccm_cfg_params.Super.AeCfgSelector.Nonce         = CS_AE_CFG_NONCE_ENABLE;
    ccm_cfg_params.Super.AeCfgSelector.AeCfgSelRfu4  = CS_AE_CFG_SEL_RFU_4_DISABLE;
    ccm_cfg_params.Super.CipherHdl                   = operation->aes_handle;
    ccm_cfg_params.Super.KeyPtr                         = &key_xblob;
    ccm_cfg_params.Super.NoncePtr                       = &nonce_xblob;
    ccm_cfg_params.TotalLenInData                    = (uint32_t)operation->plaintext_length;
    ccm_cfg_params.AdditionalDataLen                 = (uint32_t)operation->ad_length;
    ccm_cfg_params.AuthTagLen                        = (uint16_t)operation->tag_length;

    status = ifx_cryptosuite_to_psa_status(
        Cs_Cfg(operation->ccm_handle, (Cs_StdApi_CfgType *)&ccm_cfg_params));

    if (status == PSA_SUCCESS) {
        operation->ccm_configured = true;    }

    return status;
}

psa_status_t ifx_cryptosuite_transparent_aead_set_nonce(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length)
{
    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (nonce == NULL || nonce_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* CCM nonce length should be between 7 and 13 bytes */
    if (nonce_length < 7 || nonce_length > 13) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Store nonce */
    ifx_mxcryptosuite_memcpy(operation->nonce, nonce, nonce_length);
    operation->nonce_length = nonce_length;
    operation->nonce_set = true;

    return ifx_cryptosuite_ccm_try_configure(operation);
}

psa_status_t ifx_cryptosuite_transparent_aead_set_lengths(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length)
{
    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    /* Store lengths - defer Cs_Cfg until set_nonce is also called */
    operation->ad_length        = ad_length;
    operation->plaintext_length = plaintext_length;
    operation->lengths_set      = true;

    return ifx_cryptosuite_ccm_try_configure(operation);
}

psa_status_t ifx_cryptosuite_transparent_aead_update_ad(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length)
{
    Cs_Ccm_ConsumeADCtrlType ccm_aad_params;
    Cs_XBlobType aad_xblob;
    uint32_t func_id;
    psa_status_t status = PSA_SUCCESS;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (input == NULL && input_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (input_length == 0) {
        return PSA_SUCCESS; /* Nothing to do */
    }

    if (operation->body_started) {
        return PSA_ERROR_BAD_STATE; /* Cannot add AD after body started */
    }

    if (!operation->ccm_configured) {
        return PSA_ERROR_BAD_STATE; /* set_lengths + set_nonce must precede AAD */
    }

    /* Feed the AAD to CCM in <=IFX_CS_MAX_AAD_CHUNK_BYTES block-aligned ConsumeAD chunks. */
    ifx_mxcryptosuite_memset(&ccm_aad_params, 0, sizeof(ccm_aad_params));
    ccm_aad_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_ccm_oid();
    ccm_aad_params.Super.Super.TempMemPtr 			= NULL;
    ccm_aad_params.Super.Super.TempMemSize 			= 0;
    ccm_aad_params.Super.Super.ClearTempMemOnExit 	= 0;
    ccm_aad_params.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_ccm_consume_ad_fn();
    ccm_aad_params.Super.Super.FuncIDPtr 			= &func_id;
    ccm_aad_params.Super.AdditionalDataPtr 			= &aad_xblob;

    size_t aad_offset = 0;
    while (aad_offset < input_length) {
        size_t chunk = input_length - aad_offset;
        if (chunk > IFX_CS_MAX_AAD_CHUNK_BYTES) {
            chunk = IFX_CS_MAX_AAD_CHUNK_BYTES;
        }
        /* AAD input XBlob: zero-seed over the const AAD pointer. */
        ifx_mxcryptosuite_memset(&aad_xblob, 0, sizeof(aad_xblob));
        aad_xblob.Data1Ptr   = (uint8_t *)(input + aad_offset);
        aad_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                           (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        aad_xblob.ByteLen    = (uint16_t)chunk;
        aad_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&aad_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        ccm_aad_params.Super.Super.FuncIDPtr[0] = CS_AE_CONSUME_AD_INPUT_FUNC_ID;
        status = ifx_cryptosuite_to_psa_status(
            Cs_Ctrl(operation->ccm_handle, (Cs_StdApi_CtrlType *)&ccm_aad_params));
        if (status != PSA_SUCCESS) {
            break;
        }
        aad_offset += chunk;
    }

    if (status == PSA_SUCCESS) {
        operation->ad_started = true;
    }

    return status;
}

psa_status_t ifx_cryptosuite_transparent_aead_update(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    Cs_Ccm_CtrlType ccm_ctrl_params;
    Cs_XBlobType in_xblob, out_xblob;
    uint32_t func_id;
    uint32_t red_status_word = 0;
    uint32_t red_status_initial = 0;
    psa_status_t status;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((input == NULL && input_length > 0) || (output == NULL && output_size > 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* output_size must be >= PSA_AEAD_UPDATE_OUTPUT_SIZE; for AES-CCM this is the input
     * length rounded up to the next 16-byte block. */
    if (output_size < PSA_AEAD_UPDATE_OUTPUT_SIZE(PSA_KEY_TYPE_AES, operation->alg, input_length)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (input_length == 0) {
        *output_length = 0;
        return PSA_SUCCESS;
    }

    if (!operation->ccm_configured) {
        *output_length = 0;
        return PSA_ERROR_BAD_STATE; /* set_lengths + set_nonce must precede body */
    }

    /* Track cumulative body to detect the update that completes the declared plaintext length. */
    operation->body_received += input_length;
    const size_t BLOCK = IFX_CS_MAX_IV_SIZE_BYTES;
    size_t total   = operation->body_buf_len + input_length;
    bool is_final  = (operation->body_received == operation->plaintext_length);

    /* ENCRYPT fast path: when this update completes the declared body and it fits one
     * XBlob (uint16 ByteLen), encrypt it all now and stash the tag for finish(). */
    if (operation->is_encrypt && is_final && output_size >= total && total <= 0xFFFFu) {
        Cs_XBlobType tag_xblob;
        uint8_t tag_buf[IFX_CS_MAX_IV_SIZE_BYTES];

        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        if (operation->body_buf_len == 0) {
            /* No buffered tail: point the zero-seed input XBlob at the const input. */
            in_xblob.Data1Ptr = (uint8_t *)input;
        } else {
            /* Assemble tail + input into the output buffer and encrypt it there. */
            ifx_mxcryptosuite_memcpy(output, operation->body_buf, operation->body_buf_len);
            ifx_mxcryptosuite_memcpy(output + operation->body_buf_len, input, input_length);
            in_xblob.Data1Ptr = output;
        }
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)total;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, output, total);
        ifx_cryptosuite_prepare_output_xblob(&tag_xblob, tag_buf, operation->tag_length);

        ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
        ccm_ctrl_params.Super.Super.Super.OID          = ifx_cryptosuite_get_ccm_oid();
        ccm_ctrl_params.Super.Super.TempMemPtr         = NULL;
        ccm_ctrl_params.Super.Super.TempMemSize        = 0;
        ccm_ctrl_params.Super.Super.ClearTempMemOnExit = 0;
        ccm_ctrl_params.Super.Super.CccFnPtr           = ifx_cryptosuite_get_ccm_encrypt_fn();
        ccm_ctrl_params.Super.Super.FuncIDPtr          = &func_id;
        ccm_ctrl_params.Super.Super.FuncIDPtr[0]       = CS_AE_ENCRYPT_INPUT_FUNC_ID;
        ccm_ctrl_params.Super.InDataPtr                = &in_xblob;
        ccm_ctrl_params.Super.OutDataPtr               = &out_xblob;
        ccm_ctrl_params.Super.AuthTagIOPtr             = &tag_xblob;

        status = ifx_cryptosuite_to_psa_status(
            Cs_Ctrl(operation->ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));

        if (status == PSA_SUCCESS) {
            if (total > 0) {
                status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
                if (status == PSA_SUCCESS) {
                    (void)Cs_XBlob_Export(&out_xblob, output, NULL, NULL, NULL);
                }
            }
            if (status == PSA_SUCCESS) {
                status = ifx_cryptosuite_verify_output_xblob(&tag_xblob);
                if (status == PSA_SUCCESS) {
                    (void)Cs_XBlob_Export(&tag_xblob, operation->stored_tag, NULL, NULL, NULL);
                    operation->tag_stored   = true;
                    operation->body_buf_len = 0;
                }
            }
        }

        if (status != PSA_SUCCESS) {
            *output_length = 0;
            return status;
        }

        *output_length = total;
        operation->body_started = true;
        return PSA_SUCCESS;
    }

    /* General path (all decrypt, plus encrypt when the fast path cannot apply):
     * process only whole blocks guaranteed not to be the last, and defer the
     * trailing 1..16 bytes to finish()/verify(). */
    size_t process = (total > BLOCK) ? (((total - 1) / BLOCK) * BLOCK) : 0;

    if (process == 0) {
        ifx_mxcryptosuite_memcpy(operation->body_buf + operation->body_buf_len, input, input_length);
        operation->body_buf_len += input_length;
        *output_length = 0;
        operation->body_started = true;
        return PSA_SUCCESS;
    }

    /* For decrypt: pre-initialise RedStatusWord with a random value before Cs_Ccc_Ae_Dec. */
    if (!operation->is_encrypt) {
        status = ifx_cryptosuite_generate_random_u32(&red_status_initial);
        if (status != PSA_SUCCESS) {
            *output_length = 0;
            return status;
        }
        red_status_word = red_status_initial;
    }

    /* Process the block-aligned data in IFX_CS_BODY_CHUNK_SIZE chunks. */
    size_t from_input = process - operation->body_buf_len;
    size_t done = 0;
    while (done < process) {
        size_t chunk = process - done;
        if (chunk > IFX_CS_BODY_CHUNK_SIZE) {
            chunk = IFX_CS_BODY_CHUNK_SIZE;
        }

        /* Assemble the chunk (body_buf tail + input) into body_scratch_in and read it
         * with zero seeds. The buffered tail (<16 B) is present only at the start. */
        size_t filled = 0;
        if (done < operation->body_buf_len) {
            size_t from_buf = operation->body_buf_len - done;
            ifx_mxcryptosuite_memcpy(operation->body_scratch_in, operation->body_buf + done, from_buf);
            filled = from_buf;
        }
        size_t input_start = (done + filled) - operation->body_buf_len;
        ifx_mxcryptosuite_memcpy(operation->body_scratch_in + filled, input + input_start, chunk - filled);

        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = operation->body_scratch_in;
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)chunk;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        /* Output XBlob points at the caller's output buffer. */
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, output + done, chunk);

        ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
        ccm_ctrl_params.Super.Super.Super.OID            = ifx_cryptosuite_get_ccm_oid();
        ccm_ctrl_params.Super.Super.TempMemPtr           = NULL;
        ccm_ctrl_params.Super.Super.TempMemSize          = 0;
        ccm_ctrl_params.Super.Super.ClearTempMemOnExit   = 0;
        ccm_ctrl_params.Super.Super.CccFnPtr             = operation->is_encrypt ?
                                                           ifx_cryptosuite_get_ccm_encrypt_fn() :
                                                           ifx_cryptosuite_get_ccm_decrypt_fn();
        ccm_ctrl_params.Super.Super.FuncIDPtr            = &func_id;
        ccm_ctrl_params.Super.Super.FuncIDPtr[0]         = operation->is_encrypt ?
                                                           CS_AE_ENCRYPT_INPUT_FUNC_ID :
                                                           CS_AE_DECRYPT_INPUT_FUNC_ID;
        ccm_ctrl_params.Super.InDataPtr                     = &in_xblob;
        ccm_ctrl_params.Super.OutDataPtr                    = &out_xblob;
        ccm_ctrl_params.Super.AuthTagIOPtr                  = NULL;
        ccm_ctrl_params.Super.RedStatusWord              = (!operation->is_encrypt) ? &red_status_word : NULL;

        status = ifx_cryptosuite_to_psa_status(
            Cs_Ctrl(operation->ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));

        if (status == PSA_SUCCESS) {
            status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
            if (status == PSA_SUCCESS) {
                (void)Cs_XBlob_Export(&out_xblob, output + done, NULL, NULL, NULL);
            }
        }

        if (status != PSA_SUCCESS) {
            *output_length = 0;
            return status;
        }

        done += chunk;
    }

    /* Save the deferred trailing bytes (1..16) for the finalizing call. */
    size_t rem = total - process;
    ifx_mxcryptosuite_memcpy(operation->body_buf, input + from_input, rem);
    operation->body_buf_len = rem;

    *output_length = process;
    operation->body_started = true;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_aead_finish(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length)
{
    psa_status_t status;
    Cs_Ccm_CtrlType ccm_ctrl_params;
    Cs_XBlobType in_xblob, out_xblob, tag_xblob;
    uint32_t func_id;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!operation->is_encrypt) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ciphertext_length == NULL || tag_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((ciphertext == NULL && ciphertext_size > 0) || (tag == NULL && tag_size > 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (tag_size < operation->tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Configure CCM if the caller went from set_nonce to finish without set_lengths
     * (valid for CCM: treat both lengths as zero). */
    if (!operation->ccm_configured) {
        if (!operation->lengths_set) {
            operation->ad_length        = 0;
            operation->plaintext_length = 0;
            operation->lengths_set      = true;
        }
        status = ifx_cryptosuite_ccm_try_configure(operation);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (!operation->ccm_configured) {
            return PSA_ERROR_BAD_STATE; /* nonce not set */
        }
    }

    /* Tag was produced during update(); return it and emit no ciphertext. */
    if (operation->tag_stored) {
        ifx_mxcryptosuite_memcpy(tag, operation->stored_tag, operation->tag_length);
        *ciphertext_length = 0;
        *tag_length = operation->tag_length;
        return PSA_SUCCESS;
    }

    if (ciphertext_size < operation->body_buf_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Feed the deferred final body block (0..16 bytes) with the tag buffer; this
     * completes TotalLenInData so CCM emits the tag. */
    /* rem = body_buf_len, always <= 16 bytes. */
    size_t   rem     = operation->body_buf_len;
    uint8_t  tag_buf[16];
    /* Final body block input XBlob: zero-seed over body_buf. */
    ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
    in_xblob.Data1Ptr   = operation->body_buf;
    in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                      (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
    in_xblob.ByteLen    = (uint16_t)rem;
    in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                      CS_XBLOB_INTEGRITY_STANDARD, NULL);
    /* Output XBlob points at the caller's ciphertext. */
    ifx_cryptosuite_prepare_output_xblob(&out_xblob, ciphertext, rem);
    ifx_cryptosuite_prepare_output_xblob(&tag_xblob, tag_buf, operation->tag_length);

    ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
    ccm_ctrl_params.Super.Super.Super.OID            = ifx_cryptosuite_get_ccm_oid();
    ccm_ctrl_params.Super.Super.TempMemPtr           = NULL;
    ccm_ctrl_params.Super.Super.TempMemSize          = 0;
    ccm_ctrl_params.Super.Super.ClearTempMemOnExit   = 0;
    ccm_ctrl_params.Super.Super.CccFnPtr             = ifx_cryptosuite_get_ccm_encrypt_fn();
    ccm_ctrl_params.Super.Super.FuncIDPtr            = &func_id;
    ccm_ctrl_params.Super.Super.FuncIDPtr[0]         = CS_AE_ENCRYPT_INPUT_FUNC_ID;
    ccm_ctrl_params.Super.InDataPtr                     = &in_xblob;
    ccm_ctrl_params.Super.OutDataPtr                    = &out_xblob;
    ccm_ctrl_params.Super.AuthTagIOPtr                  = &tag_xblob;

    status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation->ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));

    if (status == PSA_SUCCESS) {
        if (rem > 0) {
            status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
            if (status == PSA_SUCCESS) {
                (void)Cs_XBlob_Export(&out_xblob, ciphertext, NULL, NULL, NULL);
            }
        }
        if (status == PSA_SUCCESS) {
            status = ifx_cryptosuite_verify_output_xblob(&tag_xblob);
            if (status == PSA_SUCCESS) {
                (void)Cs_XBlob_Export(&tag_xblob, tag, NULL, NULL, NULL);
            }
        }
    }

    if (status != PSA_SUCCESS) {
        *ciphertext_length = 0;
        *tag_length = 0;
        return status;
    }

    *ciphertext_length = rem;
    *tag_length = operation->tag_length;
    
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_aead_verify(
    ifx_cryptosuite_transparent_aead_operation_t *operation,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length,
    const uint8_t *tag,
    size_t tag_length)
{
    psa_status_t status;
    Cs_Ccm_CtrlType ccm_ctrl_params;
    Cs_XBlobType in_xblob, out_xblob, tag_xblob;
    uint32_t func_id;
    uint32_t red_status_word;
    uint32_t red_status_initial;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->is_encrypt) {
        return PSA_ERROR_BAD_STATE;
    }

    if (plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext == NULL && plaintext_size > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* A tag length mismatch can never match, so report INVALID_SIGNATURE. */
    if (tag_length != operation->tag_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (tag == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_size < operation->body_buf_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Configure CCM if the caller went from set_nonce to verify without set_lengths
     * (treat both lengths as zero). */
    if (!operation->ccm_configured) {
        if (!operation->lengths_set) {
            operation->ad_length        = 0;
            operation->plaintext_length = 0;
            operation->lengths_set      = true;
        }
        status = ifx_cryptosuite_ccm_try_configure(operation);
        if (status != PSA_SUCCESS) {
            *plaintext_length = 0;
            return status;
        }
        if (!operation->ccm_configured) {
            return PSA_ERROR_BAD_STATE; /* nonce not set */
        }
    }

    /* Pre-initialise RedStatusWord with a random value to guard the tag-verification
     * result against fault injection. */
    status = ifx_cryptosuite_generate_random_u32(&red_status_initial);
    if (status != PSA_SUCCESS) {
        *plaintext_length = 0;
        return status;
    }
    red_status_word = red_status_initial;

    /* Feed the deferred final ciphertext block with the supplied tag; this completes
     * TotalLenInData so CCM verifies the tag. */
    /* rem = body_buf_len, always <= 16 bytes. */
    size_t   rem     = operation->body_buf_len;
    uint8_t  tag_buf[16];
    /* Final ciphertext block input XBlob: zero-seed over body_buf. Tag stays masked
     * as a security-sensitive input. */
    ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
    in_xblob.Data1Ptr   = operation->body_buf;
    in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                      (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
    in_xblob.ByteLen    = (uint16_t)rem;
    in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                      CS_XBLOB_INTEGRITY_STANDARD, NULL);
    ifx_cryptosuite_init_xblob(&tag_xblob, tag_buf, tag, tag_length);
    /* Output XBlob points at the caller's plaintext. */
    ifx_cryptosuite_prepare_output_xblob(&out_xblob, plaintext, rem);

    ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
    ccm_ctrl_params.Super.Super.Super.OID            = ifx_cryptosuite_get_ccm_oid();
    ccm_ctrl_params.Super.Super.TempMemPtr           = NULL;
    ccm_ctrl_params.Super.Super.TempMemSize          = 0;
    ccm_ctrl_params.Super.Super.ClearTempMemOnExit   = 0;
    ccm_ctrl_params.Super.Super.CccFnPtr             = ifx_cryptosuite_get_ccm_decrypt_fn();
    ccm_ctrl_params.Super.Super.FuncIDPtr            = &func_id;
    ccm_ctrl_params.Super.Super.FuncIDPtr[0]         = CS_AE_DECRYPT_INPUT_FUNC_ID;
    ccm_ctrl_params.Super.InDataPtr                     = &in_xblob;
    ccm_ctrl_params.Super.OutDataPtr                    = &out_xblob;
    ccm_ctrl_params.Super.AuthTagIOPtr                  = &tag_xblob;
    ccm_ctrl_params.Super.RedStatusWord              = &red_status_word;

    status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation->ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));
    if (status == PSA_ERROR_GENERIC_ERROR) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

    if (status == PSA_SUCCESS &&
        red_status_word != (red_status_initial + CS_AE_REDUNDANT_VALUE_SUCCESS)) {
        *plaintext_length = 0;
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    if (status == PSA_SUCCESS && rem > 0) {
        status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
        if (status == PSA_SUCCESS) {
            (void)Cs_XBlob_Export(&out_xblob, plaintext, NULL, NULL, NULL);
        }
    }

    if (status != PSA_SUCCESS) {
        *plaintext_length = 0;
        return status;
    }

    *plaintext_length = rem;
    
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_aead_abort(
    ifx_cryptosuite_transparent_aead_operation_t *operation)
{
  	uint32_t func_id;
    
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Safely abort even if operation is in an inconsistent state */
    if (operation->initialized) {
        /* Close AES handle first */
		if (operation->aes_handle.FirstPtr != NULL) {
			  Cs_StdApi_CloseType aes_close_params;
			  
			  ifx_mxcryptosuite_memset(&aes_close_params, 0, sizeof(aes_close_params));
			  aes_close_params.Super.OID    = ifx_cryptosuite_get_aes_oid(operation->key_bits);
			  aes_close_params.FuncIDPtr    = &func_id;
			  aes_close_params.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
			  (void)Cs_Close(operation->aes_handle, &aes_close_params);	  
		}
        
        /* Close CCM handle */
        if (operation->ccm_handle.FirstPtr != NULL) 
        {
              Cs_StdApi_CloseType ccm_close_params;
			  ifx_mxcryptosuite_memset(&ccm_close_params, 0, sizeof(ccm_close_params));
			  ccm_close_params.Super.OID    = ifx_cryptosuite_get_ccm_oid();
			  ccm_close_params.FuncIDPtr    = &func_id;
			  ccm_close_params.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
			  (void)Cs_Close(operation->ccm_handle, &ccm_close_params);
		}
	}
			  
  	ifx_mxcryptosuite_memset(&operation->aes_handle, 0, sizeof(operation->aes_handle));
    ifx_mxcryptosuite_memset(&operation->ccm_handle, 0, sizeof(operation->ccm_handle));
    ifx_mxcryptosuite_memset(operation->key, 0, sizeof(operation->key));
    
    /* Free heap memory - only if using dynamic allocation */
    if (operation->aes_heap != NULL) {
        /* Use stored key_bits if available, otherwise use maximum size for safety */
        size_t heap_size = (operation->key_bits > 0) ? 
                           ifx_cryptosuite_get_aes_heap_size(operation->key_bits) : 
                           IFX_CS_HEAP_SIZE;
        ifx_mxcryptosuite_memset(operation->aes_heap, 0, heap_size);
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->aes_heap);
        #endif
        operation->aes_heap = NULL;
    }
        if (operation->ccm_heap != NULL) {
        ifx_mxcryptosuite_memset(operation->ccm_heap, 0, ifx_cryptosuite_get_ccm_heap_size());
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->ccm_heap);
        #endif
        operation->ccm_heap = NULL;
    }

    return PSA_SUCCESS;
}

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
    size_t *ciphertext_length)
{
    psa_status_t status;
    ifx_cryptosuite_transparent_aead_operation_t operation = {0};
    psa_key_type_t key_type;
    size_t key_bits;
    size_t tag_length;
    Cs_Ccm_ConsumeADCtrlType ccm_aad_params;
    Cs_Ccm_CtrlType ccm_ctrl_params;
    Cs_XBlobType aad_xblob, in_xblob, out_xblob, tag_xblob;
    uint32_t func_id;

    if (attributes == NULL || key_buffer == NULL || ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptosuite_validate_ccm_tag_length(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Get key attributes */
    key_type = psa_get_key_type(attributes);
    key_bits = psa_get_key_bits(attributes);
    tag_length = PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);

    if (ciphertext_size < plaintext_length + tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Single-XBlob ByteLen is uint16_t; reject messages larger than 0xFFFF bytes. */
    if (plaintext_length > 0xFFFFu) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Use existing setup function to initialize operation */
    status = ifx_cryptosuite_aead_setup_common(&operation, attributes, key_buffer, key_buffer_size, alg, true);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Set nonce and configure for encryption */
    status = ifx_cryptosuite_transparent_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = ifx_cryptosuite_transparent_aead_set_lengths(&operation, additional_data_length, plaintext_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Process additional data if present */
    if (additional_data_length > 0) {
        ifx_mxcryptosuite_memset(&ccm_aad_params, 0, sizeof(ccm_aad_params));
        ccm_aad_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_ccm_oid();
        ccm_aad_params.Super.Super.TempMemPtr 			= NULL;
        ccm_aad_params.Super.Super.TempMemSize 			= 0;
        ccm_aad_params.Super.Super.ClearTempMemOnExit 	= 0;
        ccm_aad_params.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_ccm_consume_ad_fn();
        ccm_aad_params.Super.Super.FuncIDPtr 			= &func_id;
        ccm_aad_params.Super.AdditionalDataPtr 			= &aad_xblob;

        /* Feed the AAD as one or more block-aligned ConsumeAD calls; ByteLen is uint16_t
         * so each chunk is at most IFX_CS_MAX_AAD_CHUNK_BYTES. */
        size_t aad_offset = 0;
        while (aad_offset < additional_data_length) {
            size_t chunk = additional_data_length - aad_offset;
            if (chunk > IFX_CS_MAX_AAD_CHUNK_BYTES) {
                chunk = IFX_CS_MAX_AAD_CHUNK_BYTES;
            }
            /* AAD input XBlob: zero-seed over the const AAD pointer. */
            ifx_mxcryptosuite_memset(&aad_xblob, 0, sizeof(aad_xblob));
            aad_xblob.Data1Ptr   = (uint8_t *)(additional_data + aad_offset);
            aad_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                               (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
            aad_xblob.ByteLen    = (uint16_t)chunk;
            aad_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&aad_xblob, CS_XBLOB_ID_DEFAULT,
                                                              CS_XBLOB_INTEGRITY_STANDARD, NULL);
            ccm_aad_params.Super.Super.FuncIDPtr[0] = CS_AE_CONSUME_AD_INPUT_FUNC_ID;
            status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation.ccm_handle, (Cs_StdApi_CtrlType *)&ccm_aad_params));
            if (status != PSA_SUCCESS) {
                goto cleanup;
            }
            aad_offset += chunk;
        }
    }

    /* Encrypt plaintext in a single body call that also produces the tag. Input uses a
     * zero-seed XBlob on the const plaintext; output points at the caller's ciphertext. */
    {
        uint8_t  tag_buf[16];
        /* Plaintext input XBlob: zero-seed over the const plaintext. */
        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = (uint8_t *)plaintext;
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)plaintext_length;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        /* Output XBlob points at the caller's ciphertext; Cs_XBlob_Export un-masks it. */
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, ciphertext, plaintext_length);
        ifx_cryptosuite_prepare_output_xblob(&tag_xblob, tag_buf, tag_length);

        ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
        ccm_ctrl_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_ccm_oid();
        ccm_ctrl_params.Super.Super.TempMemPtr 			= NULL;
        ccm_ctrl_params.Super.Super.TempMemSize 		= 0;
        ccm_ctrl_params.Super.Super.ClearTempMemOnExit 	= 0;
        ccm_ctrl_params.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_ccm_encrypt_fn();
        ccm_ctrl_params.Super.Super.FuncIDPtr 			= &func_id;
        ccm_ctrl_params.Super.Super.FuncIDPtr[0] 		= CS_AE_ENCRYPT_INPUT_FUNC_ID;
        ccm_ctrl_params.Super.InDataPtr 					= &in_xblob;
        ccm_ctrl_params.Super.OutDataPtr 					= &out_xblob;
        ccm_ctrl_params.Super.AuthTagIOPtr 				= &tag_xblob;

        status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation.ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));

        if (status == PSA_SUCCESS) {
            /* Un-mask ciphertext then tag into the caller's output buffer. */
            if (plaintext_length > 0) {
                status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
                if (status == PSA_SUCCESS) {
                    (void)Cs_XBlob_Export(&out_xblob, ciphertext, NULL, NULL, NULL);
                }
            }
            if (status == PSA_SUCCESS) {
                status = ifx_cryptosuite_verify_output_xblob(&tag_xblob);
                if (status == PSA_SUCCESS) {
                    (void)Cs_XBlob_Export(&tag_xblob, ciphertext + plaintext_length, NULL, NULL, NULL);
                    *ciphertext_length = plaintext_length + tag_length;
                }
            }
        }
    }

cleanup:
    /* Use existing abort function for cleanup */
    ifx_cryptosuite_transparent_aead_abort(&operation);
    return status;
}

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
    size_t *plaintext_length)
{
    psa_status_t status;
    ifx_cryptosuite_transparent_aead_operation_t operation = {0};
    psa_key_type_t key_type;
    size_t key_bits;
    size_t tag_length;
    size_t actual_ciphertext_length;
    Cs_Ccm_ConsumeADCtrlType ccm_aad_params;
    Cs_Ccm_CtrlType ccm_ctrl_params;
    Cs_XBlobType aad_xblob, in_xblob, out_xblob, tag_xblob;
    uint32_t func_id;
    uint32_t red_status_initial = 0;
    uint32_t red_status_word    = 0;

    if (attributes == NULL || key_buffer == NULL || plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = ifx_cryptosuite_validate_ccm_tag_length(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Get key attributes */
    key_type 	= psa_get_key_type(attributes);
    key_bits 	= psa_get_key_bits(attributes);
    tag_length 	= PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg);

    if (ciphertext_length < tag_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    actual_ciphertext_length = ciphertext_length - tag_length;

    if (plaintext_size < actual_ciphertext_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Single-XBlob ByteLen is uint16_t; reject messages larger than 0xFFFF bytes. */
    if (actual_ciphertext_length > 0xFFFFu) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Use existing setup function to initialize operation */
    status = ifx_cryptosuite_aead_setup_common(&operation, attributes, key_buffer, key_buffer_size, alg, false);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Set nonce and configure for decryption */
    status = ifx_cryptosuite_transparent_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = ifx_cryptosuite_transparent_aead_set_lengths(&operation, additional_data_length, actual_ciphertext_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Process additional data if present */
    if (additional_data_length > 0) {
        ifx_mxcryptosuite_memset(&ccm_aad_params, 0, sizeof(ccm_aad_params));
        ccm_aad_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_ccm_oid();
        ccm_aad_params.Super.Super.TempMemPtr 			= NULL;
        ccm_aad_params.Super.Super.TempMemSize 			= 0;
        ccm_aad_params.Super.Super.ClearTempMemOnExit 	= 0;
        ccm_aad_params.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_ccm_consume_ad_fn();
        ccm_aad_params.Super.Super.FuncIDPtr 			= &func_id;
        ccm_aad_params.Super.AdditionalDataPtr 			= &aad_xblob;

        /* Feed the AAD as one or more block-aligned ConsumeAD calls; ByteLen is uint16_t
         * so each chunk is at most IFX_CS_MAX_AAD_CHUNK_BYTES. */
        size_t aad_offset = 0;
        while (aad_offset < additional_data_length) {
            size_t chunk = additional_data_length - aad_offset;
            if (chunk > IFX_CS_MAX_AAD_CHUNK_BYTES) {
                chunk = IFX_CS_MAX_AAD_CHUNK_BYTES;
            }
            /* AAD input XBlob: zero-seed over the const AAD pointer. */
            ifx_mxcryptosuite_memset(&aad_xblob, 0, sizeof(aad_xblob));
            aad_xblob.Data1Ptr   = (uint8_t *)(additional_data + aad_offset);
            aad_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                               (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
            aad_xblob.ByteLen    = (uint16_t)chunk;
            aad_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&aad_xblob, CS_XBLOB_ID_DEFAULT,
                                                              CS_XBLOB_INTEGRITY_STANDARD, NULL);
            ccm_aad_params.Super.Super.FuncIDPtr[0] = CS_AE_CONSUME_AD_INPUT_FUNC_ID;
            status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation.ccm_handle, (Cs_StdApi_CtrlType *)&ccm_aad_params));
            if (status != PSA_SUCCESS) {
                goto cleanup;
            }
            aad_offset += chunk;
        }
    }

    /* Decrypt ciphertext and verify tag in a single body call. Output points at the
     * caller's plaintext buffer. */
    {
        uint8_t  tag_dst[16];
        /* Ciphertext input XBlob: zero-seed over the const ciphertext. Tag stays masked
         * as a security-sensitive input. */
        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = (uint8_t *)ciphertext;
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)actual_ciphertext_length;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        ifx_cryptosuite_init_xblob(&tag_xblob, tag_dst, ciphertext + actual_ciphertext_length, tag_length);
        /* Output XBlob points at the caller's plaintext; Cs_XBlob_Export un-masks it. */
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, plaintext, actual_ciphertext_length);

        ifx_mxcryptosuite_memset(&ccm_ctrl_params, 0, sizeof(ccm_ctrl_params));
        ccm_ctrl_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_ccm_oid();
        ccm_ctrl_params.Super.Super.TempMemPtr 			= NULL;
        ccm_ctrl_params.Super.Super.TempMemSize 		= 0;
        ccm_ctrl_params.Super.Super.ClearTempMemOnExit 	= 0;
        ccm_ctrl_params.Super.Super.CccFnPtr 			= ifx_cryptosuite_get_ccm_decrypt_fn();
        ccm_ctrl_params.Super.Super.FuncIDPtr 			= &func_id;
        ccm_ctrl_params.Super.Super.FuncIDPtr[0] 		= CS_AE_DECRYPT_INPUT_FUNC_ID;
        ccm_ctrl_params.Super.InDataPtr 					= &in_xblob;
        ccm_ctrl_params.Super.OutDataPtr 					= &out_xblob;
        ccm_ctrl_params.Super.AuthTagIOPtr 				= &tag_xblob;

        /* Pre-initialise RedStatusWord with a random value. */
        status = ifx_cryptosuite_generate_random_u32(&red_status_initial);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
        red_status_word = red_status_initial;
        ccm_ctrl_params.Super.RedStatusWord = &red_status_word;

        status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation.ccm_handle, (Cs_StdApi_CtrlType *)&ccm_ctrl_params));

        if (status == PSA_SUCCESS) {
            /* Redundant status check: verify HW updated RedStatusWord as expected. */
            if (red_status_word != (red_status_initial + CS_AE_REDUNDANT_VALUE_SUCCESS)) {
                status = PSA_ERROR_CORRUPTION_DETECTED;
                goto cleanup;
            }
            /* Un-mask the plaintext share into the caller's output buffer. */
            if (actual_ciphertext_length > 0) {
                status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
                if (status == PSA_SUCCESS) {
                    (void)Cs_XBlob_Export(&out_xblob, plaintext, NULL, NULL, NULL);
                }
            }
            if (status == PSA_SUCCESS) {
                *plaintext_length = actual_ciphertext_length;
            }
        } else if (status == PSA_ERROR_GENERIC_ERROR) {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }
    }
    
cleanup:
    /* Use existing abort function for cleanup */
    ifx_cryptosuite_transparent_aead_abort(&operation);
    return status;
}
    
#endif /* IFX_PSA_CRYPTOSUITE_CCM */

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */
