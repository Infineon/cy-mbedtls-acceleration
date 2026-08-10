/***************************************************************************//**
* \file ifx_cryptosuite_transparent_cipher.c
*
* \brief
*  PSA CryptoSuite transparent cipher driver implementation.
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

#include "ifx_cryptosuite_transparent_cipher.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#if defined(IFX_PSA_CRYPTOSUITE_AES)

/* Setup helper function - common code for encrypt and decrypt setup */
static psa_status_t ifx_cryptosuite_cipher_setup_common(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    bool is_encrypt)
{
    psa_status_t status;
    psa_key_type_t key_type;
    size_t key_bits;
    Cs_StdApi_OpenType open_params;
    Cs_Aes_CfgType cfg_params;
    Cs_XBlobType key_xblob;
    uint8_t rng_seed[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint8_t rng_seed_inv[IFX_CS_RNG_SEED_SIZE_BYTES];
    uint32_t func_id;
    Cs_StdApi_EntityFnPtrType entity_fn;
    uint32_t oid;
    size_t heap_size;

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

    /* Reject unknown / unsupported cipher algorithms with NOT_SUPPORTED. */
    if (ifx_cryptosuite_get_cipher_ccc_fn(alg, is_encrypt) == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Get entity function and OID based on key size */
    entity_fn	= ifx_cryptosuite_get_aes_entity(key_bits);
    oid 		= ifx_cryptosuite_get_aes_oid(key_bits);
    heap_size 	= ifx_cryptosuite_get_aes_heap_size(key_bits);

    if (entity_fn == NULL || oid == 0 || heap_size == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Store operation parameters */
    operation->alg 			= alg;
    operation->key_bits 	= key_bits;
    operation->is_encrypt 	= is_encrypt;
    operation->iv_length 	= PSA_CIPHER_IV_LENGTH(key_type, alg);
    ifx_mxcryptosuite_memcpy(operation->key, key_buffer, key_buffer_size);

    /* Allocate heap memory for CryptoSuite entity */
    #if defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
        /* Use static memory allocation */
        static uint8_t static_cs_heap[CS_ENTITY_AES256_SEC_HEAPSIZE];
        
        operation->cs_heap = static_cs_heap;
        ifx_mxcryptosuite_memset(operation->cs_heap, 0, heap_size);
    #else
        /* Use dynamic memory allocation */
        operation->cs_heap = (uint8_t *)ifx_mxcryptosuite_malloc(heap_size);
        if (operation->cs_heap == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ifx_mxcryptosuite_memset(operation->cs_heap, 0, heap_size);
    #endif

    /* Open CryptoSuite entity */
    ifx_mxcryptosuite_memset(&open_params, 0, sizeof(open_params));
    open_params.Super.OID 				= oid;
    open_params.EntityFnPtr 			= entity_fn;
    open_params.HeapMemPtr 				= operation->cs_heap;
    open_params.HeapMemSize 			= heap_size;
    open_params.OsHwEntryCallbackFnPtr 	= NULL;
    open_params.OsHwExitCallbackFnPtr 	= NULL;

    operation->cs_handle = Cs_Open(&open_params);
        
    if (operation->cs_handle.FirstPtr == NULL) {
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->cs_heap);
        #endif
        operation->cs_heap = NULL;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Generate RNG seed for masking */
    ifx_cryptosuite_generate_rng_seed(rng_seed, rng_seed_inv, sizeof(rng_seed));

    /* Build the key XBlob. Data1Ptr must be writable, so use operation->key
     * (a writable copy); key_buffer is the source share. */
    ifx_mxcryptosuite_memset(&key_xblob, 0, sizeof(key_xblob));
    key_xblob.Data1Ptr   = operation->key;
    key_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY << CS_XBLOB_TYPE_Pos) |
                                      (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
    key_xblob.ByteLen    = (uint16_t)key_buffer_size;
    (void)ifx_cryptosuite_generate_random_u32(&key_xblob.Seed2);
    (void)ifx_cryptosuite_generate_random_u32(&key_xblob.Seed3);
    (void)Cs_XBlob_Import(&key_xblob, key_buffer, NULL, NULL, NULL);

    /* Configure entity with key */
    ifx_mxcryptosuite_memset(&cfg_params, 0, sizeof(cfg_params));
    cfg_params.Super.Super.Super.OID 				= oid;
    cfg_params.Super.Super.TempMemPtr 				= NULL;
    cfg_params.Super.Super.TempMemSize 				= 0;
    cfg_params.Super.Super.ClearTempMemOnExit 		= 0;
    cfg_params.Super.Super.CfgSelector.RngSeed 		= ifx_cryptosuite_get_rng_seed_enable();
    cfg_params.Super.Super.CfgSelector.CfgSelRfu1 	= CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
    cfg_params.Super.Super.CfgSelector.Repetitions 	= CS_STDAPI_CFG_REPETITIONS_DISABLE;
    cfg_params.Super.Super.CfgSelector.UnprivilegedCallback = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
    cfg_params.Super.Super.RngSeedPtr 				= rng_seed;
    cfg_params.Super.Super.RngSeedInvPtr 			= rng_seed_inv;
    cfg_params.Super.Super.FuncIDPtr 				= &func_id;
    cfg_params.Super.Super.FuncIDPtr[0] 			= ifx_cryptosuite_get_cipher_cfg_func_id();
    cfg_params.Super.CipherCfgSelector.Key 			= ifx_cryptosuite_get_cipher_cfg_key_enable();
    cfg_params.Super.CipherCfgSelector.Rfu1 		= CS_CIPHER_CFG_SEL_RFU_1_DISABLE;
    cfg_params.Super.CipherCfgSelector.Rfu2 		= CS_CIPHER_CFG_SEL_RFU_2_DISABLE;
    cfg_params.Super.CipherCfgSelector.Rfu3 		= CS_CIPHER_CFG_SEL_RFU_3_DISABLE;
    cfg_params.Super.CipherCfgSelector.IV 			= CS_CIPHER_CFG_IV_DISABLE;
    cfg_params.Super.CipherCfgSelector.UseIKS 		= CS_CIPHER_CFG_USE_IKS_DISABLE;
    cfg_params.Super.CipherCfgSelector.SecControl 	= CS_CIPHER_CFG_SEC_CONTROL_DISABLE;
    cfg_params.Super.CipherCfgSelector.BlockRepetition = CS_CIPHER_CFG_BLOCK_REPETITION_DISABLE;
    cfg_params.Super.KeyPtr = &key_xblob;

    status = ifx_cryptosuite_to_psa_status(Cs_Cfg(operation->cs_handle, (Cs_StdApi_CfgType *)&cfg_params));
        
    if (status != PSA_SUCCESS) {
        Cs_StdApi_CloseType closeparams;
        ifx_mxcryptosuite_memset(&closeparams, 0, sizeof(closeparams));
        closeparams.Super.OID    = oid;
        closeparams.FuncIDPtr    = &func_id;
        closeparams.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
        (void)Cs_Close(operation->cs_handle, &closeparams);
        #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
            ifx_mxcryptosuite_free(operation->cs_heap);
        #endif
        operation->cs_heap = NULL;
        ifx_mxcryptosuite_memset(operation, 0, sizeof(*operation));
        return status;
    }

    operation->initialized = true;
        
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_cipher_encrypt_setup(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_cipher_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, true);
}

psa_status_t ifx_cryptosuite_transparent_cipher_decrypt_setup(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return ifx_cryptosuite_cipher_setup_common(operation, attributes, key_buffer, key_buffer_size, alg, false);
}

psa_status_t ifx_cryptosuite_transparent_cipher_set_iv(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    Cs_Aes_CfgType cfg_params;
    Cs_XBlobType iv_xblob;
    uint32_t func_id;
    psa_status_t status;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (iv == NULL && iv_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (iv_length != operation->iv_length) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Store IV */
    if (iv_length > 0) {
        ifx_mxcryptosuite_memcpy(operation->iv, iv, iv_length);
    }

    /* Configure IV as input XBlob: zero seeds + STANDARD checksum over operation->iv. */
    ifx_mxcryptosuite_memset(&iv_xblob, 0, sizeof(iv_xblob));
    iv_xblob.Data1Ptr   = operation->iv;
    iv_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                      (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
    iv_xblob.ByteLen    = (uint16_t)iv_length;
    iv_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&iv_xblob, CS_XBLOB_ID_DEFAULT,
                                                      CS_XBLOB_INTEGRITY_STANDARD, NULL);

    ifx_mxcryptosuite_memset(&cfg_params, 0, sizeof(cfg_params));
    cfg_params.Super.Super.Super.OID 				= ifx_cryptosuite_get_aes_oid(operation->key_bits);
    cfg_params.Super.Super.TempMemPtr 				= NULL;
    cfg_params.Super.Super.TempMemSize 				= 0;
    cfg_params.Super.Super.ClearTempMemOnExit 		= 0;
    cfg_params.Super.Super.CfgSelector.CfgSelRfu1 	= CS_STDAPI_CFG_SEL_RFU_1_DISABLE;
    cfg_params.Super.Super.CfgSelector.Repetitions 	= CS_STDAPI_CFG_REPETITIONS_DISABLE;
    cfg_params.Super.Super.CfgSelector.UnprivilegedCallback = CS_STDAPI_CFG_UNPRIVILEGED_CALLBACK_DISABLE;
    cfg_params.Super.Super.FuncIDPtr 				= &func_id;
    cfg_params.Super.Super.FuncIDPtr[0] 			= ifx_cryptosuite_get_cipher_cfg_func_id();
    cfg_params.Super.CipherCfgSelector.IV 			= ifx_cryptosuite_get_cipher_cfg_iv_enable();
    cfg_params.Super.CipherCfgSelector.Key 			= CS_CIPHER_CFG_KEY_DISABLE;
    cfg_params.Super.CipherCfgSelector.Rfu1 		= CS_CIPHER_CFG_SEL_RFU_1_DISABLE;
    cfg_params.Super.CipherCfgSelector.Rfu2 		= CS_CIPHER_CFG_SEL_RFU_2_DISABLE;
    cfg_params.Super.CipherCfgSelector.Rfu3 		= CS_CIPHER_CFG_SEL_RFU_3_DISABLE;
    cfg_params.Super.CipherCfgSelector.UseIKS 		= CS_CIPHER_CFG_USE_IKS_DISABLE;
    cfg_params.Super.CipherCfgSelector.SecControl 	= CS_CIPHER_CFG_SEC_CONTROL_DISABLE;
    cfg_params.Super.CipherCfgSelector.BlockRepetition = CS_CIPHER_CFG_BLOCK_REPETITION_DISABLE;
    cfg_params.Super.IVPtr = &iv_xblob;

    status = ifx_cryptosuite_to_psa_status(Cs_Cfg(operation->cs_handle, (Cs_StdApi_CfgType *)&cfg_params));

    /* Reset the multipart accumulators. keystream_off is set to a full block so
     * the first stream-cipher byte forces a fresh keystream block generation. */
    operation->block_buf_len = 0;
    operation->keystream_off = IFX_CS_MAX_IV_SIZE_BYTES;

    return status;
}

/* Process a block-aligned chunk (len must be a multiple of the AES block size)
 * through the cipher entity and un-mask the result into out. */
static psa_status_t ifx_cryptosuite_cipher_process(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *src, size_t len, uint8_t *out)
{
    Cs_Aes_CtrlType ctrl_params;
    Cs_XBlobType in_xblob;
    Cs_XBlobType out_xblob;
    uint32_t func_id;
    Cs_StdApi_CtrlCodeFnPtrType ccc_fn;
    psa_status_t status = PSA_SUCCESS;

    if (len == 0) {
        return PSA_SUCCESS;
    }

    ccc_fn = ifx_cryptosuite_get_cipher_ccc_fn(operation->alg, operation->is_encrypt);
    if (ccc_fn == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Process the block-aligned data in IFX_CS_BODY_CHUNK_SIZE chunks. CryptoSuite
     * continues the CBC chain (if any) in the entity handle across successive Cs_Ctrl
     * calls; each chunk is a whole number of blocks. */
    size_t done = 0;
    while (done < len) {
        size_t chunk = len - done;
        if (chunk > IFX_CS_BODY_CHUNK_SIZE) {
            chunk = IFX_CS_BODY_CHUNK_SIZE;
        }

        /* Input XBlob: zero seeds + STANDARD checksum over the const src pointer. */
        ifx_mxcryptosuite_memset(&in_xblob, 0, sizeof(in_xblob));
        in_xblob.Data1Ptr   = (uint8_t *)(src + done);
        in_xblob.Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                          (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        in_xblob.ByteLen    = (uint16_t)chunk;
        in_xblob.Checksum   = Cs_XBlob_CalculateChecksum(&in_xblob, CS_XBLOB_ID_DEFAULT,
                                                          CS_XBLOB_INTEGRITY_STANDARD, NULL);
        ifx_cryptosuite_prepare_output_xblob(&out_xblob, operation->body_scratch_out, chunk);

        ifx_mxcryptosuite_memset(&ctrl_params, 0, sizeof(ctrl_params));
        ctrl_params.Super.Super.Super.OID 			= ifx_cryptosuite_get_aes_oid(operation->key_bits);
        ctrl_params.Super.Super.TempMemPtr 			= NULL;
        ctrl_params.Super.Super.TempMemSize 		= 0;
        ctrl_params.Super.Super.ClearTempMemOnExit 	= 0;
        ctrl_params.Super.Super.CccFnPtr 			= ccc_fn;
        ctrl_params.Super.Super.FuncIDPtr 			= &func_id;
        ctrl_params.Super.Super.FuncIDPtr[0] 		= ifx_cryptosuite_get_cipher_func_id(operation->alg, operation->is_encrypt);
        ctrl_params.Super.InDataPtr 					= &in_xblob;
        ctrl_params.Super.OutDataPtr 					= &out_xblob;

        status = ifx_cryptosuite_to_psa_status(Cs_Ctrl(operation->cs_handle, (Cs_StdApi_CtrlType *)&ctrl_params));

        if (status == PSA_SUCCESS) {
            status = ifx_cryptosuite_verify_output_xblob(&out_xblob);
            if (status == PSA_SUCCESS) {
                (void)Cs_XBlob_Export(&out_xblob, out + done, NULL, NULL, NULL);
            }
        }

        if (status != PSA_SUCCESS) {
            return status;
        }

        done += chunk;
    }

    return status;
}

/* Byte-granular processing for stream ciphers (CTR).
 * PSA requires exactly input_length bytes per update(), but CryptoSuite only
 * processes whole AES blocks. */
static psa_status_t ifx_cryptosuite_cipher_stream_process(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *src, size_t len, uint8_t *out)
{
    for (size_t i = 0; i < len; i++) {
        if (operation->keystream_off >= IFX_CS_MAX_IV_SIZE_BYTES) {
            uint8_t zeros[IFX_CS_MAX_IV_SIZE_BYTES];
            ifx_mxcryptosuite_memset(zeros, 0, sizeof(zeros));
            psa_status_t s = ifx_cryptosuite_cipher_process(
                operation, zeros, IFX_CS_MAX_IV_SIZE_BYTES, operation->keystream);
            if (s != PSA_SUCCESS) {
                return s;
            }
            operation->keystream_off = 0;
        }
        out[i] = (uint8_t)(src[i] ^ operation->keystream[operation->keystream_off]);
        operation->keystream_off++;
    }
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_cipher_update(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    const size_t block_size = IFX_CS_MAX_IV_SIZE_BYTES; /* AES block = 16 bytes */
    psa_status_t status;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (input == NULL && input_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Stream ciphers (CTR) emit exactly input_length bytes on every update via
     * the cached-keystream path; finish() produces no further output. */
    if (PSA_ALG_IS_STREAM_CIPHER(operation->alg)) {
        if (input_length == 0) {
            *output_length = 0;
            return PSA_SUCCESS;
        }
        if (output == NULL) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (output_size < input_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        status = ifx_cryptosuite_cipher_stream_process(operation, input, input_length, output);
        *output_length = (status == PSA_SUCCESS) ? input_length : 0;
        return status;
    }

    /* Block modes (ECB/CBC): buffer input, emit only complete blocks, and hold
     * any partial block for the next update or finish. */
    size_t total = operation->block_buf_len + input_length;
    size_t process_len = (total / block_size) * block_size;

    if (process_len == 0) {
        if (input_length > 0) {
            ifx_mxcryptosuite_memcpy(operation->block_buf + operation->block_buf_len,
                                     input, input_length);
            operation->block_buf_len += input_length;
        }
        *output_length = 0;
        return PSA_SUCCESS;
    }

    if (output == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output_size < process_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Process the block-aligned data*/
    size_t produced = 0;
    size_t in_off   = 0;

    if (operation->block_buf_len > 0) {
        uint8_t first_block[IFX_CS_MAX_IV_SIZE_BYTES];
        size_t need = block_size - operation->block_buf_len;
        ifx_mxcryptosuite_memcpy(first_block, operation->block_buf, operation->block_buf_len);
        ifx_mxcryptosuite_memcpy(first_block + operation->block_buf_len, input, need);
        status = ifx_cryptosuite_cipher_process(operation, first_block, block_size, output);
        if (status != PSA_SUCCESS) {
            *output_length = 0;
            return status;
        }
        produced += block_size;
        in_off   += need;
        operation->block_buf_len = 0;
    }

    if (process_len > produced) {
        size_t rest = process_len - produced;
        status = ifx_cryptosuite_cipher_process(operation, input + in_off, rest, output + produced);
        if (status != PSA_SUCCESS) {
            *output_length = 0;
            return status;
        }
        in_off += rest;
    }

    /* Buffer the remaining tail of input (< 1 block). */
    size_t remainder = input_length - in_off;
    if (remainder > 0) {
        ifx_mxcryptosuite_memcpy(operation->block_buf, input + in_off, remainder);
    }
    operation->block_buf_len = remainder;

    *output_length = process_len;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_cipher_finish(
    ifx_cryptosuite_transparent_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_status_t status;

    if (operation == NULL || !operation->initialized) {
        return PSA_ERROR_BAD_STATE;
    }

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (operation->block_buf_len == 0) {
        /* All data was block-aligned and already processed. */
        *output_length = 0;
        return PSA_SUCCESS;
    }

    /* A leftover partial block remains. Only stream ciphers (CTR) can
     * finalize a partial block; block modes without padding (ECB/CBC) require
     * the total input to be a whole number of blocks. */
    if (!PSA_ALG_IS_STREAM_CIPHER(operation->alg)) {
        *output_length = 0;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t partial = operation->block_buf_len;
    if (output == NULL || output_size < partial) {
        return (output == NULL) ? PSA_ERROR_INVALID_ARGUMENT : PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Pad the partial block to a full block, process it, and keep only the
     * first `partial` bytes (the stream cipher advances its counter/state; the
     * unused keystream bytes are discarded). */
    uint8_t padded[IFX_CS_MAX_IV_SIZE_BYTES];
    uint8_t out_block[IFX_CS_MAX_IV_SIZE_BYTES];
    ifx_mxcryptosuite_memset(padded, 0, sizeof(padded));
    ifx_mxcryptosuite_memcpy(padded, operation->block_buf, partial);

    status = ifx_cryptosuite_cipher_process(operation, padded, IFX_CS_MAX_IV_SIZE_BYTES, out_block);
    if (status != PSA_SUCCESS) {
        *output_length = 0;
        return status;
    }

    ifx_mxcryptosuite_memcpy(output, out_block, partial);
    *output_length = partial;
    operation->block_buf_len = 0;

    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_transparent_cipher_abort(
    ifx_cryptosuite_transparent_cipher_operation_t *operation)
{
    if (operation == NULL) {
        return PSA_SUCCESS;
    }
    	
    if (operation->cs_handle.FirstPtr != NULL) 
    {    
        uint32_t func_id = 0;
        Cs_StdApi_CloseType close_params;
        uint32_t oid = ifx_cryptosuite_get_aes_oid(operation->key_bits);
        
        ifx_mxcryptosuite_memset(&close_params, 0, sizeof(close_params));
        close_params.Super.OID = oid;
        close_params.FuncIDPtr = &func_id;
        close_params.FuncIDPtr[0] = CS_STDAPI_CLOSE_INPUT_FUNC_ID;
        
        Cs_Close(operation->cs_handle, &close_params);
        
        ifx_mxcryptosuite_memset(&operation->cs_handle, 0, sizeof(operation->cs_handle));
        ifx_mxcryptosuite_memset(operation->key, 0, sizeof(operation->key));
        ifx_mxcryptosuite_memset(operation->iv, 0, sizeof(operation->iv));
        
        /* Free heap memory - only if using dynamic allocation */
        if (operation->cs_heap != NULL) {
            /* Use stored key_bits if available, otherwise use maximum size for safety */
            size_t heap_size = (operation->key_bits > 0) ? 
                               ifx_cryptosuite_get_aes_heap_size(operation->key_bits) : 
                               IFX_CS_HEAP_SIZE;
            ifx_mxcryptosuite_memset(operation->cs_heap, 0, heap_size);
            #if !defined(IFX_MXCRYPTOSUITE_USE_STATIC_MEM)
                ifx_mxcryptosuite_free(operation->cs_heap);
            #endif
            operation->cs_heap = NULL;
        }

    }
    
    return PSA_SUCCESS;
}

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
    size_t *output_length)
{
    ifx_cryptosuite_transparent_cipher_operation_t operation = {0};
    psa_status_t status;
    size_t update_output_length = 0;
    size_t finish_output_length = 0;

    /* Setup */
    status = ifx_cryptosuite_transparent_cipher_encrypt_setup(&operation, attributes, 
                                                               key_buffer, key_buffer_size, alg);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Set IV if provided */
    if (iv_length > 0) {
        status = ifx_cryptosuite_transparent_cipher_set_iv(&operation, iv, iv_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    /* Update */
    status = ifx_cryptosuite_transparent_cipher_update(&operation, input, input_length,
                                                        output, output_size, &update_output_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Finish */
    status = ifx_cryptosuite_transparent_cipher_finish(&operation, 
                                                        output + update_output_length,
                                                        output_size - update_output_length,
                                                        &finish_output_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    *output_length = update_output_length + finish_output_length;

cleanup:
    ifx_cryptosuite_transparent_cipher_abort(&operation);
    return status;
}

psa_status_t ifx_cryptosuite_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    ifx_cryptosuite_transparent_cipher_operation_t operation = {0};
    psa_status_t status;
    size_t update_output_length = 0;
    size_t finish_output_length = 0;
    const uint8_t *iv = NULL;
    size_t iv_length = 0;

    /* For block cipher modes that need IV, extract it from input */
    psa_key_type_t key_type = psa_get_key_type(attributes);
    iv_length = PSA_CIPHER_IV_LENGTH(key_type, alg);
    
    if (iv_length > 0) {
        if (input_length < iv_length) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        iv = input;
        input += iv_length;
        input_length -= iv_length;
    }

    /* Setup */
    status = ifx_cryptosuite_transparent_cipher_decrypt_setup(&operation, attributes, 
                                                               key_buffer, key_buffer_size, alg);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Set IV if needed */
    if (iv_length > 0) {
        status = ifx_cryptosuite_transparent_cipher_set_iv(&operation, iv, iv_length);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
    }

    /* Update */
    status = ifx_cryptosuite_transparent_cipher_update(&operation, input, input_length,
                                                        output, output_size, &update_output_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* Finish */
    status = ifx_cryptosuite_transparent_cipher_finish(&operation, 
                                                        output + update_output_length,
                                                        output_size - update_output_length,
                                                        &finish_output_length);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    *output_length = update_output_length + finish_output_length;

cleanup:
    ifx_cryptosuite_transparent_cipher_abort(&operation);
    return status;
}

#endif /* IFX_PSA_CRYPTOSUITE_AES */

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */
