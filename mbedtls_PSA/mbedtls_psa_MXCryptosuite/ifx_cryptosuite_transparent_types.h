/***************************************************************************//**
* \file ifx_cryptosuite_transparent_types.h
*
* \brief
*  PSA CryptoSuite transparent driver types.
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

#ifndef IFX_CRYPTOSUITE_TRANSPARENT_TYPES_H
#define IFX_CRYPTOSUITE_TRANSPARENT_TYPES_H

#include "psa/crypto_types.h"
#include "stdbool.h"
#include "stdint.h"
#include "stddef.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

#include "Cs_StdApi.h"
#include "Cs_Sym_Ae_Ccm.h"
#include "Cs_Sym_Mac_Ciphermac_Cmac.h"
#include "Cs_Sym_Cipher_Aes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IFX_CS_HEAP_SIZE 			CS_ENTITY_AES256_SEC_HEAPSIZE 	/* Heap size for CryptoSuite entities */
#define IFX_CS_CCM_HEAP_SIZE 		CS_ENTITY_CCM_SEC_HEAPSIZE  	/* Heap size for CCM entity */
#define IFX_CS_CMAC_HEAP_SIZE 		CS_ENTITY_CMAC_SEC_HEAPSIZE 	/* Heap size for CMAC entity */
#define IFX_CS_TEMP_MEM_SIZE 		CS_ENTITY_CMAC_SEC_TEMPMEM_SIZE /* Temporary memory size for operations */
#define IFX_CS_MAX_KEY_SIZE_BITS 	256 							/* Maximum key size in bits */
#define IFX_CS_MAX_KEY_SIZE_BYTES 	(IFX_CS_MAX_KEY_SIZE_BITS / 8) 	/* Maximum key size in bytes */
#define IFX_CS_MAX_IV_SIZE_BYTES 	16 								/* Maximum IV size in bytes (128-bit) */
#define IFX_CS_MAX_NONCE_SIZE_BYTES 16 								/* Maximum nonce size in bytes (128-bit) */
#define IFX_CS_RNG_SEED_SIZE_BYTES 	8 								/* RNG seed size in bytes */
#define IFX_CS_BODY_CHUNK_SIZE      256U                            /* Body chunk size for static scratch (multiple of 16) */
#define IFX_CS_MAX_AAD_CHUNK_BYTES  0xFFF0U                          /* Max AAD bytes per ConsumeAD XBlob (uint16 ByteLen, 16-byte aligned) */

/* Cipher operation context */
typedef struct {
    psa_algorithm_t alg;                    /* Algorithm */
    size_t key_bits;                        /* Key size in bits */
    uint8_t key[IFX_CS_MAX_KEY_SIZE_BYTES]; /* Key storage (max 256-bit) */
    uint8_t iv[IFX_CS_MAX_IV_SIZE_BYTES];   /* IV storage (128-bit) */
    size_t iv_length;                       /* IV length */
    bool is_encrypt;                        /* true for encrypt, false for decrypt */
    Cs_StdApi_HandleType cs_handle;         /* CryptoSuite entity handle */
    uint8_t *cs_heap;                       /* Heap for CryptoSuite entity (dynamically allocated) */
    uint8_t block_buf[IFX_CS_MAX_IV_SIZE_BYTES]; /* Partial-block accumulator for multipart update */
    size_t block_buf_len;                   /* Bytes currently held in block_buf */
    uint8_t keystream[IFX_CS_MAX_IV_SIZE_BYTES]; /* Cached CTR keystream block (stream ciphers) */
    size_t keystream_off;                   /* Consumed bytes of the cached keystream (0..16) */
    uint8_t body_scratch_out[IFX_CS_BODY_CHUNK_SIZE]; /* Output XBlob scratch buffer (CryptoSuite writes here) */
    bool initialized;                       /* Setup completed flag */
} ifx_cryptosuite_transparent_cipher_operation_t;

/* MAC operation context */
typedef struct {
    psa_algorithm_t alg;                    	/* Algorithm */
    size_t key_bits;                        	/* Key size in bits */
    uint8_t key[IFX_CS_MAX_KEY_SIZE_BYTES];		/* Key storage (max 256-bit) */
    bool is_sign;                           	/* true for sign, false for verify */
    Cs_StdApi_HandleType aes_handle;        	/* CryptoSuite AES entity handle */
    Cs_StdApi_HandleType cmac_handle;       	/* CryptoSuite CMAC entity handle */
    uint8_t *aes_heap;                      	/* Heap for AES entity (dynamically allocated) */
    uint8_t *cmac_heap;                     	/* Heap for CMAC entity (dynamically allocated) */
    uint8_t  pending[16U];                  	/* 16-byte block buffer: holds last <=16 bytes for sign_finish */
    size_t   pending_len;                   	/* Bytes currently in pending[] */
    uint8_t temp_mem[IFX_CS_TEMP_MEM_SIZE]; 	/* Temporary memory */
    bool initialized;                       	/* Setup completed flag */
} ifx_cryptosuite_transparent_mac_operation_t;

/* AEAD operation context */
typedef struct {
    psa_algorithm_t alg;                    	/* Algorithm */
    size_t key_bits;                        	/* Key size in bits */
    uint8_t key[IFX_CS_MAX_KEY_SIZE_BYTES]; 	/* Key storage (max 256-bit) */
    uint8_t nonce[IFX_CS_MAX_NONCE_SIZE_BYTES]; /* Nonce storage */
    size_t nonce_length;                   	 	/* Nonce length */
    size_t tag_length;                      	/* Tag length */
    size_t ad_length;                       	/* Additional data length */
    size_t plaintext_length;                	/* Plaintext length */
    bool is_encrypt;                        	/* true for encrypt, false for decrypt */
    Cs_StdApi_HandleType aes_handle;        	/* CryptoSuite AES entity handle */
    Cs_StdApi_HandleType ccm_handle;        	/* CryptoSuite CCM entity handle */
    uint8_t *aes_heap;                      	/* Heap for AES entity (dynamically allocated) */
    uint8_t *ccm_heap;                      	/* Heap for CCM entity (dynamically allocated) */
    bool initialized;                       	/* Setup completed flag */
    bool ad_started;                        	/* Additional data processing started */
    bool body_started;                      	/* Body processing started */
    bool nonce_set;                         	/* Nonce has been set */
    bool lengths_set;                       	/* Lengths have been set */
    bool ccm_configured;                    	/* CCM entity configured */
    uint8_t data_buf[16];                   	/* Tail buffer: holds partial block (0-15 bytes) pending next update()/finish() */
    size_t data_buf_len;                    	/* Bytes accumulated so far */
    size_t body_bytes_received;             	/* Total plaintext bytes given to update(), validated in finish()/verify() */
    uint32_t ad_func_id;                    	/* Persists FuncID across multiple update_ad() calls */
    uint32_t body_func_id;                  	/* Persists FuncID across multiple update() calls */
    size_t   body_received;                            /* Total body bytes received so far */
    uint8_t  body_buf[16];                             /* Partial body block accumulator */
    size_t   body_buf_len;                             /* Bytes in body_buf */
    uint8_t  body_scratch_in[IFX_CS_BODY_CHUNK_SIZE];  /* Body input XBlob scratch */
    uint8_t  body_scratch_out[IFX_CS_BODY_CHUNK_SIZE]; /* Body output XBlob scratch */
    uint8_t  stored_tag[16];                           /* Tag stored during encrypt update */
    bool     tag_stored;                               /* Tag has been stored */
    uint8_t  in_scratch[16];                           /* Small input scratch for finish */
    uint8_t  out_scratch[16];                          /* Small output scratch for finish */
} ifx_cryptosuite_transparent_aead_operation_t;

#ifdef __cplusplus
}
#endif

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */

#endif /* IFX_CRYPTOSUITE_TRANSPARENT_TYPES_H */
