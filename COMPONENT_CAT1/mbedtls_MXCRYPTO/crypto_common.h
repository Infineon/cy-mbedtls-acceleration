/*
 * mbed Microcontroller Library
 * Copyright (c) 2019-2024 Cypress Semiconductor Corporation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file    crypto_common.h
 * \version 2.3.0
 *
 * \brief   Header file for common mbedtls acceleration functions
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#if !defined(CRYPTO_COMMON_H)
#define CRYPTO_COMMON_H

#include "mbedtls/build_info.h"
/* To use mbedtls platform defined memory functions define IFX_USE_MBEDTLS_PLATFORM_C
   Otherwise stdlib memory functions are used. This abstraction allows user to allocate
   separate memory region for acceleration drivers.
*/
#if defined(MBEDTLS_PLATFORM_C) && defined (IFX_USE_MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#define ifx_mbedtls_malloc      mbedtls_malloc
#define ifx_mbedtls_calloc      mbedtls_calloc
#define ifx_mbedtls_free        mbedtls_free
#define ifx_mbedtls_memcpy      mbedtls_memcpy
#define ifx_mbedtls_memset      mbedtls_memset
#define ifx_mbedtls_printf      mbedtls_printf
#else
#include <stdlib.h>
#include <string.h>
#define ifx_mbedtls_calloc      calloc
#define ifx_mbedtls_free        free
#define ifx_mbedtls_memcpy      memcpy
#define ifx_mbedtls_memset      memset
#define ifx_mbedtls_printf      printf
#endif //defined(MBEDTLS_PLATFORM_C) && defined (IFX_USE_MBEDTLS_PLATFORM_C) 

#ifndef ifx_mbedtls_malloc
#include <stdlib.h>
#define ifx_mbedtls_malloc(...)  ifx_mbedtls_calloc(1, __VA_ARGS__)
#endif
#ifndef  ifx_mbedtls_memcpy
#include <string.h>
#define  ifx_mbedtls_memcpy      memcpy
#endif
#ifndef  ifx_mbedtls_memset
#include <string.h>
#define  ifx_mbedtls_memset      memset
#endif

#include "cy_crypto_core.h"
#include "mbedtls/private_access.h"

/* Dcache related helper macros*/
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
#define CY_MBTLS_DCACHE_LINE_ALIGNMENT_SIZE     (32u) // 32byte align
#define CY_MBTLS_IS_MEM_CACHABLE(x,y)           (Cy_Syslib_IsMemCacheable(MPU, (uint32_t)x, y))
#define CY_MBTLS_IS_MEM_CACHE_ALIGNED(x,y)      ((((uint32_t)x % CY_CRYPTO_DCAHCE_PADDING_SIZE) == 0u) && ((uint32_t)y % CY_CRYPTO_DCAHCE_PADDING_SIZE == 0u))
/* Check if memomry is cachable and algined to cache line OR memory is non-cachable */
#define CY_MBTLS_IS_MEM_CACHABLE_ALIGNED(x,y)   ((CY_MBTLS_IS_MEM_CACHABLE(x,y) && CY_MBTLS_IS_MEM_CACHE_ALIGNED(x,y))||(!CY_MBTLS_IS_MEM_CACHABLE(x,y)))
#else
#define CY_MBTLS_DCACHE_LINE_ALIGNMENT_SIZE     (0u)
#define CY_MBTLS_IS_MEM_CACHABLE(x,y)           (false)
#define CY_MBTLS_IS_MEM_CACHE_ALIGNED(x,y)      (false)
#define CY_MBTLS_IS_MEM_CACHABLE_ALIGNED(x,y)   (CY_MBTLS_IS_MEM_CACHABLE(x,y) && CY_MBTLS_IS_MEM_CACHE_ALIGNED(x,y))
#endif

#ifndef MBEDTLS_INTERNAL_VALIDATE_RET
#define MBEDTLS_INTERNAL_VALIDATE_RET(cond, ret)  do { } while (0)
#endif
#ifndef MBEDTLS_INTERNAL_VALIDATE
#define MBEDTLS_INTERNAL_VALIDATE(cond)           do { } while (0)
#endif

typedef enum
{
    /** CRC hardware acceleration */
    CY_CMGR_CRYPTO_CRC,
    /** TRNG hardware acceleration */
    CY_CMGR_CRYPTO_TRNG,
    /** VU hardware acceleration */
    CY_CMGR_CRYPTO_VU,
    /** Common features of the Crypto block  */
    CY_CMGR_CRYPTO_COMMON,
} cy_cmgr_feature_t;

/** Resource types that the hardware manager supports */
typedef enum
{
    CY_CMGR_RSC_CRYPTO,    /*!< Crypto hardware accelerator */
    CY_CMGR_RSC_INVALID,   /*!< Placeholder for invalid type */
} cy_cmgr_resource_t;

/**
  * @brief Represents a particular instance of a resource on the chip.
  * Application code should not rely on the specific contents of this struct.
  * They are considered an implementation detail which is subject to change
  * between platforms and/or HAL releases.
  */
typedef struct
{
    cy_cmgr_resource_t MBEDTLS_PRIVATE(type);      //!< The resource block type
    uint8_t            MBEDTLS_PRIVATE(block_num); //!< The resource block index
} cy_cmgr_resource_inst_t;

#define CY_CMGR_RESOURCE_INIT  {CY_CMGR_RSC_INVALID, 0U}


/** CRYPTO object */
typedef struct {
    CRYPTO_Type*                MBEDTLS_PRIVATE(base);
    cy_cmgr_resource_inst_t     MBEDTLS_PRIVATE(resource);
    cy_cmgr_feature_t           MBEDTLS_PRIVATE(feature);
} cy_cmgr_crypto_hw_t;

#define CY_CMGR_CRYPTO_OBJ_INIT  {NULL, CY_CMGR_RESOURCE_INIT, CY_CMGR_CRYPTO_COMMON}

bool cy_hw_crypto_reserve(cy_cmgr_crypto_hw_t *obj, cy_cmgr_feature_t feature);
void cy_hw_crypto_release(cy_cmgr_crypto_hw_t *obj);

void cy_hw_zeroize(void *data, uint32_t dataSize);

void cy_hw_sha_init(void *ctx, uint32_t ctxSize);
void cy_hw_sha_free(void *ctx, uint32_t ctxSize);

int cy_hw_sha_start (cy_cmgr_crypto_hw_t *obj, cy_stc_crypto_sha_state_t *hashState,
                     cy_en_crypto_sha_mode_t shaMode, void *shaBuffers);

int cy_hw_sha_update(cy_cmgr_crypto_hw_t *obj, cy_stc_crypto_sha_state_t *hashState,
                     const uint8_t *in, uint32_t inlen);

int cy_hw_sha_finish(cy_cmgr_crypto_hw_t *obj, cy_stc_crypto_sha_state_t *hashState,
                     uint8_t *output);

void cy_hw_sha_clone(void *ctxDst, const void *ctxSrc, uint32_t ctxSize,
                     cy_stc_crypto_sha_state_t *hashStateDst, void *shaBuffersDst);

int cy_hw_sha_process(cy_cmgr_crypto_hw_t *obj, cy_stc_crypto_sha_state_t *hashState,
                     const uint8_t *in);

void cy_hw_memset(void *data, uint8_t val, uint32_t dataSize);
void cy_hw_memcpy(void *dstAddr, void const *srcAddr, uint32_t dataSize);

#endif /* (CRYPTO_COMMON_H) */

#endif /* CY_IP_MXCRYPTO */
