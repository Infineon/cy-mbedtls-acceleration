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
 * \file    cryptolite_common.h
 * \version 2.3.0
 *
 * \brief   Header file for common mbedtls acceleration functions
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTOLITE)

#if !defined(CRYPTOLITE_COMMON_H)
#define CRYPTOLITE_COMMON_H

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <string.h>
#define  mbedtls_calloc      calloc
#define  mbedtls_free        free
#define  mbedtls_memcpy      memcpy
#define  mbedtls_memset      memset
#endif

#ifndef mbedtls_malloc
#include <stdlib.h>
#define mbedtls_malloc(...)  mbedtls_calloc(1, __VA_ARGS__)
#endif
#ifndef  mbedtls_memcpy
#include <string.h>
#define  mbedtls_memcpy      memcpy
#endif
#ifndef  mbedtls_memset
#include <string.h>
#define  mbedtls_memset      memset
#endif

#endif /* (CRYPTOLITE_COMMON_H) */

#endif /* CY_IP_MXCRYPTOLITE */
