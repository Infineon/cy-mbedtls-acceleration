/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_import.c
*
* \brief
*   PSA crypto transparent key import (ML-DSA / ML-KEM) driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors
*
* Copyright (C) 2026 Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.
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

#include "ifx_wolfcrypto_transparent_import.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && defined(IFX_PSA_WOLFCRYPTO_IMPORT)

/* FIPS 204 ML-DSA encoded public key sizes per parameter set. */
#define IFX_WOLFCRYPTO_MLDSA_44_PUB_KEY_SIZE    (1312u)
#define IFX_WOLFCRYPTO_MLDSA_65_PUB_KEY_SIZE    (1952u)
#define IFX_WOLFCRYPTO_MLDSA_87_PUB_KEY_SIZE    (2592u)

/* FIPS 203 ML-KEM encoded public (encapsulation) key sizes per parameter set. */
#define IFX_WOLFCRYPTO_MLKEM_512_PUB_KEY_SIZE   (800u)
#define IFX_WOLFCRYPTO_MLKEM_768_PUB_KEY_SIZE   (1184u)
#define IFX_WOLFCRYPTO_MLKEM_1024_PUB_KEY_SIZE  (1568u)

/* Copies validated key material into the slot's export representation. */
static psa_status_t ifx_wolfcrypto_import_copy(
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    if (key_buffer_size < data_length)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    ifx_wolfcrypto_memcpy(key_buffer, data, data_length);
    *key_buffer_length = data_length;
    return PSA_SUCCESS;
}

/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_import_key
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length,
    size_t *bits)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t requested_bits = psa_get_key_bits(attributes);
    psa_status_t status;
    size_t inferred_bits;

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_IMPORT)
    if (key_type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR)
    {
        byte level;
        /* The 32-byte seed does not encode the parameter set, so it must be
         * supplied via the key attributes. Fall through otherwise. */
        if (requested_bits == 0)
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        status = ifx_wolfcrypto_mldsa_level_from_bits(requested_bits, &level);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        if (data_length != IFX_WOLFCRYPTO_MLDSA_SEED_SIZE)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = ifx_wolfcrypto_import_copy(data, data_length, key_buffer,
                                            key_buffer_size, key_buffer_length);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        *bits = requested_bits;
        return PSA_SUCCESS;
    }
    if (key_type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY)
    {
        switch (data_length)
        {
        case IFX_WOLFCRYPTO_MLDSA_44_PUB_KEY_SIZE: inferred_bits = 44; break;
        case IFX_WOLFCRYPTO_MLDSA_65_PUB_KEY_SIZE: inferred_bits = 65; break;
        case IFX_WOLFCRYPTO_MLDSA_87_PUB_KEY_SIZE: inferred_bits = 87; break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (requested_bits != 0 && requested_bits != inferred_bits)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = ifx_wolfcrypto_import_copy(data, data_length, key_buffer,
                                            key_buffer_size, key_buffer_length);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        *bits = inferred_bits;
        return PSA_SUCCESS;
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_IMPORT */

#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_IMPORT)
    if (key_type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR)
    {
        int type;
        /* The 64-byte seed does not encode the parameter set. */
        if (requested_bits == 0)
        {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        status = ifx_wolfcrypto_mlkem_type_from_bits(requested_bits, &type);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        if (data_length != IFX_WOLFCRYPTO_MLKEM_SEED_SIZE)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = ifx_wolfcrypto_import_copy(data, data_length, key_buffer,
                                            key_buffer_size, key_buffer_length);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        *bits = requested_bits;
        return PSA_SUCCESS;
    }
    if (key_type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY)
    {
        switch (data_length)
        {
        case IFX_WOLFCRYPTO_MLKEM_512_PUB_KEY_SIZE:  inferred_bits = 512;  break;
        case IFX_WOLFCRYPTO_MLKEM_768_PUB_KEY_SIZE:  inferred_bits = 768;  break;
        case IFX_WOLFCRYPTO_MLKEM_1024_PUB_KEY_SIZE: inferred_bits = 1024; break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (requested_bits != 0 && requested_bits != inferred_bits)
        {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = ifx_wolfcrypto_import_copy(data, data_length, key_buffer,
                                            key_buffer_size, key_buffer_length);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        *bits = inferred_bits;
        return PSA_SUCCESS;
    }
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_IMPORT */

    (void)inferred_bits;
    (void)data;
    (void)data_length;
    (void)key_buffer;
    (void)key_buffer_size;
    (void)key_buffer_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* IFX_PSA_WOLFCRYPTO_IMPORT */
