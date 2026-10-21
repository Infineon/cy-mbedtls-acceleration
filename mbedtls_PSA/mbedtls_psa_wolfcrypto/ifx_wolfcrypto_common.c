/***************************************************************************//**
* \file ifx_wolfcrypto_common.c
*
* \brief
*  PSA crypto wolfcrypto helper functions.
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

#include "ifx_wolfcrypto_common.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT)

#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(HAVE_DILITHIUM)
#include <wolfssl/wolfcrypt/dilithium.h>
#endif
#if defined(WOLFSSL_HAVE_MLKEM)
#include <wolfssl/wolfcrypt/mlkem.h>
#endif

/*******************************************************************************
* Function Name: ifx_wolfcrypto_status_to_psa_status
****************************************************************************//**
*
* Converts a wolfCrypt return code into a PSA status code.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_status_to_psa_status(int wc_status)
{
    switch (wc_status)
    {
    case 0:
        return PSA_SUCCESS;
    case BAD_FUNC_ARG:
        return PSA_ERROR_INVALID_ARGUMENT;
    case BUFFER_E:
        return PSA_ERROR_BUFFER_TOO_SMALL;
    case MEMORY_E:
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    case NOT_COMPILED_IN:
        return PSA_ERROR_NOT_SUPPORTED;
    case SIG_VERIFY_E:
        return PSA_ERROR_INVALID_SIGNATURE;
    case RNG_FAILURE_E:
    case DRBG_CONT_FIPS_E:
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    default:
        return PSA_ERROR_GENERIC_ERROR;
    }
}

#if defined(HAVE_DILITHIUM)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_mldsa_level_from_bits
****************************************************************************//**
*
* Maps a PSA ML-DSA key size (bits) to a wolfCrypt security level.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_mldsa_level_from_bits(size_t bits, byte *level)
{
    switch (bits)
    {
    case 44:
        *level = WC_ML_DSA_44;
        return PSA_SUCCESS;
    case 65:
        *level = WC_ML_DSA_65;
        return PSA_SUCCESS;
    case 87:
        *level = WC_ML_DSA_87;
        return PSA_SUCCESS;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* HAVE_DILITHIUM */

#if defined(WOLFSSL_HAVE_MLKEM)
/*******************************************************************************
* Function Name: ifx_wolfcrypto_mlkem_type_from_bits
****************************************************************************//**
*
* Maps a PSA ML-KEM key size (bits) to a wolfCrypt key type.
*
*******************************************************************************/
psa_status_t ifx_wolfcrypto_mlkem_type_from_bits(size_t bits, int *type)
{
    switch (bits)
    {
    case 512:
        *type = WC_ML_KEM_512;
        return PSA_SUCCESS;
    case 768:
        *type = WC_ML_KEM_768;
        return PSA_SUCCESS;
    case 1024:
        *type = WC_ML_KEM_1024;
        return PSA_SUCCESS;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* IFX_PSA_WOLFCRYPTO_PRESENT */
