/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_key_generation.c
*
* \brief
*   PSA crypto transparent key generation (ML-DSA / ML-KEM) driver functions.
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

#include "ifx_wolfcrypto_transparent_key_generation.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT) && defined(IFX_PSA_WOLFCRYPTO_KEY_GENERATION)

/*******************************************************************************
* Function Name: ifx_wolfcrypto_transparent_generate_key
*******************************************************************************/
psa_status_t ifx_wolfcrypto_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    psa_status_t status;
    size_t seed_size;
    int ret;
    WC_RNG rng;

#if defined(IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION)
    if (key_type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR)
    {
        byte level;
        status = ifx_wolfcrypto_mldsa_level_from_bits(bits, &level);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        seed_size = IFX_WOLFCRYPTO_MLDSA_SEED_SIZE;
    }
    else
#endif /* IFX_PSA_WOLFCRYPTO_MLDSA_KEY_GENERATION */
#if defined(IFX_PSA_WOLFCRYPTO_MLKEM_KEY_GENERATION)
    if (key_type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR)
    {
        int type;
        status = ifx_wolfcrypto_mlkem_type_from_bits(bits, &type);
        if (status != PSA_SUCCESS)
        {
            return status;
        }
        seed_size = IFX_WOLFCRYPTO_MLKEM_SEED_SIZE;
    }
    else
#endif /* IFX_PSA_WOLFCRYPTO_MLKEM_KEY_GENERATION */
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size < seed_size)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* The PSA export representation of an ML-DSA / ML-KEM key pair is the
     * key-generation seed. A uniformly random seed of the correct length is a
     * valid key pair for the corresponding FIPS scheme. */
    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        return ifx_wolfcrypto_status_to_psa_status(ret);
    }

    ret = wc_RNG_GenerateBlock(&rng, key_buffer, (word32)seed_size);
    wc_FreeRng(&rng);
    if (ret != 0)
    {
        return ifx_wolfcrypto_status_to_psa_status(ret);
    }

    *key_buffer_length = seed_size;
    return PSA_SUCCESS;
}

#endif /* IFX_PSA_WOLFCRYPTO_KEY_GENERATION */
