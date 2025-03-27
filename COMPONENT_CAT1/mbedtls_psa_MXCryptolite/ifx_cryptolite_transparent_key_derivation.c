/***************************************************************************//**
* \file ifx_cryptolite_transparent_key_derivation.c
*
* \brief
*  PSA crypto transparent Key derivation driver functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2024 Cypress Semiconductor Corporation
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


#include "ifx_cryptolite_transparent_key_derivation.h"

#if defined(IFX_PSA_CRYPTOLITE_KEY_DERIVATION)

#if defined (CY_IP_MXCRYPTOLITE)
#include "ifx_cryptolite_transparent_mac.h"
#include "cy_cryptolite_utils.h"

psa_status_t ifx_cryptolite_key_derivation_setup(ifx_cryptolite_key_derivation_operation_t * operation, psa_algorithm_t alg)
{
    if (operation == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_INIT))
    {
        return PSA_ERROR_BAD_STATE;
    }

    if (!(alg == PSA_CRYPTOLITE_ALG_SP800_108_COUNTER_CMAC))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    Cy_Cryptolite_Vu_memset(operation, 0, sizeof(ifx_cryptolite_key_derivation_operation_t));
    operation->state = IFX_CRYPTOLITE_KEY_DERIVATION_STATE_NEED_KEY;

    return PSA_SUCCESS;
}

psa_status_t ifx_cryptolite_key_derivation_get_capacity(
    const ifx_cryptolite_key_derivation_operation_t * operation, size_t * capacity)
{
    if (operation == NULL || capacity == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_INIT)
    {
        return PSA_ERROR_BAD_STATE;
    }

    *capacity = operation->remaining_capacity;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptolite_key_derivation_set_capacity(ifx_cryptolite_key_derivation_operation_t * operation, size_t capacity)
{
    if (operation == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_NEED_KEY ||
          operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE))
    {
        return PSA_ERROR_BAD_STATE;
    }
    if (capacity == 0 || capacity > IFX_CRYPTOLITE_KEY_DERIVATION_MAXIMUM_CAPACITY)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Check for sufficient counter capacity.
    // "n := ceil(L/h). If n > 2^r -1, then indicate an error and stop."
    // Already covered by IFX_CRYPTOLITE_KEY_DERIVATION_MAXIMUM_CAPACITY but formally required.
    if (((uint64_t)capacity + 15ULL) / 16ULL > (1ULL << (8ULL * IFX_CRYPTOLITE_KEY_DERIVATION_COUNTER_LENGTH)) - 1ULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->capacity = capacity;
    operation->remaining_capacity = capacity;
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptolite_key_derivation_input_bytes( ifx_cryptolite_key_derivation_operation_t * operation,
                                                        psa_key_derivation_step_t step,
                                                        const uint8_t * data,
                                                        size_t data_length)
{
    if (operation == NULL || data == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    switch (step)
    {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
        {
            if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_NEED_KEY))
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (!(data_length == 16))
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            Cy_Cryptolite_Setnumber(operation->key, (uint8_t * )data, data_length);
            operation->key_size = data_length;
            operation->state = IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE;
            break;
        }
        case PSA_KEY_DERIVATION_INPUT_LABEL:
        {
            if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE && operation->label_size == 0UL))
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (operation->fixed_data != NULL)
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (data_length == 0UL)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            operation->label = ifx_mxcryptolite_malloc(data_length);
            if (operation->label == NULL)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            Cy_Cryptolite_Setnumber(operation->label, (uint8_t * )data, data_length);
            operation->label_size = data_length;
            break;
        }
        case PSA_KEY_DERIVATION_INPUT_SEED:
        {
            if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE && operation->seed_size == 0UL))
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (operation->fixed_data != NULL)
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (data_length == 0UL)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            operation->seed = (uint8_t *)ifx_mxcryptolite_malloc(data_length);
            if (operation->seed == NULL)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            Cy_Cryptolite_Setnumber(operation->seed, (uint8_t * )data, data_length);
            operation->seed_size = data_length;
            break;
        }
        case PSA_KEY_DERIVATION_INPUT_FIXED_DATA:
        {
            if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE && operation->fixed_data_size == 0UL))
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (operation->label_size != 0UL || operation->seed_size != 0UL)
            {
                return PSA_ERROR_BAD_STATE;
            }
            if (data_length == 0UL)
            {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            operation->fixed_data = (uint8_t *)ifx_mxcryptolite_malloc(data_length);
            if (operation->fixed_data == NULL)
            {
                return PSA_ERROR_INSUFFICIENT_MEMORY;
            }
            Cy_Cryptolite_Setnumber(operation->fixed_data, (uint8_t *)data, data_length);
            operation->fixed_data_size = data_length;
            break;
        }
        default:
        {
            return PSA_ERROR_BAD_STATE;
        }
    }

    return PSA_SUCCESS;
}

/**
 * Perform one key derivation step.
 *
 * if Label != NULL and Capacity != 0:
 *     K(i) := PRF (KI, [i]2 || Label || 0x00 || Seed || [L]2)
 * if Label != NULL and Capacity == 0:
 *     K(i) := PRF (KI, [i]2 || Label || 0x00 || Seed)
 * else if Label == NULL and Capacity != 0:
 *     K(i) := PRF (KI, [i]2 || Seed || [L]2)
 * else if Label == NULL and Capacity == 0:
 *     K(i) := PRF (KI, [i]2 || Seed)
 */
static psa_status_t perform_iteration(ifx_cryptolite_key_derivation_operation_t * operation)
{
    // Perform CMAC operation
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t mac_length;
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attributes, (uint32_t)(128));

    ifx_cryptolite_transparent_mac_operation_t cmac;
    Cy_Cryptolite_Vu_memset(&cmac, 0, sizeof(ifx_cryptolite_transparent_mac_operation_t));

    psa_status_t status =
        ifx_cryptolite_transparent_mac_sign_setup(&cmac, &key_attributes, operation->key, operation->key_size, PSA_ALG_CMAC);
    if (!(status == PSA_SUCCESS))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Perform one iteration
    // CMAC( [i]2 || Label || 0x00 || Seed || [L]2 ) or CMAC( [i]2 || Seed || [L]2 ) or
    // CMAC( [i]2 || Label || 0x00 || Seed ) or CMAC( [i]2 || Seed )

    operation->counter++;
    uint8_t counter_big_endian[4] = {operation->counter >> 24, operation->counter >> 16 ,operation->counter >> 8, operation->counter};

    status = ifx_cryptolite_transparent_mac_update(&cmac, counter_big_endian, sizeof(counter_big_endian));
    if (!(status == PSA_SUCCESS))
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    
    if (operation->fixed_data_size > 0UL)
    {
        status = ifx_cryptolite_transparent_mac_update(&cmac, operation->fixed_data, operation->fixed_data_size);
        if (!(status == PSA_SUCCESS))
        {
            return PSA_ERROR_GENERIC_ERROR;
        }
    }
    else
    {
        if (operation->label_size > 0UL)
        {
            status = ifx_cryptolite_transparent_mac_update(&cmac, operation->label, operation->label_size);
            if (!(status == PSA_SUCCESS))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
        }
        if (operation->label_size > 0UL && operation->seed_size > 0UL)
        {
            uint8_t zero = 0;
            status = ifx_cryptolite_transparent_mac_update(&cmac, &zero, sizeof(zero));
            if (!(status == PSA_SUCCESS))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
        }
        if (operation->seed_size > 0UL)
        {
            status = ifx_cryptolite_transparent_mac_update(&cmac, operation->seed, operation->seed_size);
            if (!(status == PSA_SUCCESS))
            {
                return PSA_ERROR_GENERIC_ERROR;
            }
        }

        uint8_t capacity_big_endian[4] = {(operation->capacity * 8UL) >> 24, (operation->capacity * 8UL) >> 16 ,(operation->capacity * 8UL)>> 8, (operation->capacity * 8UL)};

        status = ifx_cryptolite_transparent_mac_update(&cmac, capacity_big_endian, sizeof(capacity_big_endian));
        if (!(status == PSA_SUCCESS))
        {
            return PSA_ERROR_GENERIC_ERROR;
        }
    }

    if (ifx_cryptolite_transparent_mac_sign_finish(&cmac, operation->block, sizeof(operation->block), &mac_length) != PSA_SUCCESS)
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}

psa_status_t ifx_cryptolite_key_derivation_output_bytes(
    ifx_cryptolite_key_derivation_operation_t * operation, uint8_t * output, size_t output_length)
{
    if (operation == NULL || output == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!(operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE ||
          operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_OPERATING))
    {
        return PSA_ERROR_BAD_STATE;
    }

    // If capacity was never set, allow output once
    if (operation->capacity == 0)
    {
        operation->capacity = operation->remaining_capacity = output_length;
        // After this function:
        // - `operation->capacity == 0`
        // - `operation->remaining_capacity == 0`
        // - `operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_FINISHED`
        // This forbids to exploit this behavior.
    }

    if (operation->remaining_capacity < output_length)
    {
        operation->remaining_capacity = 0;
        return PSA_ERROR_INSUFFICIENT_DATA;
    }

    // Set to operating if not done yet
    if (operation->state == IFX_CRYPTOLITE_KEY_DERIVATION_STATE_ACTIVE)
    {
        operation->state = IFX_CRYPTOLITE_KEY_DERIVATION_STATE_OPERATING;
        if (perform_iteration(operation) != PSA_SUCCESS)
        {
            return PSA_ERROR_GENERIC_ERROR;
        }
    }

    size_t initial_output_length = output_length;
    size_t tocopy;

    while(output_length > 0)
    {
        
        tocopy = ((size_t)(16 - operation->block_index) < output_length ? ((size_t)(16 - operation->block_index)) : (output_length));

        Cy_Cryptolite_Setnumber(output, &operation->block[operation->block_index], tocopy);
        output += tocopy;
        output_length -= tocopy;
        operation->block_index += tocopy;

        if(operation->block_index == 16)
        {
            operation->block_index = 0;
            if (perform_iteration(operation) != PSA_SUCCESS)
            {
                return PSA_ERROR_GENERIC_ERROR;
            }

        }

    }

    operation->remaining_capacity -= initial_output_length;

    if (operation->remaining_capacity == 0UL)
    {
        return ifx_cryptolite_key_derivation_abort(operation);
    }

    return PSA_SUCCESS;
}

psa_status_t ifx_cryptolite_key_derivation_abort(ifx_cryptolite_key_derivation_operation_t * operation)
{
    if (operation == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    operation->state = IFX_CRYPTOLITE_KEY_DERIVATION_STATE_FINISHED;
    if (operation->label != NULL)
    {
        ifx_mxcryptolite_free(operation->label);
        operation->label = NULL;
    }
    if (operation->seed != NULL)
    {
        ifx_mxcryptolite_free(operation->seed);
        operation->seed = NULL;
    }
    if (operation->fixed_data != NULL)
    {
        ifx_mxcryptolite_free(operation->fixed_data);
        operation->fixed_data = NULL;
    }

    return PSA_SUCCESS;
}

#endif
#endif
