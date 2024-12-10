/***************************************************************************//**
* \file ifx_cryptolite_common.c
*
* \brief
*  PSA crypto cryptolite helper functions.
*
********************************************************************************
*  Copyright The Mbed TLS Contributors

* Copyright (C) 2022 Cypress Semiconductor Corporation
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

#include "ifx_cryptolite_common.h"

#if defined (CY_IP_MXCRYPTOLITE)


/*******************************************************************************
* Function Name: ifx_cryptolite_status_to_psa_status
****************************************************************************//**
*
* Function to convert the cryptolite status code to PSA status code.
*
* \param cryptolite_status
*  The status code of the cryptolite pdl driver.
*
* \return psa_status_t.
*
*******************************************************************************/ 
psa_status_t  ifx_cryptolite_status_to_psa_status (cy_en_cryptolite_status_t cryptolite_status)
{
    switch (cryptolite_status)
    {
    case CY_CRYPTOLITE_SUCCESS:
        return PSA_SUCCESS;
    case CY_CRYPTOLITE_HW_BUSY:
    case CY_CRYPTOLITE_BUS_ERROR:
    return PSA_ERROR_HARDWARE_FAILURE;
    case CY_CRYPTOLITE_BAD_PARAMS:
    case CY_CRYPTOLITE_BUFFER_NOT_ALIGNED:
    return PSA_ERROR_INVALID_ARGUMENT;
    default:
    return PSA_ERROR_GENERIC_ERROR;
    }
}
    

//This should finally be replaced by Cy_Cryptolite_Vu_memcmp
uint8_t ifx_psa_safer_memcmp(const uint8_t *a,
                             const uint8_t *b,
                             size_t n)
{
    uint8_t diff = 0u;

    for (size_t i = 0; i < n; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff;
}

#endif /* CY_IP_MXCRYPTOLITE */
