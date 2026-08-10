/***************************************************************************//**
* \file ifx_cryptosuite_common.c
*
* \brief
*  PSA CryptoSuite transparent driver common utilities.
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

#include "ifx_cryptosuite_common.h"

#if defined(IFX_PSA_CRYPTOSUITE_PRESENT)

psa_status_t ifx_cryptosuite_to_psa_status(Cs_StdApi_StatusType cs_status)
{
    switch(cs_status) {
        case CS_STATUS_SUCCESS:
            return PSA_SUCCESS;
        case CS_STATUS_ERROR_VERIFICATION_FAILED:
            return PSA_ERROR_INVALID_SIGNATURE;
        case CS_STATUS_ERROR_NOT_PERMITTED:
            return PSA_ERROR_NOT_PERMITTED;
        case CS_STATUS_ERROR_BUFFER_TOO_SMALL:
            return PSA_ERROR_BUFFER_TOO_SMALL;
        case CS_STATUS_ERROR_CATASTROPHIC_ERROR:
            return PSA_ERROR_HARDWARE_FAILURE;
        case CS_STATUS_ERROR_NOT_SUPPORTED:
            return PSA_ERROR_NOT_SUPPORTED;
        case CS_STATUS_ERROR_INSUFFICIENT_MEMORY:
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        case CS_STATUS_ERROR_INVALID_ARGUMENT:
            return PSA_ERROR_INVALID_ARGUMENT;
        case CS_STATUS_ERROR_INVALID_STATE:
            /* fall-through */
        case CS_STATUS_ERROR_CRYPTO_HDL_NOT_CONFIGURED:
            /* fall-through */
        case CS_STATUS_ERROR_KEY_NOT_CONFIGURED:
            return PSA_ERROR_BAD_STATE;
        case CS_STATUS_ERROR_INVALID_CONFIGURATION:
            return PSA_ERROR_INVALID_ARGUMENT;
        case CS_STATUS_ERROR_INVALID_HANDLE:
            return PSA_ERROR_INVALID_HANDLE;
        case CS_STATUS_ERROR_GENERIC:
            /* fall-through */
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

#define GETXBLOBINTEGRITY(Value)   (((Value)& CS_XBLOB_INTEGRITY_Msk) >> CS_XBLOB_INTEGRITY_Pos)
void ifx_cryptosuite_init_xblob(Cs_XBlobType *xblob, uint8_t *dst_buf,
                                const uint8_t *src, size_t length)
{
    if (xblob != NULL) {
        xblob->Data1Ptr   = dst_buf;
        xblob->Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY    << CS_XBLOB_TYPE_Pos) |
                                       (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
        xblob->ByteLen    = (uint16_t)length;
        (void)ifx_cryptosuite_generate_random_u32(&xblob->Seed2);
        (void)ifx_cryptosuite_generate_random_u32(&xblob->Seed3);
        if (src != NULL && length > 0) {
            (void)Cs_XBlob_Import(xblob, src, NULL, NULL, NULL);
        } else {
            xblob->Checksum = Cs_XBlob_CalculateChecksum(xblob, CS_XBLOB_ID_DEFAULT,
                                                         GETXBLOBINTEGRITY(xblob->Properties), NULL);
        }
    }
}

psa_status_t ifx_cryptosuite_prepare_output_xblob(Cs_XBlobType *xblob, uint8_t *out_buf,
                                                  size_t length)
{
    if (xblob == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ifx_mxcryptosuite_memset(xblob, 0, sizeof(*xblob));
    xblob->Data1Ptr   = out_buf;
    xblob->Properties = (uint16_t)((CS_XBLOB_TYPE_BYTE_ARRAY << CS_XBLOB_TYPE_Pos) |
                                   (CS_XBLOB_INTEGRITY_STANDARD << CS_XBLOB_INTEGRITY_Pos));
    xblob->ByteLen    = (uint16_t)length;
    (void)ifx_cryptosuite_generate_random_u32(&xblob->Seed2);
    (void)ifx_cryptosuite_generate_random_u32(&xblob->Seed3);
    /* Output XBlobs use CS_XBLOB_INTEGRITY_SHORT so the checksum covers only the XBlob
     * metadata, not the uninitialised output buffer. */
    xblob->Checksum   = Cs_XBlob_CalculateChecksum(xblob, CS_XBLOB_ID_DEFAULT,
                                                   CS_XBLOB_INTEGRITY_SHORT, NULL);

    return PSA_SUCCESS;
}

psa_status_t ifx_cryptosuite_generate_random_u32(uint32_t *out)
{
    cy_en_cryptolite_status_t result;

    if (out == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    result = Cy_Cryptolite_Trng_Init(CRYPTOLITE, NULL);
    if (result != CY_CRYPTOLITE_SUCCESS)
    {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    result = Cy_Cryptolite_Trng(CRYPTOLITE, out);

    (void)Cy_Cryptolite_Trng_DeInit(CRYPTOLITE);

    return (result == CY_CRYPTOLITE_SUCCESS) ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

psa_status_t ifx_cryptosuite_generate_rng_seed(uint8_t *rng_seed, uint8_t *rng_seed_inv, size_t size)
{
    cy_en_cryptolite_status_t result = Cy_Cryptolite_Trng_Init(CRYPTOLITE, NULL);
    if (result != CY_CRYPTOLITE_SUCCESS)
    {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    result = Cy_Cryptolite_Trng_Enable(CRYPTOLITE);
    uint8_t *p     = rng_seed;
    uint8_t *q     = rng_seed_inv;
    size_t   count = size;
    while (result == CY_CRYPTOLITE_SUCCESS && count > 0)
    {
        uint32_t randWord;
        result = Cy_Cryptolite_Trng_ReadData(CRYPTOLITE, &randWord);
        if (result == CY_CRYPTOLITE_SUCCESS)
        {
            uint32_t randWordInv = ~randWord;
            size_t   bytesToCopy = (count < sizeof(randWord)) ? count : sizeof(randWord);
            memcpy(p, &randWord, bytesToCopy);
            p += bytesToCopy;
            if (q != NULL)
            {
                memcpy(q, &randWordInv, bytesToCopy);
                q += bytesToCopy;
            }
            count -= bytesToCopy;
        }
    }
    (void)Cy_Cryptolite_Trng_Disable(CRYPTOLITE);
    (void)Cy_Cryptolite_Trng_DeInit(CRYPTOLITE);
    return (result == CY_CRYPTOLITE_SUCCESS) ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

#endif /* IFX_PSA_CRYPTOSUITE_PRESENT */
