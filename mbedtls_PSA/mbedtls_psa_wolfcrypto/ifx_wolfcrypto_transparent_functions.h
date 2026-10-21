/***************************************************************************//**
* \file ifx_wolfcrypto_transparent_functions.h
*
* \brief
*  PSA crypto wolfcrypto transparent driver functions.
*
*  Aggregates the per-operation transparent driver headers into a single
*  include used by the PSA driver dispatch layer.
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

#if !defined(IFX_WOLFCRYPTO_TRANSPARENT_FUNCS_H)
#define IFX_WOLFCRYPTO_TRANSPARENT_FUNCS_H

#include "ifx_wolfcrypto_config.h"

#if defined(IFX_PSA_WOLFCRYPTO_PRESENT)

#include "ifx_wolfcrypto_transparent_sign.h"
#include "ifx_wolfcrypto_transparent_signature_verify.h"
#include "ifx_wolfcrypto_transparent_key_generation.h"
#include "ifx_wolfcrypto_transparent_public_key_export.h"
#include "ifx_wolfcrypto_transparent_import.h"
#include "ifx_wolfcrypto_transparent_key_encapsulation.h"

#endif /* IFX_PSA_WOLFCRYPTO_PRESENT */

#endif /* #if !defined (IFX_WOLFCRYPTO_TRANSPARENT_FUNCS_H) */
