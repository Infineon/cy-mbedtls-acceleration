
/***************************************************************************//**
* \file ifx_cryptolite_transparent_functions.h
*
* \brief
*  PSA crypto transparent driver functions.
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

#if !defined(IFX_CRYPTOLITE_TRANSPARENT_FUNCS_H)
#define IFX_CRYPTOLITE_TRANSPARENT_FUNCS_H

#include "mbedtls/build_info.h"

#include "ifx_cryptolite_transparent_hash.h"
#include "ifx_cryptolite_transparent_mac.h"
#include "ifx_cryptolite_transparent_signature_verify.h"
#include "ifx_cryptolite_transparent_cipher.h"
#include "ifx_cryptolite_transparent_key_agreement.h"
#include "ifx_cryptolite_transparent_aead.h"
#include "ifx_cryptolite_transparent_key_generation.h"
#include "ifx_cryptolite_transparent_public_key_export.h"
#include "ifx_cryptolite_transparent_sign.h"

#endif /* #if !defined (IFX_CRYPTOLITE_TRANSPARENT_FUNCS_H) */
