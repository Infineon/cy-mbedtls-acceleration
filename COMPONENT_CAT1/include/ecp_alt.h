/*
 *  mbed Microcontroller Library
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (c) (2019-2022), Cypress Semiconductor Corporation (an Infineon company) or
 *  an affiliate of Cypress Semiconductor Corporation.
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * \file    ecp_alt.h
 * \version 1.4
 *
 * \brief   This file provides an API for Elliptic Curves over GF(P) (ECP).
 *
 *          The use of ECP in cryptography and TLS is defined in
 *          <em>Standards for Efficient Cryptography Group (SECG): SEC1
 *          Elliptic Curve Cryptography</em> and
 *          <em>RFC-4492: Elliptic Curve Cryptography (ECC) Cipher Suites
 *          for Transport Layer Security (TLS)</em>.
 *
 *          <em>RFC-2409: The Internet Key Exchange (IKE)</em> defines ECP
 *          group types.
 *
 */

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)
    #include "ecp_alt_mxcrypto.h"
#else
    #error mbedTLS ALT for ECP is not supported
#endif /* CY_IP_MXCRYPTO */
