# Cypress PSoC6 MCUs acceleration for mbedTLS library

This repository contains mbedTLS hardware accelerated basic cryptography implemented for Cypress PSoC 6 MCUs.

It provides an easy to use mbedTLS library for PSoC 6 MCU with crypto accelerated hardware. The goal is to make the cryptography features of Cypress devices available to the developer using a simple configuration flow.

### mbedTLS library
The [mbedTLS][mbedTLS-lib] library makes it easy for developers to include cryptographic and SSL/TLS capabilities in their products, facilitating this functionality with a minimal coding footprint.

mbedTLS provides a software-only implementation of basic crypto algorithms. The API is defined by ARM and widely utilized in embedded devices for crypto services. The available modules are:

- Encryption/decryption
- Hashing
- Random number generator (RNG)
- SSL/TLS communication
- TCP/IP communication
- X.509
- Asn1

### cy-mbedtls-acceleration
This repo is implemented as an extension of mbedTLS to add PSoC6 MCU hardware acceleration for the basic crypto algorithms.
It requires these other Cypress products:

- [psoc6pdl][psoc6pdl] - PDL driver library
- [psoc6hal][psoc6hal] - HAL layer for Cypress PSoC6 MCUs
- [core-lib][core-lib] - Core library for Cypress PSoC6 MCUs

mbedTLS library v2.x provides a standardized method to extend the implementation by defining special macros.

### How to enable PSoC6 hardware acceleration
To enable any accelerated feature, add the appropriate define to the mbedtls configuration file.

For example, to use the accelerated implementation for AES algorithm, add the **MBEDTLS_AES_ALT** macro definition to the configuration file (***mbedtls-config.h***):
```c++
#define MBEDTLS_AES_ALT
```

After that the mbedTLS library uses the implementation of this function from the acceleration library instead of the internal software implementation.
```c++
/* These defines can be added to the project's MBEDTLS_CONFIG_FILE */

/* Currently this target supports SHA1 */
#define MBEDTLS_SHA1_C

#define MBEDTLS_SHA1_ALT
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_SHA512_ALT

/* Currently this target supports CBC, CFB, OFB, CTR and XTS cipher modes */
#define MBEDTLS_AES_ALT
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_OFB
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_XTS

/* Only NIST-P curves are currently supported */
#define MBEDTLS_ECP_ALT
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED

#define MBEDTLS_ECDSA_SIGN_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT

#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
```

### How to use mbedTLS library with accelerated ALT implementations
To use the mbedTLS library with Cypress hardware acceleration, perform these steps
(you can skip steps 3-4 if mbedTLS library is already present in the project).

1. download cy-mbedtls-acceleration package into your project root directory
    ```shell
    git clone https://github.com/cypresssemiconductorco/cy-mbedtls-acceleration
    ```
1. add this location to INCLUDES and SOURCES directory search
    ```make
    INCLUDES += -Imbedtls_MXCRYPTO
    SOURCES += $(wildcard mbedtls_MXCRYPTO/*.c)
    ```
1. download mbedTLS library into your project's root directory
    ```shell
    git clone --recursive https://github.com/ARMmbed/mbedtls.git
    ```
1. add it files to INCLUDES and SOURCES directory search
    ```make
    INCLUDES += -Imbedtls/include/mbedtls -Imbedtls/crypto/include/mbedtls
    SOURCES += $(wildcard mbedtls/crypto/library/*.c) $(wildcard mbedtls/library/*.c)
    ```
1. define a macro MBEDTLS_CONFIG_FILE with configuration file name add to project environment a define:
    ```make
    CFLAGS += -DMBEDTLS_CONFIG_FILE="<mbedtls-config.h>"
    ```
1. make the project

### How to use mbedTLS library with accelerated ALT implementations in ModusToolbox 2.x
To use mbedTLS library with accelerated ALT implementations in ModusToolbox 2.x, the project should have the required submodules:

- [psoc6pdl][psoc6pdl]
- [psoc6hal][psoc6hal]
- [core-lib][core-lib]

Then perform these steps:

1. make all steps from previous section to download and setup mbedtls library and acceleration files
1. add a new text file named ***.cyignore*** to your project root directory with this content:
    ```
    libs/mbedtls/3rdparty
    libs/mbedtls/configs
    libs/mbedtls/doxygen
    libs/mbedtls/programs
    libs/mbedtls/scripts
    libs/mbedtls/tests
    libs/mbedtls/visualc
    libs/mbedtls/crypto/3rdparty
    libs/mbedtls/crypto/configs
    libs/mbedtls/crypto/docs
    libs/mbedtls/crypto/doxygen
    libs/mbedtls/crypto/programs
    libs/mbedtls/crypto/scripts
    libs/mbedtls/crypto/tests
    libs/mbedtls/crypto/visualc
    ```

### How to use mbedTLS library with or without psoc6hal in ModusToolbox 2.x
The [cy-mbedtls-acceleration][cy-mbedtls-acceleration] package requires concurrent access from two CPUs to the CRYPTO hardware.
The acceleration package has its own internal resource management to control concurrent access.
Or you can use the Cypress Hardware Abstraction Layer (HAL).

By default ModusToolbox uses [psoc6hal][psoc6hal] for access to all hardware resources including CRYPTO hardware.
It defines macro **CY_USING_HAL**. In this case the [cy-mbedtls-acceleration][cy-mbedtls-acceleration] library uses [psoc6hal][psoc6hal]
instead of own internal resource management.

To use the acceleration package internal resource management instead of [psoc6hal][psoc6hal], disable the CRYPTO HAL. The project defines macro **CY_CRYPTO_HAL_DISABLE**.

_**Note:** that not disables the HAL completely, so the application still use HAL for other hardware resources as usually._

Define the macro in the project's configuration files (for example)
```c++
#define CY_CRYPTO_HAL_DISABLE
```
or in the main Makefile (for example):
```make
# Add additional defines to the build process (without a leading -D).
DEFINES=MBEDTLS_CONFIG_FILE="<mbedtls-user-config.h>" CY_CRYPTO_HAL_DISABLE
```

### Features

Supported algorithms:

- AES:
    * ECB,
    * CBC,
    * CFB,
    * CFB,
    * XTS.
- SHA:
    * SHA1,
    * SHA2-256,
    * SHA2-512.
- ECP support for NIST P curves:
    * SECP192R1,
    * SECP224R1,
    * SECP256R1,
    * SECP384R1,
    * SECP521R1.
- ECDH support for NIST P curves:
    * key generation
- ECDSA support for NIST P curves:
    * sign,
    * verify

### License
This project is licensed under the [Apache 2.0 License][apache-licenses] - see the [LICENSE][LICENSE] file for details

### More information
* [Cypress PSoC6 MCU acceleration for mbedTLS library RELEASE information][RELEASE]
* [Peripheral Driver Library API Reference Manual][psoc6pdl-api]
* [PSoC 6 Technical Reference Manuals][psoc6-trm]
* [PSoC 6 MCU Datasheets][psoc6-ds]
* [mbed-os repository][mbed-os]
* [mbedtls repository][mbedTLS-lib]
* [Alternative cryptography engines implementation][mbedTLS-alts]
* [mbedTLS supported features][mbedTLS-features]
* [Cypress Semiconductor][cypress]

---
© Cypress Semiconductor Corporation, 2019-2020.

[cypress]: http://www.cypress.com
[mbed-os]: https://github.com/ARMmbed/mbed-os
[mbedTLS-lib]: https://github.com/ARMmbed/mbedtls
[mbedTLS-alts]: https://tls.mbed.org/kb/development/hw_acc_guidelines
[mbedTLS-features]: https://tls.mbed.org/core-features
[psoc6pdl]: https://github.com/cypresssemiconductorco/psoc6pdl
[psoc6hal]: https://github.com/cypresssemiconductorco/psoc6hal
[core-lib]: https://github.com/cypresssemiconductorco/core-lib
[psoc6-ds]: https://www.cypress.com/search/all?f%5b0%5d=meta_type%3Atechnical_documents&f%5b1%5d=resource_meta_type%3A575&f%5b2%5d=field_related_products%3A114026
[psoc6-trm]: https://www.cypress.com/search/all/PSoC%206%20Technical%20Reference%20Manual?f%5b0%5d=meta_type%3Atechnical_documents&f%5b1%5d=resource_meta_type%3A583
[psoc6pdl-api]: https://cypresssemiconductorco.github.io/psoc6pdl/pdl_api_reference_manual/html/index.html
[cy-mbedtls-acceleration]: https://github.com/cypresssemiconductorco/cy-mbedtls-acceleration
[apache-licenses]: http://www.apache.org/licenses/
[LICENSE]: LICENSE
[RELEASE]: RELEASE.md
