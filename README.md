# mbedTLS Crypto acceleration for PSOC-Edge MCU Family

This repository contains mbedTLS hardware accelerated basic cryptography implemented for PSOC-Edge MCU.

It provides an easy to use mbedTLS library with hardware accelerated crypto. The goal is to make the cryptography features available to the developer using a simple configuration flow.

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
This repo is implemented as an extension of mbedTLS to add available MCU hardware acceleration for the basic crypto algorithms.
mbedTLS library provides a standardized method to extend the implementation by defining special macros.

### How to use mbedTLS library with accelerated ALT implementations without using ModusToolbox
To use the mbedTLS library with MCU hardware acceleration, perform these steps
( you can skip steps 1-2 if mbedTLS library is already present in the project ).

1. Download mbedTLS library into your project's root directory
    ```shell
    git clone -b mbedtls-3.0.0 --recursive https://github.com/ARMmbed/mbedtls.git
    ```
    _**Note:** Above command will check out mbedtls-3.0.0 tag. To get the list of compatible mbedTLS tags with cy-mbedtls-acceleration package, refer to [dependencies to mbedTLS versions](./RELEASE.md/#dependencies-to-mbedtls-versions)._
1. Add its files to INCLUDES and SOURCES directory search in makefile. For more details about mbedTLS, refer to [mbedTLS Knowledge Base](https://tls.mbed.org/kb).
1. Download cy-mbedtls-acceleration package into your project root directory.
    ```shell
    git clone https://github.com/Infineon/cy-mbedtls-acceleration.git

    ```
    _**Note:** Use appropriate version of cy-mbedtls-acceleration, as listed in [dependencies to mbedTLS versions](./RELEASE.md/#dependencies-to-mbedtls-versions)._
2. To enable hardware acceleration for PSOC Edge platform, use following files.
      ```make
      INCLUDES += -Iinclude -Imbedtls_MXCRYPTO
      SOURCES += $(wildcard mbedtls_MXCRYPTO/*.c)
      ```
3. To enable any accelerated feature, add the appropriate define to the mbedtls configuration file. The list of supported features for your platform is available at [features section](#features).

	For example, to use the accelerated implementation for AES algorithm, add the **MBEDTLS_AES_ALT** macro definition to the configuration file (***mbedtls-config.h***):
	```c++
	#define MBEDTLS_AES_ALT
	```

	After that the mbedTLS library uses the implementation of this function from the acceleration library instead of the internal software implementation.
	```c++
	/* These defines can be added to the project's MBEDTLS_CONFIG_FILE */

	/* Currently this target supports SHA1 & SHA256 */
	#define MBEDTLS_SHA1_C
    #define MBEDTLS_SHA224_C
    #define MBEDTLS_SHA256_C

	#define MBEDTLS_SHA1_ALT
	#define MBEDTLS_SHA256_ALT
	#define MBEDTLS_SHA512_ALT

	/* Currently this target supports CBC, CFB, OFB, CTR, XTS and GCM cipher modes */
	#define MBEDTLS_AES_ALT
	#define MBEDTLS_CIPHER_MODE_CBC
	#define MBEDTLS_CIPHER_MODE_CFB
	#define MBEDTLS_CIPHER_MODE_OFB
	#define MBEDTLS_CIPHER_MODE_CTR
	#define MBEDTLS_CIPHER_MODE_XTS
    #define MBEDTLS_GCM_ALT

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

    #define MBEDTLS_NO_PLATFORM_ENTROPY
	```

1. Define a macro MBEDTLS_CONFIG_FILE with configuration file name and add to project environment a define:
    ```make
    DEFINES += MBEDTLS_CONFIG_FILE="<mbedtls-config.h>"
    ```
1. Create your application source file and add to those SOURCES directory search in makefile. [Sample application source file](#hardware-accelerated-mbedtls-code-example) can be used for the reference.
1. Make the project.

### How to use mbedTLS library with accelerated ALT implementations in ModusToolbox 2.3+

To use the mbedTLS library using ModusToolbox, perform following steps:

1. Create `Empty_App` project using ModusToolbox.
   
   _**Note:** If you want to enable the standard input output over UART, create Hello_World project from ModusToolbox instead of Empty_App project._
2. To add mbedTLS and cy-mbedtls-acceleration libraries to project, use the Library Manager. Use appropriate version of cy-mbedtls-acceleration, as listed in [dependencies to mbedTLS versions](./RELEASE.md/#dependencies-to-mbedtls-versions). For more details about Library Manager, refer to [ModusToolbox Software Environment, Quick Start Guide, Documentation, and Videos][modustoolbox-software-environment].
3. To ignore MbedTLS sample programs, tests and 3rdparty files, create .cyignore file in root directory of project and add following lines:
    ```make
    $(SEARCH_mbedtls)/3rdparty
    $(SEARCH_mbedtls)/programs
    $(SEARCH_mbedtls)/tests
    ```
4. To configure mbedTLS and to use alt implementation, follow instructions provided from section 5 of **[How to use mbedTLS library with accelerated ALT implementations without using ModusToolbox](#how-to-use-mbedtls-library-with-accelerated-alt-implementations-without-using-modustoolbox)**.

### How to use hardware entropy
To enable hardware entropy perform these steps:

   Add the **MBEDTLS_ENTROPY_HARDWARE_ALT** macro definition to the configuration file (***mbedtls-config.h***):
    ``` #define MBEDTLS_ENTROPY_HARDWARE_ALT ```


### Hardware accelerated MbedTLS code example

This code example demonstrates MbedTLS hardware acceleration capabilities using the cryptographic hardware block of MCU. It uses SHA-256 algorithm.

_**Note:** To enable the standard input output over UART communication, you can create `Hello_World` project from ModusToolbox_

```c++
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/platform.h"

int sha256(void)
{
    printf("\r\nSHA-256 Test Application...\r\n");

    /* Run hardware accelerated SHA-256 test */
#if defined(MBEDTLS_SHA256_C)
        const int IS_SHA_224 = 0;
        mbedtls_sha256_context pCtx;
        unsigned char sha256sum[32];
        memset(sha256sum, 0, sizeof(sha256sum));

        /* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf */
        /* Input message */
        static const char* INPUT_MESSAGE = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        static const uint8_t DIGEST[] = { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 };

        /* Initialize sha engine */
        mbedtls_sha256_init(&pCtx);

        /* Compute the hash */
        mbedtls_sha256((const unsigned char*)INPUT_MESSAGE, strlen(INPUT_MESSAGE), sha256sum, IS_SHA_224);

        /* Compare result */
        if(memcmp(sha256sum, DIGEST, 32) == 0)
        {
            printf("\r\nTest Case passed.\r\n");
        }
        else
        {
            printf("\r\nTest Case failed.\r\n");
        }
#endif /* MBEDTLS_SHA256_C */

    return 0;
}

int main(void)
{
    sha256();

    return 0;
}
```

### Features

+ **Supported algorithms in PSOC-EDGE MCUs:**

  - AES:
      * ECB,
      * CBC,
      * CFB,
      * CTR,
      * XTS,
      * GCM.
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
* [PSOC-Edge MCU acceleration for mbedTLS library RELEASE information][RELEASE]
* [mbedtls repository][mbedTLS-lib]
* [Alternative cryptography engines implementation][mbedTLS-alts]
* [mbedTLS supported features][mbedTLS-features]
* [Cypress Semiconductor][cypress]


### How to use PSA Crypto in ModusToolbox 3.5+

1. Create `Empty_App` project using ModusToolbox.
   
   _**Note:** If you want to enable the standard input output over UART create Hello_World project from ModusToolbox instead of Empty_App project._
2. Using Library Manager add 'ifx-mbedTLS' and 'cy-mbedtls-acceleration' libraries to project. 
   Use appropriate version of cy-mbedtls-acceleration, as listed in [dependencies to mbedTLS versions](../../RELEASE.md/#dependencies-to-mbedtls-versions).
   For more details about Library Manager, refer to [ModusToolbox Software Environment, Quick Start Guide, Documentation, and Videos][modustoolbox-software-environment].
3. Ignore MbedTLS sample programs and 3rdparty files, create .cyignore file in root directory of project and add following lines:
    ```make
    $(SEARCH_mbedtls)/3rdparty
    $(SEARCH_mbedtls)/programs
    $(SEARCH_mbedtls)/tests
    ```
4. Enable desired PSA Crypto driver feature, add the appropriate defines to the mbedtls configuration file. The list of supported features for your platform is available at [features section](#features).

    For example, to use the PSA SHA Crypto driver, add macro definition to the configuration file as below (***mbedtls_config.h***):
    ```c++
    /* These defines can be added to the project's MBEDTLS_CONFIG_FILE */
    #define IFX_PSA_MXCRYPTO_PRESENT

    /* This define supports HMAC,SHA,HKDF */

    #define MBEDTLS_NO_PLATFORM_ENTROPY
    #define MBEDTLS_PSA_CRYPTO_DRIVERS
    #define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    #define MBEDTLS_PSA_CRYPTO_CONFIG
    #define MBEDTLS_ASN1_PARSE_C
    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_PLATFORM_C
    #define MBEDTLS_PSA_CRYPTO_C
    #define MBEDTLS_CIPHER_C

    #define PSA_WANT_ALG_HKDF                       1
    #define PSA_WANT_ALG_HMAC                       1
    #define PSA_WANT_ALG_SHA_256                    1
    #define PSA_WANT_KEY_TYPE_HMAC                  1


5. Define a macro MBEDTLS_CONFIG_FILE and assign configuration file name. Add it in project makefile as suggested below:
    ```make
    DEFINES += MBEDTLS_CONFIG_FILE="<mbedtls-config.h>"
    ```
6. Update your application source file 'main.c' to include sample SHA test code. Refer to the [Sample source code](#psa-code-example).
7. Build the project and program to Target.


### PSA code example

This code example demonstrates MbedTLS PSA-SHA driver capabilities using the cryptographic hardware block.

```c++

#include "psa/crypto.h"

int psa_sha256(void)
{
    printf("\r\nSHA-256 Test Application...\r\n");

    /* Run hardware accelerated SHA-256 test */
#if defined(MBEDTLS_PSA_CRYPTO_C)
        unsigned char sha256sum[32];
        static unsigned char tmp[200];
        size_t hash_length;
        memset(sha256sum, 0, sizeof(sha256sum));

        /* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf */
        /* Input message */
        static const char* INPUT_MESSAGE = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        static const uint8_t DIGEST[] = { 0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 };

        /* Initialize PSA */
        psa_crypto_init();

        /* Compute the hash */
        psa_hash_compute( PSA_ALG_SHA_256, INPUT_MESSAGE, strlen(INPUT_MESSAGE), tmp, PSA_HASH_LENGTH(PSA_ALG_SHA_256), &hash_length);

        /* Compare result */
        if(memcmp(tmp, DIGEST, 32) == 0)
        {
            printf("\r\nTest Case passed!!\r\n");
        }
        else
        {
            printf("\r\nTest Case failed!!\r\n");
        }
#endif /* MBEDTLS_PSA_CRYPTO_C */

    return 0;
}

int main(void)
{
    psa_sha256();

    return 0;
}

```
### Features

+ **Supported algorithms in PSOC-EDGE MCUs:**

  - AES:
      * ECB (Encrypt),
      * CBC (Encrypt),
      * CFB (Encrypt, Decrypt),
      * CTR (Encrypt, Decrypt),
      * CCM, GCM (AEAD).
  - SHA:
      * SHA-256.
  - Elliptic Curve Cryptography (ECC) Key generation:

      * Sign
      * Verify
      * Hash
  - RSA (Encrypt, Decrypt, Sign/Verify)
  - CMAC-AES, HMAC-SHA, HKDF, TRNG.

### License
This project is licensed under the [Apache 2.0 License][apache-licenses] - see the [LICENSE][LICENSE] file for details

### More information
* [Conditional Inclusion of PSA Crypto features][additional-ref] 
* [mbedTLS supported features][mbedTLS-features]
* [Infineon][Infineon]

---
© Cypress Semiconductor Corporation (an Infineon company), 2019-2024.

[Infineon]:(http://www.infineon.com)
[mbedTLS-lib]: https://github.com/ARMmbed/mbedtls
[mbedTLS-alts]: https://tls.mbed.org/kb/development/hw_acc_guidelines
[mbedTLS-features]: https://tls.mbed.org/core-features
[additional-ref]: https://github.com/Mbed-TLS/mbedtls/blob/v3.5.0/docs/proposed/psa-conditional-inclusion-c.md
[mtb-pdl]: (https://www.infineon.com/dgdl/Infineon-ModusToolbox_3_3_Tools_Package_User_Guide-GettingStarted-v23_00-EN.pdf?fileId=8ac78c8c8386267f0183a8e9720c5915&redirId=188343) of [ModusToolbox&trade; tools package user guide](https://www.infineon.com/dgdl/Infineon-ModusToolbox_3_3_Tools_Package_User_Guide-GettingStarted-v23_00-EN.pdf?fileId=8ac78c8c8386267f0183a8e9720c5915&redirId=188343)
[cy-mbedtls-acceleration]: https://github.com/Infineon/cy-mbedtls-acceleration
[apache-licenses]: http://www.apache.org/licenses/
[modustoolbox-software-environment]: https://www.infineon.com/cms/en/design-support/tools/sdk/modustoolbox-software/
[LICENSE]: LICENSE
[RELEASE]: RELEASE.md
