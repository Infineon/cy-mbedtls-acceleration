# mbedTLS Crypto PSA acceleration for PSOC EDGE MCUs

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

This code example demonstrates MbedTLS PSA-SHA driver capabilities using the cryptographic hardware block of PSOC EDGE MCUs.

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

+ **Supported algorithms PSOC EDGE MCUs:**

- AES (ECB, CBC, CFB, CTR) AEAD (GCM, CCM)
- RSA (Encrypt, Decrypt, Sign/Verify)
- Elliptic Curve Cryptography (ECC) Key generation,Sign and Verify, ECDH Key agreement
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- CMAC-AES, HMAC-SHA, HKDF, TRNG

### License
This project is licensed under the [Apache 2.0 License][apache-licenses] - see the [LICENSE][LICENSE] file for details

### More information
* [Conditional Inclusion of PSA Crypto features][additional-ref] 
* [mbedtls repository][mbedTLS-lib]
* [Alternative cryptography engines implementation][mbedTLS-alts]
* [mbedTLS supported features][mbedTLS-features]
* [Infineon][Infineon]

---
© Cypress Semiconductor Corporation (an Infineon company), 2019-2024.

[Infineon]:(http://www.infineon.com)
[mbedTLS-lib]: https://github.com/ARMmbed/mbedtls
[mbedTLS-alts]: https://tls.mbed.org/kb/development/hw_acc_guidelines
[mbedTLS-features]: https://tls.mbed.org/core-features
[additional-ref]: https://github.com/Mbed-TLS/mbedtls/blob/v3.5.0/docs/proposed/psa-conditional-inclusion-c.md
[cy-mbedtls-acceleration]: https://github.com/Infineon/cy-mbedtls-acceleration
[apache-licenses]: http://www.apache.org/licenses/
[modustoolbox-software-environment]: https://www.infineon.com/cms/en/design-support/tools/sdk/modustoolbox-software/
[LICENSE]: LICENSE
[RELEASE]: RELEASE.md