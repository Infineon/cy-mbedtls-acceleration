IFX CryptoSuite PSA Driver
---------------------------------

Based on CryptoSuite Release Version: v6.1.2 (crypto-suite-psc3x8-release-v6.1.2)

Supported Algorithms:
- AES-ECB (Electronic Codebook) - 128/256-bit keys
- AES-CBC (Cipher Block Chaining) - 128/256-bit keys
- AES-CTR (Counter Mode) - 128/256-bit keys
- AES-CMAC (Cipher-based MAC) - 128/256-bit keys
- AES-CCM (Counter with CBC-MAC) - 128/256-bit keys


Device Supported: PSC3M8 (PSC3x8 family)
Compilers Tested: ARM Compiler 6.22 (armclang)

Known Limitations:
- SecControl is disabled
- XBlob creation for input plain data uses no seed2 and seed3
- GCM AEAD mode not supported (only CCM)

Build Configuration:
--------------------
Define below config macros:

#define IFX_PSA_CRYPTOSUITE_PRESENT
#define PSA_WANT_KEY_TYPE_AES           1
#define PSA_WANT_ALG_ECB_NO_PADDING     1  // Enables IFX_PSA_CRYPTOSUITE_CIPHER_ECB
#define PSA_WANT_ALG_CBC_NO_PADDING     1  // Enables IFX_PSA_CRYPTOSUITE_CIPHER_CBC
#define PSA_WANT_ALG_CTR                1  // Enables IFX_PSA_CRYPTOSUITE_CIPHER_CTR
#define PSA_WANT_ALG_CMAC               1  // Enables IFX_PSA_CRYPTOSUITE_MAC
#define PSA_WANT_ALG_CCM                1  // Enables IFX_PSA_CRYPTOSUITE_AEAD

Default ifx_cryptosuite_config.h enables all supported PSA algorithm drivers. User can override by defining custom config header.

Compiler Flags (ARM Compiler 6.22):
---------------------------------
CC = armclang
CFLAGS=-fshort-enums

Stack requirements
---------------------
- MAC : 5KB
- Others : 4KB

Memory allocation
--------------------
Memory is dynamically allocated by default, define IFX_MXCRYPTOSUITE_USE_STATIC_MEM for static memory use, 
Use macros below to use custom function instead of std libc used by default.
  
#define ifx_mxcryptosuite_memset user_memset
#define ifx_mxcryptosuite_memcpy user_memcpy
#define ifx_mxcryptosuite_malloc user_malloc
#define ifx_mxcryptosuite_free   user_free
