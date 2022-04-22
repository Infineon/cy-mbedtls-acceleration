#if defined (COMPONENT_CAT1)

#include "cy_device.h"
#include "cy_syslib.h"

#if CY_CPU_CORTEX_M0P || (CY_CPU_CORTEX_M4 && !defined(CY_DEVICE_SECURE))
#if defined (CY_IP_MXCRYPTO)
#if (CPUSS_CRYPTO_AES == 1)
    #define MBEDTLS_AES_ALT
#endif /* CPUSS_CRYPTO_AES */
#if ((CPUSS_CRYPTO_SHA1 == 1) || (CPUSS_CRYPTO_SHA2 == 1))
    #define MBEDTLS_SHA1_ALT
#endif /* CPUSS_CRYPTO_SHA1, CPUSS_CRYPTO_SHA2 */
#if (CPUSS_CRYPTO_SHA2 == 1)
    #define MBEDTLS_SHA256_ALT
    #define MBEDTLS_SHA512_ALT
#endif /* CPUSS_CRYPTO_SHA2 */
#if (CPUSS_CRYPTO_VU == 1)
    #define MBEDTLS_ECP_ALT
    #define MBEDTLS_ECDSA_SIGN_ALT
    #define MBEDTLS_ECDSA_VERIFY_ALT
    #define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#endif /* CPUSS_CRYPTO_VU */
#endif /* CY_IP_MXCRYPTO */
#endif /* CY_CPU_CORTEX_M0P || (CY_CPU_CORTEX_M4 && !defined(CY_DEVICE_SECURE)) */
#endif /* COMPONENT_CAT1 */