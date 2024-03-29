#if defined (COMPONENT_CAT1)

#include "cy_device.h"
#include "cy_syslib.h"

#if CY_CPU_CORTEX_M0P || ((CY_CPU_CORTEX_M7 || CY_CPU_CORTEX_M4 || CY_CPU_CORTEX_M33) && !defined(CY_DEVICE_SECURE))
#if defined (CY_IP_MXCRYPTO)
#if (CPUSS_CRYPTO_AES == 1)
    #define MBEDTLS_AES_ALT
#endif /* CPUSS_CRYPTO_AES */

#if (((CY_SYSLIB_DRV_VERSION_MAJOR == 3) && (CY_SYSLIB_DRV_VERSION_MINOR >= 30)) || (CY_SYSLIB_DRV_VERSION_MAJOR >= 4))
#if (CPUSS_CRYPTO_GCM == 1)
    #define MBEDTLS_GCM_ALT
#endif /* CPUSS_CRYPTO_GCM */
#endif

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
#elif defined (CY_IP_MXCRYPTOLITE)
#if (CRYPTOLITE_SHA_PRESENT == 1)
    #define MBEDTLS_SHA256_ALT
#endif /* CRYPTO_SHA_PRESENT */
#endif /*  CY_IP_MXCRYPTO, CY_IP_MXCRYPTOLITE */
#endif/* CY_CPU_CORTEX_M0P || ((CY_CPU_CORTEX_M7 || CY_CPU_CORTEX_M4 || CY_CPU_CORTEX_M33) && !defined(CY_DEVICE_SECURE)) */
#endif /* COMPONENT_CAT1 */
