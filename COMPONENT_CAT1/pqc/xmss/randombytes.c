/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include "cy_pdl.h"
#include "cycfg.h"

#if defined(CY_IP_MXCRYPTO)
#include "cy_crypto_core_trng_config.h"
#endif

#define MAX_TRNG_BIT_SIZE                (32UL)


void randombytes(unsigned char *x, unsigned long long xlen)
{
    uint32_t random = 0u;
    size_t olen = 0;

#if defined(CY_IP_MXCRYPTO)
    /* Get Random byte */
    while ((olen < xlen))
    {
        if ( Cy_Crypto_Core_Trng(CRYPTO, CY_CRYPTO_DEF_TR_GARO, CY_CRYPTO_DEF_TR_FIRO,
                                                MAX_TRNG_BIT_SIZE, &random) != CY_CRYPTO_SUCCESS)
        {
            return;
        } 
        else
        {
            for (uint8_t i = 0; (i < 4) && (olen < xlen) ; i++)
            {
                *x++ = ((uint8_t *)&random)[i];
                olen += 1;
            }
        }
    }
    
    random = 0uL;

    Cy_Crypto_Core_Trng_DeInit(CRYPTO);

#else

    (void)Cy_Cryptolite_Trng_Init(CRYPTOLITE, NULL);
    (void)Cy_Cryptolite_Trng_Enable(CRYPTOLITE);

    /* Get Random byte */
    while ((olen < xlen))
    {
        if (Cy_Cryptolite_Trng_ReadData(CRYPTOLITE, &random) != CY_CRYPTOLITE_SUCCESS)
        {
            return;
        } 
        else
        {
            for (uint8_t i = 0; (i < 4) && (olen < xlen) ; i++)
            {
                *x++ = ((uint8_t *)&random)[i];
                olen += 1;
            }
        }
    }
    
    random = 0uL;

    (void)Cy_Cryptolite_Trng_Disable(CRYPTOLITE);
    (void)Cy_Cryptolite_Trng_DeInit(CRYPTOLITE);

#endif
    
}
