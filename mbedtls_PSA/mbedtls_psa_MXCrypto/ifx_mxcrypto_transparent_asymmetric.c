/***************************************************************************//**
* \file ifx_mxcrypto_transparent_asymmetric.c
*
* \brief
*  PSA crypto transparent asymmetric encrypt/decrypt driver functions.
*
********************************************************************************
* Copyright (C) 2023 Cypress Semiconductor Corporation
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

#include "ifx_mxcrypto_transparent_asymmetric.h"
#if (defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT) || defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT))

#include "cy_device.h"

#if defined (CY_IP_MXCRYPTO)

#define IFX_RSA_CRYPT       2 

#if defined (IFX_PSA_MXCRYPTO_RSA_OEAP)
#include "ifx_mxcrypto_transparent_hash.h"
#endif

/*******************************************************************************
* Function Name: ifx_mxcrypto_rsa_encrypt_decrypt
****************************************************************************//**
*
* Function to Encrypt/decrypt RSA message.
*
* \param rsa_key
* The pointer to rsa private/public key context.
*
* \param input
* The pointer to the input message.
*
* \param output
* The pointer to the output message.
* 
* \return psa_status_t.
*
*******************************************************************************/
static psa_status_t ifx_mxcrypto_rsa_encrypt_decrypt(cy_stc_crypto_rsa_pub_key_t *rsa_key, const uint8_t *input, uint8_t *output)
{

    cy_en_crypto_status_t cy_status = CY_CRYPTO_BAD_PARAMS;
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t *input_ptr = NULL;
    uint8_t *modulus_ptr = NULL;
    uint8_t *keyexp_ptr = NULL;
    uint32_t pubkey_mod_len; 
    uint32_t pubkey_exp_len; 

    pubkey_mod_len = PSA_BITS_TO_BYTES(rsa_key->moduloLength);
    pubkey_exp_len = PSA_BITS_TO_BYTES(rsa_key->pubExpLength);

    #if defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        CY_ALIGN(32) static uint8_t input_data[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
        CY_ALIGN(32) static uint8_t modulus[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
        CY_ALIGN(32) static uint8_t keyexp[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE))];
#else
        CY_ALIGN(4) static uint8_t input_data[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t modulus[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
        CY_ALIGN(4) static uint8_t keyexp[PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)];
#endif
        input_ptr =  input_data;
        modulus_ptr = modulus;
        keyexp_ptr = keyexp;
    #elif defined (IFX_PSA_MXCRYPTO_USE_STACK_MEM)
        CY_ALIGN(4) uint8_t input_data[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
        CY_ALIGN(4) uint8_t modulus[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
        CY_ALIGN(4) uint8_t keyexp[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_BITS_TO_BYTES(IFX_PSA_MXCRYPTO_RSA_MODULUS_SIZE)) + CY_CRYPTO_DCAHCE_PADDING_SIZE];

        input_ptr =  (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)input_data);
        modulus_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)modulus);
        keyexp_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)keyexp);
    #else
        uint32_t *in_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(pubkey_mod_len) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        uint32_t *mod_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(pubkey_mod_len) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        uint32_t *exp_ptr = (uint32_t *)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(pubkey_exp_len) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        input_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)in_ptr);
        modulus_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)mod_ptr);
        keyexp_ptr = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)exp_ptr);
    #endif


    if( (NULL != input_ptr) && (NULL != modulus_ptr) && (NULL != keyexp_ptr))
    {
        ifx_mxcrypto_memcpy(modulus_ptr, rsa_key->moduloPtr, pubkey_mod_len);
        Cy_Crypto_InvertEndianness(modulus_ptr, pubkey_mod_len);
        rsa_key->moduloPtr = modulus_ptr;

        ifx_mxcrypto_memcpy(keyexp_ptr, rsa_key->pubExpPtr, pubkey_exp_len);
        Cy_Crypto_InvertEndianness(keyexp_ptr, pubkey_exp_len);
        rsa_key->pubExpPtr = keyexp_ptr;

        ifx_mxcrypto_memcpy(input_ptr, input, pubkey_mod_len);
        Cy_Crypto_InvertEndianness(input_ptr, pubkey_mod_len);

        cy_status = Cy_Crypto_Core_Rsa_Proc(CRYPTO, rsa_key, input_ptr, pubkey_mod_len, output);

        if(cy_status == CY_CRYPTO_SUCCESS)
        {
            Cy_Crypto_InvertEndianness(output, pubkey_mod_len);
        }
            
        psa_status = ifx_mxcrypto_status_to_psa_status(cy_status);
    }
    else
    {
        psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    #if !defined(IFX_PSA_MXCRYPTO_USE_STATIC_MEM) && !defined(IFX_PSA_MXCRYPTO_USE_STACK_MEM)

    if(NULL != in_ptr)
    {
        ifx_mxcrypto_free(in_ptr);
    }

    if(NULL != mod_ptr)
    {
        ifx_mxcrypto_free(mod_ptr);
    }

    if(NULL != exp_ptr)
    {
        ifx_mxcrypto_free(exp_ptr);
    }

    #endif

    if (PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }
    
    return PSA_SUCCESS;

}


#if defined(IFX_PSA_MXCRYPTO_RSA_OEAP)
static psa_status_t mgf_mask(unsigned char *dst, size_t dlen, unsigned char *src,
                    size_t slen, psa_algorithm_t alg)
{
    unsigned char counter_t[CY_CRYPTO_ALIGN_CACHE_LINE(4) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;
    unsigned char mask_t[CY_CRYPTO_ALIGN_CACHE_LINE(PSA_HASH_MAX_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    unsigned char *mask = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)mask_t);
    unsigned char *counter = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)counter_t);
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_SUCCESS;
    size_t out_len;

    hlen = PSA_HASH_LENGTH(alg);

    Cy_Crypto_Core_MemSet(CRYPTO, (void *)mask, 0, PSA_HASH_MAX_SIZE);
    Cy_Crypto_Core_MemSet(CRYPTO, (void *)counter, 0, 4u);

    /* Generate and apply dbMask */
    p = dst;

    while (dlen > 0)
    {
        use_len = hlen;

        if (dlen < hlen)
        {
            use_len = dlen;
        }

        if ((status = psa_hash_setup(&op, alg)) != PSA_SUCCESS)
        {
            break;
        }

        if ((status = psa_hash_update(&op, src, slen)) != PSA_SUCCESS)
        {
            break;
        }

        if ((status = psa_hash_update(&op, counter, 4)) != PSA_SUCCESS)
        {
            break;
        }

        if((status = psa_hash_finish(&op, mask, PSA_HASH_MAX_SIZE, &out_len)) != PSA_SUCCESS)
        {
            break;
        }

        for (i = 0; i < use_len; ++i)
        {
            *p++ ^= mask[i];
        }

        counter[3]++;

        dlen -= use_len;
    }

    psa_hash_abort(&op);

    return status;
}
#endif


#if defined(IFX_PSA_MXCRYPTO_RSA_OEAP) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)
psa_status_t ifx_mxcrypto_rsa_oaep_encrypt(cy_stc_crypto_rsa_pub_key_t *rsa_pub_key, psa_algorithm_t alg,
                                   const unsigned char *label, size_t label_len,
                                   size_t ilen,
                                   const unsigned char *input,
                                   unsigned char *output)
{
    size_t olen;
    unsigned char *p = output;
    unsigned int hlen;
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t out_len;

    hlen = PSA_HASH_LENGTH(PSA_ALG_RSA_OAEP_GET_HASH(alg));  
    if (hlen == 0)
    {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    olen = PSA_BITS_TO_BYTES(rsa_pub_key->moduloLength) ;

    /* first comparison checks for overflow */
    if (ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    Cy_Crypto_Core_MemSet(CRYPTO, (void *)output, 0, olen);

    *p++ = 0;

    /* Generate a random octet string seed */
    if ((psa_status= psa_generate_random(p, hlen)) != PSA_SUCCESS)
    {
        return psa_status;
    }

    p += hlen;

    /* Construct DB */
    psa_status = psa_hash_compute(PSA_ALG_RSA_OAEP_GET_HASH(alg), label, label_len, p, hlen, &out_len);

    if( PSA_SUCCESS != psa_status)
    {
        return psa_status;
    }

    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;

    if (ilen != 0)
    {
        ifx_mxcrypto_memcpy( p, input, ilen);
    }

    /* maskedDB: Apply dbMask to DB */
    if ((psa_status = mgf_mask(output + hlen + 1, olen - hlen - 1, output + 1, hlen,
                        PSA_ALG_RSA_OAEP_GET_HASH(alg))) != PSA_SUCCESS)
    {
        return psa_status;
    }

    /* maskedSeed: Apply seedMask to seed */
    if ((psa_status = mgf_mask(output + 1, hlen, output + hlen + 1, olen - hlen - 1,
                        PSA_ALG_RSA_OAEP_GET_HASH(alg))) != PSA_SUCCESS)
    {
        return psa_status;
    }

    return ifx_mxcrypto_rsa_encrypt_decrypt(rsa_pub_key, output, output);
}
#endif /*(IFX_PSA_MXCRYPTO_RSA_OEAP) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)*/



#if defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)
psa_status_t ifx_mxcrypto_rsa_pkcs1_v15_encrypt(cy_stc_crypto_rsa_pub_key_t *rsa_pub_key, psa_algorithm_t alg,
                                        size_t ilen,
                                        const unsigned char *input,
                                        unsigned char *output)
{
    (void)alg;
    size_t nb_pad, olen;
    unsigned char *p = output;
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    olen = PSA_BITS_TO_BYTES(rsa_pub_key->moduloLength) ;

    /* first comparison checks for overflow */
    if (ilen + 11 < ilen || olen < ilen + 11)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    nb_pad = olen - 3 - ilen;

    *p++ = 0;

    *p++ = IFX_RSA_CRYPT;

     while (nb_pad-- > 0)
     {
        int rng_dl = 100;
        do
        {
            psa_status= psa_generate_random(p, 1);
        } while (*p == 0 && --rng_dl && psa_status == PSA_SUCCESS);
        /* Check if RNG failed to generate data */
        if (rng_dl == 0 || psa_status != PSA_SUCCESS)
        {
            return psa_status;
        }
        p++;
    }
    *p++ = 0;

    if (ilen != 0)
    {
        ifx_mxcrypto_memcpy(p, input, ilen);
    }
    

    return ifx_mxcrypto_rsa_encrypt_decrypt(rsa_pub_key, output, output);
}
#endif  /*(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)*/



#if (defined (IFX_PSA_MXCRYPTO_RSA_OEAP) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT))
psa_status_t ifx_mxcrypto_rsa_oaep_decrypt(cy_stc_crypto_rsa_pub_key_t *rsa_priv_key, psa_algorithm_t alg,
                                   const unsigned char *label, size_t label_len,
                                   size_t *olen,
                                   const unsigned char *input,
                                   unsigned char *output,
                                   size_t output_max_len)
{
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    unsigned char lhash[PSA_HASH_MAX_SIZE];
    unsigned int hlen;
    size_t out_len;

    ilen = PSA_BITS_TO_BYTES(rsa_priv_key->moduloLength) ;

    if (ilen < 16 || ilen > sizeof(buf)) {
        return psa_status;
    }

    hlen = PSA_HASH_LENGTH(PSA_ALG_RSA_OAEP_GET_HASH(alg));  
    if (hlen == 0) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    // checking for integer underflow
    if (2 * hlen + 2 > ilen) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    /*
     * RSA operation
     */
    
    psa_status =  ifx_mxcrypto_rsa_encrypt_decrypt(rsa_priv_key, input, buf);

    if (psa_status != PSA_SUCCESS) 
    {
        return psa_status;
    }

    /*
     * Unmask data and generate lHash
     */
    /* seed: Apply seedMask to maskedSeed */
    if ((psa_status = mgf_mask(buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
                        PSA_ALG_RSA_OAEP_GET_HASH(alg))) != PSA_SUCCESS ||
        /* DB: Apply dbMask to maskedDB */
        (psa_status = mgf_mask(buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
                        PSA_ALG_RSA_OAEP_GET_HASH(alg))) != PSA_SUCCESS) {
        return psa_status;
    }

    /* Generate lHash */

    psa_status = psa_hash_compute(PSA_ALG_RSA_OAEP_GET_HASH(alg), label, label_len, lhash, hlen, &out_len);

    if (psa_status != PSA_SUCCESS) {
        return psa_status;
    }

    /*
     * Check contents, in "constant-time"
     */
    p = buf;
    bad = 0;

    bad |= *p++; /* First byte must be 0 */

    p += hlen; /* Skip seed */

    /* Check lHash */
    for (i = 0; i < hlen; i++) {
        bad |= lhash[i] ^ *p++;
    }

    /* Get zero-padding len, but always read till end of buffer
     * (minus one, for the 01 byte) */
    pad_len = 0;
    pad_done = 0;
    for (i = 0; i < ilen - 2 * hlen - 2; i++) {
        pad_done |= p[i];
        pad_len += ((pad_done | (unsigned char) -pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
    if (bad != 0) {
        return PSA_ERROR_INVALID_PADDING;
    }

    if (ilen - (p - buf) > output_max_len) {
        return PSA_ERROR_INVALID_PADDING;
    }

    *olen = ilen - (p - buf);
    if (*olen != 0) {
        Cy_Crypto_Core_MemCpy(CRYPTO, output, p, *olen);

    }
    psa_status = 0;

    return psa_status;
}
#endif /*(defined (IFX_PSA_MXCRYPTO_RSA_OEAP) && defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT))*/

static unsigned ifx_ct_size_gt(size_t x,
                                   size_t y)
{
    /* Return the sign bit (1 for negative) of (y - x). */
    return (y - x) >> (sizeof(size_t) * 8 - 1);
}

unsigned ifx_ct_uint_mask(unsigned value)
{
    return -((value | -value) >> (sizeof(value) * 8 - 1));
}

unsigned ifx_ct_uint_if(unsigned condition,
                            unsigned if1,
                            unsigned if0)
{
    unsigned mask = ifx_ct_uint_mask(condition);
    return (mask & if1) | (~mask & if0);
}

static void mbedtls_ct_mem_move_to_left(void *start,
                                        size_t total,
                                        size_t offset)
{
    volatile unsigned char *buf = start;
    size_t i, n;
    if (total == 0) {
        return;
    }
    for (i = 0; i < total; i++) {
        unsigned no_op = ifx_ct_size_gt(total - offset, i);
        /* The first `total - offset` passes are a no-op. The last
         * `offset` passes shift the data one byte to the left and
         * zero out the last byte. */
        for (n = 0; n < total - 1; n++) {
            unsigned char current = buf[n];
            unsigned char next = buf[n+1];
            buf[n] = ifx_ct_uint_if(no_op, current, next);
        }
        buf[total-1] = ifx_ct_uint_if(no_op, buf[total-1], 0);
    }
}

#if defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT) && defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT)
psa_status_t ifx_mxcrypto_rsa_pkcs1_v15_unpadding(unsigned char *input,
                                         size_t ilen,
                                         unsigned char *output,
                                         size_t output_max_len,
                                         size_t *olen)
{
    int ret = 0;
    size_t i, plaintext_max_size;

    /* The following variables take sensitive values: their value must
     * not leak into the observable behavior of the function other than
     * the designated outputs (output, olen, return value). Otherwise
     * this would open the execution of the function to
     * side-channel-based variants of the Bleichenbacher padding oracle
     * attack. Potential side channels include overall timing, memory
     * access patterns (especially visible to an adversary who has access
     * to a shared memory cache), and branches (especially visible to
     * an adversary who has access to a shared code cache or to a shared
     * branch predictor). */
    size_t pad_count = 0;
    unsigned bad = 0;
    unsigned char pad_done = 0;
    size_t plaintext_size = 0;
    unsigned output_too_large;

    plaintext_max_size = (output_max_len > ilen - 11) ? ilen - 11
                                                        : output_max_len;

    /* Check and get padding length in constant time and constant
     * memory trace. The first byte must be 0. */
    bad |= input[0];


    /* Decode EME-PKCS1-v1_5 padding: 0x00 || 0x02 || PS || 0x00
     * where PS must be at least 8 nonzero bytes. */
    bad |= input[1] ^ IFX_RSA_CRYPT;

    /* Read the whole buffer. Set pad_done to nonzero if we find
     * the 0x00 byte and remember the padding length in pad_count. */
    for (i = 2; i < ilen; i++) {
        pad_done  |= ((input[i] | (unsigned char) -input[i]) >> 7) ^ 1;
        pad_count += ((pad_done | (unsigned char) -pad_done) >> 7) ^ 1;
    }


    /* If pad_done is still zero, there's no data, only unfinished padding. */
    bad |= ifx_ct_uint_if(pad_done, 0, 1);

    /* There must be at least 8 bytes of padding. */
    bad |= ifx_ct_size_gt(8, pad_count);

    /* If the padding is valid, set plaintext_size to the number of
     * remaining bytes after stripping the padding. If the padding
     * is invalid, avoid leaking this fact through the size of the
     * output: use the maximum message size that fits in the output
     * buffer. Do it without branches to avoid leaking the padding
     * validity through timing. RSA keys are small enough that all the
     * size_t values involved fit in unsigned int. */
    plaintext_size = ifx_ct_uint_if(
        bad, (unsigned) plaintext_max_size,
        (unsigned) (ilen - pad_count - 3));

    /* Set output_too_large to 0 if the plaintext fits in the output
     * buffer and to 1 otherwise. */
    output_too_large = ifx_ct_size_gt(plaintext_size,
                                          plaintext_max_size);

    /* Set ret without branches to avoid timing attacks. Return:
     * - INVALID_PADDING if the padding is bad (bad != 0).
     * - OUTPUT_TOO_LARGE if the padding is good but the decrypted
     *   plaintext does not fit in the output buffer.
     * - 0 if the padding is correct. */
    ret = ifx_ct_uint_if(
        bad, (unsigned)PSA_ERROR_INVALID_PADDING,
        ifx_ct_uint_if(output_too_large,
                (unsigned)PSA_ERROR_BUFFER_TOO_SMALL,
                           0));

    /* If the padding is bad or the plaintext is too large, zero the
     * data that we're about to copy to the output buffer.
     * We need to copy the same amount of data
     * from the same buffer whether the padding is good or not to
     * avoid leaking the padding validity through overall timing or
     * through memory or cache access patterns. */
    bad = ifx_ct_uint_mask(bad | output_too_large);
    for (i = 11; i < ilen; i++) {
        input[i] &= ~bad;
    }

    /* If the plaintext is too large, truncate it to the buffer size.
     * Copy anyway to avoid revealing the length through timing, because
     * revealing the length is as bad as revealing the padding validity
     * for a Bleichenbacher attack. */
    plaintext_size = ifx_ct_uint_if(output_too_large,
                                        (unsigned) plaintext_max_size,
                                        (unsigned) plaintext_size);

    /* Move the plaintext to the leftmost position where it can start in
     * the working buffer, i.e. make it start plaintext_max_size from
     * the end of the buffer. Do this with a memory access trace that
     * does not depend on the plaintext size. After this move, the
     * starting location of the plaintext is no longer sensitive
     * information. */
    mbedtls_ct_mem_move_to_left(input + ilen - plaintext_max_size,
                                plaintext_max_size,
                                plaintext_max_size - plaintext_size);

    /* Finally copy the decrypted plaintext plus trailing zeros into the output
     * buffer. If output_max_len is 0, then output may be an invalid pointer
     * and the result of memcpy() would be undefined; prevent undefined
     * behavior making sure to depend only on output_max_len (the size of the
     * user-provided output buffer), which is independent from plaintext
     * length, validity of padding, success of the decryption, and other
     * secrets. */
    if (output_max_len != 0) {
        ifx_mxcrypto_memcpy(output, input + ilen - plaintext_max_size, plaintext_max_size);
    }

    /* Report the amount of data we copied to the output buffer. In case
     * of errors (bad padding or output too large), the value of *olen
     * when this function returns is not specified. Making it equivalent
     * to the good case limits the risks of leaking the padding validity. */
    *olen = plaintext_size;

    return ret;
}

psa_status_t ifx_mxcrypto_rsa_pkcs1_v15_decrypt(cy_stc_crypto_rsa_pub_key_t *rsa_priv_key,
                                        size_t *olen,
                                        const unsigned char *input,
                                        unsigned char *output,
                                        size_t output_max_len)
{
    size_t ilen;
    unsigned char buf_t[CY_CRYPTO_ALIGN_CACHE_LINE(MBEDTLS_MPI_MAX_SIZE) + CY_CRYPTO_DCAHCE_PADDING_SIZE];
    unsigned char *buf = (unsigned char *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)buf_t);
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;

    ilen = PSA_BITS_TO_BYTES(rsa_priv_key->moduloLength) ;

    if (ilen < 16 || ilen > MBEDTLS_MPI_MAX_SIZE)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status =  ifx_mxcrypto_rsa_encrypt_decrypt(rsa_priv_key, input, buf);

    if (psa_status != PSA_SUCCESS)
    {
        return psa_status;
    }

    return  ifx_mxcrypto_rsa_pkcs1_v15_unpadding(buf, ilen,output, output_max_len, olen);
}

#endif /* defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT) && defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT)*/


#if defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_asymmetric_encrypt
****************************************************************************//**
*
* Function to encrypt RSA message.
*
* \param key_buffer
* The pointer to rsa public key.
*
* \param key_buffer_size
* The rsa private key size.
*
*\param alg
* The algorithm for the encrypting the message
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The input message size.
*
* \param salt
* The pointer to the salt.
*
* \param salt_length
* The salt size.
*
* \param output
* The pointer to the output message.
* 
* \param output_size
* The size of the output buffer size.
*
* \param output_length
* The pointer to output buffer stored size.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_asymmetric_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{

    cy_stc_crypto_rsa_pub_key_t rsa_pub_key;
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type;
    unsigned char *p;

    key_type = psa_get_key_type(attributes);

    if(!PSA_KEY_TYPE_IS_RSA(key_type))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    p = (unsigned char *)key_buffer;

    ifx_mxcrypto_memset((void *)&rsa_pub_key, 0, sizeof(rsa_pub_key));

    psa_status =  ifx_mxcrypto_get_rsa_public_key(key_type, &p,  p + key_buffer_size, &rsa_pub_key);
    
    if (psa_status != PSA_SUCCESS)
    {
        return psa_status;
    }

    if (output_size <  PSA_BITS_TO_BYTES(rsa_pub_key.moduloLength)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if((Cy_Crypto_Core_GetVuMemorySize(CRYPTO) <= 4096u) && (rsa_pub_key.moduloLength > 2048u))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_input = NULL;
    uint8_t *aligned_input = (uint8_t *)input;
    uint8_t *ptr_output = NULL;
    uint8_t *aligned_output = (uint8_t *)output;
    uint32_t modulo_len = PSA_BITS_TO_BYTES(rsa_pub_key.moduloLength);
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
    {
        ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == ptr_input)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
        ifx_mxcrypto_memcpy((void *)aligned_input, (void *)input, input_length);
    }
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, modulo_len) )
    {
        ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(modulo_len) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == ptr_output)
        {
            psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
            goto cleanup;
        }
        aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
    }
#endif
    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT)
    {
        #if defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        psa_status = ifx_mxcrypto_rsa_pkcs1_v15_encrypt(&rsa_pub_key, alg, input_length, aligned_input, aligned_output);
#else
        psa_status = ifx_mxcrypto_rsa_pkcs1_v15_encrypt(&rsa_pub_key, alg, input_length, input, output);
        #endif
#endif
    }
    else if(PSA_ALG_IS_RSA_OAEP(alg) )
    {
        #if defined(IFX_PSA_MXCRYPTO_RSA_OEAP)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        psa_status = ifx_mxcrypto_rsa_oaep_encrypt(&rsa_pub_key, alg, salt, salt_length, input_length, aligned_input, aligned_output);
#else
        psa_status = ifx_mxcrypto_rsa_oaep_encrypt(&rsa_pub_key, alg, salt, salt_length, input_length, input, output);
#endif
        #endif
    }
    else 
    {
        psa_status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (psa_status == PSA_SUCCESS)
    {
        *output_length = PSA_BITS_TO_BYTES(rsa_pub_key.moduloLength) ;
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        ifx_mxcrypto_memcpy( (void *)output,(void *)aligned_output, *output_length);
#endif
    }
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
cleanup:
    if (NULL != ptr_input)
    {
        ifx_mxcrypto_free(ptr_input);
    }
    if (NULL != ptr_output)
    {
        ifx_mxcrypto_free(ptr_output);
    }
#endif

    return psa_status;
        
}   
#endif /*defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT)*/

#if defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT)
/*******************************************************************************
* Function Name: ifx_mxcrypto_transparent_asymmetric_decrypt
****************************************************************************//**
*
* Function to decrypt RSA encrypted message.
*
* \param key_buffer
* The pointer to rsa private key.
*
* \param key_buffer_size
* The rsa private key size.
*
*\param alg
* The algorithm for the decrypting the message
*
* \param input
* The pointer to the input message.
*
* \param input_length
* The input message size.
*
* \param salt
* The pointer to the salt.
*
* \param salt_length
* The salt size.
*
* \param output
* The pointer to the output message.
* 
* \param output_size
* The size of the output buffer size.
*
* \param output_length
* The pointer to output buffer stored size.
*
* \return psa_status_t.
*
*******************************************************************************/
psa_status_t ifx_mxcrypto_transparent_asymmetric_decrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *input,
                                            size_t input_length,
                                            const uint8_t *salt,
                                            size_t salt_length,
                                            uint8_t *output,
                                            size_t output_size,
                                            size_t *output_length)
{
    cy_stc_crypto_rsa_pub_key_t rsa_priv_key;
    psa_status_t psa_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type;
    unsigned char *p;

    key_type = psa_get_key_type(attributes);

    if(!PSA_KEY_TYPE_IS_RSA(key_type))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *output_length = 0;

    p = (unsigned char *)key_buffer;
    ifx_mxcrypto_memset((void *)&rsa_priv_key, 0, sizeof(rsa_priv_key));

    psa_status =  ifx_mxcrypto_get_rsa_private_key(&p,  p + key_buffer_size, &rsa_priv_key);

    if (input_length  !=  PSA_BITS_TO_BYTES(rsa_priv_key.moduloLength)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if((Cy_Crypto_Core_GetVuMemorySize(CRYPTO) <= 4096u) && (rsa_priv_key.moduloLength > 2048u))
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    uint8_t *ptr_input = NULL;
    uint8_t *aligned_input = (uint8_t *)input;
    uint8_t *ptr_output = NULL;
    uint8_t *aligned_output = (uint8_t *)output;
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)input, input_length) )
    {
        ptr_input = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(input_length) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == ptr_input)
        {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        aligned_input = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_input);
        ifx_mxcrypto_memcpy((void *)aligned_input, (void *)input, input_length);
    }
    if( !CY_PSA_IS_MEM_CACHABLE_ALIGNED((uint32_t)output, output_size) )
    {
        ptr_output = (uint8_t*)ifx_mxcrypto_malloc(CY_CRYPTO_ALIGN_CACHE_LINE(output_size) + CY_CRYPTO_DCAHCE_PADDING_SIZE);
        if (NULL == ptr_output)
        {
            psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
            goto cleanup;
        }
        aligned_output = (uint8_t *)CY_CRYPTO_DCACHE_ALIGN_ADDRESS((size_t)ptr_output);
    }
#endif
    if (alg == PSA_ALG_RSA_PKCS1V15_CRYPT)
    {
        #if defined(IFX_PSA_MXCRYPTO_RSA_PKCS1V15_CRYPT)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        psa_status = ifx_mxcrypto_rsa_pkcs1_v15_decrypt(&rsa_priv_key, output_length, aligned_input, aligned_output, output_size);
#else
        psa_status = ifx_mxcrypto_rsa_pkcs1_v15_decrypt(&rsa_priv_key, output_length, input, output, output_size);
        #endif
#endif
    }
    else if(PSA_ALG_IS_RSA_OAEP(alg) )
    {
        #if defined(IFX_PSA_MXCRYPTO_RSA_OEAP)
#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
        psa_status = ifx_mxcrypto_rsa_oaep_decrypt(&rsa_priv_key, alg, salt, salt_length, output_length, aligned_input, aligned_output, output_size);
#else
        psa_status = ifx_mxcrypto_rsa_oaep_decrypt(&rsa_priv_key, alg, salt, salt_length, output_length, input, output, output_size);
        #endif
#endif
    }
    else 
    {
        psa_status = PSA_ERROR_INVALID_ARGUMENT;
    }

#if (((CY_CPU_CORTEX_M7) && defined (ENABLE_CM7_DATA_CACHE)) || CY_CPU_CORTEX_M55)
    if (psa_status == PSA_SUCCESS)
    {
        ifx_mxcrypto_memcpy( (void *)output,(void *)aligned_output, *output_length);
    }
cleanup:
    if (NULL != ptr_input)
    {
        ifx_mxcrypto_free(ptr_input);
    }
    if (NULL != ptr_output)
    {
        ifx_mxcrypto_free(ptr_output);
    }
#endif
    return psa_status;
}
#endif /*defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT)*/


#endif  /* (CY_IP_MXCRYPTO) */
#endif /*#if (defined(IFX_PSA_MXCRYPTO_RSA_ENCRYPT) || defined(IFX_PSA_MXCRYPTO_RSA_DECRYPT))*/
