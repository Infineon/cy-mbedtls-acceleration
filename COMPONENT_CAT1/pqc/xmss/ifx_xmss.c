
#include "params.h"
#include "ifx_xmss.h"
#include "xmss.h"

/**
 * 
 * \brief                    This function Verifies a given message & signature pair
 *                           using a given public key.
 *
 * \param message            User Output buffer of size (sig size + message size) which will contain the message if verification succeeds.
 * \param messagelen         The size of the message if verification succeeds.
 * \param signed_message     The signature to be verified. This should contain (signature + message)
 * \param signed_message_len The total size of the signature (signature+message) to be verified.
 * \param public_key         The public key to be used for verification.
 * 
 * \return         0x05555555 on successful verification.
 * \return         0x0AAAAAAA on verification failure.
 * \return         0x03333333 if signature variant is not supported.
 *
 * Note: 'message' and 'messagelen' are pure outputs which carry the message in case
 * verification succeeds. The input message is assumed to be contained in 'signed_message'
 * which has the form [signature + message] and 'signed_message_len' should indicate total size
 */

int32_t ifx_xmss_verify(uint8_t *message, uint64_t *messagelen,
                   const uint8_t  *signed_message, uint64_t signed_message_len,
                   const uint8_t  *public_key)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= public_key[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    if (xmss_parse_oid(&params, oid)) {
        return IFX_XMSS_SIG_NOTSUPPORTED;
    }

    if(params.func == XMSS_SHAKE256 || params.func == XMSS_SHAKE128)
    {
        return IFX_XMSS_SIG_NOTSUPPORTED;
    }

    return xmss_sign_open(message, messagelen,
                         signed_message, signed_message_len,
                         public_key);

}

