#ifndef IFX_XMSS_H
#define IFX_XMSS_H

#include <stdint.h>

#define IFX_XMSS_SIG_VALID          (0x05555555)
#define IFX_XMSS_SIG_INVALID        (0x0AAAAAAA)
#define IFX_XMSS_SIG_NOTSUPPORTED   (0x03333333)

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: 'message' and 'messagelen' are pure outputs which carry the message in case
 * verification succeeds. The input message is assumed to be contained in 'signed_message'
 * which has the form [signature + message] and 'signed_message_len' should indicate total size
 */
 int32_t ifx_xmss_verify(uint8_t *message, uint64_t *messagelen,
                         const uint8_t  *signed_message, uint64_t signed_message_len,
                         const uint8_t  *public_key);

#endif
