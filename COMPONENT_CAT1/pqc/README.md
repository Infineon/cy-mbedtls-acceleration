Post Quantum Cryptographic (PQC) algorithms
--------------------------------------------
Supported Signature algorithms:
- LMS Verify Only
- XMSS(eXtended Merkle Signature Scheme) Verify Only

LMS signature Verify
---------------------
Supports Only LMS-SHA256-M32-H10 Only, This is one of the signature schemes
recommended by the IETF draft SUIT standard for IOT firmware upgrades (RFC9019)

Device supported : PSC3
Compilers tested : GCC-ARM, ARMCC, IAR
Benchmark per verify - 255ms (CM33 and Cryptolite @ 180Mhz, code in flash mem)

Mbedtls :  lms + mbedtls - 5772 bytes
PSA : ifx-sha-cryptolite - 316
PDL : sha-cryptolite- 996 bytes
Total Code Size - 7084 Bytes.

Note:
mbedTLS Library public release supports LMS algorithm, and APIs are defined in lms.h 
https://github.com/Mbed-TLS/mbedtls/blob/v3.6.5/include/mbedtls/lms.h 

User needs to enable IFX-PSA-SHA HW acceleration (define MBEDTLS_PSA_BUILTIN_ALG_SHA_256)
to be enabled HW accelerated hash for use in LMS.


XMSS Signatuere Verify
----------------------
Supports XMSS-SHA2_10_256 verify Only, based on https://github.com/XMSS/xmss-reference

Device Supported : PSC3
Compilers tested : GCCARM, ARMCC, IAR
(Note: For IAR build compiler option --vla must be used)
Benchmark per verify - 29ms (CM33 and Cryptolite @ 180Mhz, code in flash mem)

xmss- 3272 bytes
cryptolite PDL SHA- 1078 bytes
Total code size - 4350 Bytes

Note: The Stack size of 8KB is required.

References:
-----------
- RFC 8554: LMS (Leighton - Micali Hash based signatures)
- RFC 8391 - XMSS: eXtended Merkle Signature Scheme
- NIST SP 800-208 - State management for Hash-Based Signatures
- https://github.com/XMSS/xmss-reference

