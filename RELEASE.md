# mbedTLS Crypto acceleration for PSOC-Edge MCU Family v3.0.0

### What's Included?
Please refer to the [README.md](./README.md) for a complete description of the acceleration support for mbedTLS library.

New in this release:

* Added PSA Crypto acceleration support for PSOC-EDGE Family

### Limitations
Currently PSOC-EDGE MCU acceleration doesn't support:

- ECP NIST-B curves
- ECP NIST-K curves
- CHACHA20
- POLY1305

Supports

mbedtls ALT supports only

- SHA1,256,512
- ECC curves, ECDSA, ECDH (Sign, Verify of curves P192R1, P224R1, P256R1 & P384R1)
- AES-128/256 ECB, CBC, XTS, GCM and CTR.
- TRNG via mbedtls_hardware_poll

PSA acceleration supports only

- AES (ECB, CBC, CFB, CTR) AEAD (GCM, CCM)
- RSA (Encrypt, Decrypt, Sign/Verify)
- Elliptic Curve Cryptography (ECC) Key generation,Sign and Verify, ECDH Key agreement
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- CMAC-AES, HMAC-SHA, HKDF, TRNG


### Supported Software and Tools
This version of the acceleration for mbedTLS library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version   |
| :---                                                    | :-------: |
| ModusToolbox Software Environment                       | 3.6       |
| Device Support Library (DSL)                            | 1.0.0     |
| GCC Compiler                                            | 14.2.1    |
| IAR Compiler                                            | 9.50.2    |
| ARM Compiler 6                                          | 6.22      |
| LLVM-ARM Compiler                                       | 19.1.5    |

### Dependencies to mbedTLS versions
| cy-mbedtls-acceleration version | mbedTLS version | ifx-mbedTLS version for PSA |
| :------------------------------: | :--------------: | :-------------------------: |
| 2.2, 2.3, 2.5                   | 3.6.2            | 3.6.2                       |
| 2.0, 2.1                        | 3.0.0            |                             |



### Change log

| Version |	Changes                                             | Reason for Change |
| :----:  |	:---                                                | :----             |
| 3.0.0   |	Added support for PSA Crypto drivers on PSOC-Edge MCU family.| Major version update. |
| 2.7.0   |	Added support for EDDSA Sign,Verify, Keygen, Removed align pragma use for XMC DCache management in ALT drivers  |
| 2.6.0   |	Added support for ECP 25519 curve, DCache coherency management done (GCC_ARM).| New alt driver and Dcahce coherency bug fixes  |
| 2.5.0   |	Added mbedTLS PSA HW accelerated driver support for AIROC MCUs.|	 PSA driver added  |
| 2.4.0   |	Added EDDSA Hardware  acceleration for PSOC and XMC MCUs.|	 New alt driver added  |
| 2.3.0   |	Added AES & ECDSA Verify acceleration for AIROC and PSOC-CONTROL MCU. Added Hardware Entropy acceleration for PSOC, XMC & AIROC MCUs.|	 New alt driver added  |
| 2.2.0   |	Added Crypto HAL resource allocation check|	 Avoid extra resource allocation |
| 2.1.1   |	Fixed sha1 finish api signature|	 Compilation warning  |
| 2.1   |	Added AES-GCM acceleration for PSOC and XMC MCUs | New alt driver added |
| 2.0   |	Initial version adding support for MbedTLS 3.0      | MbedTLS 3.0 support |


---
© Cypress Semiconductor Corporation, 2019-2025.
