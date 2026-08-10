# mbedTLS Crypto acceleration for PSoC, PSC, PSE & XMC MCUs v3.1.0

### What's Included?
Please refer to the [README.md](./README.md) for a complete description of the PSoC, PSC , PSE & XMC acceleration for mbedTLS library.

New in this release:

* Added PSA drivers for CryptoSuite.
* Added support for XMSS Sigverify

### Limitations
Currently Cypress PSoC, PSE & XMC acceleration doesn't support:

- RSA
- ECP NIST-B curves
- ECP NIST-K curves
- CHACHA20
- SHA3
- POLY1305

Currently Infineon PSC acceleration supports only

- SHA 256,384,512
- ECC curves, ECDSA (Sign, Verify of curves P192R1, P224R1, P256R1, P384R1 & P512R1(Verify only))
- Ed25519 DSA (Sign, Verify) 
- AES-128 ECB and CBC (Encrypt), OFB, CFB and CTR (Encrypt, Decrypt)
- TRNG via mbedtls_hardware_poll
- XMSS-SHA2-10-256 SigVerify

Currently Infineon PSC PSA acceleration supports only

- AES-128 ECB and CBC (Encrypt), CFB and CTR (Encrypt, Decrypt), AES-CCM (AEAD)
- RSA (Encrypt, Decrypt, Verify)
- Elliptic Curve Cryptography (ECC) Key generation (Sign, Verify Hash)
- SHA-256, HMAC-SHA256, HKDF, TRNG
- AES-ECB, CBC, CTR, CMAC, CCM for Cryptosuite


### Supported Software and Tools
This version of the PSoC, PSC , PSE & XMC acceleration for mbedTLS library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version   |
| :---                                                    | :-------: |
| ModusToolbox Software Environment                       | 3.8       |
| Device Support Library (DSL)                            | 1.6.0     |
| GCC Compiler                                            | 14.2.1    |
| IAR Compiler                                            | 9.70.2    |
| ARM Compiler                                            | 6.22      |

### Dependencies to mbedTLS versions
| cy-mbedtls-acceleration version | mbedTLS version | ifx-mbedTLS version for PSA |
| :------------------------------: | :--------------: | :-------------------------: |
| 2.2, 2.3, 2.5 ,2.7, 3.0, 3.1         | 3.5.0            | 3.6.105                     |
| 2.0, 2.1                        | 3.0.0            |                             |



### Change log

| Version |	Changes                                             | Reason for Change |
| :----:  |	:---                                                | :----             |
| 3.2.0   |	Updated support for Cryptosuite 6.1.2 release. | Cryptosuite Library upgrade.  |
| 3.1.0   |	Added support for PSA Cryptosuite, XMSS drivers on PSCC3 Control MCU family.| Cryptosuite and PQC Support.  |
| 3.0.0   |	Added support for PSA Crypto drivers on PSOC-Edge MCU family.| Major version update.  |
| 2.7.0   |	Added support for EDDSA Sign,Verify, Keygen, Removed align pragma use for XMC DCache management in ALT drivers  |
| 2.6.0   |	Added support for ECP 25519 curve, DCache coherency management done (GCC_ARM).| New alt driver and Dcahce coherency bug fixes  |
| 2.5.0   |	Added mbedTLS PSA HW accelerated driver support for PSC MCUs.|	 PSA driver added  |
| 2.4.0   |	Added EDDSA Hardware  acceleration for PSoC and XMC MCUs.|	 New alt driver added  |
| 2.3.0   |	Added AES & ECDSA Verify acceleration for PSC MCU. Added Hardware Entropy acceleration for PSoC, PSC & XMC MCUs.|	 New alt driver added  |
| 2.2.0   |	Added Crypto HAL resource allocation check|	 Avoid extra resource allocation |
| 2.1.1   |	Fixed sha1 finish api signature|	 Compilation warning  |
| 2.1   |	Added AES-GCM acceleration for PSoC and XMC MCUs | New alt driver added |
| 2.0   |	Initial version adding support for MbedTLS 3.0      | MbedTLS 3.0 support |


---
© Cypress Semiconductor Corporation, 2019-2025.
