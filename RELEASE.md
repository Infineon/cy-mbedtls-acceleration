# mbedTLS Crypto acceleration for CAT1A, CAT1B & CAT1C MCUs v2.5.0

### What's Included?
Please refer to the [README.md](./README.md) for a complete description of the CAT1A, CAT1B & CAT1C acceleration for mbedTLS library.

New in this release:

* Added mbedTLS PSA HW accelerated driver support for CAT1B MCUs.

### Limitations
Currently Cypress CAT1A & CAT1C acceleration doesn't support:

- RSA
- ECP NIST-B curves
- ECP NIST-K curves
- ECP 25519 curve
- CHACHA20
- SHA3
- POLY1305

Currently Cypress CAT1B acceleration supports only

- SHA256
- ECC curves, ECDSA (Sign, Verify of curves P192R1, P224R1 & P521R1), ECDH

Currently Cypress CAT1B PSA acceleration supports only

- AES-128 ECB and CBC (Encrypt), CFB and CTR (Encrypt, Decrypt), AES-CCM (AEAD)
- RSA (Encrypt, Decrypt, Verify)
- Elliptic Curve Cryptography (ECC) Key generation (Sign, Verify Hash)
- SHA-256, HMAC-SHA256, HKDF, TRNG 


### Supported Software and Tools
This version of the CAT1A, CAT1B & CAT1C acceleration for mbedTLS library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version   |
| :---                                                    | :-------: |
| ModusToolbox Software Environment                       | 3.2       |
| mtb-pdl-cat1  Peripheral Driver Library (PDL)           | PSOC Control C3 |
| GCC Compiler                                            | 11.3.1    |
| IAR Compiler                                            | 9.40.2    |
| ARM Compiler 6                                          | 6.16      |

### Dependencies to mbedTLS versions
| cy-mbedtls-acceleration version | mbedTLS version | ifx-mbedTLS version for PSA |
| :------------------------------: | :--------------: | :-------------------------: |
| 2.2, 2.3, 2.5                   | 3.4.0            | 3.5.0                       |
| 2.0, 2.1                        | 3.0.0            |                             |



### Change log

| Version |	Changes                                             | Reason for Change |
| :----:  |	:---                                                | :----             |
| 2.5.0   |	Added mbedTLS PSA HW accelerated driver support for CAT1B MCUs.|	 PSA driver added  |
| 2.4.0   |	Added EDDSA Hardware  acceleration for CAT1A and CAT1C MCUs.|	 New alt driver added  |
| 2.3.0   |	Added AES & ECDSA Verify acceleration for CAT1B MCU. Added Hardware Entropy acceleration for CAT1A, CAT1B & CAT1C MCUs.|	 New alt driver added  |
| 2.2.0   |	Added Crypto HAL resource allocation check|	 Avoid extra resource allocation |
| 2.1.1   |	Fixed sha1 finish api signature|	 Compilation warning  |
| 2.1   |	Added AES-GCM acceleration for CAT1A and CAT1C MCUs | New alt driver added |
| 2.0   |	Initial version adding support for MbedTLS 3.0      | MbedTLS 3.0 support |


---
© Cypress Semiconductor Corporation, 2019-2024.
