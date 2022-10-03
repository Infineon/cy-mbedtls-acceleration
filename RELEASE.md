# mbedTLS Crypto acceleration for CAT1A, CAT1B & CAT1C MCUs

### What's Included?
Please refer to the [README.md](./README.md) for a complete description of the CAT1A, CAT1B & CAT1C acceleration for mbedTLS library.
New in this release:

* Added support for MbedTLS 3.0

### Limitations
Currently Cypress CAT1A & CAT1C acceleration doesn't support:

- RSA
- ECP NIST-B curves
- ECP NIST-K curves
- ECP 25519 curve
- CHACHA20
- SHA3
- AES GCM
- POLY1305

Currently Cypress CAT1B acceleration supports only

-SHA256


### Supported Software and Tools
This version of the CAT1A, CAT1B & CAT1C acceleration for mbedTLS library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version   |
| :---                                                    | :-------: |
| ModusToolbox Software Environment                       | 3.0       |
| mtb-pdl-cat1  Peripheral Driver Library (PDL)           | 3.0       |
| mtb-hal-cat1 Hardware Abstraction Layer(HAL)            | 2.2       |
| GCC Compiler                                            | 10.2.1.72 |
| IAR Compiler                                            | 8.4       |
| ARM Compiler 6                                          | 6.13      |

### Dependencies to mbedTLS versions
| cy-mbedtls-acceleration version                         | mbedTLS version |
| :---:                                                   | :----:  |
| 2.0 												  | 3.0.0   |


### Change log

| Version |	Changes                                       | Reason for Change |
| :----:  |	:---                                          | :----             |
| 2.0   |	Initial version adding support for MbedTLS 3.0 | MbedTLS 3.0 support |


---
© Cypress Semiconductor Corporation, 2019-2022.
