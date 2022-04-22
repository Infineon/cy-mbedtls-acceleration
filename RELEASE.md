# mbedTLS Crypto acceleration for CAT1A MCUs

### What's Included?
Please refer to the [README.md](./README.md) for a complete description of the CAT1A acceleration for mbedTLS library.
New in this release:

* Support for new MTB projects flow
* Small documentation cleanup

### Limitations
Currently Cypress CAT1A acceleration doesn't support:

- RSA
- ECP NIST-B curves
- ECP NIST-K curves
- ECP 25519 curve
- Montgomery Curve for ECDH
- CHACHA20
- SHA3
- AES GCM
- POLY1305

### Supported Software and Tools
This version of the CAT1A acceleration for mbedTLS library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version   |
| :---                                                    | :-------: |
| ModusToolbox Software Environment                       | 2.4       |
| mtb-pdl-cat1 Peripheral Driver Library (PDL)            | 2.4       |
| mtb-hal-cat1 Hardware Abstraction Layer (HAL)           | 2.1       |
| GCC Compiler                                            | 10.3.1    |
| IAR Compiler                                            | 8.2       |
| ARM Compiler 6                                          | 6.12      |

### Dependencies to mbedTLS versions
| cy-mbedtls-acceleration version                         | mbedTLS version |
| :---:                                                   | :----:  |
| 1.4												      | 2.26    |
| 1.3    											      | 2.24    |
| 1.2 	   											      | 2.19.1  |
| 1.1 												      | 2.19    |
| 1.0 												      | 2.19    |

### Change log

| Version |	Changes                                                                                                | Reason for Change |
| :----:  |	:---                                                                                                   | :----             |
| 1.4     |	Support for new MTB projects flow, small documentation cleanup                                         | ModusToolbox 2.4 support |
| 1.3     |	Added ECDH acceleration, small code and documentation cleanup                                          | ModusToolbox 2.X support |
| 1.2     |	New internal resource management instead of using psoc6hal                                             | Simple projects support without psoc6hal |
| 1.1     |	Reorganized SHA implementation                                                                         | New Cypress MCUs support |
| 1.0     |	The initial version                                                                                    |                   |

---
© Cypress Semiconductor Corporation (an Infineon company), 2019-2022.