# Introduction

This manual is written as a technical guide to the wolfHSM embedded hardware security module library. It
will explain how to build and get started with wolfHSM, provide an overview of build
options, features, portability enhancements, support, and much more.

You can find the PDF version of this document [here](https://www.wolfssl.com/documentation/manuals/wolfhsm/wolfHSM-Manual.pdf).

## Why Choose wolfHSM?

Automotive HSMs (Hardware Security Modules) dramatically improve the security of cryptographic keys and processing. They achieve this by isolating signature verification and cryptographic execution, the very foundations of security, into physically independent processors. These HSMs are not just recommended, but often mandatory for ECUs that demand robust security. In line with this, wolfSSL has seamlessly integrated our popular, rigorously tested, and industry-leading cryptographic library to operate in widely used Automotive HSMs such as Aurix Tricore TC3XX. WolfHSM, with its sole dependency on wolfCrypt, ensures portability across almost any runtime environment. It also facilitates a user-friendly client interface, allowing direct utilization of wolfCrypt APIs.

wolfHSM provides a portable and open-source abstraction to hardware cryptography, non-volatile memory, and isolated secure processing, maximizing security and performance for ECUs. By integrating the wolfCrypt software crypto engine on hardware HSMs like Infineon Aurix Tricore TC3XX, Chinese-mandated government algorithms like SM2, SM3, and SM4 are available. Additionally, Post Quantum Cryptography algos like Kyber, LMS, XMSS, and others are easily made available to automotive users to meet customer requirements. At the same time, when hardware cryptographic processing is available on the HSM, we consume it to enhance performance.

wolfBoot is a mature, portable, secure bootloader solution designed for bare-metal bootloaders and equipped with failsafe NVM controls. It offers comprehensive firmware authentication and update mechanisms, leveraging a minimalistic design and a tiny HAL API, which makes it fully independent from any operating system or bare-metal application. wolfBoot efficiently manages the flash interface and pre-boot environment, accurately measures and authenticates applications, and utilizes low-level hardware cryptography as needed. wolfBoot can use the wolfHSM client to support HSM-assisted application core secure boot. Additionally, wolfBoot can run on the HSM core to ensure the HSM server is intact, offering a secondary layer of protection. This setup ensures a secure boot sequence, aligning well with the booting processes of HSM cores that rely on NVM support.


