# wolfHSM

wolfHSM is a software framework that provides a portable and open-source client-server
abstraction for hardware cryptography, non-volatile memory, and isolated secure processing
that maximizes security and performance. It consists of a client-server library architecture,
where the wolfHSM server application runs in a trusted environment, and client applications
communicate with the server through the wolfHSM client library. wolfHSM is intended to simplify
the challenge of moving between hardware with enhanced security features without being tied to
any vendor-specific library calls. wolfHSM also dramatically simplifies client HSM applications
by allowing direct use of wolfCrypt APIs, with the framework automatically offloading all sensitive
cryptographic operations to the wolfHSM server as remote procedure calls with no additional logic
required by the client app. 

Although initially targeted to automotive-style HSM-enabled microcontrollers,
wolfHSM can run on any platform that provides a secure/trusted execution environment
for the server. wolfHSM provides an extensible solution to support future capabilities
of any platform while still supporting standardized interfaces and protocols such as
PKCS11 and AUTOSAR SHE.

For a technical overview of wolfHSM and instructions on using wolfHSM in your application,
please refer to the following resources.

## Resources

- [wolfHSM Manual](https://www.wolfssl.com/documentation/manuals/wolfhsm/index.html)
- [wolfHSM API Reference](https://www.wolfssl.com/documentation/manuals/wolfhsm/appendix01.html)
- [wolfHSM Examples](https://www.github.com/wolfSSL/wolfHSM-examples)
