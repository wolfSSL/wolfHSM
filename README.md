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
- [wolfHSM Examples](https://github.com/wolfSSL/wolfHSM/tree/main/examples)

## SBOM / EU CRA Compliance

wolfHSM generates a Software Bill of Materials (SBOM) in CycloneDX 1.6 and
SPDX 2.3 formats to support compliance with the EU Cyber Resilience Act (CRA).

Generate both SBOMs with the `sbom` Makefile target:

```sh
make sbom WOLFSSL_DIR=../wolfssl
```

This parses the version from `ChangeLog.md`, collects `src/*.c`, and writes
`wolfhsm-<version>.cdx.json` and `wolfhsm-<version>.spdx.json`.

The SBOM records the build configuration by preprocessing
`wolfhsm/wh_settings.h` against a config directory. `WOLFHSM_CFG_DIR`
(default: `test/config`) selects the directory holding the `wolfhsm_cfg.h`
and `user_settings.h` your build uses — point it at your port's config so the
recorded `WOLFHSM_CFG_*` and wolfSSL options match the library you ship:

```sh
make sbom WOLFSSL_DIR=../wolfssl WOLFHSM_CFG_DIR=path/to/your/config
```

Note: alongside the real config macros, the dump currently includes libc
constants pulled in by `wh_settings.h`'s system includes; see the comment on
the `sbom` target in `Makefile` for why they are not filtered here and what
the planned gen-sbom fix is.

`WOLFSSL_DIR` must point to a wolfssl source tree containing `scripts/gen-sbom`,
which ships in wolfSSL PR #10343 (pending a future wolfSSL release). If the
script is absent the target fails with a message telling you what is missing.

Requires `python3` and `pyspdxtools` (`pip install spdx-tools`).

To invoke `gen-sbom` directly instead of through the target, run the same
command it runs:

```sh
cc -dM -E -DWOLFHSM_CFG -DWOLFSSL_USER_SETTINGS \
    -I. -Itest/config -I$WOLFSSL_DIR \
    -include wolfhsm/wh_settings.h -x c /dev/null > wolfhsm-defines.h
python3 $WOLFSSL_DIR/scripts/gen-sbom \
    --name wolfhsm \
    --version $(sed -n 's/^# wolfHSM Release v\([0-9][0-9.]*\).*/\1/p' ChangeLog.md | head -1) \
    --supplier "wolfSSL Inc." \
    --license-file LICENSING \
    --options-h wolfhsm-defines.h \
    --srcs src/*.c \
    --cdx-out wolfhsm.cdx.json \
    --spdx-out wolfhsm.spdx.json
```

For further CRA guidance see [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md).
