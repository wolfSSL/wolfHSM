# STM32H5 TrustZone port

The STM32H5 wolfHSM TrustZone port (HAL adapter, secure-side server,
flash/NVM backend, non-secure demo app, linker layout, and test
harness) is maintained in
[wolfBoot](https://github.com/wolfSSL/wolfBoot) under
`port/stmicro/stm32h5-tz-wolfhsm/` and `test-app/wcs/`.

It consumes the generic ARMv8-M TrustZone NSC bridge transport in
`port/armv8m-tz/` of this repository. See `docs/src/chapter08.md` for
the transport description.
