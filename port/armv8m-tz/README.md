# ARMv8-M TrustZone NSC bridge transport

A synchronous wolfHSM transport for ARMv8-M TrustZone targets that
bridges a non-secure client to a secure-world server through a single
Non-Secure Callable (NSC) veneer. See `wh_transport_nsc.h` for the C
API.

## How it works

Client and server share a single secure-callable function. The
non-secure side packs a wolfHSM request into a buffer, calls the
veneer, and waits for the veneer to return with the response written
into a second buffer. The secure side runs the wolfHSM server in the
same process; there is no separate task, no IRQ, and no shared-memory
ring — just a function call across the security boundary.

## Host-side veneer contract

The integrator provides one function with this exact shape:

```c
int wcs_wolfhsm_transmit(const uint8_t *cmd, uint32_t cmdSz,
                         uint8_t *rsp, uint32_t *rspSz);
```

declared `cmse_nonsecure_entry` from the secure side. On entry,
`cmd[0..cmdSz)` holds the request and `*rspSz` is the maximum response
size the client can accept; on return the function writes the
response into `rsp[0..*rspSz)` and updates `*rspSz` to the actual
size. Return value follows wolfHSM's `WH_ERROR_*` convention.

The veneer must not block on anything outside the secure server; the
non-secure side treats it as a synchronous call.

## Known integrations

- **wolfBoot STM32H5 demo app** at
  [`port/stmicro/stm32h5-tz-wolfhsm/`](https://github.com/wolfSSL/wolfBoot/tree/main/port/stmicro/stm32h5-tz-wolfhsm)
  in wolfBoot. Reference integration on a NUCLEO-H563ZI;
  verified end-to-end on real silicon and on the m33mu emulator.

To add a new integration, copy the veneer skeleton from wolfBoot's
demo, wire `wh_transport_nsc.h` into the non-secure client init, and
write a `whServerCb` table for the secure server.
