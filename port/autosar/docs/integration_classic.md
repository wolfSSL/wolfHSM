# Classic Platform Integration

How to drop the wolfHSM Crypto Driver into an existing AUTOSAR Classic
BSW project (MICROSAR, RTA-BSW, EB tresos, etc.).

## What this port replaces

In a stock AUTOSAR Classic stack the Crypto Driver sits below CryIf:

```
SWC --> CSM --> CryIf --> [Crypto Driver]  ==  HSM firmware
```

The wolfHSM port is dropped in as `[Crypto Driver]`, with the wolfHSM
server playing the role of the HSM firmware. The customer keeps their
CSM, CryIf, RTE, OS, Det, and SchM modules from their existing BSW
vendor; only the Crypto Driver and the HSM firmware are replaced.

## Source files to compile

```
port/autosar/common/src/wh_autosar_alg_map.c
port/autosar/classic/src/Crypto.c
port/autosar/classic/src/Crypto_ProcessJob.c
port/autosar/classic/src/Crypto_KeyMgmt.c
port/autosar/classic/src/Crypto_Keystore.c
port/autosar/classic/src/Crypto_KeyGen.c
port/autosar/classic/src/Crypto_KeyDerive.c
port/autosar/classic/src/Crypto_KeyExchange.c
port/autosar/classic/src/Crypto_Random.c
port/autosar/classic/config/Crypto_PBcfg.c    (or the generator-produced equivalent)
+ wolfHSM client + wolfCrypt sources           (see existing port/posix/ examples)
```

Include paths:

```
port/autosar/classic/include
port/autosar/common/include
wolfhsm/                                       (the wolfHSM repo root)
<your wolfssl headers>
<your BSW headers — Std_Types.h, Crypto_GeneralTypes.h, Det.h, CryIf_Cbk.h, ...>
```

**Vendor BSW headers are integrator-supplied.** That includes
`Crypto_GeneralTypes.h` — the wolfHSM port deliberately ships no copy
of this header inside `classic/include/`. Use the one your BSW vendor
ships with their CSM / CryIf so struct layouts agree across the
toolchain. The csm_smoke harness keeps a minimal placeholder in
`classic/examples/csm_smoke/fake_bsw/` for tool-free CI builds; it is
**not** the source of truth.

## Required external symbols

Provide one definition each:

- `int wh_Autosar_PlatformClientConfig(whClientContext* client)` — fill
  the `whClientConfig` for your transport (TCP, shared memory, MMIO,
  whatever connects to your wolfHSM server) and call `wh_Client_Init`.
  Sample TCP implementation is in `examples/csm_smoke/csm_smoke.c`.
- `void CryIf_CallbackNotification(Crypto_JobType*, Std_ReturnType)` —
  supplied by your BSW's CryIf module.
- `Std_ReturnType Det_ReportError(uint16, uint8, uint8, uint8)` —
  supplied by your BSW.

## ARXML / configuration

Customers using a config tool (DaVinci / ISOLAR / tresos) import
`config/AUTOSAR_MOD_CryptoDriver.arxml` into their project and
configure CryptoDriverObjects + CryptoKeys from there. The tool
generates a project-specific `Crypto_PBcfg.c` containing both
`Crypto_DefaultConfig` (driver objects) and `Crypto_KeyDescriptorTable`
/ `Crypto_KeyDescriptorCount` (per-key algorithm metadata that drives
KeyGenerate / KeyDerive / KeyExchange).

The default `Crypto_PBcfg.c` shipped in `config/` provides a single
driver object with **no** key descriptors — enough for the csm_smoke
harness, which installs its own descriptors via a strong override of
`Crypto_KeyDescriptorTable`. Replace it with the generator output in
your project.

### Per-project tunables

Override these in your `Crypto_Cfg.h` (or via `-D`):

- `CRYPTO_VENDOR_ID` — your AUTOSAR-registered vendor identifier.
  Defaults to `0` so an unconfigured build is visibly unconfigured.
- `CRYPTO_DRIVER_OBJECT_COUNT` — number of Crypto Driver Objects.
- `CRYPTO_MAX_ASYNC_JOBS` — async slots per driver object.

### Slot lock hooks

`wh_Autosar_LockSlots(obj)` / `wh_Autosar_UnlockSlots(obj)` are weak
no-ops by default. If `Crypto_ProcessJob` and `Crypto_MainFunction`
are called from different priority tasks, provide strong
definitions in your port glue that wrap your SchM-managed critical
section.

The weak-symbol attribute is portable across the major AUTOSAR
toolchains via the `WH_AUTOSAR_WEAK` macro
(`wh_autosar_classic_internal.h`): GCC / Clang / Greenhills / TI /
Tasking use `__attribute__((weak))`; IAR uses the `__weak` keyword.
Unsupported toolchains fall back to strong-only symbols (override
requires editing the port files in place).

### Async behaviour

`Crypto_ProcessJob` with `processingType=1` returns immediately —
the slot transitions to QUEUED. `Crypto_MainFunction` promotes the
oldest QUEUED slot to PENDING and drives the `wh_Client_*Request /
*Response` pair; **at most one slot is in flight per driver object**,
honouring the wolfHSM client's single-in-flight contract. Set
`CRYPTO_ASYNC_TIMEOUT_TICKS` (default 10000 MainFunction ticks) to
control how long a hung PENDING slot waits before the dispatcher
forces it to fail.

## Licensing

This port is GPLv3. ECUs that cannot ship GPLv3 take a commercial
license from wolfSSL Inc. — same dual-licensing model as the rest of
wolfHSM / wolfSSL. The commercial license does not require any code
changes on this side.

This port does not include any vendor BSW headers. Your BSW vendor
supplies `Std_Types.h`, `Det.h`, `CryIf_Cbk.h`, etc.
