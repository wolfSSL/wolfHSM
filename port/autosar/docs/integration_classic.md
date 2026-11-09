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
<your BSW headers: Std_Types.h, Crypto_GeneralTypes.h, Det.h, CryIf_Cbk.h, ...>
```

**Vendor BSW headers are integrator-supplied.** That includes
`Crypto_GeneralTypes.h` - the wolfHSM port deliberately ships no copy
of this header inside `classic/include/`. Use the one your BSW vendor
ships with their CSM / CryIf so struct layouts agree across the
toolchain. The csm_smoke harness keeps a minimal placeholder in
`classic/examples/csm_smoke/fake_bsw/` for tool-free CI builds; it is
**not** the source of truth.

`Crypto.c` checks at compile time that your header's service, family and
mode values match R22-11. A mismatch fails the build rather than routing
jobs to the wrong primitive. The driver reads the key from
`job->cryptoKeyId`, which CryIf fills in.

R22-11 defines no family for ML-DSA or CMAC-KDF. The port uses
`WH_AUTOSAR_ALGOFAM_MLDSA` (default `0x80`) and
`WH_AUTOSAR_ALGOFAM_CMAC_KDF` (default `0x81`); override them with `-D` to
match your configuration.

## Required external symbols

Provide one definition each:

- `int wh_Autosar_PlatformClientConfig(whClientContext* client)` - fill
  the `whClientConfig` for your transport (TCP, shared memory, MMIO,
  whatever connects to your wolfHSM server) and call `wh_Client_Init`.
  Sample TCP implementation is in `examples/csm_smoke/csm_smoke.c`.
- `void CryIf_CallbackNotification(Crypto_JobType*, Crypto_ResultType)` -
  supplied by your BSW's CryIf module.
- `Std_ReturnType Det_ReportError(uint16, uint8, uint8, uint8)` -
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
driver object with **no** key descriptors - enough for the csm_smoke
harness, which installs its own descriptors via a strong override of
`Crypto_KeyDescriptorTable`. Replace it with the generator output in
your project.

### Per-project tunables

Override these in your `Crypto_Cfg.h` (or via `-D`):

- `CRYPTO_VENDOR_ID` - your AUTOSAR-registered vendor identifier.
  Defaults to `0` so an unconfigured build is visibly unconfigured.
- `CRYPTO_DRIVER_OBJECT_COUNT` - number of Crypto Driver Objects.
- `CRYPTO_MAX_ASYNC_JOBS` - async slots per driver object.
- `CRYPTO_MAX_INVALID_KEYS` - keys that can be written and not yet set
  valid at the same time (default 16).
- `CRYPTO_MAX_RAM_ELEMENTS` - IV and salt elements the driver holds at
  the same time (default 8).
- `CRYPTO_CMAC_MIN_VERIFY_BITS` - shortest accepted MAC verify length
  in bits (default 64). Shorter truncated MACs, as some SecOC profiles
  use, need a lower value; every bit below it is guessable one at a
  time by a caller that can run verify jobs.
- `CRYPTO_AEAD_MIN_TAG_LEN` - shortest AES-GCM tag in bytes (default
  12, wolfCrypt's own minimum).
- `CRYPTO_ASYNC_TIMEOUT_TICKS` - MainFunction ticks one request may
  stay unanswered before the job fails (default 10000).
- `CRYPTO_KEY_COPY_BUF_SIZE` - largest element that `KeyElementCopy`,
  `KeyCopy` and `KeyElementCopyPartial` handle (default 512 bytes). The
  buffer is on the stack, twice for CopyPartial.
- `CRYPTO_PUBKEY_DER_BUF_SIZE` - stack buffer for the DER public key
  read during key exchange (default 160 bytes).
- `CRYPTO_DEV_ERROR_DETECT` - `STD_ON` (default) reports parameter
  errors to DET.

With `CRYPTO_DRIVER_OBJECT_COUNT` above 1, each driver object has its own
wolfHSM client. Give each client its own `devId` in the platform hook, and
build client and server with `WOLFHSM_CFG_GLOBAL_KEYS`: the driver then
stores keys in the server's global namespace so every object can use them.

### Key descriptors

Each `Crypto_KeyDescriptorType` entry gives the algorithm for one
`cryptoKeyId`: `family`, `mode`, `keyLength` in bits, `eccCurveId` for
ECC keys, `hashType` for HKDF targets and `mlDsaLevel`
(`WC_ML_DSA_44/65/87`) for ML-DSA keys, and `exportable`. KeyGenerate,
KeyDerive, the key exchange calls and ML-DSA signing read it.

Keys are cached with `WH_NVM_FLAGS_USAGE_ANY`: AUTOSAR leaves key
usage policy to the CSM, which the driver cannot see.

Keys are created non-exportable unless their descriptor sets
`exportable`, and `Crypto_KeyElementGet` and `Crypto_KeyElementCopy` on
such a key return `CRYPTO_E_KEY_READ_FAIL`. Public keys stay readable
through the key exchange calls. The private key from `CalcPubVal` is
never exportable, and `KeyElementCopyPartial` needs an exportable
target unless the target does not exist yet. Symmetric keys from
`Crypto_KeyGenerate` are generated on the HSM.

## Job and key conventions

The driver follows SWS_Crypto_00073 for job buffers:

1. Encrypt and decrypt take the IV from key element
   `CRYPTO_KE_CIPHER_IV` (5) and clear it, so set it before every job.
   The driver keeps it in RAM; setting it does not invalidate the key,
   and writing new key material clears it. An async job takes the IV
   when `Crypto_ProcessJob` accepts it.
2. AEAD encrypt takes the associated data in `secondaryInputPtr` and
   writes the tag to `secondaryOutputPtr`. AEAD decrypt reads the tag
   from `tertiaryInputPtr`.
3. Signature jobs sign the message in `inputPtr`. When
   `secondaryFamily` names a SHA-2 hash, the driver hashes the message
   first; with `CRYPTO_ALGOFAM_NOT_SET` the input is taken as the
   digest and must be 32, 48 or 64 bytes. Ed25519 and ML-DSA always
   sign the message.
4. Key exchange public values are raw: X || Y for ECDH, 32 bytes for
   X25519. CalcSecret stores the shared value in key element 1.
5. `Crypto_KeyDerive` takes the salt from the source key's element
   `CRYPTO_KE_KEYDERIVATION_SALT` (13), kept in RAM and cleared by new
   key material like the IV. CMAC-KDF
   needs a 16, 24 or 32 byte salt and uses a zero block when none is set.
6. A streamed hash job stays `CRYPTO_JOBSTATE_ACTIVE` from START until
   FINISH.
7. Verify jobs write `CRYPTO_E_VER_NOT_OK` to `verifyPtr` on entry, so
   a job that fails before verifying never reads as verified.
8. Key ids are the plain client ids 1 to 255, with the global flag when
   `CRYPTO_DRIVER_OBJECT_COUNT` is above 1.

Key state follows SWS_Crypto_00039. A key written in this session is
invalid until `Crypto_KeySetValid`, and jobs using it return
`CRYPTO_E_KEY_NOT_VALID`. Keys provisioned on the HSM before
`Crypto_Init` count as valid. `Crypto_KeySetValid` commits material written
in this session to the HSM's NVM. The valid/invalid state itself lives in
driver RAM, so a host reset forgets `Crypto_KeySetInvalid` and treats
keys written but never set valid as valid again. `KeyExchangeCalcSecret`
refuses a key that was explicitly set invalid, but accepts the fresh key
from `CalcPubVal`.

The key management API uses driver object 0's wolfHSM client by
default, and a client carries one request at a time. While an async
request is in flight on that client, sync jobs and key management calls
return `CRYPTO_E_BUSY`. If you override `wh_Autosar_KeystoreClient` with a
dedicated client, the key calls serialise among themselves the same way.

`Crypto_CancelJob` returns `E_NOT_OK` for a job that `Crypto_MainFunction`
is running as a blocking call or is still sending, or for a streamed
hash whose UPDATE is running on another task, because its buffers are
in use.

Provide strong `wh_Autosar_LockKeys` / `wh_Autosar_UnlockKeys` when key
calls and `Crypto_MainFunction` run on different tasks; they guard the
key state, IV and salt tables.

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

`Crypto_ProcessJob` with `processingType=CRYPTO_PROCESSING_ASYNC`
returns immediately:
the slot transitions to QUEUED. `Crypto_MainFunction` promotes the
oldest QUEUED slot to PENDING and drives the `wh_Client_*Request /
*Response` pair; **at most one slot is in flight per driver object**,
honouring the wolfHSM client's single-in-flight contract. Set
`CRYPTO_ASYNC_TIMEOUT_TICKS` (default 10000 MainFunction ticks) to
control how long a hung PENDING slot waits before the dispatcher
forces it to fail.

## Licensing

This port is GPLv3. ECUs that cannot ship GPLv3 take a commercial
license from wolfSSL Inc. - same dual-licensing model as the rest of
wolfHSM / wolfSSL. The commercial license does not require any code
changes on this side.

This port does not include any vendor BSW headers. Your BSW vendor
supplies `Std_Types.h`, `Det.h`, `CryIf_Cbk.h`, etc.
