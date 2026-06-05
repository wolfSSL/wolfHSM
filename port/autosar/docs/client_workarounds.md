# Client-side workarounds in the AUTOSAR port

The wolfHSM AUTOSAR port carries one small client-side translation
that bridges a gap between wolfHSM's current verify-handler return
contract and the AUTOSAR R22-11 SWS verify-result contract. This
note documents what the translation is, where it lives, and why
it's necessary today.

A wolfHSM-side improvement that would let us drop the translation
is under discussion upstream; the port will remain compatible
either way.

---

## The mismatch

R22-11 AUTOSAR splits the outcome of a verify primitive across two
return surfaces:

- `Std_ReturnType` — whether the API **call** succeeded.
- `Crypto_JobPrimitiveInputOutputType::verifyPtr` — whether the
  signature / tag **validated**.

So a malformed signature is "API succeeded; signature invalid":
`E_OK + verifyPtr=CRYPTO_E_VER_NOT_OK`. Only a real transport
problem or setup failure surfaces as `E_NOT_OK`.

wolfHSM's verify handlers (`_HandleEccVerify`,
`_HandleEd25519Verify`, `_HandleMlDsaVerify`, the GCM-decrypt branch
of `_HandleAesGcm`, plus the DMA variants) currently put wolfCrypt
rejection codes (`ASN_PARSE_E`, `MP_VAL`, `SIG_VERIFY_E`,
`AES_GCM_AUTH_E`, …) directly into `respHeader.rc`. The client
wrappers (`wh_Client_EccVerifyResponse`, peers) only read
`*out_res` when `rc >= 0`:

```c
ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDSA_VERIFY, ...);
if (ret >= 0) {
    *out_res = res->res;
    ...
}
return ret;
```

So a caller cannot distinguish

- "valid DER, math rejected" → clean `rc=0`, `res=0`
- "malformed DER, wolfCrypt couldn't parse" → `rc<0`, `res` untouched

both of which are "verification failed" from the SWS perspective.

(Note: RSA verify is **not** affected — it routes through
`_HandleRsaFunction`, not a dedicated verify handler.)

---

## Where the workaround lives

`port/autosar/classic/src/Crypto_ProcessJob.c::isVerifyRejection`:

```c
/* wolfHSM transport codes live in -2000..-2199.
 * wolfCrypt errors live in -100..-300 (and a few scattered
 * neighbouring ranges, all > -2000). A negative rc above
 * WH_ERROR_BADARGS is therefore a wolfCrypt-side rejection. */
static boolean isVerifyRejection(int rc)
{
    return (rc < 0 && rc > -2000) ? TRUE : FALSE;
}
```

Applied in both the sync `doEcdsaSync` verify path and the async
`pollAsyncResponse` ECDSA verify arm. When `wh_Client_EccVerify`
returns a wolfCrypt-range negative `rc` with `verifyRes`
untouched, the dispatcher surfaces SWS-correct
`E_OK + verifyPtr=NOT_OK`. The same translation will carry over to
Ed25519, ML-DSA, and AES-GCM decrypt verify the moment those
contexts are wired through the dispatcher.

---

## Upstream direction

The wolfHSM team has confirmed the verify-handler contract is
real and is discussing folding a curated allowlist of
verify-rejection codes (`ASN_PARSE_E`, `MP_VAL`, `SIG_VERIFY_E`,
`AES_GCM_AUTH_E`, …) into `(rc=0, res=0)` at the handler boundary.
The list must stay explicit so that genuine failures (`MEMORY_E`,
keystore lookup errors, hardware-init issues, transport-level
problems) keep surfacing as `rc<0`.

If/when that lands, our `isVerifyRejection` branch becomes
defence-in-depth — the `verifyRes==0/1` branch handles the clean
case, and `isVerifyRejection` covers any rejection code the
upstream allowlist doesn't explicitly fold. **No port-side
changes are needed when the upstream patch lands.**

A second item the original investigation flagged (POSIX server main
loop terminating on every non-OK return) is **already fixed**
upstream: commit `9a70643` ("Unify server handler return code
processing") landed in `main` and is an ancestor of `cc433c0`,
this repo's base. `wh_Server_HandleRequestMessage` captures
handler rc into `handlerRc` for logging only and returns the
`SendResponse` rc; handler errors cannot reach the POSIX main
loop.

---

## Smoke coverage

The `csm_smoke` ECDSA test exercises three paths:

1. **Valid signature** → `verifyPtr=OK + E_OK`.
2. **Math-rejected signature** (byte flipped inside the value
   region; wolfCrypt parses, math rejects, clean `rc=0`,
   `verifyRes=0`) → `verifyPtr=NOT_OK + E_OK` via the
   `verifyRes==0` branch.
3. **Malformed-DER signature** (SEQUENCE tag flipped; wolfCrypt
   rejects before math, returns a wolfCrypt-range negative)
   → `verifyPtr=NOT_OK + E_OK` via `isVerifyRejection`.

Path 3 is gated behind `-DWH_SMOKE_TEST_MALFORMED_SIG=1`. Against
the current unpatched POSIX server, the wolfCrypt rejection
surfaces a `rc<0` in the response which causes the wolfHSM client
to tear down the connection, hanging subsequent requests. Once
upstream folds the rejection codes, the flag can be enabled and
all three paths run end-to-end.
