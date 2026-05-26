# Certificate Chain Validation in wolfHSM

## 1. Overview

wolfHSM provides a server-resident X.509 certificate manager that lets clients
provision trusted root anchors into NVM and then verify candidate certificate
chains against those anchors over the standard wolfHSM client/server protocol.
The chain walk, signature checks, anchor selection, and any custom verify
callbacks all run inside the trusted server environment; the client only ever
ships DER bytes and trust-anchor identifiers, never private key material or
root certificates that have been provisioned with the non-exportable flag.

The feature set is layered. Each layer below adds capability without
invalidating the layer above it, and each is independently gated by a
compile-time configuration macro.

| Capability                              | Macro                                              | Notes |
|-----------------------------------------|----------------------------------------------------|-------|
| Trusted-root NVM CRUD + chain verify    | `WOLFHSM_CFG_CERTIFICATE_MANAGER`                  | Base feature. Requires crypto. |
| Multi-root chain verify                 | (always available with the base feature)           | Bounded by `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS`. |
| Trusted CA verify-result cache          | `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE`             | Per-server cache by default. |
| Cross-client (global) verify cache      | `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL`      | Layered on top of the verify cache. |
| Cache leaf public key after verify      | `WH_CERT_FLAGS_CACHE_LEAF_PUBKEY` request flag     | Available on every verify variant. |
| Attribute-certificate (X.509 ACERT)     | `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT`            | Single-root verify only. |
| DMA transport for large chains          | `WOLFHSM_CFG_DMA`                                  | Available on every cert API. |
| User-supplied verify callback           | `whServerCertConfig.verifyCb` (server-side only)   | Applied per cert manager. |

The remaining sections walk the client API for each operation, then dive into
the multi-root and trusted-cache features in detail and describe the precise
semantics that result when both are enabled together.

## 2. Build Configuration

### Required

- `WOLFHSM_CFG_CERTIFICATE_MANAGER` — enables every API in this document.
  Requires `!WOLFHSM_CFG_NO_CRYPTO` (the implementation depends on
  `WOLFSSL_CERT_MANAGER` and the wolfCrypt ASN.1 decoder).

### Optional

- `WOLFHSM_CFG_DMA` — enables the `*Dma*` variants that pass the candidate
  chain by client address rather than copying it through the comm buffer.
- `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT` — enables `wh_Client_CertVerifyAcert`
  / `wh_Client_CertVerifyAcertDma`. Requires wolfSSL built with `WOLFSSL_ACERT`
  and `WOLFSSL_ASN_TEMPLATE`.
- `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE` — enables the trusted CA verify cache
  (Section 6). Pulls in `wh_Client_CertVerifyCacheClear` and
  `wh_Client_CertVerifyCacheSetEnabled` on the client.
- `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL` — relocates the verify cache
  from the per-server context into the shared NVM context so it is reused
  across every client connected to the server. Requires
  `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE`.

### Bounds

- `WOLFHSM_CFG_MAX_CERT_SIZE` — maximum DER size of any single certificate
  read from or written to NVM. Defaults to `WOLFHSM_CFG_COMM_DATA_LEN` when
  DMA is off, `4096` when DMA is on.
- `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS` — upper bound on the number of trusted
  root NVM IDs that may be supplied to a single multi-root verify call.
  Defaults to `8`. This bound also sizes the inline root-id array in the
  multi-root DMA request and the per-slot root binding in the verify cache.
  Fails a static assert if the resulting DMA request struct would exceed
  `WOLFHSM_CFG_COMM_DATA_LEN`.
- `WOLFHSM_CFG_CERT_VERIFY_CACHE_COUNT` — number of slots in the verify
  cache (FIFO ring). Defaults to `16`.

## 3. Common Concepts

### 3.1 Trust anchors live in NVM

Every trusted root is a regular NVM object identified by a `whNvmId`. The
client provisions roots with `wh_Client_CertAddTrusted`, removes them with
`wh_Client_CertEraseTrusted`, and reads them back with
`wh_Client_CertReadTrusted`. Verification operations take the NVM ID(s) of
the root(s) to anchor against — the root certificate bytes themselves are
never sent inline with a verify request.

Roots respect normal NVM access and flag policy. A root provisioned with
`WH_NVM_FLAGS_NONEXPORTABLE` cannot be read back via
`wh_Client_CertReadTrusted` (the server returns `WH_ERROR_ACCESS`) but is
still usable as a verify anchor.

### 3.2 Verification flags (`whCertFlags`)

Defined in `wolfhsm/wh_common.h`:

- `WH_CERT_FLAGS_NONE` — verify only.
- `WH_CERT_FLAGS_CACHE_LEAF_PUBKEY` — on a successful verify, extract the
  leaf certificate's `SubjectPublicKeyInfo` and cache it in the server's
  key cache so subsequent crypto operations can address it by `whKeyId`.

### 3.3 Cached leaf key id

Verify variants whose name contains `AndCacheLeafPubKey` take an `inout_keyId`
argument. On entry, supply either an explicit `whKeyId` or `WH_KEYID_ERASED`
to let the server pick a unique id; on success, the caller-side id is updated
with the value the server actually used. Failed verifies leave the prior id
contents undisturbed and do not populate the key cache.

`cachedKeyFlags` carries the NVM usage flags applied to the cached key —
typically `WH_NVM_FLAGS_USAGE_VERIFY` for a leaf certificate's public key.

### 3.4 Async (request/response) split

Every verify and trusted-root mutation API has three forms:

- A single blocking call (e.g. `wh_Client_CertVerify`).
- A non-blocking `*Request` call that returns as soon as the request is on
  the wire.
- A non-blocking `*Response` call that returns `WH_ERROR_NOTREADY` until the
  server has replied, then yields `out_rc`.

The blocking forms loop on `WH_ERROR_NOTREADY` internally. Use the split
pair when the calling thread needs to remain responsive (for example, to
service a separate request).

### 3.5 Return-code conventions

All client functions return a wolfHSM transport-layer `int`:
`WH_ERROR_OK` if the request and response cycle completed, or a negative
error code if the comm layer itself failed.

The server's verify result is returned separately via `out_rc`:

| `out_rc`                | Meaning                                                              |
|-------------------------|----------------------------------------------------------------------|
| `WH_ERROR_OK` (0)       | Chain anchored successfully.                                         |
| `WH_ERROR_CERT_VERIFY`  | Chain did not anchor (signature, expiry, or path failure).           |
| `WH_ERROR_NOTFOUND`     | (Multi-root only) every supplied root id was absent from NVM.        |
| `WH_ERROR_BADARGS`      | Argument shape or wire-payload size violation.                       |
| `WH_ERROR_ACCESS`       | Read-trusted on a non-exportable cert.                               |
| Other negative codes    | Underlying NVM, transport, or cert-manager environment errors.       |

This separation lets callers distinguish a real trust failure
(`WH_ERROR_CERT_VERIFY`) from "the trust store itself is empty"
(`WH_ERROR_NOTFOUND`) and from infrastructure errors.

## 4. Client API

All prototypes below live in `wolfhsm/wh_client.h`. The `*Request` /
`*Response` split forms are omitted from the listing for brevity but exist
for every blocking entry point shown.

### 4.1 Initialization

```c
int wh_Client_CertInit(whClientContext* c, int32_t* out_rc);
```

Initializes the server's certificate manager subsystem. Required once per
server before any other cert call. When the trusted-cert verify cache is
enabled in per-client mode, `CertInit` clears the calling client's cache
(see Section 6.4).

### 4.2 Trusted root provisioning

```c
int wh_Client_CertAddTrusted(whClientContext* c, whNvmId id,
                             whNvmAccess access, whNvmFlags flags,
                             uint8_t* label, whNvmSize label_len,
                             const uint8_t* cert, uint32_t cert_len,
                             int32_t* out_rc);

int wh_Client_CertEraseTrusted(whClientContext* c, whNvmId id, int32_t* out_rc);

int wh_Client_CertReadTrusted(whClientContext* c, whNvmId id, uint8_t* cert,
                              uint32_t* cert_len, int32_t* out_rc);
```

`CertAddTrusted` writes a DER root certificate into NVM under the supplied
`whNvmId` with the given access and flag policy. `CertEraseTrusted` removes
it. `CertReadTrusted` reads it back, with `*cert_len` updated to the actual
stored size on success (or, on `WH_ERROR_BUFFER_SIZE`, the size needed).

When the verify cache is enabled, both `AddTrusted` and `EraseTrusted` also
trigger a cache eviction for the affected root id (Section 6.4).

DMA variants:

```c
int wh_Client_CertAddTrustedDma(whClientContext* c, whNvmId id,
                                whNvmAccess access, whNvmFlags flags,
                                uint8_t* label, whNvmSize label_len,
                                const void* cert, uint32_t cert_len,
                                int32_t* out_rc);

int wh_Client_CertReadTrustedDma(whClientContext* c, whNvmId id, void* cert,
                                 uint32_t cert_len, int32_t* out_rc);
```

### 4.3 Single-root chain verify

```c
int wh_Client_CertVerify(whClientContext* c, const uint8_t* cert,
                         uint32_t cert_len, whNvmId trustedRootNvmId,
                         int32_t* out_rc);
```

Walks the chain in `cert` (concatenated DER in leaf-last certificate order),
anchoring against the single root identified by `trustedRootNvmId`. The server
constructs a fresh `WOLFSSL_CERT_MANAGER` for the call, loads the root, walks
the chain via `wolfSSL_CertManagerVerifyBuffer`, and returns the result via
`out_rc`.

DMA variant:

```c
int wh_Client_CertVerifyDma(whClientContext* c, const void* cert,
                            uint32_t cert_len, whNvmId trustedRootNvmId,
                            int32_t* out_rc);
```

### 4.4 Single-root verify with leaf-key caching

```c
int wh_Client_CertVerifyAndCacheLeafPubKey(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    whNvmId trustedRootNvmId, whNvmFlags cachedKeyFlags, whKeyId* inout_keyId,
    int32_t* out_rc);
```

Same chain walk as `wh_Client_CertVerify`, plus on success the leaf
certificate's public key is copied into the server's key cache under
`*inout_keyId` (or a server-chosen id if the input was `WH_KEYID_ERASED`)
with `cachedKeyFlags` as its NVM usage policy. Subsequent crypto operations
can address the key by id.

DMA variant: `wh_Client_CertVerifyDmaAndCacheLeafPubKey`.

### 4.5 Multi-root chain verify

```c
int wh_Client_CertVerifyMultiRoot(whClientContext* c, const uint8_t* cert,
                                  uint32_t       cert_len,
                                  const whNvmId* trustedRootNvmIds,
                                  uint16_t numRoots, int32_t* out_rc);
```

Identical to the single-root call, except the server loads up to
`numRoots` roots (`1 .. WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS`) into a single
cert manager and the chain succeeds if it anchors to *any* of them. See
Section 5 for the full semantics.

DMA variant: `wh_Client_CertVerifyMultiRootDma`.

### 4.6 Multi-root verify with leaf-key caching

```c
int wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
    whClientContext* c, const uint8_t* cert, uint32_t cert_len,
    const whNvmId* trustedRootNvmIds, uint16_t numRoots,
    whNvmFlags cachedKeyFlags, whKeyId* inout_keyId, int32_t* out_rc);
```

DMA variant: `wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKey`.

### 4.7 Attribute certificate verify

```c
int wh_Client_CertVerifyAcert(whClientContext* c, const void* cert,
                              uint32_t cert_len, whNvmId trustedRootNvmId,
                              int32_t* out_rc);
```

Verifies an X.509 attribute certificate's signature against the public key
of the trusted root identified by `trustedRootNvmId`. Available only when
the server is built with `WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT`. There is
no multi-root or leaf-cache variant — attribute certificates are signed
directly by an attribute authority and the call carries a single anchor.

A signature mismatch is reported as `WH_ERROR_CERT_VERIFY` in `out_rc`, the
same convention as the standard verify path.

DMA variant: `wh_Client_CertVerifyAcertDma`.

### 4.8 Verify-cache management

Available only when `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE` is enabled:

```c
int wh_Client_CertVerifyCacheClear(whClientContext* c, int32_t* out_rc);

int wh_Client_CertVerifyCacheSetEnabled(whClientContext* c, uint8_t enable,
                                        int32_t* out_rc);
```

`CertVerifyCacheClear` drops every entry from the server's verify cache. In
per-client mode this clears only the calling client's cache; in global mode
(Section 6.5) it clears the shared cache for all clients. Subsequent verifies
fall back to running the full wolfSSL signature path until the cache is
repopulated.

`CertVerifyCacheSetEnabled` toggles the cache at runtime. The cache is
initialized enabled at server (and, in global mode, NVM) init, so this call
is only needed to opt out or to re-enable after opting out. Disabling
flushes all existing entries and makes subsequent Lookup miss / Insert a
no-op until the cache is re-enabled. The scope of the toggle matches the
cache mode: per-client mode affects this client's server only, global mode
affects the shared cache observed by every connected client.

Both APIs have the usual `*Request` / `*Response` split forms.

## 5. The Multi-Root Feature

### 5.1 Why it exists

The single-root entry point couples each verify to exactly one trust anchor.
Callers needing to validate a chain against any of several acceptable roots
otherwise have to either fold every acceptable root under a single super-root
(operationally awkward when the root infrastructures are independent) or
loop over `wh_Client_CertVerify` per root, parsing the chain again each
attempt and inferring at the application layer whether a per-anchor failure
should trigger a retry against the next anchor.

`wh_Client_CertVerifyMultiRoot` collapses both of those into a single
request: hand the server an array of up to `WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS`
NVM ids, the server loads each one as a CA into a single cert manager, and
the chain is walked exactly once. If it anchors to any of the supplied
roots the verify succeeds; otherwise it fails with `WH_ERROR_CERT_VERIFY`.

### 5.2 Order independence

The cert manager picks an issuer for each child cert by subject/issuer
matching during chain walk, not by load order. Listing root A before root B
does not "prefer" A.

### 5.3 Mixed-failure semantics

Multi-root distinguishes three failure modes via `out_rc`:

| Outcome                                                   | `out_rc`                |
|-----------------------------------------------------------|-------------------------|
| Chain anchors to ≥ 1 loaded root                          | `WH_ERROR_OK`           |
| ≥ 1 anchor loaded; chain does not anchor to any of them   | `WH_ERROR_CERT_VERIFY`  |
| Every supplied root id is absent from NVM                 | `WH_ERROR_NOTFOUND`     |
| Any non-absent failure reading or loading a supplied root | underlying error code   |

Roots that are absent from NVM are skipped silently — they do not abort the
operation and do not count against the chain's chance of anchoring. A read
or load failure on an *existing* root, by contrast, is treated as an
environment error and aborts the call.

## 6. The Trusted Verify Cache

### 6.1 Overview

When `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE` is enabled, the server keeps a
fixed-size FIFO ring of slots, each holding:

- A SHA-256 hash of a successfully-verified DER-encoded **CA** certificate.
- The set of trusted root NVM ids that were loaded into the cert manager
  when that cert was verified.

On a subsequent verify, before the server invokes
`wolfSSL_CertManagerVerifyBuffer` for a CA cert in the chain, it hashes
that cert and looks the hash up in the cache. A hit short-circuits the
public-key signature check; the rest of the chain walk (CA decode, store
load for downstream certs, leaf pubkey extract) continues unchanged.

Only CA certs are ever inserted. Leaves are deliberately excluded.

The verify cache is never stored in NVM and does not persist across power
cycles.

The cache also carries a runtime enable flag. It is initialized **enabled**
at server (and, in global mode, NVM) init, so the cache is active out of the
box on builds that compile it in. Clients can toggle it at runtime via
`wh_Client_CertVerifyCacheSetEnabled`; disabling clears all entries and
suppresses subsequent Lookup / Insert until re-enabled. Deployments that
want to fail-safe should disable the cache immediately after init and
re-enable it only when the threat-model implications below have been
accepted.

This feature is intended to provide a substantial performance enhancement by
eliminating multiple potentially redundant and expensive public key verification
operations, however it does so at the expense of security in some scenarios. If
deploying this feature in production it is paramount that the nuances regarding
the trust anchor consequences are fully understood and align with the threat
model of the application. **This feature should be used with caution and for most
scenarios is NOT recommended.**

### 6.2 Internals

The wolfHSM trusted certificate cache binds each entry to the *set* of
trusted roots that were actually loaded when the verify occured, and lookups
require the cached set to be a **subset of the caller's currently loaded set**.

The soundness argument rests on the monotonicity of X.509 verification: adding
more trusted roots should never invalidate a previously successful verify, so a
chain that validated under set `S` still validates under any superset `T ⊇ S`.
A cache hit therefore implies the cached verify's anchor (whichever root in `S`
actually closed the chain) is currently trusted, regardless of which element of
`S` it was, since every element of `S` is known to be in `T`.

### 6.3 Hits, misses, and recording the loaded set

Crucially, the *loaded* set is recorded — not the caller-supplied set. If a
caller passes three roots but only two are present in NVM, the cache slot
records the two-element loaded set. Forwarding the three-element supplied
set instead would let a stale entry under the missing root match a verify
whose effective trust store does not contain that root.

Insertion is deduplicated on exact `(set, hash)` match under the cache lock, so
concurrent inserts of the same verify collapse to a single slot. Two
entries with the same hash but different sets coexist: each is an
independent claim about a distinct verify, and dropping either could lose
hit coverage for callers whose loaded set is a superset of one but not the
other.

The ring overwrites using a FIFO pattern once full.

### 6.4 Cache lifecycle and eviction

Five mutation paths interact with the cache:

- **`wh_Client_CertAddTrusted`** evicts every cache slot whose stored set
  contains the affected root id. `AddObject` supersedes any prior object at
  that id, so cached verifies anchored at the previous root would otherwise
  short-circuit a verify under the new (different) root resident at that id.
- **`wh_Client_CertEraseTrusted`** evicts the same way. Without this, a
  later `AddTrusted` reusing the freed id would inherit phantom cache hits
  from the now-departed root.
- **`wh_Client_CertVerifyCacheClear`** drops every slot.
- **`wh_Client_CertVerifyCacheSetEnabled`** with `enable=0` drops every
  slot and suppresses subsequent Lookup / Insert until re-enabled.
  Re-enabling resumes caching from an empty state.
- **`wh_Client_CertInit`** drops every slot in **per-client mode only**.
  Under `WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL` the cache lives in
  the shared NVM context and is initialized exactly once in `wh_Nvm_Init` —
  clearing it on a per-client `CertInit` would wipe entries populated by
  other clients.

Eviction happens on success only. Otherwise, a failed `AddTrusted` or
`EraseTrusted` leaves the prior root and any cache entries bound to it in
place.

### 6.5 Per-client vs global mode

By default the cache lives in `whServerCertContext` and is per-server (and
therefore per-client connection). Each client connection sees its own slots
and its own hit rate; a verify under client A does not warm client B's
cache.

`WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL` relocates the cache into the
shared NVM context, where every connected client shares one `whCertVerify­
CacheContext`. Hits then apply across client boundaries: once any client
has verified a CA against root R, every client whose loaded root set
contains R hits the cache for that CA.

Global mode adds a dedicated lock embedded in the cache so cache operations
do not serialize behind general NVM I/O. In per-client mode the cache
piggybacks on the NVM lock — adequate given the cache is private to one
server and `CertInit` resets it on each (re)connect.

In global mode the dedicated lock must be initialized by the deployment.
`whNvmConfig` gains a `certVerifyCacheLockConfig` field (`whLockConfig*`)
that is wired into the shared cache at `wh_Nvm_Init`. It must reference a
distinct platform lock context from the NVM `lockConfig` (e.g. a separate
`posixLockContext`) so the two locks back independent mutexes; pointing
both at the same context would re-serialize cache operations behind NVM
I/O and defeat the point. Pass `NULL` for no-op locking on single-threaded
builds (`WOLFHSM_CFG_THREADSAFE` undefined drops the field entirely).

### 6.6 The user-supplied verify callback

The verify callback is independent of the verify cache — it is available on
any build with `WOLFHSM_CFG_CERTIFICATE_MANAGER` and is documented here
because its only subtle behavior is how it interacts with the cache.

**Registration.** `whServerConfig` carries an optional
`whServerCertConfig* certConfig` field whose `verifyCb` member is the
callback applied to every per-request `WOLFSSL_CERT_MANAGER`. `certConfig`
is optional; leaving it `NULL` (or leaving `verifyCb` `NULL` inside it) is
the no-callback default. The signature matches wolfSSL's `VerifyCallback`
exactly, so a callback that works with `wolfSSL_CertManagerSetVerify` works
here unchanged.

```c
/* Server-side registration at init */
whServerCertConfig certCfg = { .verifyCb = my_verify_cb };
whServerConfig     srvCfg  = { /* ... */, .certConfig = &certCfg };
wh_Server_Init(server, &srvCfg);
```

The callback can also be replaced (or removed) at runtime:

```c
int wh_Server_CertSetVerifyCb(whServerContext* server, VerifyCallback cb);
```

Pass `NULL` to unregister. The change applies to subsequent verify requests;
in-flight requests continue to use whichever callback was registered when
they entered `wh_Server_CertVerifyMultiRoot`. Both registration paths are
server-side only — there is no client API for installing or replacing the
callback, because the callback executes in the trusted server context.

**Lifecycle.** The callback is installed on a fresh per-request
`WOLFSSL_CERT_MANAGER` via `wolfSSL_CertManagerSetVerify` immediately after
the cert manager is constructed and before any roots are loaded. wolfSSL
invokes it during chain walk inside `wolfSSL_CertManagerVerifyBuffer`.

**Cache interaction.** Verify-cache hits short-circuit
`wolfSSL_CertManagerVerifyBuffer` and so deliberately **do not** invoke the
callback. Callbacks that gate on properties other than wolfSSL's standard
chain validation (e.g. policy OIDs, EKU pinning, application-specific
revocation checks) therefore see only the first verify of a given CA cert
under a given root set — subsequent hits silently bypass them. Deployments
that rely on the callback as a hard gate should disable the verify cache
via `wh_Client_CertVerifyCacheSetEnabled(c, 0, ...)` (or omit
`WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE` at build time).

## 7. Multi-Root and the Verify Cache Together

When both features are compiled in, the cache participates in both
single-root and multi-root verifies. The combination preserves the
single-root behavior exactly while extending hit semantics to the larger
trust-set landscape multi-root callers create. The interaction has three
corner cases worth being explicit about.

### 7.1 Cache entries record which roots were actually used, not which were asked for

A multi-root verify request lists the trusted roots the caller is willing
to trust, but some of those roots may not currently exist in NVM. The
server skips any missing roots and only loads the ones it finds, so the
trust store the chain is actually verified against can be smaller than the
list the caller supplied.

When a successful verify produces a new cache entry, the entry remembers
that smaller, real trust store — not the original request. For example, a
caller that asks for eight roots but only has three present in NVM
produces a three-root cache entry, not an eight-root one.

This matters because cache lookups use the subset rule: an entry hits only
when its recorded roots are all present in the looking-up caller's
currently-loaded set. Recording roots that were never actually loaded
would let a future verify hit an entry under a root that wasn't part of
the trust store when the cached chain originally validated, and the
subset rule's soundness argument would no longer hold.

### 7.2 Single-root verifies populate the cache too — and produce the broadest entries

The single-root path is implemented as a one-element multi-root call.
Successful single-root verifies therefore insert one-element entries
(`{R}`) — the narrowest possible set. Under the subset rule, those entries
are also the most reusable: any future multi-root call whose loaded set
contains `R` (e.g. `{R, R₂}`, `{R, R₂, R₃}`) hits.

Multi-root entries with larger sets (`{R₁, R₂, R₃}`) have correspondingly
narrower reuse — only future verifies whose loaded set is a superset
(`{R₁, R₂, R₃}` itself, or `{R₁, R₂, R₃, R₄}`, etc.) will hit. They are
still useful: they capture verifies that pure single-root traffic would
not generate.

A practical consequence: if a deployment runs both single-root traffic
against `R₁` and multi-root traffic against `{R₁, R₂}`, the single-root
verifies populate `{R₁}`-bound entries that the multi-root traffic also
hits, while the multi-root verifies populate `{R₁, R₂}`-bound entries that
do *not* serve future single-root `{R₁}` traffic. The cache is therefore
biased toward maximizing reuse from single-root callers.

### 7.3 A single root rotation invalidates entries across both paths

`AddTrusted` and `EraseTrusted` call `CertVerifyCache_EvictRoot(id)`, which
drops every slot whose recorded set *contains* `id`. This does the right
thing for both single- and multi-root populated entries:

- A `{R₁}` entry is dropped on a rotation of `R₁` and is unaffected by
  rotations of any other root — exactly what monotonicity demands.
- A `{R₁, R₂}` entry is dropped on a rotation of either `R₁` or `R₂`. The
  original verify may have anchored at the rotated root, and the remaining
  set is no longer a sound claim about which stores still validate the
  chain. Stripping just the rotated id from the set would leave a slot
  that falsely claims `{R_other}` validated this chain on its own.

A multi-root caller's "live" cache footprint therefore depends on the
stability of every root in its supplied sets, not just the one that
ultimately anchored. This is intrinsic to the soundness argument — the
cache cannot identify which anchor closed any given chain after the fact —
and is the trade-off paid for cross-anchor cache reuse.

### 7.4 Cache miss falls back to the regular multi-root path

A miss does not change semantics relative to a no-cache build: the server
runs `wolfSSL_CertManagerVerifyBuffer` against the populated cert manager
just as it would have without the cache. There is no path by which a miss
weakens the verify; the cache is a pure performance optimization.

### 7.5 Recommendations

- Provision long-lived roots with stable NVM ids when targeting a high
  cache hit rate. Frequent rotations will keep the cache cold.
- Prefer per-client mode (the default) when client trust stores diverge
  significantly. Prefer global mode when most clients verify against the
  same set of roots (e.g. fleet-uniform PKI).
- Single-root callers benefit from the cache without any additional design.
  Multi-root callers benefit most when the supplied set is reasonably
  stable across calls — the recorded set is what determines hit eligibility
  for downstream traffic.

## 8. Worked Example

Provision two roots, verify a chain against either, and cache the leaf
public key for subsequent signing-key lookup:

```c
whClientContext* c = /* ... */;
whNvmId rootIds[2] = { 100, 101 };
int32_t rc;
whKeyId leafKeyId = WH_KEYID_ERASED;

/* One-time provisioning (can also be done offline) */
wh_Client_CertInit(c, &rc);
wh_Client_CertAddTrusted(c, rootIds[0], WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
                         (uint8_t*)"primary", 7,
                         primary_root_der, primary_root_len, &rc);
wh_Client_CertAddTrusted(c, rootIds[1], WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
                         (uint8_t*)"backup",  6,
                         backup_root_der,  backup_root_len,  &rc);

/* Verify a chain against either root and cache the leaf public key */
int ret = wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
    c, chain_der, chain_len, rootIds, 2,
    WH_NVM_FLAGS_USAGE_VERIFY, &leafKeyId, &rc);

if (ret == WH_ERROR_OK && rc == WH_ERROR_OK) {
    /* leafKeyId now refers to the leaf cert's public key in the server's
     * key cache; subsequent crypto operations can use it by id. With the verify
     * cache enabled, a repeat verify of this chain against this root set hits
     * the cache for every CA in the chain and skips the wolfSSL signature path.
     */
}
```

