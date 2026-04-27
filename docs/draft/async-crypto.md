# Async Crypto API

**Status: Work in Progress**

## Background: Crypto in wolfHSM Today

wolfHSM offloads cryptographic operations from a client application to a secure
server (typically running on an HSM or trusted core) using a request/response
protocol over a shared communication buffer.  Today this works through
wolfCrypt's **crypto callback** mechanism:

1. The application initializes a wolfCrypt context with `devId = WH_DEV_ID`.
2. When a wolfCrypt function (`wc_Sha256Update`, `wc_AesCbcEncrypt`, etc.) is
   called, wolfCrypt invokes the registered callback `wh_Client_CryptoCb`.
3. The callback serializes the operation into the comm buffer, sends the request
   to the server, and **blocks** polling `wh_Client_RecvResponse()` until the
   server replies.
4. The result is deserialized and returned to the caller.

This is transparent to application code -- standard wolfCrypt API calls "just
work" -- but every crypto operation is **synchronous and blocking**.  The client
thread cannot do useful work while the server is processing.  On embedded
targets where the transport is shared memory and the server runs on a different
core, this means the client core sits idle for the entire round-trip.

### Why Blocking is a Problem

- **CPU waste**: the client spins in a polling loop while the HSM computes.
- **No pipelining**: multi-step operations (e.g., hashing a large file followed
  by signing the digest) cannot overlap.
- **RTOS integration**: a blocking call cannot yield to higher-priority tasks
  or cooperate with event-driven schedulers.

## The Async Crypto API

The async crypto API introduces a **non-blocking request/response split** for
each cryptographic operation.  Every blocking function is decomposed into:

- **`*Request()`** -- serializes and sends the request.  Returns immediately.
- **`*Response()`** -- attempts a single non-blocking receive.  Returns
  `WH_ERROR_NOTREADY` if the server has not yet replied, or the final result
  on completion.

The existing blocking functions are retained as thin wrappers that call
`Request()` then poll `Response()` in a loop.  The crypto callback path
(`wh_Client_CryptoCb`) continues to use these blocking wrappers, so existing
application code is unaffected.

```
                          +-----------+
  Application             |           |
  (async)                 |  wolfHSM  |
       |                  |  Server   |
       |-- Request() ---->|           |
       |                  |  (compute)|
       | (do other work)  |           |
       |                  |           |
       |<-- Response() ---|           |
       |   WH_ERROR_NOTREADY          |
       |                  |           |
       |<-- Response() ---|           |
       |   WH_ERROR_OK    |           |
       |   (result)       +-----------+
```

### Design Principles

- **Stateless responses**: output buffers are passed as parameters to the
  Response function, not stored in `whClientContext`.
- **No server-side changes**: the server already handles each request
  independently -- it doesn't know or care whether the client blocked.
- **Preserve existing wire formats where possible**: for operations whose
  request/response layout is already suitable, the async API only changes the
  client-side calling pattern. Some algorithms (notably the SHA family) still
  require new message layouts to carry async-specific inputs such as
  intermediate state, variable-length trailing input, and DMA metadata.
- **Pre-cached keys required**: async Request functions require keys to already
  be cached on the server.  The blocking wrappers retain automatic key import
  for convenience.
- **One outstanding request per client context**: only one async crypto
  request may be in flight at a time on a given `whClientContext`.

### Usage Pattern

```c
/* Send the request */
ret = wh_Client_EccSignRequest(ctx, key, hash, hashLen);
if (ret != WH_ERROR_OK) { /* handle error */ }

/* ... do other work while server computes ... */

/* Poll for completion */
do {
    ret = wh_Client_EccSignResponse(ctx, sig, &sigLen);
    if (ret == WH_ERROR_NOTREADY) {
        /* yield to scheduler, do other work, etc. */
    }
} while (ret == WH_ERROR_NOTREADY);
/* ret has final result, sig/sigLen are populated */
```

## SHA: The First Async Algorithm

SHA hash functions are the first algorithm family to receive the async
treatment.  All four SHA-2 variants are supported: SHA-224, SHA-256, SHA-384,
and SHA-512.

SHA is a particularly interesting case because hashing is inherently a
**streaming, multi-call** operation (`Init` / `Update*` / `Final`), unlike
single-shot operations like RSA sign or AES-CBC encrypt where one
request/response round-trip suffices.  The async SHA API must handle:

- Inputs that vastly exceed the communication buffer size
- Partial-block buffering on the client
- Intermediate hash state that must be preserved across round-trips
- A stateless server that reconstructs state from each request

### Wire Protocol

Each SHA request carries the **full intermediate hash state** inline so the
server can process the data statelessly.  The wire layout in the comm buffer
is:

```
+------------------------------------------+
| GenericRequestHeader (12 bytes)          |  algo type, affinity
+------------------------------------------+
| Sha256Request / Sha512Request            |  resumeState + control fields
|   resumeState.hiLen     (4 bytes)        |
|   resumeState.loLen     (4 bytes)        |
|   resumeState.hash      (32 or 64 bytes) |  intermediate digest
|   [resumeState.hashType (4 bytes)]       |  SHA-512 family only
|   isLastBlock           (4 bytes)        |
|   inSz                  (4 bytes)        |
+------------------------------------------+
| uint8_t in[inSz]                         |  variable-length input data
+------------------------------------------+
```

The response carries the updated state (or final digest) back:

```
+------------------------------------------+
| GenericResponseHeader (12 bytes)         |  algo type, return code
+------------------------------------------+
| Sha2Response                             |
|   hiLen, loLen          (8 bytes)        |
|   hash                  (64 bytes)       |  updated/final digest
|   hashType              (4 bytes)        |
+------------------------------------------+
```

### Block Alignment and MTU Filling

The comm buffer has a fixed size (`WOLFHSM_CFG_COMM_DATA_LEN`, default 1280
bytes).  The async SHA design maximizes throughput by packing as many **whole
hash blocks** into each message as possible.

SHA-256 and SHA-224 use a 64-byte block size.  SHA-384 and SHA-512 use 128
bytes.  The maximum inline data capacity per message is:

```c
#define WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ       \
    (((WOLFHSM_CFG_COMM_DATA_LEN                           \
       - sizeof(whMessageCrypto_GenericRequestHeader)       \
       - sizeof(whMessageCrypto_Sha256Request))             \
      / 64u) * 64u)
```

This rounds **down** to the nearest block boundary so that non-final Update
messages always carry whole blocks.

With the default 1280-byte comm buffer:

| Variant        | Header Overhead | Block Size | Max Inline Data | Blocks/Message |
|----------------|-----------------|------------|-----------------|----------------|
| SHA-256/224    | 60 bytes        | 64 bytes   | 1216 bytes      | 19 blocks      |
| SHA-512/384    | 96 bytes        | 128 bytes  | 1152 bytes      | 9 blocks       |

> *Header overhead = GenericRequestHeader (12 bytes) + algorithm-specific
> request struct (48 bytes for SHA-256, 84 bytes for SHA-512).*

The per-call capacity is slightly larger than the inline wire capacity because
the client can absorb up to `BLOCK_SIZE - 1` additional tail bytes into its
local buffer without needing to send them:

```c
capacity = MAX_INLINE_UPDATE_SZ + (BLOCK_SIZE - 1 - sha->buffLen)
```

### Client-Side Partial-Block Buffering

The SHA block cipher operates on fixed-size blocks (64 or 128 bytes).  When the
caller provides input that isn't block-aligned, the client must buffer the
partial tail locally until enough data arrives to form a complete block.  This
buffering uses the `buffer` and `buffLen` fields already present in wolfCrypt's
`wc_Sha256` (and related) structures -- no additional memory is needed.

The Update request function performs three steps:

1. **Top up the existing partial block**: if there are already bytes buffered
   from a previous call (`buffLen > 0`), pull bytes from the new input until
   either a full block is assembled or the input is exhausted.  If a full block
   is formed, it becomes the first inline block on the wire.

2. **Pack whole blocks from input**: copy as many remaining complete blocks from
   the caller's input as fit in the inline data area.

3. **Stash the tail**: any leftover bytes (less than one block) go into the
   local buffer for the next call.

```
  Caller input (e.g., 200 bytes, buffLen=30 from prior call):
  ┌──────────────────────────────────────────────────────────┐
  │ input data (200 bytes)                                   │
  └──────────────────────────────────────────────────────────┘

  Step 1: Top up partial block (34 bytes from input complete the block)
  ┌────────┬──────────────────────────────────────────────────┐
  │buff(30)│ 34 bytes │                                       │
  └────────┴──────────┘  remaining: 166 bytes                 │
           ↓                                                  │
  [Block 0: 64 bytes] → wire                                  │
                                                              │
  Step 2: Pack whole blocks (2 more blocks = 128 bytes)       │
  [Block 1: 64 bytes] → wire                                  │
  [Block 2: 64 bytes] → wire                                  │
                                                              │
  Step 3: Stash tail (166 - 128 = 38 bytes)                   │
  buffLen = 38                                                │
                                                              │
  Wire payload: 192 bytes (3 blocks)                          │
  └───────────────────────────────────────────────────────────┘
```

If the total input is small enough to fit entirely in the partial-block buffer
without completing a block, no server round-trip is issued at all.  The
`requestSent` output flag tells the caller whether a matching `*Response()` call
is needed:

```c
bool requestSent;
ret = wh_Client_Sha256UpdateRequest(ctx, sha, smallData, 10, &requestSent);
/* requestSent == false: data absorbed locally, no Response needed */
```

### State Rollback on Send Failure

Before mutating the buffer state, the Request function snapshots `buffLen` and
the partial buffer contents.  If `wh_Client_SendRequest()` fails (e.g.,
transport error), the snapshot is restored so the caller can retry without data
loss:

```c
/* Save state before mutation */
savedBuffLen = sha->buffLen;
memcpy(savedBuffer, sha->buffer, sha->buffLen);

/* ... mutate buffer, assemble wire payload ... */

ret = wh_Client_SendRequest(...);
if (ret != 0) {
    /* Restore -- SHA state is as if the call never happened */
    sha->buffLen = savedBuffLen;
    memcpy(sha->buffer, savedBuffer, savedBuffLen);
}
```

### Finalization

The Final request sends whatever partial data remains in the client's buffer
(0 to `BLOCK_SIZE - 1` bytes) with `isLastBlock = 1`.  The server handles
the padding and produces the final digest.  The Final response copies the
digest to the caller's output buffer and resets the `wc_Sha*` context (via
`wc_InitSha*_ex`, preserving `devId`).

### Stateless Server

The server is fully stateless with respect to SHA operations.  Each request
carries the complete intermediate hash state (`digest`, `loLen`, `hiLen`) in
the `resumeState` field.  The server:

1. Initializes a fresh `wc_Sha256` (or variant) context.
2. Restores `digest`, `loLen`, `hiLen` from the request.
3. Calls `wc_Sha256Update()` with the inline data.
4. If `isLastBlock`, calls `wc_Sha256Final()` and returns the digest.
5. Otherwise, returns the updated intermediate state.

This design has a key benefit: **no server-side per-client hash state is
needed**.  The server can handle SHA requests from multiple clients
interleaved without any context tracking.  The tradeoff is larger messages
(~40-84 bytes of state overhead per request), which is negligible relative to
the data payload.

The server also enforces invariants:
- Non-final updates: `inSz` must be a multiple of the block size.
- Final: `inSz` must be strictly less than one block.
- After processing a non-final update, `buffLen` must be 0 (sanity check).

### Blocking Wrapper

The existing `wh_Client_Sha256()` function is retained as a blocking wrapper
that loops over the async primitives:

```c
int wh_Client_Sha256(whClientContext* ctx, wc_Sha256* sha256,
                     const uint8_t* in, uint32_t inLen, uint8_t* out)
{
    /* Update phase: chunk input to fit per-call capacity */
    while (consumed < inLen) {
        capacity = _Sha256UpdatePerCallCapacity(sha256);
        chunk    = min(remaining, capacity);

        wh_Client_Sha256UpdateRequest(ctx, sha256, in + consumed, chunk, &sent);
        if (sent) {
            do {
                ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
            } while (ret == WH_ERROR_NOTREADY);
        }
        consumed += chunk;
    }

    /* Final phase */
    wh_Client_Sha256FinalRequest(ctx, sha256);
    do {
        ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
    } while (ret == WH_ERROR_NOTREADY);
}
```

The crypto callback (`wh_Client_CryptoCb`) calls this blocking wrapper, so
existing code using `wc_Sha256Update()` / `wc_Sha256Final()` with
`devId = WH_DEV_ID` continues to work identically.

### DMA Variant

When `WOLFHSM_CFG_DMA` is enabled, a parallel set of DMA async functions is
available.  The DMA variant differs from the inline variant in how bulk data
reaches the server:

- **Inline (non-DMA)**: all input data is copied into the comm buffer message.
- **DMA**: whole blocks are referenced by address via a `DmaBuffer` descriptor
  (the server reads them directly from client memory).  Only the assembled first
  block (from the partial buffer) or the final tail travels inline.

The hash state (`resumeState`) always travels **inline**, not via DMA, for
cross-architecture concerns (endian translation, etc.)

DMA async functions require the client to stash the translated DMA address
across the Request/Response boundary for POST cleanup.  This context is stored
in `whClientContext.dma.asyncCtx.sha`:

```c
typedef struct {
    uintptr_t ioAddr;      /* translated DMA address for POST */
    uintptr_t clientAddr;  /* original client address for POST */
    uint64_t  ioSz;        /* DMA'd size for POST */
} whClientDmaAsyncSha;
```

### API Reference

All variants follow the same pattern.  SHA-224 uses the SHA-256 wire format
(same block size); SHA-384 uses the SHA-512 wire format.

#### Non-DMA

```c
/* SHA-256 */
int wh_Client_Sha256UpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent);
int wh_Client_Sha256UpdateResponse(whClientContext* ctx, wc_Sha256* sha);
int wh_Client_Sha256FinalRequest(whClientContext* ctx, wc_Sha256* sha);
int wh_Client_Sha256FinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                  uint8_t* out);

/* SHA-224: identical pattern, s/256/224/ */
/* SHA-384: identical pattern, s/256/384/, uses SHA-512 wire format */
/* SHA-512: identical pattern, s/256/512/ */
```

#### DMA

```c
/* SHA-256 DMA (requires WOLFHSM_CFG_DMA) */
int wh_Client_Sha256DmaUpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent);
int wh_Client_Sha256DmaUpdateResponse(whClientContext* ctx, wc_Sha256* sha);
int wh_Client_Sha256DmaFinalRequest(whClientContext* ctx, wc_Sha256* sha);
int wh_Client_Sha256DmaFinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                     uint8_t* out);

/* SHA-224, SHA-384, SHA-512: same pattern */
```

#### Blocking (unchanged, now wraps async internally)

```c
int wh_Client_Sha256(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                     uint32_t inLen, uint8_t* out);
int wh_Client_Sha256Dma(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out);
/* SHA-224, SHA-384, SHA-512: same pattern */
```

### Design Tradeoffs

| Decision | Tradeoff |
|----------|----------|
| **State on wire** | Larger messages (~40-84 bytes overhead), but the server is fully stateless and needs no per-client hash context |
| **Whole-block alignment** | Wastes up to `BLOCK_SIZE - 1` bytes of comm buffer capacity per message, but guarantees the server never has a partial block (simplifies server logic and invariant checking) |
| **Client-side partial buffering** | Requires wolfCrypt's buffer/buffLen fields, but avoids allocating separate storage and enables the `requestSent` optimization for small inputs |
| **Per-call capacity limit** | Callers of the async API must respect the capacity and chunk large inputs themselves (the blocking wrapper handles this automatically), but each call is bounded and predictable |
| **`requestSent` flag** | Adds a parameter to the API, but avoids unnecessary round-trips when input is absorbed entirely into the local buffer |
| **Snapshot/rollback on send failure** | Small CPU cost to copy the partial buffer, but guarantees SHA state consistency even on transport failures |

## RNG: Single-Shot with Caller-Driven Chunking

The RNG generate operation is the second algorithm to receive the async
treatment.  Unlike SHA, RNG is **single-shot** -- there is no intermediate
state to carry, no partial-block buffering, and no multi-call Init/Update/Final
sequence.  Each Request asks for N random bytes and the matching Response
delivers them.

RNG is still interesting because the existing blocking API silently chunks
large requests into multiple round-trips when the caller asks for more bytes
than fit in one comm-buffer message.  The async split has to decide where
that chunking logic lives.

### Chunking Policy

The async Request/Response pair is **single-shot per call**: one Request
produces one Response.  Callers requesting more bytes than fit in a single
inline message must loop themselves.  The per-call inline cap is exposed as:

```c
#define WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ                    \
    (WOLFHSM_CFG_COMM_DATA_LEN -                               \
     (uint32_t)sizeof(whMessageCrypto_GenericResponseHeader) - \
     (uint32_t)sizeof(whMessageCrypto_RngResponse))
```

Requests exceeding this cap (or of size zero) are rejected with
`WH_ERROR_BADARGS` before any bytes hit the wire.

The existing blocking `wh_Client_RngGenerate()` function is retained as a
thin wrapper that chunks internally against the cap, so application code
using the wolfCrypt RNG callback path continues to work without changes:

```c
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    while (remaining > 0) {
        uint32_t chunk = min(remaining, WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ);
        uint32_t got   = chunk;
        wh_Client_RngGenerateRequest(ctx, chunk);
        do {
            ret = wh_Client_RngGenerateResponse(ctx, out, &got);
        } while (ret == WH_ERROR_NOTREADY);
        out += got; remaining -= got;
    }
}
```

This keeps the async primitives predictable (each call is bounded by a single
round trip) and pushes the scheduling decision -- "when should I yield
between chunks?" -- up to the async caller, who is the only one with enough
context to answer it.

### Response Size Negotiation

The Response function takes an `inout_size` parameter: on entry it is the
capacity of the output buffer; on exit it is the actual number of bytes the
server wrote.  This lets the caller distinguish short reads from bugs:

```c
uint32_t got = requested;
ret = wh_Client_RngGenerateResponse(ctx, out, &got);
/* got may be < requested if the server returned a shorter reply */
```

If the server somehow returns more bytes than the caller's buffer can hold
(should not happen, but defended against), the Response returns
`WH_ERROR_ABORTED` instead of overflowing.

### DMA Variant

The DMA variant bypasses the comm buffer entirely for the data payload: the
server writes random bytes directly into the client's output buffer via
translated DMA addresses.  The Request/Response split introduces the same
address-stashing pattern used by SHA DMA:

```c
typedef struct {
    uintptr_t outAddr;     /* translated DMA address */
    uintptr_t clientAddr;  /* original client address (for POST) */
    uint64_t  outSz;       /* DMA'd size (0 means "nothing to clean up") */
} whClientDmaAsyncRng;
```

Stored in `whClientContext.dma.asyncCtx.rng`, this context carries the
translated address across the Request/Response boundary so the Response can
perform the matching POST cleanup.

Two points worth calling out:

- **Fail-fast on occupied transport**: the DMA Request checks
  `wh_CommClient_IsRequestPending()` *before* acquiring the DMA mapping.
  Without this check, a request that would be rejected by `SendRequest` would
  still leave a leaked DMA mapping behind, because the Response (which
  normally releases the mapping) would never run.
- **POST runs on every non-NOTREADY exit**: once the Response receives a
  reply -- success or otherwise -- it performs the POST cleanup
  unconditionally, so the client buffer is safe to read regardless of the
  final return code.

Unlike the non-DMA variant, the DMA variant has no per-call size cap: the
server writes directly to client memory, so a single DMA call can fulfill
arbitrarily large requests.

### API Reference

```c
/* Non-DMA */
int wh_Client_RngGenerateRequest(whClientContext* ctx, uint32_t size);
int wh_Client_RngGenerateResponse(whClientContext* ctx, uint8_t* out,
                                  uint32_t* inout_size);

/* DMA (requires WOLFHSM_CFG_DMA) */
int wh_Client_RngGenerateDmaRequest(whClientContext* ctx, uint8_t* out,
                                    uint32_t size);
int wh_Client_RngGenerateDmaResponse(whClientContext* ctx);

/* Blocking (unchanged; now wraps the async primitives and chunks internally) */
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size);
int wh_Client_RngGenerateDma(whClientContext* ctx, uint8_t* out, uint32_t size);
```

## AES: One-Shot with DMA Support

AES modes (CBC, CTR, ECB, GCM) are all **one-shot** operations — every call
consumes a fixed buffer of input and returns a fixed buffer of output. There
is no streaming state to accumulate across multiple Request/Response pairs
the way SHA does, which makes the async split significantly simpler than
SHA:

- **No partial-block buffering** on the client.  The entire plaintext or
  ciphertext is handed to one Request and the full result comes back in
  one Response.
- **No `requestSent` flag.**  Each call sends exactly one request and
  expects exactly one response.  If the request's serialised size would
  exceed `WOLFHSM_CFG_COMM_DATA_LEN`, the inline Request returns
  `WH_ERROR_BADARGS` up front; DMA variants bypass the cap for payload
  data.
- **No snapshot/rollback.**  There is no local buffer to corrupt: the key
  lives on `aes->devKey` (or as a cached keyId), the IV on `aes->reg`, and
  these are read-only until the Response arrives.

### Mutable state: IV and counter

For **CBC** and **CTR**, the Response updates mutable state on the `Aes`
struct so subsequent calls chain correctly:

- **CBC** — `aes->reg` is updated with the last ciphertext block. For
  decryption, the Request captures the last ciphertext block from the
  input buffer into `aes->reg` *before* sending, so in-place (input
  pointer == output pointer) operation still produces the right chaining
  state after the Response overwrites the plaintext.
- **CTR** — `aes->reg`, `aes->tmp`, and `aes->left` are updated from the
  Response so the counter advances correctly for subsequent calls.  CTR
  is symmetric: callers should use `AES_ENCRYPTION` for the key schedule
  and pass `enc = 1` in both directions.

**ECB** and **GCM** carry no inter-call state on the `Aes` struct.  For
GCM, the IV, AAD, and (on decrypt) the expected tag are passed as explicit
arguments on each call.

### DMA variant contract

The DMA pairs follow the same pattern as SHA DMA:

1. **Fail-fast** on `wh_CommClient_IsRequestPending()` before acquiring
   any DMA mapping, so a Request cannot be issued while another call is
   still outstanding and cannot leak a translated address if
   `wh_Client_SendRequest` later rejects the call.
2. **PRE-translate** input, output, and (for GCM) AAD buffers.  Non-DMA
   payload fields (key material, IV, auth tag) stay inline in the
   request message.
3. **Stash** the translated addresses in `ctx->dma.asyncCtx.aes` so the
   matching Response can issue POST cleanup.
4. **POST cleanup** runs on every non-`WH_ERROR_NOTREADY` return from the
   Response, so the caller's buffers are safe to read regardless of
   success or error.
5. The caller must keep the input, output, and AAD buffers valid until
   the Response returns something other than `WH_ERROR_NOTREADY`.

### API Reference

Inline (non-DMA) pairs:

- `wh_Client_AesCbcRequest` / `wh_Client_AesCbcResponse`
- `wh_Client_AesCtrRequest` / `wh_Client_AesCtrResponse`
- `wh_Client_AesEcbRequest` / `wh_Client_AesEcbResponse`
- `wh_Client_AesGcmRequest` / `wh_Client_AesGcmResponse`

DMA pairs (require `WOLFHSM_CFG_DMA`):

- `wh_Client_AesCbcDmaRequest` / `wh_Client_AesCbcDmaResponse`
- `wh_Client_AesCtrDmaRequest` / `wh_Client_AesCtrDmaResponse`
- `wh_Client_AesEcbDmaRequest` / `wh_Client_AesEcbDmaResponse`
- `wh_Client_AesGcmDmaRequest` / `wh_Client_AesGcmDmaResponse`

The existing blocking wrappers (`wh_Client_AesCbc`, `wh_Client_AesCtr`,
`wh_Client_AesEcb`, `wh_Client_AesGcm`, and their `*Dma` variants) are now
thin shells that call the new async primitives in a poll loop, so blocking
and async paths share identical wire behaviour.

## Roadmap: Remaining Algorithms

The async split pattern will be applied algorithm by algorithm to all crypto
operations currently handled by `wh_Client_CryptoCb`.  The table below shows
the full set of operations and their planned async status.

**Completed:**

| Algorithm      | Functions                        | Notes |
|----------------|----------------------------------|-------|
| SHA-256        | Update/Final Request/Response    | Non-DMA and DMA variants |
| SHA-224        | Update/Final Request/Response    | Shares SHA-256 wire format |
| SHA-384        | Update/Final Request/Response    | Shares SHA-512 wire format |
| SHA-512        | Update/Final Request/Response    | Non-DMA and DMA variants |
| RNG Generate   | `wh_Client_RngGenerate{Request,Response}` and DMA variants | Single-shot per call; non-DMA callers chunk against `WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ`, DMA has no per-call cap |
| AES-CBC        | `wh_Client_AesCbc{,Dma}{Request,Response}` | Non-DMA and DMA variants |
| AES-CTR        | `wh_Client_AesCtr{,Dma}{Request,Response}` | Non-DMA and DMA variants |
| AES-ECB        | `wh_Client_AesEcb{,Dma}{Request,Response}` | Non-DMA and DMA variants |
| AES-GCM        | `wh_Client_AesGcm{,Dma}{Request,Response}` | Non-DMA and DMA variants; AAD supports DMA |

**Planned:**

| Algorithm         | Functions                                  | Complexity | Notes |
|-------------------|--------------------------------------------|------------|-------|
| RSA Sign/Verify   | `wh_Client_RsaFunction{Request,Response}`  | Low        | Single-shot; may need auto-import removed from Request |
| RSA Get Size      | `wh_Client_RsaGetSize{Request,Response}`   | Low        | Trivial query |
| ECDSA Sign        | `wh_Client_EccSign{Request,Response}`      | Low        | Single-shot |
| ECDSA Verify      | `wh_Client_EccVerify{Request,Response}`    | Low        | Single-shot |
| ECDH              | `wh_Client_EccSharedSecret{Request,Response}` | Low     | Single-shot |
| Curve25519        | `wh_Client_Curve25519SharedSecret{Request,Response}` | Low | Single-shot |
| Ed25519 Sign      | `wh_Client_Ed25519Sign{Request,Response}`  | Low        | Single-shot |
| Ed25519 Verify    | `wh_Client_Ed25519Verify{Request,Response}`| Low        | Single-shot |
| CMAC              | `wh_Client_Cmac{Request,Response}`         | Medium     | Streaming (Init/Update/Final), so follows SHA-style pattern rather than the one-shot AES pattern |
| ML-DSA Sign       | `wh_Client_MlDsaSign{Request,Response}`    | Low        | Post-quantum; single-shot |
| ML-DSA Verify     | `wh_Client_MlDsaVerify{Request,Response}`  | Low        | Post-quantum; single-shot |

Most remaining algorithms are **single-shot** operations (one request, one
response) and are straightforward to split compared to SHA's streaming
semantics.  SHA was done first because it exercises the hardest design
constraints: multi-round-trip streaming, partial-block buffering, and state
resumption.

### Future: Async Crypto Callbacks

The long-term goal is to also make the **crypto callback path itself
asynchronous**, so that standard wolfCrypt API calls (`wc_Sha256Update`,
`wc_AesCbcEncrypt`, etc.) can return a "not ready" indicator and be resumed
later, rather than blocking.  This requires changes in wolfCrypt's crypto
callback infrastructure and is outside the scope of the current native async
API work.  The native async API being introduced here is a prerequisite: it
establishes the per-algorithm Request/Response split that a future async
callback mechanism will build upon.
