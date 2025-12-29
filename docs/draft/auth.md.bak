# wolfHSM Authentication Manager — PR #270 Overview (v2)

---

## 1. TL;DR

PR #270 introduces a **PKCS11-flavored Authentication/Authorization Manager** to wolfHSM. It provides:

- **Login/logout** with two credential methods: **PIN** (SHA-256 hashed) or **X.509 certificate**.
- A **user database** managed via add/delete/get and set-permissions / set-credentials APIs.
- A **permission model** of (admin flag) + (per-group allow boolean) + (per-group bitmap of 256 allowed actions) + (a small per-user list of accessible key IDs — not yet wired into crypto paths).
- A **server-side request gate** that, on every incoming request, consults the Auth Manager and rejects messages the current session is not permitted to run.
- A **message group** `WH_MESSAGE_GROUP_AUTH = 0x0D00` with 7 new actions (login, logout, user add/delete/get, set-permissions, set-credentials), complete with endian/magic translation functions.
- A **pluggable backend**: everything goes through a `whAuthCb` callback vtable. A default in-memory backend lives in `src/wh_auth_base.c` (up to 5 users, credential storage up to 2 KiB per user, used by examples and tests).
- The feature is **opt-in**: entire subsystem is guarded by `WOLFHSM_CFG_ENABLE_AUTHENTICATION`. With it compiled in but no context configured (`server->auth == NULL`), the server logs a SECEVENT and processes all requests without any authorization check — preserving backwards compatibility.

Design notes called out by the author:
- The "check key use" callback (`CheckKeyAuthorization`) is wired into the interface but **not yet invoked** on the key paths — it's a TODO placeholder.
- The base user list is in RAM, not NVM — deliberate for an initial cut.
- Logging of auth events (login success/failure, crypto actions) is another TODO, though authorization failures already log via `WH_LOG_ON_ERROR_F`.

---

## 2. High-level architecture

```
         ┌──────────────────────┐
         │      Client App      │
         │  wh_Client_Auth*()   │   client-side request/response helpers
         └──────────┬───────────┘
                    │  WH_MESSAGE_GROUP_AUTH (0x0D00)
                    │
     ┌──────────────▼────────────────────────────────────────────┐
     │                  Server dispatch                          │
     │  wh_Server_HandleRequestMessage()  (src/wh_server.c)      │
     │    1. Recv packet -> extract (group, action)              │
     │    2. wh_Auth_CheckRequestAuthorization(group, action)    │  <-- the gate
     │    3. Dispatch by group                                   │
     └──────────────┬─────────────────────────┬──────────────────┘
                    │                         │
        WH_MESSAGE_GROUP_AUTH            any other group
                    │                         │
                    ▼                         ▼
     ┌─────────────────────────┐   (NVM/key/crypto/SHE/etc. handlers;
     │ wh_Server_HandleAuth-   │    they do not re-check auth — the gate
     │ Request()               │    above has already vetted the call)
     │ (src/wh_server_auth.c)  │
     └───────┬─────────────────┘
             │ wh_Auth_Login / _Logout / _UserAdd / _UserDelete /
             │ _UserGet / _UserSetPermissions / _UserSetCredentials
             ▼
     ┌─────────────────────────┐
     │   Auth Manager core     │   transport/protocol-agnostic wrappers
     │   src/wh_auth.c         │   that take the lock and delegate to cb
     └───────┬─────────────────┘
             │ whAuthCb->Login / ->UserAdd / ...
             ▼
     ┌─────────────────────────┐
     │   Pluggable backend     │
     │   default: wh_auth_base │   in-memory user db, SHA-256 PIN hashing,
     │   (src/wh_auth_base.c)  │   optional wolfSSL cert verification
     └─────────────────────────┘
```

Key separation of concerns:

1. `wh_auth.h` / `wh_auth.c` — **the "front end":** public API, session state, locking, policy decisions (the default group+action bitmap check). Always compiled when auth is on; does not depend on any specific user-store format.
2. `wh_auth_base.h` / `wh_auth_base.c` — **reference backend:** owns the user list, hashes PINs, verifies certificates, stores permissions. Can be swapped for a custom backend by registering a different `whAuthCb` vtable.
3. `wh_message_auth.h` / `wh_message_auth.c` — wire format and endian translation for all 7 auth messages (plus a flatten/unflatten pair for the permissions struct, which is too large and array-heavy for the usual `WH_T*()` helpers).
4. `wh_server_auth.c` / `wh_client_auth.c` — the message handlers on each side, each of which lives under both `WOLFHSM_CFG_ENABLE_{SERVER,CLIENT}` and `WOLFHSM_CFG_ENABLE_AUTHENTICATION` guards.

---

## 3. Files touched (grouped)

| Area | Files |
|------|-------|
| New public headers | `wolfhsm/wh_auth.h`, `wolfhsm/wh_auth_base.h`, `wolfhsm/wh_message_auth.h`, `wolfhsm/wh_server_auth.h` |
| Core & base impl | `src/wh_auth.c`, `src/wh_auth_base.c`, `src/wh_message_auth.c` |
| Server integration | `src/wh_server.c`, `src/wh_server_auth.c`, `wolfhsm/wh_server.h` |
| Client integration | `src/wh_client.c`, `src/wh_client_auth.c`, `wolfhsm/wh_client.h` |
| Error / message enums | `wolfhsm/wh_error.h` (3 new codes), `wolfhsm/wh_message.h` (new group + actions) |
| Examples | `examples/posix/wh_posix_server/wh_posix_server_cfg.c`, `wh_posix_server_cfg.h`, `wh_posix_server.c`; `examples/posix/wh_posix_client/Makefile`; `examples/posix/wh_posix_server/Makefile`; `examples/demo/client/wh_demo_client_auth.{c,h}`; `examples/demo/client/wh_demo_client_all.c` |
| Tests | `test/wh_test_auth.{c,h}` (1440 LOC), hook-ins in `test/wh_test.c`, `wh_test_clientserver.c`, `wh_test_crypto.c`, `wh_test_keywrap.c`, `wh_test_she.c`, `wh_test_log.c`, `wh_test_posix_threadsafe_stress.c`, `wh_test_common.h`, `test/Makefile` |
| Misc | `src/wh_server_she.c` (SHE tests now log in as admin), `src/wh_utils.c` + `wolfhsm/wh_utils.h` (new `wh_Utils_ForceZero` and `wh_Utils_ConstantCompare`), `port/posix/posix_transport_tls.c`, CI workflows, `docs/src/chapter09.md` (new docs chapter) |

---

## 4. Data model (what an "individual user" looks like)

### 4.1 Identity: `whUserId`

`whUserId` is a `uint16_t`. Zero is reserved as `WH_USER_ID_INVALID`. The base backend assigns IDs 1..`WH_AUTH_BASE_MAX_USERS` (5 by default), where the ID is literally the 1-based slot in the static users array (`id = slot_index + 1`).

### 4.2 Credentials: `whAuthMethod`

```c
typedef enum {
    WH_AUTH_METHOD_NONE        = 0,
    WH_AUTH_METHOD_PIN,         // SHA-256 hashed when crypto is enabled
    WH_AUTH_METHOD_CERTIFICATE, // wolfSSL cert verification; gated on WOLFHSM_CFG_CERTIFICATE_MANAGER
} whAuthMethod;
```

- PIN: the base backend stores the 32-byte SHA-256 of the PIN (falls back to a direct copy when `WOLFHSM_CFG_NO_CRYPTO` is set). Comparison uses `wh_Utils_ConstantCompare` — a new utility added by this PR.
- Certificate: the user's stored "credential" is a CA in DER; login presents a leaf cert, which the base backend feeds through `wolfSSL_CertManagerLoadCABuffer` + `wolfSSL_CertManagerVerifyBuffer`.

### 4.3 Permissions: `whAuthPermissions`

#### 4.3.1 The two-tier concept

Every wolfHSM request on the wire is identified by a 16-bit `kind` that splits into:

- **Group** (high byte): the category of operation. `WH_MESSAGE_GROUP_*` defines 13 groups today (`wolfhsm/wh_message.h:38-50`): `COMM=0x0100`, `NVM=0x0200`, `KEY=0x0300`, `CRYPTO=0x0400`, `IMAGE=0x0500`, `PKCS11=0x0600`, `SHE=0x0700`, `COUNTER=0x0800`, `CUSTOM=0x0A00`, `CRYPTO_DMA=0x0B00`, `CERT=0x0C00`, `AUTH=0x0D00`.
- **Action** (low byte): the specific operation within that group. Action enums are *group-local* — `KEY_CACHE` and `CRYPTO_SIGN` may both be value `0`, but they live in different groups so they're unambiguous in context.

The auth manager mirrors that split in the user's `whAuthPermissions` struct as **two independent filters that both must pass** before a request is admitted to its handler:

```c
typedef struct {
    uint8_t   groupPermissions[WH_NUMBER_OF_GROUPS + 1];           // boolean allow per group; last byte = admin flag
    uint32_t  actionPermissions[WH_NUMBER_OF_GROUPS][WH_AUTH_ACTION_WORDS]; // 256 bits per group (8 x uint32_t)
    uint16_t  keyIdCount;
    uint32_t  keyIds[WH_AUTH_MAX_KEY_IDS];                          // small allowlist; default WH_AUTH_MAX_KEY_IDS = 2
} whAuthPermissions;
```

#### 4.3.2 Filter 1 — group boolean

`groupPermissions[groupIndex]` (where `groupIndex = (group >> 8) & 0xFF`) is a single byte: nonzero means "this user is allowed to talk to this group at all." If it's 0, the request is denied without ever looking at the bitmap. It's a fast reject path *and* a coarse on/off switch — useful for "this user only ever uses NVM, never crypto."

The `+1` slot at the end (`groupPermissions[WH_NUMBER_OF_GROUPS]`) is reused as the **admin flag** — `WH_AUTH_IS_ADMIN(p)` reads it. Admin isn't a group; it's a separate capability that gates things like `UserAdd` of another admin and cross-user logout.

#### 4.3.3 Filter 2 — action bitmap

If the group passes, the gate then checks the per-group **256-bit bitmap** stored as 8 × `uint32_t`. The mapping is straightforward (`wolfhsm/wh_auth.h:79`):

```c
wordIdx = action / 32
bitMask = 1U << (action % 32)
allowed = actionPermissions[groupIndex][wordIdx] & bitMask
```

Wire actions are `uint16_t`, so 65 536 are theoretically possible — the model caps at 256 and rejects anything beyond. That's a deliberate trade: 256 bits per group keeps the struct flat and copy-friendly (the whole `whAuthPermissions` flattens to ~473 bytes for the wire) at the cost of an upper limit on actions per group. Today no group comes close.

#### 4.3.4 Derived constants and byte shape

- `WH_NUMBER_OF_GROUPS = (WH_MESSAGE_GROUP_MAX >> 8) + 1` — currently 14, since `WH_MESSAGE_GROUP_MAX = WH_MESSAGE_GROUP_AUTH = 0x0D00`.
- `WH_AUTH_ACTIONS_PER_GROUP = 256`, `WH_AUTH_ACTION_WORDS = 8`.

Shape in bytes (exactly what gets flattened on the wire, `WH_FLAT_PERMISSIONS_LEN`):
```
(WH_NUMBER_OF_GROUPS + 1)                  // group booleans + admin
+ 4 * WH_NUMBER_OF_GROUPS * WH_AUTH_ACTION_WORDS  // action bitmap (per-group)
+ 2                                         // keyIdCount
+ 4 * WH_AUTH_MAX_KEY_IDS                   // keyIds
= 15 + (4 * 14 * 8) + 2 + 8 = 473 bytes     // with current defaults
```

#### 4.3.5 Helper macros

The two filters compose through the macros in `wolfhsm/wh_auth.h:86-125`:

| Macro | Group byte | Action bitmap |
|-------|------------|---------------|
| `WH_AUTH_IS_ADMIN(p)` | reads admin slot (byte index `WH_NUMBER_OF_GROUPS`) | — |
| `WH_AUTH_SET_IS_ADMIN(p, v)` | writes admin slot (`v ? 1 : 0`) | — |
| `WH_AUTH_SET_ALLOWED_GROUP(p, group)` | set to 1 | set all 256 bits |
| `WH_AUTH_SET_ALLOWED_ACTION(p, group, action)` | set to 1 | OR in one bit (existing bits preserved — Copilot flagged a mismatch with the header comment that says "only the given action bit") |
| `WH_AUTH_CLEAR_ALLOWED_GROUP(p, group)` | set to 0 | zero all bits |
| `WH_AUTH_CLEAR_ALLOWED_ACTION(p, group, action)` | left alone | clear one bit |

So enabling a single action also implicitly enables its group, but disabling a single action leaves the group enabled (you can still use *other* actions in it). Disabling the group nukes everything.

#### 4.3.6 Worked examples

**Crypto-only signer:** group byte set for `CRYPTO`, only the `SIGN` action bit set in the CRYPTO bitmap, every other group byte = 0. Any NVM/KEY/IMAGE/etc. request hits filter 1 and is denied; any CRYPTO request other than `SIGN` passes filter 1 but fails filter 2.

**Admin everything:** the example POSIX server seeds admin with `memset(&permissions, 0xFF, sizeof(permissions))` (`examples/posix/wh_posix_server/wh_posix_server_cfg.c:719`). That sets every group byte, every action bit, and the admin slot in one shot.

#### 4.3.7 Exceptions to the bitmap

The gate (`src/wh_auth.c:206`) hard-codes a few unconditional allows that bypass both filters:

- Unauthenticated session → all of group `COMM`, plus `(AUTH, LOGIN)`. Without these, no one could ever open a connection or log in.
- Authenticated session → `(AUTH, LOGOUT)` always succeeds. You can always log yourself out regardless of permission state.

Everything else flows through the two-tier filter described above, optionally followed by the backend's `cb->CheckRequestAuthorization` override (see §7.1) which sees the tentative verdict and can flip it either way.

### 4.4 Session: `whAuthUser` / `whAuthContext`

```c
typedef struct {
    whUserId          user_id;
    char              username[32];
    whAuthPermissions permissions;
    bool              is_active;
} whAuthUser;

struct whAuthContext_t {
    whAuthCb*  cb;        // backend vtable
    whAuthUser user;      // *the* currently-logged-in user for this connection
    void*      context;   // opaque backend state
#ifdef WOLFHSM_CFG_THREADSAFE
    whLock     lock;
#endif
};
```

A single `whAuthContext` holds **one** logged-in user at a time (src/wh_auth.c:139: "allowing only one user logged in to an open connection at a time"). A second login attempt while someone is already logged in returns success at the protocol level with `loggedIn=0` set — i.e. the call was processed fine, authentication simply didn't happen.

---

## 5. The plugin contract: `whAuthCb`

The core wraps every operation, acquires the lock, and then calls into this vtable:

```c
typedef struct {
    int (*Init)(void* ctx, const void* cfg);
    int (*Cleanup)(void* ctx);

    int (*Login)(void* ctx, uint8_t client_id, whAuthMethod method,
                 const char* username, const void* auth_data, uint16_t auth_data_len,
                 whUserId* out_user_id, whAuthPermissions* out_permissions,
                 int* loggedIn);
    int (*Logout)(void* ctx, whUserId current_user_id, whUserId user_id);

    /* Optional authorization-decision overrides */
    int (*CheckRequestAuthorization)(void* ctx, int err, uint16_t user_id,
                                     uint16_t group, uint16_t action);
    int (*CheckKeyAuthorization)(void* ctx, int err, uint16_t user_id,
                                 uint32_t key_id, uint16_t action);

    /* User management */
    int (*UserAdd)(void* ctx, const char* username, whUserId* out_user_id,
                   whAuthPermissions permissions, whAuthMethod method,
                   const void* credentials, uint16_t credentials_len);
    int (*UserDelete)(void* ctx, whUserId current_user_id, whUserId user_id);
    int (*UserSetPermissions)(void* ctx, whUserId current_user_id,
                              whUserId user_id, whAuthPermissions permissions);
    int (*UserGet)(void* ctx, const char* username,
                   whUserId* out_user_id, whAuthPermissions* out_permissions);
    int (*UserSetCredentials)(void* ctx, whUserId user_id, whAuthMethod method,
                              const void* current_credentials, uint16_t current_credentials_len,
                              const void* new_credentials, uint16_t new_credentials_len);
} whAuthCb;
```

The two "Check*" callbacks are **overrides, not gates** — see §7 below for exactly how they're layered over the default decision.

---

## 6. Default backend (`wh_auth_base.c`)

- **Storage:** `static whAuthBase_User users[WH_AUTH_BASE_MAX_USERS]` (=5). Each slot has the public `whAuthUser`, the chosen method, and a `credentials[2048]` byte buffer (+ length). The author notes this is intentionally simple and not yet NVM-backed.
- **Thread safety:** explicitly documented (src/wh_auth_base.c:54) — the global array is protected by the auth context's lock which the core `wh_Auth_*` wrappers acquire before calling any backend entry. The backend itself does no locking.
- **PIN path:** `wh_Auth_BaseCheckPin` hashes the incoming PIN with `wc_Sha256Hash_ex` and compares to the stored digest using `wh_Utils_ConstantCompare`. Hash buffer is `wh_Utils_ForceZero`d on exit whether the compare succeeded or not. When `WOLFHSM_CFG_NO_CRYPTO` is set, the PIN is stored verbatim (bounded by `WH_AUTH_BASE_MAX_CREDENTIALS_LEN`).
- **Certificate path:** guarded by `WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO`. Uses a per-call `WOLFSSL_CERT_MANAGER` seeded with the user's stored DER as a CA and then verifies the supplied leaf.
- **Admin enforcement:** `wh_Auth_BaseUserDelete` and `wh_Auth_BaseUserSetPermissions` both require `current_user_id` (the caller session) to have the admin flag. `wh_Auth_BaseLogout` allows logging out someone *other* than yourself only if you're admin.
- **Set-credentials:** if the target user already has credentials, the old ones must be presented and match (constant-time compare, PIN hashed first); otherwise `current_credentials` must be NULL. PINs are rehashed before replacement, and intermediate hash buffers are force-zeroed.
- **User ID policy:** 1-based indexes into `users[]`; 0 reserved. Duplicate usernames are rejected by `wh_Auth_BaseUserAdd` with `WH_ERROR_BADARGS`. `keyIdCount` is clamped to `WH_AUTH_MAX_KEY_IDS` and unused `keyIds` entries are zeroed (done both on add and on set-permissions).

---

## 7. Authorization — how the server enforces it on *every* request

The integration point is **`wh_Server_HandleRequestMessage`** in `src/wh_server.c`. After a packet is received and the `(group, action)` are extracted, before the switch on `group`:

```c
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    if (server->auth != NULL) {
        rc = wh_Auth_CheckRequestAuthorization(server->auth, group, action);
        if (rc != WH_ERROR_OK) {
            int32_t  error_code = (int32_t)WH_AUTH_PERMISSION_ERROR;
            uint16_t resp_size  = _FormatAuthErrorResponse(magic, group, action,
                                                           error_code, data);
            do { rc = wh_CommServer_SendResponse(server->comm, magic, kind,
                                                 seq, resp_size, data);
            } while (rc == WH_ERROR_NOTREADY);
            WH_LOG_ON_ERROR_F(&server->log, WH_LOG_LEVEL_ERROR,
                              WH_AUTH_PERMISSION_ERROR,
                              "Authorization failed for (group=%d, action=%d, seq=%d)",
                              group, action, seq);
            return rc;
        }
    }
#endif
```

Two deliberate design points here:

1. **The check happens once per request**, up-front, on the front end — as explicitly requested by @bigbrett in review ("the actual authorization check … should be part of the generic 'front end' and not delegated to the back-end"). Backends only affect authorization through the optional override callback.
2. **When `server->auth == NULL`** (auth compiled in but not configured) the check is skipped entirely and a SECEVENT log line is emitted at init time to announce this. That keeps existing code/tests working without having to introduce logins everywhere.

### 7.1 The default decision (`wh_Auth_CheckRequestAuthorization`)

In `src/wh_auth.c` the flow inside the lock is:

1. Read `user_id = context->user.user_id`.
2. **If no user is logged in** (`user_id == WH_USER_ID_INVALID`):
   - Allow `WH_MESSAGE_GROUP_COMM` (so a client can still perform comm handshakes/echo/close).
   - Allow `WH_MESSAGE_GROUP_AUTH` + `WH_MESSAGE_AUTH_ACTION_LOGIN` (so a client can actually log in).
   - Deny everything else → `WH_ERROR_ACCESS`.
3. **If a user is logged in:**
   - Always allow `WH_MESSAGE_GROUP_AUTH` + `WH_MESSAGE_AUTH_ACTION_LOGOUT` (you can always log yourself out).
   - Otherwise, look up `groupIndex = (group >> 8) & 0xFF`:
     - Bounds-check `groupIndex < WH_NUMBER_OF_GROUPS`.
     - If `permissions.groupPermissions[groupIndex] == 0` → deny.
     - If `action >= WH_AUTH_ACTIONS_PER_GROUP` → deny.
     - Map `action → (wordIdx, bitMask)` via `WH_AUTH_ACTION_TO_WORD_AND_BITMASK`. Allow iff the bit is set in `permissions.actionPermissions[groupIndex][wordIdx]`.
4. **Override hook:** if `cb->CheckRequestAuthorization != NULL`, invoke it with the preliminary `rc`, the user id, and the (group, action). Its return becomes the final decision. This is what `test/wh_test_auth.c` exercises to confirm backends can see the result and flip it either direction.

If this stage denies the request, the server synthesizes a per-group/per-action error response via `_FormatAuthErrorResponse` (new helper) so the client always gets a well-formed reply carrying `WH_AUTH_PERMISSION_ERROR`. The helper handles the three auth responses that are bigger than `SimpleResponse` (Login / UserAdd / UserGet), the oversized NVM ones, the Cert group, and falls back to writing just a translated `int32_t` rc for everything else.

### 7.2 Key-level authorization — deferred

`wh_Auth_CheckKeyAuthorization` and the `CheckKeyAuthorization` callback are defined and tested (presence-of-callback), but **no current request handler calls it**. The PR author called this out explicitly: "I added a callback function framework for checking authorization of key use based on key ID and user permissions but did not tie in that check yet." The reviewer should confirm no crypto/key handler was modified to call it — otherwise callers silently skip that layer today.

### 7.3 Admin gating in auth operations

Two additional checks live above the backend in `wh_Auth_UserAdd` (src/wh_auth.c):

- `WH_AUTH_IS_ADMIN(permissions_to_assign) && !WH_AUTH_IS_ADMIN(current_session_permissions)` → `WH_AUTH_PERMISSION_ERROR`. That is, **a non-admin session can never promote another user to admin**. This is enforced in the core, not the backend, so any custom backend inherits it.

The backend `wh_Auth_BaseUserDelete` and `wh_Auth_BaseUserSetPermissions` additionally require the caller to be admin. `wh_Auth_BaseLogout` requires admin for cross-user logouts.

### 7.4 Auto-logout on disconnect

The COMM group's `CLOSE` action handler (src/wh_server.c:270) now logs the current user out when the comm channel is torn down. This prevents a stale session from persisting across client reconnects on the same server.

---

## 8. Wire protocol — the auth message group

Added to `wolfhsm/wh_message.h`:

```c
WH_MESSAGE_GROUP_AUTH = 0x0D00
WH_MESSAGE_GROUP_MAX  = 0x0D00   // bumped so WH_NUMBER_OF_GROUPS reflects it

enum {
    WH_MESSAGE_AUTH_ACTION_LOGIN,
    WH_MESSAGE_AUTH_ACTION_LOGOUT,
    WH_MESSAGE_AUTH_ACTION_USER_ADD,
    WH_MESSAGE_AUTH_ACTION_USER_DELETE,
    WH_MESSAGE_AUTH_ACTION_USER_GET,
    WH_MESSAGE_AUTH_ACTION_USER_SET_PERMISSIONS,
    WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS,
};
```

The 7 request/response pairs live in `wh_message_auth.h`. Three of them carry **variable-length payloads** after a fixed header (login auth data, user-add credentials, set-credentials' two credential buffers). Those use `Translate*Request(void* src_packet, uint16_t src_size, ...)` helpers that validate `src_size` against the header-plus-declared-payload length (returning `WH_ERROR_BUFFER_SIZE` on mismatch), and each type has its own cap:

```c
WH_MESSAGE_AUTH_LOGIN_MAX_AUTH_DATA_LEN
  = COMM_DATA_LEN - sizeof(LoginRequest)
WH_MESSAGE_AUTH_USERADD_MAX_CREDENTIALS_LEN
  = COMM_DATA_LEN - sizeof(UserAddRequest)
WH_MESSAGE_AUTH_SETCREDS_MAX_CREDENTIALS_LEN
  = (COMM_DATA_LEN - sizeof(UserSetCredentialsRequest)) / 2
```

`whAuthPermissions` is large and contains nested arrays, so the PR adds `wh_MessageAuth_FlattenPermissions` / `_Unflatten…` to marshal it into a fixed-size little-endian byte buffer (`WH_FLAT_PERMISSIONS_LEN` bytes) that's embedded in the UserAdd, UserGet, and UserSetPermissions messages. Everything else uses the standard `WH_T16`/`WH_T32` magic-aware translation helpers.

Responses either use a dedicated type (Login → user_id, UserAdd → user_id, UserGet → user_id + flat permissions) or the shared `whMessageAuth_SimpleResponse { int32_t rc; }`.

---

## 9. Client API (`src/wh_client_auth.c`)

Every action comes in the wolfHSM-standard three flavors — a non-blocking send, a non-blocking receive, and a blocking loop on `WH_ERROR_NOTREADY`:

```c
/* One-shot helpers */
int wh_Client_AuthLogin(whClientContext* c, whAuthMethod method,
                        const char* username, const void* auth_data,
                        uint16_t auth_data_len,
                        int32_t* out_rc, whUserId* out_user_id);
int wh_Client_AuthLogout(whClientContext* c, whUserId user_id, int32_t* out_rc);
int wh_Client_AuthUserAdd(whClientContext* c, const char* username,
                          whAuthPermissions permissions, whAuthMethod method,
                          const void* credentials, uint16_t credentials_len,
                          int32_t* out_rc, whUserId* out_user_id);
int wh_Client_AuthUserDelete(whClientContext*, whUserId, int32_t* out_rc);
int wh_Client_AuthUserGet(whClientContext*, const char* username,
                          int32_t* out_rc, whUserId* out_user_id,
                          whAuthPermissions* out_permissions);
int wh_Client_AuthUserSetPermissions(whClientContext*, whUserId,
                                     whAuthPermissions, int32_t* out_rc);
int wh_Client_AuthUserSetCredentials(whClientContext*, whUserId, whAuthMethod,
                                     const void* current, uint16_t current_len,
                                     const void* new,     uint16_t new_len,
                                     int32_t* out_rc);
```

Client-side defensive behavior to notice during review:

- **Username validity** (`_UserNameIsValid` in wh_client_auth.c) requires non-NULL, non-empty, `< WH_MESSAGE_AUTH_MAX_USERNAME_LEN` (32) chars.
- The client stages all credential-carrying requests in a **stack buffer of size `WOLFHSM_CFG_COMM_DATA_LEN`** and calls `wh_Utils_ForceZero(buffer, sizeof(buffer))` before returning. This is the client-side mirror of the zeroization the server does after processing.
- `wh_Client_AuthLoginResponse` tolerates a server that responds with a `SimpleResponse` instead of a `LoginResponse` — that's how the server signals `WH_AUTH_NOT_ENABLED` to older/simpler clients; the demo (`wh_demo_client_auth.c`) keys off this to skip the demo cleanly.
- Every response handler validates `(resp_group, resp_action, resp_size)` before trusting the buffer. This is defense-in-depth against a desynchronized server — important since responses are returned in the same memory the request was written to.

---

## 10. A concrete end-to-end: "user logs in and does a crypto op"

To make the per-request/per-user flow concrete, here's what happens when a client does a `Login` followed by, say, a cached-key crypto call. Assume the server has been seeded with an admin `admin/1234` and a non-admin `demo` with `CRYPTO` group access (the exact setup in the POSIX example and the demo):

1. **Client sends `Login("demo", PIN="…")`.**
   - `wh_Client_AuthLogin` packs `whMessageAuth_LoginRequest` + PIN bytes into the comm buffer and sends with `(group=AUTH, action=LOGIN)`.
   - The buffer is `ForceZero`d before return.
2. **Server front end** (`wh_Server_HandleRequestMessage`) receives the packet, extracts `(AUTH, LOGIN)`, and calls `wh_Auth_CheckRequestAuthorization`. No one is logged in yet, but the gate explicitly whitelists `(AUTH, LOGIN)` — passes.
3. **`wh_Server_HandleAuthRequest`** is dispatched, which for `LOGIN`:
   - Translates the header (endian/magic) via `wh_MessageAuth_TranslateLoginRequest`.
   - Calls `wh_Auth_Login(server->auth, comm->client_id, method, username, auth_data, auth_data_len, &loggedIn)`.
4. **`wh_Auth_Login`** acquires the auth lock. If someone is already logged in on this context, it returns `WH_ERROR_OK` with `loggedIn=0` (the slot is "busy"). Otherwise it calls the backend `Login`. On success it stashes `user.user_id`, `user.permissions`, and `user.is_active = true` inside the `whAuthContext`.
5. **`wh_Auth_BaseLogin`** (PIN path) hashes the provided PIN with `wc_Sha256Hash_ex`, looks the username up in the static array, constant-time compares the digests, sets `loggedIn=1` and copies out the user id and permissions on match. The hash scratch buffer is `ForceZero`d on every exit path.
6. **Server sends `LoginResponse`** containing either the new `user_id` or `WH_AUTH_LOGIN_FAILED`. The request packet's `auth_data` region is `ForceZero`d before the server returns.
7. **Client receives**, pulls out `out_rc` and `out_user_id` for later `Logout`.
8. **Client now does a crypto call**, e.g. `wc_…` which goes through the crypto-callback layer and ultimately sends `(group=CRYPTO, action=<some op>)`.
9. **Server front end** runs `wh_Auth_CheckRequestAuthorization(CRYPTO, op)`. Inside:
   - `user_id` is non-invalid.
   - `groupIndex = (WH_MESSAGE_GROUP_CRYPTO >> 8) & 0xFF = 4`.
   - `permissions.groupPermissions[4]` is 1 → proceed to action bitmap.
   - `(wordIdx, bitMask)` is computed from the action enum; allowed iff the bit is set.
   - If a `CheckRequestAuthorization` callback is registered, it gets the tentative verdict and can flip it. In the example server it is `NULL`, so the callback step is skipped.
10. **If allowed** — the normal crypto handler runs; **no additional auth check** is performed today, even when the operation names a specific `keyId`. That's the TODO: the `CheckKeyAuthorization` callback and per-user `keyIds` allowlist exist in the data model and public API but the PR does not wire them into the crypto path.
11. **If denied** — `_FormatAuthErrorResponse` writes a group-appropriate error response carrying `WH_AUTH_PERMISSION_ERROR` (-2301), `wh_CommServer_SendResponse` ships it, and `WH_LOG_ON_ERROR_F` logs "Authorization failed for (group=%d, action=%d, seq=%d)". The request never reaches the crypto handler.
12. **Eventually the client sends `Close` on the comm channel.** The server's COMM close handler detects a live user, calls `wh_Auth_Logout`, which clears the `user` field inside `whAuthContext`. This happens even if the client forgets to call `AuthLogout` explicitly.

---

## 11. Noteworthy security posture

Things that are present and worth confirming during review:

- **Constant-time credential compare** (`wh_Utils_ConstantCompare`, new utility) used for PIN hashes and cert buffers in the base backend.
- **Force-zero of sensitive buffers** (`wh_Utils_ForceZero`, new utility) on both client and server: PIN hash scratch, request-packet credential regions after processing, response packets with credentials, entire staging buffer on the client before return, and the user array on base-backend cleanup. Several of the later commits in the PR were exactly to add more of these.
- **Single-session-per-connection** semantics reduce the attack surface for cross-user confusion inside one comm channel.
- **Admin promotion guard** sits in the generic front end (`wh_Auth_UserAdd`), so backends can't accidentally allow it even if their `UserAdd` doesn't check.
- **Lock discipline**: all `wh_Auth_*` wrappers take the lock before calling into the backend; `wh_Auth_BaseLogin` and friends document that they expect to be called under the lock. Reviewer should verify any new call sites honor this.
- **Graceful fallback responses**: clients that get `WH_AUTH_NOT_ENABLED` when auth isn't configured server-side still see a well-formed message, not a malformed/oversized frame.

Things that are **explicit open items** (per PR body and code comments):

- No NVM backing for the user list — the base backend is RAM-only and losses on reboot.
- `CheckKeyAuthorization` is wired but not called anywhere in the request-handling paths in this PR.
- Logging of login attempts (successes and failures) is a TODO — only authorization denials are logged today.
- The `WH_AUTH_SET_ALLOWED_ACTION` macro comment says "and only the given action bit," but the implementation ORs (Copilot raised this during review). Either the comment or the semantics should change.

---

## 12. Review checklist (suggested focus areas)

1. **Front-end gate placement** — confirm every server-side request path goes through `wh_Server_HandleRequestMessage` before reaching a group handler. In particular, check DMA, SHE, PKCS11, CERT, and custom handler dispatch paths; anything that inserts a second dispatch could bypass the gate.
2. **`server->auth == NULL` semantics** — tests should confirm (a) auth-compiled + no context lets all non-auth requests through and (b) auth requests in that state return `WH_AUTH_NOT_ENABLED`, not `WH_ERROR_BADARGS`.
3. **Cross-user logout semantics** — `wh_Auth_Logout` in the core still wipes local session memory only if `user_id == context->user.user_id`, but the backend `wh_Auth_BaseLogout` can also deactivate a different user if the caller is admin. That asymmetry is intentional but worth double-checking against the test cases.
4. **Message validation against `WOLFHSM_CFG_COMM_DATA_LEN`** — particularly UserSetCredentials, which packs *two* variable-length buffers back to back. The per-message caps exist (`WH_MESSAGE_AUTH_SETCREDS_MAX_CREDENTIALS_LEN`) but verify both client and server reject an aggregate-size overrun.
5. **Macro behavior vs docs** on `WH_AUTH_SET_ALLOWED_ACTION` (OR vs assign) — the project should decide intended semantics since callers (including the demo) rely on OR behavior.
6. **`keyIdCount` clamping + unused slot zeroing** is duplicated between `UserAdd` and `UserSetPermissions` — worth a small helper to keep these in sync.
7. **Thread-safety contract** — backend docs say "protected by the auth context lock"; confirm any future backend author can't easily step outside the lock by, e.g., calling `wh_Auth_BaseFindUser` directly.
8. **Auto-logout on close** — confirm tests cover a client that crashes mid-session and reconnects; `CLOSE` isn't the only path to disconnection.
9. **`CheckKeyAuthorization` TODO** — decide whether merging without at least a scaffolded call site in the key/crypto handlers is acceptable, or whether it should be added (even if defaulting to allow) before merge so customers don't build against an interface that changes behavior later.
10. **Force-zero coverage** — spot-check that every function that stages credentials or PIN digests on the stack `ForceZero`s before return, even on error paths. The commit log shows several late additions here, suggesting it's easy to miss.

---

## 13. Build & try it locally

Per `docs/src/chapter09.md`, enable the feature via `WOLFHSM_CFG_ENABLE_AUTHENTICATION` and use the `AUTH=1` Make flag in the POSIX examples/tests:

```bash
# Tests
cd test && make clean && make -j AUTH=1 && make run

# Example server + demo client
cd examples/posix/wh_posix_server && make AUTH=1
cd examples/posix/wh_posix_client && make AUTH=1
```

The example server seeds an `admin/1234` user with everything-allowed permissions at startup (see `wh_PosixServer_ExampleAuthConfig` in `examples/posix/wh_posix_server/wh_posix_server_cfg.c`). The demo client (`examples/demo/client/wh_demo_client_auth.c`) logs in as admin, adds `demo/1234` with USER_SET_CREDENTIALS permission, rotates the `demo` PIN to `5678`, verifies the old PIN fails and the new PIN works, then logs out. Running the demo against an auth-disabled server returns `WH_AUTH_NOT_ENABLED` and the demo prints "Authentication not enabled on server, skipping …" and returns `WH_ERROR_OK` — useful for CI matrix coverage without separate test binaries.
