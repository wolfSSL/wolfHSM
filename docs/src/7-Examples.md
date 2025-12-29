# Examples

This chapter describes the example applications and demo code that ship with wolfHSM. These are *not* part of the runtime library — they live under `examples/` and exist so that an integrator can see a complete, end-to-end wolfHSM client and server running on a host, and so that a developer can find a working, runnable answer to the question "how do I do *X* in wolfHSM?" The example applications wire together the transport, comm, NVM, and crypto subsystems described in [5-Features.md](5-Features.md); the demos are the port-agnostic exercises those applications run.

## Table of Contents

- [POSIX Example Server and Client](#posix-example-server-and-client)
    - [Building and Running](#building-and-running)
    - [Transport Selection](#transport-selection)
    - [Server NVM Initialization](#server-nvm-initialization)
- [Demo Client Library](#demo-client-library)
    - [Philosophy](#philosophy)
    - [Demo Categories](#demo-categories)

## POSIX Example Server and Client

The POSIX example consists of two simple host applications — a server (`examples/posix/wh_posix_server/`) and a client (`examples/posix/wh_posix_client/`) — that talk to each other over a transport of the user's choosing. They are intentionally minimal: each is a single `main()` that configures the appropriate context, calls the wolfHSM init routines, and then either services requests (server) or issues them (client). They are the smallest complete demonstration of a wolfHSM deployment on a system with a real OS, and they double as the reference for what a port-specific server and client application need to do at startup.

The server runs as a foreground process that waits for a client to connect on the selected transport, dispatches incoming requests through `wh_Server_HandleRequestMessage()`, and exits when the client disconnects. The client connects to a running server, sends a fixed sequence of `Echo` messages to verify the transport is alive, and — if invoked with `--test` — runs the full demo client library against the server before disconnecting. Both applications share a small set of helper configuration sources (`wh_posix_*_cfg.c`) that build the per-transport `whClientConfig` / `whServerConfig` structures; the configuration helpers are deliberately separated from the `main()` driver so the same transport plumbing can be lifted into an integrator's own application.

### Building and Running

The applications expect to find wolfHSM and wolfSSL as sibling directories. From a clean checkout:

```sh
cd examples/posix/wh_posix_server && make
cd examples/posix/wh_posix_client && make
```

This produces `wh_posix_server.elf` and `wh_posix_client.elf` under each directory's `Build/`. Launch the server in one shell and the client in another:

```sh
./examples/posix/wh_posix_server/Build/wh_posix_server.elf
./examples/posix/wh_posix_client/Build/wh_posix_client.elf
```

To exercise the demo client library against the running server, pass `--test` to the client:

```sh
./wh_posix_client.elf --test
```

The full set of supported build options for the example applications is documented in [11-Configuration.md](11-Configuration.md); the same `DMA=1`, `SHE=1`, `AUTH=1`, `TLS=1` knobs that gate features in the test and benchmark suites apply here.

### Transport Selection

Both applications accept a `--type <transport>` argument that selects which configuration helper builds the comm context. The supported types depend on how the example was compiled:

- `tcp` — POSIX TCP socket on `127.0.0.1:23456` (the default).
- `shm` — POSIX inter-process shared memory.
- `dma` — Shared memory plus a wolfSSL static-memory DMA buffer, where requests pass DMA offsets instead of inline payloads. Requires `WOLFSSL_STATIC_MEMORY`.
- `tls` — wolfSSL TLS over TCP. Requires `WOLFHSM_CFG_TLS`.
- `psk` — TLS with a pre-shared key. Requires `WOLFHSM_CFG_TLS` and `!NO_PSK`.

The server and client must be started with the same `--type`. Each transport is defined by a corresponding `wh_PosixServer_Example<Type>Config()` / `wh_PosixClient_Example<Type>Config()` helper that an integrator can copy verbatim into their own application.

### Server NVM Initialization

By default the server starts with an empty NVM. Two arguments let the example pre-populate it before the dispatch loop begins:

- `--key <path> --id <keyId> [--client <clientId>]` loads a single DER-encoded key from disk and caches it under the specified key ID for the specified client (default client 12).
- `--nvminit <path>` reads a [whnvmtool](6-Utilities.md#nvm-provisioning-tool)-style configuration file and loads every key and object it lists.

Both forms are conveniences specific to the POSIX example — in a real deployment, NVM contents typically come from a pre-built image programmed at manufacture (see [6-Utilities.md](6-Utilities.md)). They are included here so the demo client library can exercise paths that assume keys or objects already exist on the server.

## Demo Client Library

The demo client library (`examples/demo/client/`) is a collection of self-contained C functions, one file per feature area, that drive the wolfHSM client API through a representative workflow for each subsystem. The library is port-agnostic: it depends only on a fully initialized `whClientContext*` and the wolfHSM client headers. The POSIX example client is one consumer of this library, but the same code compiles and runs from any port that can hand it an initialized client context — and that is the point.

### Philosophy

The demos are **living documentation expressed as code**. They are written to answer "how do I do *X* in wolfHSM?" by being the shortest complete program that does *X*, with the surrounding setup and teardown spelled out so the reader can copy and adapt without guessing. Because the library is checked into the same repository as the runtime code, it cannot fall out of sync with the API the way prose documentation can: if a function signature changes, the demos break the build, and the demos are updated as part of the same change.

Two consequences of that philosophy are worth calling out explicitly, because they make the demo code look different from the rest of the codebase:

- **Aggressive inline commentary at the expense of error checking.** A production caller would propagate every return code, free every allocation on every path, and handle every edge case. The demos generally check return codes only enough to bail out cleanly at the top level and instead spend their lines explaining *why* the next call is shaped the way it is. The goal is for the reader to walk away understanding the *intent* of the sequence, not a robust template they can paste into production. Production code should treat the demos as a starting point and add the missing rigor.
- **Clarity over efficiency.** The demos preference straight-line code, fixed-size local buffers, and explicit step-by-step sequences over the more compact or efficient idioms a production integration would use. Where there is a tension between "how a developer learns this" and "how a developer should ship this," the demos pick the former.

Each demo function takes a `whClientContext*` and returns `0` on success or a wolfHSM error code on failure, so the same set of demos can be wired into an integrator's own application — not just the POSIX example client — by calling them after their `wh_Client_Init()` succeeds. The top-level `wh_DemoClient_All()` in `wh_demo_client_all.c` runs the full suite in order and is what the POSIX client invokes when launched with `--test`.

### Demo Categories

The demos are organized by wolfHSM feature area, with one source/header pair per area. Each category lives in `examples/demo/client/wh_demo_client_<area>.c` and is gated by the same build-time configuration macros as the underlying feature, so a demo for a feature that is not compiled in is simply elided from the suite.

- **NVM** (`wh_demo_client_nvm.c`) — Adding, reading back, enumerating, and reclaiming non-volatile objects through the client NVM API. Shows the full lifecycle of an NVM object including metadata, access flags, and reclamation of freed space.
- **Keystore** (`wh_demo_client_keystore.c`) — Caching raw key material in the server, querying cached keys by ID and label, committing cached keys to NVM, and using a cached key from a wolfCrypt operation. The reference for the basic key-cache / NVM-backing-store flow described in [5-Features.md](5-Features.md#keystore).
- **Key Wrapping** (`wh_demo_client_keywrap.c`) — Importing wrapped key blobs, unwrapping them on the server, and using the resulting cached key without ever exposing plaintext key material on the client. Gated by `WOLFHSM_CFG_KEYWRAP`.
- **Cryptography** (`wh_demo_client_crypto.c`) — The largest demo file: end-to-end signing, verification, key agreement, symmetric encryption, KDF, and MAC examples for each algorithm wolfHSM supports through the crypto callback path. Covers RSA, ECC, Curve25519, AES-CBC, AES-GCM, HKDF, CMAC, and CMAC-KDF, each in both an "import a key as part of the call" form and a "use a key already in the cache" form so the reader can see the two shapes of the API side-by-side.
- **Secure Boot** (`wh_demo_client_secboot.c`) — A complete provisioning-and-boot workflow: generating a server-side signing keypair, hashing an image with SHA-256, signing the hash, and later re-verifying it on boot. Acts as a worked example of how the keystore, NVM, and crypto subsystems compose for an image-authentication use case.
- **Authentication** (`wh_demo_client_auth.c`) — Logging in as a user, exercising role-based access controls on protected operations, and logging out. Gated by `WOLFHSM_CFG_ENABLE_AUTHENTICATION`. The POSIX example client logs in as an `admin` user after running the auth demos so subsequent demos run with full privileges.
- **Counters** (`wh_demo_client_counter.c`) — Reading, incrementing, and resetting non-volatile monotonic counters through the client counter API.
- **wolfCrypt Test Passthrough** (`wh_demo_client_wctest.c`) — Runs the standard wolfCrypt unit test suite as a wolfHSM client, exercising every supported algorithm through the crypto callback path. Gated by `WH_DEMO_WCTEST`. This is the same surface validated by the test utility in [6-Utilities.md](6-Utilities.md#test-suite), but invoked from inside an example application rather than the standalone test runner.
- **wolfCrypt Benchmark Passthrough** (`wh_demo_client_wcbench.c`) — Runs the standard wolfCrypt benchmark as a wolfHSM client. Useful for sanity-checking that an integration produces sensible numbers; for thorough measurement use the dedicated [benchmark suite](6-Utilities.md#benchmark-suite).

To add a demo for a new feature, drop a new `wh_demo_client_<area>.c/.h` pair into `examples/demo/client/`, gate it on the appropriate `WOLFHSM_CFG_*` macro, and call it from `wh_DemoClient_All()` under the same guard. The new demo is then automatically picked up by every port-specific example application that builds against the demo library.
