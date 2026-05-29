# Client API Reference

This chapter is the complete reference for the wolfHSM **client** API. It is generated directly from the documentation comments in the public client headers (`wolfhsm/wh_client.h`, `wolfhsm/wh_client_crypto.h`, and `wolfhsm/wh_client_she.h`), so it always tracks the source. For a conceptual, feature-oriented walkthrough of what these functions are for, see [Features](5-Features.md); this chapter documents the precise signatures, parameters, and return values.

- **[Client API](wh__client_8h.md)** — client context lifecycle, communication, NVM, keystore, certificate, image-manager, and counter operations (`wolfhsm/wh_client.h`).
- **[Client Crypto API](wh__client__crypto_8h.md)** — split-transaction, non-blocking crypto request/response calls (`wolfhsm/wh_client_crypto.h`).
- **[Client SHE API](wh__client__she_8h.md)** — AUTOSAR SHE (Secure Hardware Extension) client interface: key update protocol (M1–M5), encrypted message handling, secure boot, deterministic PRNG, and status register access (`wolfhsm/wh_client_she.h`).
