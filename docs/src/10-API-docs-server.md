# Server API Reference

This chapter is the complete reference for the wolfHSM **server** API. It is generated directly from the documentation comments in the public server headers ([`wolfhsm/wh_server.h`](../../wolfhsm/wh_server.h), [`wolfhsm/wh_server_keystore.h`](../../wolfhsm/wh_server_keystore.h), [`wolfhsm/wh_server_img_mgr.h`](../../wolfhsm/wh_server_img_mgr.h), [`wolfhsm/wh_server_cert.h`](../../wolfhsm/wh_server_cert.h), and [`wolfhsm/wh_server_cert_cache.h`](../../wolfhsm/wh_server_cert_cache.h)), so it always tracks the source. For a conceptual, feature-oriented walkthrough of what these functions are for, see [Features](5-Features.md); this chapter documents the precise signatures, parameters, and return values.

- **[Server API](wh__server_8h.md)** — server context lifecycle, configuration, and top-level request dispatch (`wolfhsm/wh_server.h`).
- **[Server Keystore API](wh__server__keystore_8h.md)** — server-side key cache and keystore operations: cache and evict slots, NVM commit, key export, and metadata access (`wolfhsm/wh_server_keystore.h`).
- **[Server Image Manager API](wh__server__img__mgr_8h.md)** — image manager configuration, verification, and verify-state queries (`wolfhsm/wh_server_img_mgr.h`).
- **[Server Cert API](wh__server__cert_8h.md)** — server-side certificate manager: trusted root storage, chain verification, attribute certificate support, and the user-injectable verify callback (`wolfhsm/wh_server_cert.h`).
- **[Server Cert Cache API](wh__server__cert__cache_8h.md)** — trusted-cert verify-result cache: hash-based result lookup and invalidation (`wolfhsm/wh_server_cert_cache.h`).
