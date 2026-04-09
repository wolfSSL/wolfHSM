/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * port/pkcs11/wh_pkcs11_store.h
 *
 * wolfHSM-backed storage for the wolfPKCS11 standalone library.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * INTEGRATION DESIGN — read this before touching any related code
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Context: what we are building
 * ──────────────────────────────
 * We are building a Linux daemon (wh_server_uds) that exposes a wolfHSM
 * server as a PKCS#11 token over a Unix domain socket, using the p11-kit
 * remote protocol so that any application using p11-kit can discover and use
 * it without installing a custom module.
 *
 * The PKCS#11 implementation is provided by the standalone wolfPKCS11 library
 * (github.com/wolfSSL/wolfPKCS11).  We wire wolfHSM into wolfPKCS11 at two
 * integration points:
 *
 *   1. Crypto backend  — wolfPKCS11 routes crypto through wolfCrypt's devId
 *                        callback mechanism.  We register wolfHSM's client
 *                        callback at WH_DEV_ID so all wolfCrypt operations
 *                        that wolfPKCS11 performs on hardware-bound keys are
 *                        offloaded to the wolfHSM server.
 *
 *   2. Key storage     — wolfPKCS11 uses a pluggable storage API
 *                        (WOLFPKCS11_CUSTOM_STORE).  This file declares the
 *                        five wolfPKCS11_Store_* functions that route key
 *                        persistence through wolfHSM NVM instead of the
 *                        default filesystem.
 *
 * ── Crypto backend ──────────────────────────────────────────────────────────
 *
 * wolfCrypt's CryptoCb mechanism (wolfssl/wolfcrypt/cryptocb.h) allows any
 * cryptographic operation to be routed to a registered callback by device ID:
 *
 *   wc_CryptoCb_RegisterDevice(WH_DEV_ID, wh_Client_CryptoCb, &clientCtx);
 *
 * wolfPKCS11 stores a devId per slot.  The WOLFPKCS11_WOLFHSM backend
 * (implemented in wolfPKCS11's wp11_Slot_Init, in ~/wolfssl branch
 * feature/wolfhsm-backend) sets slot->devId = WH_DEV_ID after registering
 * the callback.  All wolfCrypt key objects subsequently created in that slot
 * inherit WH_DEV_ID and route their operations to the wolfHSM server.
 *
 * Device IDs:
 *   WH_DEV_ID     = 0x5748534D  ("WHSM") — wolfHSM standard transport
 *   WH_DEV_ID_DMA = 0x57444D41  ("WDMA") — wolfHSM DMA transport (optional)
 *
 * Decision: use one shared whClientContext per daemon process (not one per
 * PKCS#11 session).  wolfPKCS11 already serialises crypto operations via its
 * internal lock; wolfHSM's request-response protocol is inherently
 * single-inflight per client context.  One shared context avoids the overhead
 * of per-session client init/cleanup and matches how the wolfHSM test suite
 * uses clients.
 *
 * ── Key storage ─────────────────────────────────────────────────────────────
 *
 * wolfPKCS11 serialises key objects to DER, AES-CBC-encrypts them using a
 * key derived from the user PIN, and calls the five store functions below.
 * With WOLFPKCS11_CUSTOM_STORE defined at build time, wolfPKCS11 calls our
 * implementations instead of the default filesystem backend.
 *
 * wolfPKCS11 store types (from wolfpkcs11/store.h):
 *   WOLFPKCS11_STORE_OBJECT     — individual key/certificate objects
 *   WOLFPKCS11_STORE_SYMMKEY    — symmetric key objects
 *   WOLFPKCS11_STORE_TOKENDATA  — slot/token metadata (label, PIN hash, etc.)
 *
 * NVM object ID mapping:
 *   wolfHSM NVM uses 16-bit object IDs.  We carve out a reserved namespace
 *   for PKCS#11 objects:
 *
 *     Bits 15..12  = PKCS11_NVM_NAMESPACE (0xP, value TBD; see wh_nvm.h)
 *     Bits 11.. 8  = store type (0..7)
 *     Bits  7.. 4  = id1 low nibble (slot/token index)
 *     Bits  3.. 0  = id2 low nibble (object index within slot)
 *
 *   Decision: 4 bits each for id1 and id2 limits us to 16 slots and 16
 *   objects per slot in a single NVM namespace.  For the daemon use case
 *   (single slot, O(10) keys) this is ample.  If the limit ever bites, the
 *   namespace field can be widened at the cost of a NVM migration.
 *
 *   Objects are stored as opaque blobs; wolfPKCS11 owns the serialisation
 *   format (encrypted DER).  The NVM store does not interpret the content.
 *
 * ── Key opacity note ─────────────────────────────────────────────────────────
 *
 * wolfPKCS11 deserialises keys into wolfCrypt structs in RAM during a session.
 * The private key material therefore exists in the daemon process's address
 * space while it is in use — it is NOT hardware-isolated.  wolfHSM enforces
 * key opacity at the server boundary: keys cached in the server are not
 * accessible to the client.  But the wolfPKCS11 layer sits above that
 * boundary and loads keys from NVM into RAM.
 *
 * This is acceptable for the general wolfHSM use case (the daemon process is
 * the trusted party) but is insufficient for hardware-isolated use cases such
 * as Caliptra Managed Keys (CMKs), which are designed to never leave the
 * hardware.  Opaque-key enforcement for CMKs is out of scope here and will
 * require a separate design that bypasses wolfPKCS11's key deserialisation.
 *
 * ── Daemon wiring ────────────────────────────────────────────────────────────
 *
 * Startup sequence (implemented in examples/posix/wh_server_uds/main.c):
 *
 *   1. wh_Client_Init(&clientCtx, &clientCfg)     // connect to wolfHSM server
 *   2. wc_CryptoCb_RegisterDevice(WH_DEV_ID,       // route crypto to wolfHSM
 *                                  wh_Client_CryptoCb, &clientCtx)
 *   3. C_Initialize(NULL)                          // wolfPKCS11 init; calls
 *                                                  // wp11_WolfHSM_Init which
 *                                                  // sets slot->devId
 *   4. C_GetFunctionList(&fnList)
 *   5. accept loop:
 *        p11_kit_remote_serve_module(fnList, fd, fd)
 *
 * Build flags required:
 *   -DWOLFPKCS11_WOLFHSM          (new backend guard in wolfPKCS11)
 *   -DWOLFPKCS11_CUSTOM_STORE     (use our wolfPKCS11_Store_* below)
 *   -DP11_KIT_FUTURE_UNSTABLE_API (unlock p11_kit_remote_serve_module)
 *   Include paths: wolfPKCS11 headers, wolfHSM headers, p11-kit headers
 *   Link: wolfPKCS11 (.a or .so), wolfHSM client lib, libp11-kit
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * Store API declarations
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * These five functions implement the wolfPKCS11 custom store interface.
 * wolfPKCS11 calls them when WOLFPKCS11_CUSTOM_STORE is defined.
 *
 * wolfPKCS11 defines these types in wolfpkcs11/store.h; include that header
 * before including this one.
 *
 * The void* store handle returned by wolfPKCS11_Store_Open is a pointer to a
 * whPkcs11StoreCtx allocated on the heap.  wolfPKCS11 passes it back to the
 * other functions and finally to wolfPKCS11_Store_Close.
 */

#ifndef PORT_PKCS11_WH_PKCS11_STORE_H_
#define PORT_PKCS11_WH_PKCS11_STORE_H_

#include <stdint.h>

#include "wolfhsm/wh_client.h"  /* whClientContext */

/*
 * NVM namespace for wolfPKCS11 objects.  NVM object IDs in the range
 * [WH_PKCS11_NVM_ID_BASE, WH_PKCS11_NVM_ID_BASE + WH_PKCS11_NVM_ID_COUNT)
 * are reserved for PKCS#11 storage and must not be used by the application.
 *
 * Decision: 256 IDs (0x0100..0x01FF) gives us room for all store type +
 * id1 + id2 combinations within the 4-bit-each encoding described above.
 */
/*
 * wolfPKCS11 "not available" sentinel.
 *
 * wolfPKCS11_Store_Open must return this value when an NVM object does not
 * exist (fresh token, never persisted).  wolfPKCS11 treats -4 as "no data"
 * and initialises with defaults rather than failing.  This matches the
 * NOT_AVAILABLE_E value documented in wolfpkcs11/store.h.
 */
#define WH_PKCS11_NOT_AVAILABLE (-4)

#define WH_PKCS11_NVM_ID_BASE  0x0100u
#define WH_PKCS11_NVM_ID_COUNT 0x0100u  /* 256 IDs reserved */

/*
 * Encode a (type, id1, id2) tuple into a wolfHSM NVM object ID.
 *
 * Layout: [namespace=0x01][type:4][id1:2][id2:2]
 *   type nibble: 0..15 (wolfPKCS11 store type values fit in 4 bits)
 *   id1 nibble:  lower 2 bits of id1 (slot index; single slot = 0)
 *   id2 nibble:  lower 2 bits of id2 (object index within slot)
 *
 * This is intentionally compact; widening any field requires a NVM migration.
 */
#define WH_PKCS11_NVM_ENCODE_ID(type, id1, id2) \
    (uint16_t)(WH_PKCS11_NVM_ID_BASE              \
               | (((uint16_t)(type)  & 0x0Fu) << 4) \
               | (((uint16_t)(id1)   & 0x03u) << 2) \
               |  ((uint16_t)(id2)   & 0x03u))

/*
 * Internal store context.  One is heap-allocated per wolfPKCS11_Store_Open
 * call and freed by wolfPKCS11_Store_Close.
 */
typedef struct {
    whClientContext* client;   /* Shared; not owned by this context */
    uint16_t         nvm_id;   /* Encoded NVM object ID for this object */
    int              is_read;  /* 1 = opened for read, 0 = opened for write */

    /* Read state: entire NVM object is loaded into buf on Open; Read drains it. */
    /* Write state: buf accumulates all Write calls; committed atomically on Close. */
    uint8_t*         buf;
    uint32_t         buf_size;    /* Allocated size of buf */
    uint32_t         buf_offset;  /* Current read/write position */
    uint32_t         data_len;    /* Total valid bytes (read: NVM size; write: accumulated) */
} whPkcs11StoreCtx;


/*
 * Set the shared whClientContext that wolfPKCS11_Store_* functions use.
 *
 * Must be called once before C_Initialize.  The client context must remain
 * valid for the lifetime of the daemon.
 *
 * Decision: a global client pointer is set here rather than threading the
 * client through wolfPKCS11's opaque store handle, because wolfPKCS11 calls
 * wolfPKCS11_Store_Open/Remove with only (type, id1, id2) — there is no
 * caller-supplied context parameter.  A per-process global is the only way
 * to pass the client handle in.
 */
void wh_Pkcs11Store_SetClient(whClientContext* client);


/* ── wolfPKCS11 custom store interface ─────────────────────────────────────
 *
 * These are called by wolfPKCS11 when WOLFPKCS11_CUSTOM_STORE is defined.
 * See wolfpkcs11/store.h for the type constants and calling conventions.
 *
 * wolfPKCS11_Store_Open:
 *   Allocates a whPkcs11StoreCtx.
 *   read=1: loads the NVM object into an internal buffer.
 *   read=0: allocates an empty write buffer.
 *   Returns 0 on success, negative on failure.
 *
 * wolfPKCS11_Store_Close:
 *   read=0: commits the accumulated write buffer to NVM atomically, then
 *           frees the context.
 *   read=1: just frees the context (NVM was not modified).
 *   wolfPKCS11 always calls Close after Open, even on error paths.
 *
 * wolfPKCS11_Store_Read:
 *   Copies up to len bytes from the internal buffer into buffer.
 *   Returns bytes read on success, negative on failure.
 *
 * wolfPKCS11_Store_Write:
 *   Appends len bytes from buffer into the internal write buffer,
 *   growing it if necessary.
 *   Returns bytes written on success, negative on failure.
 *
 * wolfPKCS11_Store_Remove:
 *   Deletes the NVM object for (type, id1, id2) if it exists.
 *   Returns 0 on success, negative on failure (ENOENT is not an error).
 */
int wolfPKCS11_Store_Open(int type, unsigned long id1, unsigned long id2,
        int read, void** store);
void wolfPKCS11_Store_Close(void* store);
int wolfPKCS11_Store_Read(void* store, unsigned char* buffer, int len);
int wolfPKCS11_Store_Write(void* store, unsigned char* buffer, int len);
int wolfPKCS11_Store_Remove(int type, unsigned long id1, unsigned long id2);

#endif /* PORT_PKCS11_WH_PKCS11_STORE_H_ */
