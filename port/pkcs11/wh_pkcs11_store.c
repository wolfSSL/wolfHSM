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
 * port/pkcs11/wh_pkcs11_store.c
 *
 * Implements the five wolfPKCS11 custom store callbacks backed by wolfHSM NVM.
 *
 * wolfPKCS11 calls these functions when WOLFPKCS11_CUSTOM_STORE is defined at
 * build time.  The shared whClientContext is injected once via
 * wh_Pkcs11Store_SetClient before C_Initialize is called.
 *
 * Read the design documentation in wh_pkcs11_store.h before modifying this
 * file.  Decision rationale (NVM ID encoding, buffer strategy, error handling
 * conventions) is recorded there, not here.
 *
 * Implementation notes:
 *
 * wolfPKCS11 serialises each object to DER, AES-CBC-encrypts it with a PIN-
 * derived key, then calls:
 *   Open(write) → Write × N → Close     to persist
 *   Open(read)  → Read × N  → Close     to load
 *   Remove                              to delete
 *
 * wolfPKCS11 always calls Close after Open, even on error paths, so Close must
 * never crash on a partially-initialised context.
 *
 * We buffer the entire object in RAM during both read and write.  On write-
 * close we commit the buffer to NVM in one atomic AddObject call.  This
 * matches the NVM layer's expectation: objects are written whole, not in
 * streaming chunks.
 *
 * Buffer growth strategy (write mode): start at WH_PKCS11_WRITE_BUF_INITIAL
 * bytes, double on each realloc.  Most objects fit in the initial allocation
 * (a 2048-bit RSA private key in encrypted DER is < 2 KB).
 *
 * Error handling in Close: Close is void so errors cannot be returned.  If
 * the NVM commit fails, wolfPKCS11 will detect a missing or corrupt object on
 * the next Open-read and treat it as non-existent.  This is safe: wolfPKCS11
 * will re-create the object on the next write.
 *
 * Zeroing before free: the buffer holds wolfPKCS11's encrypted key material.
 * We zero before free so the sensitive bytes leave no heap artefacts.  The
 * wolfPKCS11 layer is responsible for zeroing its own plaintext.
 */

#include <stddef.h>   /* NULL, size_t */
#include <stdint.h>   /* uint8_t, uint16_t, uint32_t */
#include <stdlib.h>   /* malloc, realloc, free */
#include <string.h>   /* memcpy, memset */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"  /* whNvmId, whNvmSize, whNvmAccess, whNvmFlags,
                                   WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE */
#include "wolfhsm/wh_client.h"  /* wh_Client_Nvm* */
#include "port/pkcs11/wh_pkcs11_store.h"

/*
 * Process-global client pointer.
 *
 * wolfPKCS11_Store_Open and wolfPKCS11_Store_Remove receive no caller-supplied
 * context parameter, so we must use a global.  See wh_pkcs11_store.h design
 * note "Decision: a global client pointer..."
 *
 * Access pattern: written once (wh_Pkcs11Store_SetClient before C_Initialize),
 * then read-only for the daemon lifetime.  wolfPKCS11 serialises all store
 * calls through its internal lock, so no additional synchronisation needed.
 */
static whClientContext* s_pkcs11_client = NULL;

/*
 * Initial write-buffer allocation in bytes.  Sized to cover a small cert or
 * symmetric key without realloc.  Double on overflow.
 */
#define WH_PKCS11_WRITE_BUF_INITIAL 256u


/* ── Public: inject shared client ──────────────────────────────────────────── */

void wh_Pkcs11Store_SetClient(whClientContext* client)
{
    s_pkcs11_client = client;
}


/* ── wolfPKCS11 custom store interface ─────────────────────────────────────── */

int wolfPKCS11_Store_Open(int type, unsigned long id1, unsigned long id2,
        int read, void** store)
{
    whPkcs11StoreCtx* ctx = NULL;
    uint16_t          nvm_id;
    int               rc = 0;
    int32_t           server_rc = 0;

    /* ── Parameter validation ── */
    if (store == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (s_pkcs11_client == NULL) {
        /* wh_Pkcs11Store_SetClient was not called before C_Initialize */
        return WH_ERROR_BADARGS;
    }

    /* ── Encode (type, id1, id2) into a wolfHSM NVM object ID ── */
    nvm_id = WH_PKCS11_NVM_ENCODE_ID(type, id1, id2);

    /*
     * Sanity check: encoded ID must land inside the reserved PKCS#11
     * namespace.  An out-of-range ID means the (type, id1, id2) combination
     * exceeds what our 4-bit fields can represent.  Return BADARGS rather than
     * silently aliasing to a different NVM object.
     */
    if (nvm_id < WH_PKCS11_NVM_ID_BASE ||
            nvm_id >= WH_PKCS11_NVM_ID_BASE + WH_PKCS11_NVM_ID_COUNT) {
        return WH_ERROR_BADARGS;
    }

    /* ── Allocate store context ── */
    ctx = (whPkcs11StoreCtx*)malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return WH_ERROR_ABORTED;  /* OOM is fatal */
    }
    memset(ctx, 0, sizeof(*ctx));

    ctx->client  = s_pkcs11_client;
    ctx->nvm_id  = nvm_id;
    ctx->is_read = (read != 0) ? 1 : 0;

    if (ctx->is_read) {
        /*
         * Read mode: query the NVM object size, then load its entire content
         * into an internal buffer.  wolfPKCS11_Store_Read will drain it.
         *
         * We call GetMetadata first to learn the size.  If the object does not
         * exist (server_rc != 0), we return the server error to wolfPKCS11 so
         * it knows no persistent state exists for this (type, id1, id2).
         */
        whNvmSize data_len = 0;

        rc = wh_Client_NvmGetMetadata(s_pkcs11_client, nvm_id, &server_rc,
                NULL,  /* out_id   — not needed */
                NULL,  /* out_access — not needed */
                NULL,  /* out_flags  — not needed */
                &data_len,
                0,     /* label_len  — not interested in label */
                NULL); /* label      — not interested in label */
        if (rc != 0) {
            /* Transport error */
            free(ctx);
            return rc;
        }
        if (server_rc != 0) {
            free(ctx);
            /*
             * wolfPKCS11 store contract (wolfpkcs11/store.h): return -4 when
             * data is not available.  wolfPKCS11 treats -4 (NOT_AVAILABLE_E)
             * as "fresh token, no persistent state" — it initialises with
             * defaults rather than failing C_Initialize.  Any other non-zero
             * value propagates as a hard failure.
             *
             * WH_ERROR_NOTFOUND means the NVM object was never written, which
             * is the normal case on first boot or after a factory reset.
             */
            if ((int)server_rc == WH_ERROR_NOTFOUND) {
                return WH_PKCS11_NOT_AVAILABLE;
            }
            return (int)server_rc;
        }

        if (data_len > 0) {
            ctx->buf = (uint8_t*)malloc(data_len);
            if (ctx->buf == NULL) {
                free(ctx);
                return WH_ERROR_ABORTED;
            }
            ctx->buf_size = data_len;

            rc = wh_Client_NvmRead(s_pkcs11_client, nvm_id,
                    0,           /* offset: read from beginning */
                    data_len,
                    &server_rc,
                    NULL,        /* out_len: don't need echoed length */
                    ctx->buf);
            if (rc != 0 || server_rc != 0) {
                /* Zero before free: buf may hold encrypted key material */
                memset(ctx->buf, 0, ctx->buf_size);
                free(ctx->buf);
                free(ctx);
                return (rc != 0) ? rc : (int)server_rc;
            }

            ctx->data_len = (uint32_t)data_len;
        }
        /* buf_offset stays at 0: Read will advance it */

    } else {
        /*
         * Write mode: allocate an initial accumulation buffer.
         * wolfPKCS11_Store_Write appends into it; wolfPKCS11_Store_Close
         * commits the whole thing to NVM in one atomic AddObject call.
         */
        ctx->buf = (uint8_t*)malloc(WH_PKCS11_WRITE_BUF_INITIAL);
        if (ctx->buf == NULL) {
            free(ctx);
            return WH_ERROR_ABORTED;
        }
        ctx->buf_size   = WH_PKCS11_WRITE_BUF_INITIAL;
        ctx->buf_offset = 0;
        ctx->data_len   = 0;
    }

    *store = ctx;
    return 0;
}


void wolfPKCS11_Store_Close(void* store)
{
    whPkcs11StoreCtx* ctx = (whPkcs11StoreCtx*)store;
    int32_t           server_rc = 0;

    if (ctx == NULL) {
        return;
    }

    if (!ctx->is_read && ctx->data_len > 0 && ctx->client != NULL) {
        /*
         * Write mode: commit accumulated buffer to NVM.
         *
         * Overflow guard: whNvmSize is uint16_t (max 65535 bytes).  We reject
         * any write that would overflow here rather than silently truncating.
         * In practice wolfPKCS11 objects are well within this limit.
         */
        if (ctx->data_len <= (uint32_t)0xFFFFu) {
            /* Errors are discarded: Close is void.  wolfPKCS11 will detect a
             * missing object on the next Open-read and re-create it. */
            (void)wh_Client_NvmAddObject(ctx->client, ctx->nvm_id,
                    WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
                    0, NULL,
                    (whNvmSize)ctx->data_len, ctx->buf,
                    &server_rc);
        }
        /* If data_len > 0xFFFF: object is too large; silently skip commit.
         * This should never happen for any wolfPKCS11 object type. */
    }

    /* Zero and free: buf may hold wolfPKCS11's encrypted key material */
    if (ctx->buf != NULL) {
        memset(ctx->buf, 0, ctx->buf_size);
        free(ctx->buf);
        ctx->buf = NULL;
    }
    free(ctx);
}


int wolfPKCS11_Store_Read(void* store, unsigned char* buffer, int len)
{
    whPkcs11StoreCtx* ctx = (whPkcs11StoreCtx*)store;
    uint32_t          available;
    uint32_t          to_copy;

    if (ctx == NULL || buffer == NULL || len < 0) {
        return WH_ERROR_BADARGS;
    }

    /*
     * Compute bytes still unread.  buf_offset <= data_len is maintained as an
     * invariant: we never advance past the end of valid data.
     */
    available = ctx->data_len - ctx->buf_offset;
    to_copy   = (available < (uint32_t)len) ? available : (uint32_t)len;

    if (to_copy > 0) {
        memcpy(buffer, ctx->buf + ctx->buf_offset, (size_t)to_copy);
        ctx->buf_offset += to_copy;
    }

    /*
     * Return bytes copied, not the requested len.  wolfPKCS11 uses the return
     * value as the actual read count and loops until it has all the bytes it
     * needs, so returning less than len when data runs out is correct.
     */
    return (int)to_copy;
}


int wolfPKCS11_Store_Write(void* store, unsigned char* buffer, int len)
{
    whPkcs11StoreCtx* ctx = (whPkcs11StoreCtx*)store;
    uint32_t          new_used;
    uint32_t          new_size;
    uint8_t*          new_buf;

    if (ctx == NULL || buffer == NULL || len < 0) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->is_read) {
        /* Write called on a read-mode context: programming error */
        return WH_ERROR_BADARGS;
    }

    /*
     * Overflow check 1: buf_offset + len must not wrap uint32_t.
     * buf_offset is always <= data_len <= 0xFFFF at entry (enforced by the
     * whNvmSize limit check in Close), so this can only overflow with a
     * pathologically large len.
     */
    if ((uint32_t)len > (uint32_t)0xFFFFFFFFu - ctx->buf_offset) {
        return WH_ERROR_BADARGS;
    }
    new_used = ctx->buf_offset + (uint32_t)len;

    /*
     * Overflow check 2: total accumulated size must fit in whNvmSize
     * (uint16_t, max 65535).  Reject now so Close can cast safely.
     */
    if (new_used > (uint32_t)0xFFFFu) {
        return WH_ERROR_BADARGS;
    }

    if (new_used > ctx->buf_size) {
        /* Grow buffer: double current size or new_used, whichever is larger */
        new_size = ctx->buf_size * 2u;
        if (new_size < new_used) {
            new_size = new_used;
        }
        new_buf = (uint8_t*)realloc(ctx->buf, (size_t)new_size);
        if (new_buf == NULL) {
            return WH_ERROR_ABORTED;
        }
        ctx->buf      = new_buf;
        ctx->buf_size = new_size;
    }

    memcpy(ctx->buf + ctx->buf_offset, buffer, (size_t)len);
    ctx->buf_offset += (uint32_t)len;
    ctx->data_len    = ctx->buf_offset;  /* Always equal for write mode */

    return len;
}


int wolfPKCS11_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    uint16_t nvm_id;
    int32_t  server_rc = 0;
    int      rc;

    if (s_pkcs11_client == NULL) {
        return WH_ERROR_BADARGS;
    }

    nvm_id = WH_PKCS11_NVM_ENCODE_ID(type, id1, id2);

    /*
     * wh_Client_NvmDestroyObjects is idempotent for missing IDs: the server
     * does not error if an ID is not found.  So WH_ERROR_NOTFOUND from the
     * server side should not occur, but we treat it as success anyway.
     */
    rc = wh_Client_NvmDestroyObjects(s_pkcs11_client, 1, &nvm_id, &server_rc);
    if (rc != 0) {
        return rc;  /* Transport error */
    }
    if ((int)server_rc == WH_ERROR_NOTFOUND) {
        /* Object already absent — idempotent delete is success */
        return 0;
    }
    return (int)server_rc;
}
