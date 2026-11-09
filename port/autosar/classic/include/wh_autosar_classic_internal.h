/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * port/autosar/classic/include/wh_autosar_classic_internal.h
 *
 * Private bridge state between the AUTOSAR Crypto Driver shell and the
 * wolfHSM client. Not part of the public API.
 */

#ifndef WH_AUTOSAR_CLASSIC_INTERNAL_H_
#define WH_AUTOSAR_CLASSIC_INTERNAL_H_

#include "Std_Types.h"
#include "Crypto_GeneralTypes.h"
#include "Crypto_Cfg.h"
#include "wh_autosar_alg_map.h"

#include "wolfhsm/wh_client.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/ecc.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Lets integrators override the default hooks. */
#if defined(__GNUC__) || defined(__clang__) || defined(__GHS__) || \
    defined(__TI_COMPILER_VERSION__) || defined(__TASKING__)
#define WH_AUTOSAR_WEAK __attribute__((weak))
#elif defined(__IAR_SYSTEMS_ICC__)
#define WH_AUTOSAR_WEAK __weak
#else
/* Unknown toolchain: emit a warning so the integrator notices that the
 * weak-symbol fallback is silently empty. Strong overrides of any
 * WH_AUTOSAR_WEAK symbol will collide with the default at link time. To
 * silence this warning, extend the toolchain matrix above with the
 * correct weak-symbol spelling for the new compiler. */
#if defined(__GNUC__) || defined(__clang__)
#warning "WH_AUTOSAR_WEAK: unknown toolchain, weak fallback is a no-op"
#endif
#define WH_AUTOSAR_WEAK /* no weak support; strong-only build */
#endif

/* Vendor headers disagree on CRYPTO_E_VER_NOT_OK, so use local values. */
#define WH_AUTOSAR_VER_OK_VAL ((uint8)0x00u)
#define WH_AUTOSAR_VER_NOT_OK_VAL ((uint8)0x01u)

/* -------------------------------------------------------------------
 * Slot state machine
 * ------------------------------------------------------------------- */

typedef enum {
    WH_AUTOSAR_ASYNC_IDLE = 0,
    /* Accepted, waiting for the object's client to be free. */
    WH_AUTOSAR_ASYNC_QUEUED = 1,
    /* Request is on the wire; awaiting Response. */
    WH_AUTOSAR_ASYNC_PENDING = 2,
    /* Response received; callback owed to CryIf. */
    WH_AUTOSAR_ASYNC_COMPLETE = 3,
    /* Cancelled in flight; the response is dropped without a callback. */
    WH_AUTOSAR_ASYNC_CANCELLING = 4
} wh_AutosarAsyncState;

/* Sub-phase of a streamed hash; other ops stay ONESHOT. */
typedef enum {
    WH_AUTOSAR_PHASE_ONESHOT     = 0,
    WH_AUTOSAR_PHASE_HASH_UPDATE = 1,
    WH_AUTOSAR_PHASE_HASH_FINAL  = 2
} wh_AutosarPhase;

/* Per-op state union. Lives across the Request/Response pair(s) so the
 * Response handler can decode the reply and write back into the
 * caller's job buffers. */
typedef struct {
#ifndef WOLFHSM_CFG_NO_CRYPTO
    union {
        wc_Sha256 sha256;
#ifdef WOLFSSL_SHA384
        wc_Sha384 sha384;
#endif
#ifdef WOLFSSL_SHA512
        wc_Sha512 sha512;
#endif
        Aes  aes;
        Cmac cmac;
    } wc;
#endif

    /* Hash async: input chunking state for multi-Update streaming. */
    const uint8* hashInput;
    uint32       hashRemaining;
    uint8*       digestOut;
    uint32       digestLen;

    /* Expected value for verify ops, compared when the response arrives. */
    const uint8* verifyRef;
    uint32       verifyRefLen;

    uint8  sigDigest[64];
    uint32 sigDigestLen;

    /* AES async: caller buffers (captured at Request time so the
     * Response handler can write back even if the caller mutates the
     * job struct). */
    uint8* cipherOut;
    uint32 cipherLen;
    uint8* tagOut;
    uint32 tagLen;
    uint8  iv[16];
    uint32 ivLen;

    /* Generic raw buffer (RNG, ECDSA sig, ECDH secret). */
    uint8* rawOut;
    uint16 rawLen16;
    uint32 rawLen32;
} wh_AutosarOpState;

typedef struct {
    Crypto_JobType*      job;
    wh_AutosarAsyncState state;
    wh_AutosarOpKind     opKind;
    wh_AutosarPhase      phase;
    Std_ReturnType       result;
    /* tickCount when the slot went PENDING, for the timeout check. */
    uint32 ticksAtIssue;
    /* Allocation sequence number for FIFO Queue ordering. */
    uint32            seq;
    boolean           blocking;
    wh_AutosarOpState op;
} wh_AutosarJobSlot;

/* -------------------------------------------------------------------
 * Streamed-hash state (sync path, multi-call START/UPDATE/FINISH)
 *
 * Keyed by jobId AND lives per-driver-object so two driver objects
 * with overlapping jobIds don't collide.
 * ------------------------------------------------------------------- */

#define WH_AUTOSAR_HASH_SLOTS_PER_OBJ 4u

#ifndef WOLFHSM_CFG_NO_CRYPTO
typedef struct {
    boolean inUse;
    /* TRUE once an UPDATE/FINISH has failed on this slot. The slot
     * stays allocated (so the caller's jobId still resolves and we
     * don't leak the wc_Sha* state for FINISH to free) but every
     * subsequent UPDATE/FINISH returns E_NOT_OK without touching
     * wolfCrypt — the hash state is undefined after a wire failure. */
    boolean          errored;
    boolean          busy;
    uint32           jobId;
    wh_AutosarOpKind op;
    union {
        wc_Sha256 sha256;
#ifdef WOLFSSL_SHA384
        wc_Sha384 sha384;
#endif
#ifdef WOLFSSL_SHA512
        wc_Sha512 sha512;
#endif
    } wc;
} wh_AutosarHashState;
#endif

typedef struct {
    whClientContext   client;
    boolean           initialised;
    uint32            nextSeq;
    uint32            tickCount;
    boolean           wireBusy;
    wh_AutosarJobSlot asyncSlots[CRYPTO_MAX_ASYNC_JOBS];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wh_AutosarHashState hashStates[WH_AUTOSAR_HASH_SLOTS_PER_OBJ];
#endif
} wh_AutosarDriverObject;

wh_AutosarDriverObject* wh_Autosar_GetDriverObject(uint32 objectId);

int wh_Autosar_DriverObjectInit(wh_AutosarDriverObject* obj);
int wh_Autosar_DriverObjectCleanup(wh_AutosarDriverObject* obj);

Std_ReturnType wh_Autosar_ProcessJobSync(wh_AutosarDriverObject* obj,
                                         Crypto_JobType*         job);

/* Claims the object's client for a blocking exchange; CRYPTO_E_BUSY while an
 * async request is in flight. */
Std_ReturnType wh_Autosar_WireAcquire(wh_AutosarDriverObject* obj);
void           wh_Autosar_WireRelease(wh_AutosarDriverObject* obj);

/* Keystore client plus wire ownership for the direct key APIs. */
Std_ReturnType wh_Autosar_KeystoreBegin(whClientContext** outCtx);
void           wh_Autosar_KeystoreEnd(whClientContext* ctx);

Std_ReturnType wh_Autosar_KeyMarkInvalid(uint32 cryptoKeyId);
void           wh_Autosar_KeyMarkValid(uint32 cryptoKeyId);
boolean        wh_Autosar_KeyIsValid(uint32 cryptoKeyId);
Std_ReturnType wh_Autosar_KeyIvGet(uint32 cryptoKeyId, const uint8** iv,
                                   uint32* ivLen);

Std_ReturnType wh_Autosar_KeyElementSetImpl(whClientContext* ctx,
                                            uint32           cryptoKeyId,
                                            uint32           keyElementId,
                                            const uint8* key, uint32 keyLength);
Std_ReturnType wh_Autosar_KeySetValidImpl(whClientContext* ctx,
                                          uint32           cryptoKeyId);
Std_ReturnType wh_Autosar_KeyGenerateImpl(whClientContext* ctx,
                                          uint32           cryptoKeyId);
Std_ReturnType wh_Autosar_KeyDeriveImpl(whClientContext* ctx,
                                        uint32           cryptoKeyId,
                                        uint32           targetCryptoKeyId);
Std_ReturnType
wh_Autosar_KeyExchangeCalcPubValImpl(whClientContext* ctx, uint32 cryptoKeyId,
                                     uint8*  publicValuePtr,
                                     uint32* publicValueLengthPtr);
Std_ReturnType
wh_Autosar_KeyExchangeCalcSecretImpl(whClientContext* ctx, uint32 cryptoKeyId,
                                     const uint8* partnerPublicValuePtr,
                                     uint32       partnerPublicValueLength);
Std_ReturnType wh_Autosar_ProcessJobAsync(wh_AutosarDriverObject* obj,
                                          Crypto_JobType*         job);

/* Advances one object's async slots; wolfHSM allows one request in flight
 * per client. */
void wh_Autosar_MainFunctionObject(wh_AutosarDriverObject* obj);

/* -------------------------------------------------------------------
 * Keystore (logically separate from per-driver-object job clients)
 * ------------------------------------------------------------------- */

whClientContext* wh_Autosar_KeystoreClient(void);
int              wh_Autosar_KeystoreInit(void);
int              wh_Autosar_KeystoreCleanup(void);

/* Slot lock hooks; weak no-ops by default. */
void wh_Autosar_LockSlots(wh_AutosarDriverObject* obj);
void wh_Autosar_UnlockSlots(wh_AutosarDriverObject* obj);

/* Provided by the integrator. */
int wh_Autosar_PlatformClientConfig(whClientContext* client);

extern void CryIf_CallbackNotification(Crypto_JobType*   job,
                                       Crypto_ResultType result);

typedef struct {
    uint32                     cryptoKeyId;
    Crypto_AlgorithmFamilyType family;
    Crypto_AlgorithmModeType   mode;
    uint32                     keyLength;  /* in bits */
    int                        eccCurveId; /* wolfCrypt ECC_SECP* */
    int                        hashType;   /* wolfCrypt WC_HASH_TYPE_* */
    int                        mlDsaLevel; /* WC_ML_DSA_44 / 65 / 87 */
} Crypto_KeyDescriptorType;

/* Key descriptor table from the post-build configuration. */
extern const Crypto_KeyDescriptorType* const Crypto_KeyDescriptorTable;
extern const uint32                          Crypto_KeyDescriptorCount;

const Crypto_KeyDescriptorType*
wh_Autosar_LookupKeyDescriptor(uint32 cryptoKeyId);

/* -------------------------------------------------------------------
 * whKeyId composition
 *
 * Default scheme:
 *   bits 15..12   WH_KEYTYPE_CRYPTO
 *   bits 11..8    keyElementId (4 bits, supports element ids 0..15)
 *   bits  7..0    cryptoKeyId  (8 bits, supports 256 distinct keys)
 *
 * cryptoKeyId > 255 or keyElementId > 15 are rejected (returns 0,
 * which all wolfHSM calls treat as an invalid id). Integrators needing
 * more capacity install a strong override of wh_Autosar_ComposeKeyId.
 * ------------------------------------------------------------------- */

whKeyId wh_Autosar_ComposeKeyId(uint32 cryptoKeyId, uint32 keyElementId);

/* -------------------------------------------------------------------
 * Async timeout (in MainFunction ticks). Override at compile time. A
 * PENDING slot older than this is force-cleaned and reported E_NOT_OK.
 * ------------------------------------------------------------------- */
#ifndef CRYPTO_ASYNC_TIMEOUT_TICKS
#define CRYPTO_ASYNC_TIMEOUT_TICKS 10000u
#endif

/* -------------------------------------------------------------------
 * Test introspection hooks
 *
 * Used by the in-tree test harness to assert leak-freedom, drive
 * timeout paths deterministically, and inject synthetic state. Cheap
 * to include in production builds (a handful of small accessors) and
 * the inject helpers are explicitly guarded so they cannot fire
 * unless a test calls them.
 * ------------------------------------------------------------------- */

/* Returns the number of asyncSlots in a non-IDLE state (i.e. anything
 * the dispatcher is tracking). Tests assert == 0 between cases. */
uint32 wh_Autosar_DebugActiveSlotCount(const wh_AutosarDriverObject* obj);

/* Returns the number of streamed-hash state slots currently allocated.
 * Tests assert == 0 between cases. */
uint32 wh_Autosar_DebugActiveHashStateCount(const wh_AutosarDriverObject* obj);

/* Force-advance the MainFunction tick counter. Used by the timeout test
 * to push a slot past CRYPTO_ASYNC_TIMEOUT_TICKS without waiting wall-
 * clock-real time. */
void wh_Autosar_DebugAdvanceTicks(wh_AutosarDriverObject* obj, uint32 by);

/* Inject a synthetic PENDING slot tied to job, but WITHOUT issuing any
 * wolfHSM Request on the wire. Used exclusively by the timeout test:
 * combined with DebugAdvanceTicks, lets the timeout path fire
 * deterministically without server-side orchestration. Returns 0 on
 * success, -1 if no slot is free. */
int wh_Autosar_DebugInjectFakePending(wh_AutosarDriverObject* obj,
                                      Crypto_JobType* job, wh_AutosarOpKind op);

/* Force every slot back to IDLE without consulting the wire, freeing
 * the wolfCrypt context of each. Used by the test runner after a
 * failing test that exited early without draining its in-flight async
 * jobs — otherwise MainFunction's eventual Response handler would
 * write to a freed stack frame. Skips any callback notifications. */
void wh_Autosar_DebugForceResetSlots(wh_AutosarDriverObject* obj);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WH_AUTOSAR_CLASSIC_INTERNAL_H_ */
