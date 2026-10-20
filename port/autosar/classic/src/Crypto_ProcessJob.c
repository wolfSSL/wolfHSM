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
 * port/autosar/classic/src/Crypto_ProcessJob.c
 *
 * Sync and async job dispatch.
 *
 * Async path obeys the wolfHSM per-context contract: "at most one
 * outstanding async request may be in flight per whClientContext."
 * ProcessJobAsync places jobs into QUEUED slots; MainFunctionObject
 * promotes the oldest QUEUED slot to PENDING (issues the *Request)
 * only when no other slot is PENDING.
 *
 * Multi-call hash (CRYPTO_OPERATIONMODE_START / UPDATE / FINISH) keeps
 * a per-(driver-object, jobId) wc_Sha* state alive across
 * ProcessJob calls (sync path).
 *
 * Hash async chunks input across as many wh_Client_Sha*UpdateRequest
 * calls as needed; each Update Response either issues the next Update
 * (if hashRemaining > 0) or transitions to FinalRequest.
 *
 * All resource cleanup goes through finishSlot() so that wc_*Free
 * always runs exactly once regardless of which error path the slot
 * exits on.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"
#include "wh_autosar_alg_map.h"
#include "wh_autosar_safe_compare.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"

#include <string.h>

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/ecc.h"
#ifdef HAVE_ED25519
#include "wolfssl/wolfcrypt/ed25519.h"
#endif
#ifndef NO_RSA
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"
#endif
#endif

/* -------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------- */

static Crypto_JobPrimitiveInputOutputType* jobIo(Crypto_JobType* job)
{
    return &job->jobPrimitiveInputOutput;
}

static void writeVerifyResult(Crypto_JobType* job, boolean ok)
{
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    if (io->verifyPtr != NULL) {
        *io->verifyPtr = ok ? WH_AUTOSAR_VER_OK_VAL : WH_AUTOSAR_VER_NOT_OK_VAL;
    }
}

static wh_AutosarOpKind resolveOpKind(const Crypto_JobType* job)
{
    const Crypto_PrimitiveInfoType* pi = job->jobPrimitiveInfo->primitiveInfo;
    wh_AutosarOpKind                op = WH_AUTOSAR_OP_INVALID;
    (void)wh_AutosarMap_OpKind(pi->service, pi->algorithm.family,
                               pi->algorithm.mode,
                               pi->algorithm.secondaryFamily, &op);
    return op;
}

static boolean isEncryptService(Crypto_ServiceInfoType svc)
{
    return (svc == CRYPTO_ENCRYPT || svc == CRYPTO_AEADENCRYPT) ? TRUE : FALSE;
}

/* Thin C alias over the shared helper. Both Classic and Adaptive
 * classify verify-result rc the same way; the rationale lives in
 * port/autosar/common/include/wh_autosar_safe_compare.h. */
static boolean isVerifyRejection(int rc)
{
    return wh_Autosar_IsVerifyRejection(rc) ? TRUE : FALSE;
}

/* -------------------------------------------------------------------
 * Multi-call hash state (sync path, per driver object)
 * ------------------------------------------------------------------- */

#ifndef WOLFHSM_CFG_NO_CRYPTO

static void hashStateFreeWc(wh_AutosarHashState* s)
{
    if (s == NULL || !s->inUse)
        return;
    switch (s->op) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            wc_Sha256Free(&s->wc.sha256);
            break;
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            wc_Sha384Free(&s->wc.sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            wc_Sha512Free(&s->wc.sha512);
            break;
#endif
        default:
            break;
    }
}

static wh_AutosarHashState* hashStateFind(wh_AutosarDriverObject* obj,
                                          uint32                  jobId)
{
    uint32 i;
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        if (obj->hashStates[i].inUse && obj->hashStates[i].jobId == jobId) {
            return &obj->hashStates[i];
        }
    }
    return NULL;
}

static wh_AutosarHashState* hashStateAcquire(wh_AutosarDriverObject* obj,
                                             uint32                  jobId)
{
    /* If an entry already exists for this jobId, free its wolfCrypt
     * state before recycling — a re-START without a prior FINISH
     * otherwise leaks device-side state. */
    wh_AutosarHashState* s = hashStateFind(obj, jobId);
    if (s != NULL) {
        hashStateFreeWc(s);
        (void)memset(s, 0, sizeof(*s));
        s->inUse = TRUE;
        s->jobId = jobId;
        return s;
    }
    {
        uint32 i;
        for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
            if (!obj->hashStates[i].inUse) {
                (void)memset(&obj->hashStates[i], 0,
                             sizeof(obj->hashStates[i]));
                obj->hashStates[i].inUse = TRUE;
                obj->hashStates[i].jobId = jobId;
                return &obj->hashStates[i];
            }
        }
    }
    return NULL;
}

static void hashStateRelease(wh_AutosarHashState* s)
{
    if (s == NULL)
        return;
    hashStateFreeWc(s);
    s->inUse = FALSE;
}

static int hashInit(wh_AutosarHashState* s, wh_AutosarOpKind op)
{
    s->op = op;
    switch (op) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            return wc_InitSha256_ex(&s->wc.sha256, NULL, WH_DEV_ID);
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            return wc_InitSha384_ex(&s->wc.sha384, NULL, WH_DEV_ID);
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            return wc_InitSha512_ex(&s->wc.sha512, NULL, WH_DEV_ID);
#endif
        default:
            return WH_ERROR_NOTIMPL;
    }
}

/* Drive a complete Update sequence (Request + spin on Response,
 * chunking through as many calls as the per-call capacity demands). */
static int hashUpdateSync(whClientContext* ctx, wh_AutosarHashState* s,
                          const uint8* in, uint32 inLen)
{
    int rc = WH_ERROR_OK;
    while (inLen > 0u) {
        bool   sent      = false;
        uint32 thisChunk = inLen;
        /* wh_Client_Sha*UpdateRequest may reject if inLen exceeds the
         * per-call capacity; halve until accepted (binary fallback). */
        while (thisChunk > 0u) {
            switch (s->op) {
                case WH_AUTOSAR_OP_HASH_SHA256:
                    rc = wh_Client_Sha256UpdateRequest(ctx, &s->wc.sha256, in,
                                                       thisChunk, &sent);
                    break;
#ifdef WOLFSSL_SHA384
                case WH_AUTOSAR_OP_HASH_SHA384:
                    rc = wh_Client_Sha384UpdateRequest(ctx, &s->wc.sha384, in,
                                                       thisChunk, &sent);
                    break;
#endif
#ifdef WOLFSSL_SHA512
                case WH_AUTOSAR_OP_HASH_SHA512:
                    rc = wh_Client_Sha512UpdateRequest(ctx, &s->wc.sha512, in,
                                                       thisChunk, &sent);
                    break;
#endif
                default:
                    return WH_ERROR_NOTIMPL;
            }
            if (rc == WH_ERROR_OK)
                break;
            if (rc != WH_ERROR_BADARGS)
                return rc;
            thisChunk /= 2u; /* halve and retry */
        }
        if (rc != WH_ERROR_OK)
            return rc;
        if (sent) {
            switch (s->op) {
                case WH_AUTOSAR_OP_HASH_SHA256:
                    do {
                        rc = wh_Client_Sha256UpdateResponse(ctx, &s->wc.sha256);
                    } while (rc == WH_ERROR_NOTREADY);
                    break;
#ifdef WOLFSSL_SHA384
                case WH_AUTOSAR_OP_HASH_SHA384:
                    do {
                        rc = wh_Client_Sha384UpdateResponse(ctx, &s->wc.sha384);
                    } while (rc == WH_ERROR_NOTREADY);
                    break;
#endif
#ifdef WOLFSSL_SHA512
                case WH_AUTOSAR_OP_HASH_SHA512:
                    do {
                        rc = wh_Client_Sha512UpdateResponse(ctx, &s->wc.sha512);
                    } while (rc == WH_ERROR_NOTREADY);
                    break;
#endif
                default:
                    return WH_ERROR_NOTIMPL;
            }
            if (rc != WH_ERROR_OK)
                return rc;
        }
        in += thisChunk;
        inLen -= thisChunk;
    }
    return WH_ERROR_OK;
}

static int hashFinishSync(whClientContext* ctx, wh_AutosarHashState* s,
                          uint8* out, uint32* outLen)
{
    int rc = WH_ERROR_NOTIMPL;
    switch (s->op) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            if (*outLen < WC_SHA256_DIGEST_SIZE)
                return WH_ERROR_BUFFER_SIZE;
            rc = wh_Client_Sha256FinalRequest(ctx, &s->wc.sha256);
            if (rc != WH_ERROR_OK)
                return rc;
            do {
                rc = wh_Client_Sha256FinalResponse(ctx, &s->wc.sha256, out);
            } while (rc == WH_ERROR_NOTREADY);
            if (rc == WH_ERROR_OK)
                *outLen = WC_SHA256_DIGEST_SIZE;
            return rc;
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            if (*outLen < WC_SHA384_DIGEST_SIZE)
                return WH_ERROR_BUFFER_SIZE;
            rc = wh_Client_Sha384FinalRequest(ctx, &s->wc.sha384);
            if (rc != WH_ERROR_OK)
                return rc;
            do {
                rc = wh_Client_Sha384FinalResponse(ctx, &s->wc.sha384, out);
            } while (rc == WH_ERROR_NOTREADY);
            if (rc == WH_ERROR_OK)
                *outLen = WC_SHA384_DIGEST_SIZE;
            return rc;
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            if (*outLen < WC_SHA512_DIGEST_SIZE)
                return WH_ERROR_BUFFER_SIZE;
            rc = wh_Client_Sha512FinalRequest(ctx, &s->wc.sha512);
            if (rc != WH_ERROR_OK)
                return rc;
            do {
                rc = wh_Client_Sha512FinalResponse(ctx, &s->wc.sha512, out);
            } while (rc == WH_ERROR_NOTREADY);
            if (rc == WH_ERROR_OK)
                *outLen = WC_SHA512_DIGEST_SIZE;
            return rc;
#endif
        default:
            return WH_ERROR_NOTIMPL;
    }
}

static Std_ReturnType hashSyncDispatch(wh_AutosarDriverObject* obj,
                                       wh_AutosarOpKind op, Crypto_JobType* job)
{
    Crypto_JobPrimitiveInputOutputType* io   = jobIo(job);
    Crypto_OperationModeType            mode = io->mode;
    wh_AutosarHashState*                state;
    int                                 rc;

    if (mode & CRYPTO_OPERATIONMODE_START) {
        state = hashStateAcquire(obj, job->jobId);
        if (state == NULL)
            return E_NOT_OK;
        rc = hashInit(state, op);
        if (rc != WH_ERROR_OK) {
            hashStateRelease(state);
            return E_NOT_OK;
        }
    }
    else {
        state = hashStateFind(obj, job->jobId);
        if (state == NULL)
            return E_NOT_OK;
    }

    /* If a prior call on this slot already failed, every subsequent
     * UPDATE/FINISH must report E_NOT_OK; the wolfCrypt state is
     * unusable. The slot is released only when FINISH arrives, so the
     * caller's jobId-based lookup still succeeds and we don't leak
     * the cached wc_Sha* state. */
    if (state->errored) {
        if (mode & CRYPTO_OPERATIONMODE_FINISH) {
            hashStateRelease(state);
        }
        return E_NOT_OK;
    }

    if (mode & CRYPTO_OPERATIONMODE_UPDATE) {
        if (io->inputLength > 0u && io->inputPtr != NULL) {
            rc = hashUpdateSync(&obj->client, state, io->inputPtr,
                                io->inputLength);
            if (rc != WH_ERROR_OK) {
                state->errored = TRUE;
                if (mode & CRYPTO_OPERATIONMODE_FINISH) {
                    hashStateRelease(state);
                }
                return E_NOT_OK;
            }
        }
    }

    if (mode & CRYPTO_OPERATIONMODE_FINISH) {
        uint32 outLen;
        if (io->outputPtr == NULL || io->outputLengthPtr == NULL) {
            hashStateRelease(state);
            return E_NOT_OK;
        }
        outLen = *io->outputLengthPtr;
        rc     = hashFinishSync(&obj->client, state, io->outputPtr, &outLen);
        hashStateRelease(state);
        if (rc != WH_ERROR_OK)
            return E_NOT_OK;
        *io->outputLengthPtr = outLen;
    }
    return E_OK;
}
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* -------------------------------------------------------------------
 * Sync AES / CMAC / ECDSA / RNG
 * ------------------------------------------------------------------- */

#ifndef WOLFHSM_CFG_NO_CRYPTO
static Std_ReturnType doAesSync(whClientContext* ctx, wh_AutosarOpKind op,
                                int enc, Crypto_JobType* job, whKeyId keyId)
{
    Aes                                 aes;
    int                                 rc;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    const Crypto_PrimitiveInfoType* pi = job->jobPrimitiveInfo->primitiveInfo;

    rc = wc_AesInit(&aes, NULL, WH_DEV_ID);
    if (rc != 0)
        return E_NOT_OK;
    /* wh_Client_AesCbcRequest et al. read aes->keylen to build the
     * request envelope; only setting the key id is not enough. */
    aes.keylen = (int)(pi->algorithm.keyLength / 8u);
    rc         = wh_Client_AesSetKeyId(&aes, keyId);
    if (rc == 0 && io->secondaryInputPtr != NULL &&
        op != WH_AUTOSAR_OP_CIPHER_AES_ECB) {
        rc = wc_AesSetIV(&aes, io->secondaryInputPtr);
    }
    if (rc == 0) {
        switch (op) {
#ifdef HAVE_AES_ECB
            case WH_AUTOSAR_OP_CIPHER_AES_ECB:
                rc = wh_Client_AesEcb(ctx, &aes, enc, io->inputPtr,
                                      io->inputLength, io->outputPtr);
                break;
#endif
#ifdef HAVE_AES_CBC
            case WH_AUTOSAR_OP_CIPHER_AES_CBC:
                rc = wh_Client_AesCbc(ctx, &aes, enc, io->inputPtr,
                                      io->inputLength, io->outputPtr);
                break;
#endif
#ifdef WOLFSSL_AES_COUNTER
            case WH_AUTOSAR_OP_CIPHER_AES_CTR:
                rc = wh_Client_AesCtr(ctx, &aes, enc, io->inputPtr,
                                      io->inputLength, io->outputPtr);
                break;
#endif
#ifdef HAVE_AESGCM
            case WH_AUTOSAR_OP_AEAD_AES_GCM: {
                uint8* tagOut = io->secondaryOutputPtr;
                uint32 tagLen = (io->secondaryOutputLengthPtr != NULL)
                                    ? *io->secondaryOutputLengthPtr
                                    : 16u;
                rc            = wh_Client_AesGcm(
                    ctx, &aes, enc, io->inputPtr, io->inputLength,
                    io->secondaryInputPtr, io->secondaryInputLength,
                    io->tertiaryInputPtr, io->tertiaryInputLength,
                    enc ? NULL : tagOut, enc ? tagOut : NULL, tagLen,
                    io->outputPtr);
                if (!enc) {
                    if (rc == 0) {
                        writeVerifyResult(job, TRUE);
                    }
                    else if (isVerifyRejection(rc)) {
                        /* GCM tag mismatch surfaces here. SWS path:
                         * E_OK + verifyPtr=NOT_OK. Mask rc so the
                         * outer return treats this as API success. */
                        writeVerifyResult(job, FALSE);
                        rc = 0;
                    }
                    /* else: rc stays negative, caller gets E_NOT_OK. */
                }
                break;
            }
#endif
            default:
                rc = WH_ERROR_NOTIMPL;
                break;
        }
    }
    if (rc == 0 && io->outputLengthPtr != NULL) {
        *io->outputLengthPtr = io->inputLength;
    }
    wc_AesFree(&aes);
    return (rc == 0) ? E_OK : E_NOT_OK;
}

static Std_ReturnType doCmacSync(whClientContext* ctx, Crypto_JobType* job,
                                 whKeyId keyId, boolean verify)
{
    Cmac                                cmac;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    uint8                               macBuf[16];
    uint32                              macLen = (uint32)sizeof(macBuf);
    int                                 rc;

    (void)memset(&cmac, 0, sizeof(cmac));
    rc = wh_Client_CmacSetKeyId(&cmac, keyId);
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_Cmac(ctx, &cmac, WC_CMAC_AES, NULL, 0u, io->inputPtr,
                        io->inputLength, macBuf, &macLen);
    if (rc != 0)
        return E_NOT_OK;

    if (verify) {
        /* Constant-time MAC compare: timing leak about which byte
         * mismatched first is a CVE-class issue for authenticated
         * primitives. */
        boolean ok =
            (io->secondaryInputPtr != NULL &&
             io->secondaryInputLength == macLen &&
             wh_Autosar_ConstantCompare(macBuf, io->secondaryInputPtr, macLen))
                ? TRUE
                : FALSE;
        writeVerifyResult(job, ok);
        return E_OK;
    }
    if (io->outputPtr != NULL && io->outputLengthPtr != NULL) {
        uint32 want =
            (*io->outputLengthPtr < macLen) ? *io->outputLengthPtr : macLen;
        (void)memcpy(io->outputPtr, macBuf, want);
        *io->outputLengthPtr = want;
    }
    return E_OK;
}

static Std_ReturnType doEcdsaSync(whClientContext* ctx, Crypto_JobType* job,
                                  whKeyId keyId, boolean verify)
{
    ecc_key                             key;
    int                                 rc;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    Std_ReturnType                      ret;

    rc = wc_ecc_init_ex(&key, NULL, WH_DEV_ID);
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_EccSetKeyId(&key, keyId);
    if (rc == 0) {
        if (verify) {
            int verifyRes = -1;
            rc = wh_Client_EccVerify(ctx, &key, io->secondaryInputPtr,
                                     (uint16)io->secondaryInputLength,
                                     io->inputPtr, (uint16)io->inputLength,
                                     &verifyRes);
            /* Two ways a bad signature surfaces:
             *   1. rc=0 with verifyRes=0 — wolfCrypt parsed the DER and
             *      the math rejected. Clean path.
             *   2. rc<0 in wolfCrypt range with verifyRes untouched —
             *      wolfCrypt rejected the signature before completing
             *      math (malformed DER, etc.).
             * Both are SWS "API succeeded, signature invalid" → E_OK
             * with verifyPtr=NOT_OK. Only wolfHSM-transport-range
             * negatives are genuine API failures. */
            if (verifyRes == 0 || verifyRes == 1) {
                writeVerifyResult(job, verifyRes == 1);
                wc_ecc_free(&key);
                return E_OK;
            }
            if (isVerifyRejection(rc)) {
                writeVerifyResult(job, FALSE);
                wc_ecc_free(&key);
                return E_OK;
            }
            /* Else: transport-level error. Fall through to E_NOT_OK. */
        }
        else {
            uint16 sigLen = (io->outputLengthPtr != NULL)
                                ? (uint16)(*io->outputLengthPtr)
                                : 0u;
            rc            = wh_Client_EccSign(ctx, &key, io->inputPtr,
                                              (uint16)io->inputLength, io->outputPtr,
                                              &sigLen);
            if (rc == 0 && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = sigLen;
            }
        }
    }
    /* For verify, the API call succeeded as long as wolfHSM reported no
     * transport / cryptographic error — even if the signature itself
     * was rejected (which is communicated through verifyPtr). */
    ret = (rc == 0) ? E_OK : E_NOT_OK;
    wc_ecc_free(&key);
    return ret;
}

#ifdef HAVE_ED25519
static Std_ReturnType doEd25519Sync(whClientContext* ctx, Crypto_JobType* job,
                                    whKeyId keyId, boolean verify)
{
    ed25519_key                         key;
    int                                 rc;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    Std_ReturnType                      ret;

    rc = wc_ed25519_init_ex(&key, NULL, WH_DEV_ID);
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_Ed25519SetKeyId(&key, keyId);
    if (rc == 0) {
        if (verify) {
            int verifyRes = -1;
            rc = wh_Client_Ed25519Verify(ctx, &key, io->secondaryInputPtr,
                                         io->secondaryInputLength, io->inputPtr,
                                         io->inputLength,
                                         /* Ed25519 pure (RFC 8032 §5.1) */
                                         0u, NULL, 0u, &verifyRes);
            if (verifyRes == 0 || verifyRes == 1) {
                writeVerifyResult(job, verifyRes == 1);
                wc_ed25519_free(&key);
                return E_OK;
            }
            if (isVerifyRejection(rc)) {
                writeVerifyResult(job, FALSE);
                wc_ed25519_free(&key);
                return E_OK;
            }
        }
        else {
            uint32_t sigLen =
                (io->outputLengthPtr != NULL) ? *io->outputLengthPtr : 0u;
            rc = wh_Client_Ed25519Sign(ctx, &key, io->inputPtr, io->inputLength,
                                       /* pure mode, no context bytes */
                                       0u, NULL, 0u, io->outputPtr, &sigLen);
            if (rc == 0 && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = sigLen;
            }
        }
    }
    ret = (rc == 0) ? E_OK : E_NOT_OK;
    wc_ed25519_free(&key);
    return ret;
}
#endif /* HAVE_ED25519 */

#ifndef NO_RSA
/* RSA-PKCS#1 v1.5 sign / verify. The job's inputPtr is expected to be
 * the hash digest the application wants signed (CSM is responsible for
 * the hashing step). wc_RsaSSL_Sign applies the PKCS#1 v1.5 signature
 * padding internally and routes the private-key op through wolfHSM via
 * the cryptocb registered by wc_InitRsaKey_ex(..., WH_DEV_ID). */
static Std_ReturnType doRsaSync(whClientContext* ctx, Crypto_JobType* job,
                                whKeyId keyId, boolean verify)
{
    RsaKey rsa;
    WC_RNG rng;
    /* ctx is unused: wc_RsaSSL_Sign / Verify route through the wolfCrypt
     * cryptocb registered by wc_InitRsaKey_ex(..., WH_DEV_ID), which
     * picks up the wolfHSM client from the global devId binding. */
    (void)ctx;
    int                                 rc;
    int                                 rngInited = 0;
    Crypto_JobPrimitiveInputOutputType* io        = jobIo(job);
    Std_ReturnType                      ret       = E_NOT_OK;

    rc = wc_InitRsaKey_ex(&rsa, NULL, WH_DEV_ID);
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_RsaSetKeyId(&rsa, keyId);
    if (rc != 0)
        goto cleanup;

    if (verify) {
        /* wc_RsaSSL_Verify returns the recovered, unpadded plaintext
         * (the hash digest that was signed) on success. We compare to
         * the caller's inputPtr (= the hash they expected) to decide
         * the verifyPtr outcome. */
        uint8_t plain[512];
        int     plainLen;
        plainLen =
            wc_RsaSSL_Verify(io->secondaryInputPtr, io->secondaryInputLength,
                             plain, (word32)sizeof(plain), &rsa);
        if (plainLen >= 0) {
            boolean ok = ((uint32)plainLen == io->inputLength &&
                          wh_Autosar_ConstantCompare(plain, io->inputPtr,
                                                     io->inputLength) != 0)
                             ? TRUE
                             : FALSE;
            writeVerifyResult(job, ok);
            ret = E_OK;
            goto cleanup;
        }
        if (isVerifyRejection(plainLen)) {
            writeVerifyResult(job, FALSE);
            ret = E_OK;
            goto cleanup;
        }
        /* Else: real transport / setup error. */
        ret = E_NOT_OK;
        goto cleanup;
    }

    /* Sign path. */
    rc = wc_InitRng_ex(&rng, NULL, WH_DEV_ID);
    if (rc != 0)
        goto cleanup;
    rngInited = 1;
    {
        word32 sigLen =
            (io->outputLengthPtr != NULL) ? *io->outputLengthPtr : 0u;
        rc = wc_RsaSSL_Sign(io->inputPtr, io->inputLength, io->outputPtr,
                            sigLen, &rsa, &rng);
        if (rc < 0) {
            ret = E_NOT_OK;
            goto cleanup;
        }
        if (io->outputLengthPtr != NULL) {
            *io->outputLengthPtr = (uint32)rc;
        }
        ret = E_OK;
    }

cleanup:
    if (rngInited)
        (void)wc_FreeRng(&rng);
    (void)wc_FreeRsaKey(&rsa);
    return ret;
}
#endif /* !NO_RSA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

static Std_ReturnType doRngSync(whClientContext* ctx, Crypto_JobType* job)
{
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    int                                 rc;
    if (io->outputPtr == NULL || io->outputLengthPtr == NULL) {
        return E_NOT_OK;
    }
    rc = wh_Client_RngGenerate(ctx, io->outputPtr, *io->outputLengthPtr);
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}

/* -------------------------------------------------------------------
 * Sync entry
 * ------------------------------------------------------------------- */

Std_ReturnType wh_Autosar_ProcessJobSync(wh_AutosarDriverObject* obj,
                                         Crypto_JobType*         job)
{
    const Crypto_PrimitiveInfoType* pi = job->jobPrimitiveInfo->primitiveInfo;
    wh_AutosarOpKind                op = resolveOpKind(job);
    whKeyId                         keyId =
        wh_Autosar_ComposeKeyId(job->jobPrimitiveInfo->cryIfKeyId, 1u);
    Std_ReturnType ret = E_NOT_OK;

    if (op == WH_AUTOSAR_OP_INVALID) {
        return E_NOT_OK;
    }
    job->jobState = CRYPTO_JOBSTATE_ACTIVE;

    switch (op) {
        case WH_AUTOSAR_OP_RNG_GENERATE:
            ret = doRngSync(&obj->client, job);
            break;
#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_AUTOSAR_OP_HASH_SHA224:
        case WH_AUTOSAR_OP_HASH_SHA256:
        case WH_AUTOSAR_OP_HASH_SHA384:
        case WH_AUTOSAR_OP_HASH_SHA512:
            ret = hashSyncDispatch(obj, op, job);
            break;
        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM:
            ret = doAesSync(&obj->client, op, isEncryptService(pi->service),
                            job, keyId);
            break;
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
            ret = doCmacSync(&obj->client, job, keyId,
                             pi->service == CRYPTO_MACVERIFY);
            break;
        case WH_AUTOSAR_OP_SIG_ECDSA:
            ret = doEcdsaSync(&obj->client, job, keyId,
                              pi->service == CRYPTO_SIGNATUREVERIFY);
            break;
#ifdef HAVE_ED25519
        case WH_AUTOSAR_OP_SIG_ED25519:
            ret = doEd25519Sync(&obj->client, job, keyId,
                                pi->service == CRYPTO_SIGNATUREVERIFY);
            break;
#endif
#ifndef NO_RSA
        case WH_AUTOSAR_OP_SIG_RSA_PKCS1_V1_5:
            ret = doRsaSync(&obj->client, job, keyId,
                            pi->service == CRYPTO_SIGNATUREVERIFY);
            break;
            /* PSS mode left as E_NOT_OK pending a separate wiring pass. */
#endif
#endif
        default:
            ret = E_NOT_OK;
            break;
    }

    job->jobState = CRYPTO_JOBSTATE_IDLE;
    return ret;
}

/* -------------------------------------------------------------------
 * Async dispatch — Request/Response with single in-flight per client
 *
 * Slot lifecycle:
 *   IDLE → QUEUED  (ProcessJobAsync, caller returns immediately)
 *   QUEUED → PENDING (MainFunction, sends *Request)
 *   PENDING → COMPLETE (MainFunction, drains *Response)
 *   * → CANCELLING (CancelJob)
 *   COMPLETE → IDLE (MainFunction, after CryIf callback)
 *   CANCELLING → IDLE (MainFunction, after silent drain)
 *
 * Invariant: at most ONE slot is in PENDING or CANCELLING per driver
 * object (the wolfHSM client supports one in-flight request).
 * ------------------------------------------------------------------- */

static wh_AutosarJobSlot* findSlotInState(wh_AutosarDriverObject* obj,
                                          wh_AutosarAsyncState    st)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        if (obj->asyncSlots[i].state == st) {
            return &obj->asyncSlots[i];
        }
    }
    return NULL;
}

static boolean anySlotInFlight(wh_AutosarDriverObject* obj)
{
    return (findSlotInState(obj, WH_AUTOSAR_ASYNC_PENDING) != NULL ||
            findSlotInState(obj, WH_AUTOSAR_ASYNC_CANCELLING) != NULL)
               ? TRUE
               : FALSE;
}

static wh_AutosarJobSlot* allocSlot(wh_AutosarDriverObject* obj)
{
    return findSlotInState(obj, WH_AUTOSAR_ASYNC_IDLE);
}

static wh_AutosarJobSlot* oldestQueuedSlot(wh_AutosarDriverObject* obj)
{
    wh_AutosarJobSlot* oldest = NULL;
    uint32             i;
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        wh_AutosarJobSlot* s = &obj->asyncSlots[i];
        if (s->state != WH_AUTOSAR_ASYNC_QUEUED)
            continue;
        if (oldest == NULL || s->seq < oldest->seq) {
            oldest = s;
        }
    }
    return oldest;
}

static void slotInit(wh_AutosarDriverObject* obj, wh_AutosarJobSlot* slot,
                     Crypto_JobType* job, wh_AutosarOpKind op)
{
    (void)memset(&slot->op, 0, sizeof(slot->op));
    slot->job          = job;
    slot->opKind       = op;
    slot->phase        = WH_AUTOSAR_PHASE_ONESHOT;
    slot->state        = WH_AUTOSAR_ASYNC_QUEUED;
    slot->result       = E_OK;
    slot->seq          = obj->nextSeq++;
    slot->ticksAtIssue = 0u;
}

/* Release wolfCrypt resources tied to a slot. Called by finishSlot at
 * every terminal transition (success, error, cancel-drain). */
static void slotFreeWcResources(wh_AutosarJobSlot* slot)
{
#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)slot;
#else
    switch (slot->opKind) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            wc_Sha256Free(&slot->op.wc.sha256);
            break;
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            wc_Sha384Free(&slot->op.wc.sha384);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            wc_Sha512Free(&slot->op.wc.sha512);
            break;
#endif
        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM:
            wc_AesFree(&slot->op.wc.aes);
            break;
        case WH_AUTOSAR_OP_SIG_ECDSA:
            wc_ecc_free(&slot->op.wc.ecc);
            break;
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
            /* wolfCrypt's Cmac struct holds no dynamic state, but free
             * is harmless and future-proof. */
            (void)wc_CmacFree(&slot->op.wc.cmac);
            break;
        default:
            break;
    }
#endif
}

/* --- Request half (issue): runs under the slot lock. ---------------- */

static int chunkSizeFor(wh_AutosarOpKind op, uint32 want)
{
    /* wh_Client_Sha*UpdateRequest reject if want > per-call capacity.
     * Bound aggressively (1 KiB) to fit any sane comm buffer. */
    (void)op;
    return (want > 1024u) ? 1024 : (int)want;
}

static int issueOneHashUpdate(whClientContext* ctx, wh_AutosarJobSlot* slot,
                              bool* outSent)
{
    int    rc   = WH_ERROR_NOTIMPL;
    uint32 want = chunkSizeFor(slot->opKind, slot->op.hashRemaining);

    *outSent = false;
    switch (slot->opKind) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            rc = wh_Client_Sha256UpdateRequest(
                ctx, &slot->op.wc.sha256, slot->op.hashInput, want, outSent);
            break;
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            rc = wh_Client_Sha384UpdateRequest(
                ctx, &slot->op.wc.sha384, slot->op.hashInput, want, outSent);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            rc = wh_Client_Sha512UpdateRequest(
                ctx, &slot->op.wc.sha512, slot->op.hashInput, want, outSent);
            break;
#endif
        default:
            return WH_ERROR_NOTIMPL;
    }
    if (rc == WH_ERROR_OK) {
        slot->op.hashInput += want;
        slot->op.hashRemaining -= want;
    }
    return rc;
}

static int issueHashFinalRequest(whClientContext* ctx, wh_AutosarJobSlot* slot)
{
    switch (slot->opKind) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            return wh_Client_Sha256FinalRequest(ctx, &slot->op.wc.sha256);
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            return wh_Client_Sha384FinalRequest(ctx, &slot->op.wc.sha384);
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            return wh_Client_Sha512FinalRequest(ctx, &slot->op.wc.sha512);
#endif
        default:
            return WH_ERROR_NOTIMPL;
    }
}

static int issueAsyncRequest(wh_AutosarDriverObject* obj,
                             wh_AutosarJobSlot*      slot)
{
    whClientContext*                    ctx = &obj->client;
    Crypto_JobType*                     job = slot->job;
    Crypto_JobPrimitiveInputOutputType* io  = jobIo(job);
    int                                 rc  = WH_ERROR_NOTIMPL;
    whKeyId                             keyId =
        wh_Autosar_ComposeKeyId(job->jobPrimitiveInfo->cryIfKeyId, 1u);

    switch (slot->opKind) {
        case WH_AUTOSAR_OP_RNG_GENERATE:
            if (io->outputPtr == NULL || io->outputLengthPtr == NULL) {
                return WH_ERROR_BADARGS;
            }
            slot->op.rawOut   = io->outputPtr;
            slot->op.rawLen32 = *io->outputLengthPtr;
            rc = wh_Client_RngGenerateRequest(ctx, slot->op.rawLen32);
            break;

#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_AUTOSAR_OP_HASH_SHA256:
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
#endif
        {
            bool sent = false;
            rc        = (slot->opKind == WH_AUTOSAR_OP_HASH_SHA256)
                            ? wc_InitSha256_ex(&slot->op.wc.sha256, NULL, WH_DEV_ID)
#ifdef WOLFSSL_SHA384
                 : (slot->opKind == WH_AUTOSAR_OP_HASH_SHA384)
                     ? wc_InitSha384_ex(&slot->op.wc.sha384, NULL, WH_DEV_ID)
#endif
#ifdef WOLFSSL_SHA512
                 : (slot->opKind == WH_AUTOSAR_OP_HASH_SHA512)
                     ? wc_InitSha512_ex(&slot->op.wc.sha512, NULL, WH_DEV_ID)
#endif
                     : WH_ERROR_NOTIMPL;
            if (rc != 0)
                break;
            slot->op.digestOut = io->outputPtr;
            slot->op.digestLen =
                (io->outputLengthPtr != NULL) ? *io->outputLengthPtr : 0u;
            slot->op.hashInput     = io->inputPtr;
            slot->op.hashRemaining = io->inputLength;
            if (slot->op.hashRemaining > 0u) {
                rc = issueOneHashUpdate(ctx, slot, &sent);
                if (rc == WH_ERROR_OK && !sent) {
                    /* Locally buffered; either issue Final (no more
                     * input) or another Update (input remaining). */
                    if (slot->op.hashRemaining > 0u) {
                        rc = issueOneHashUpdate(ctx, slot, &sent);
                    }
                }
                if (rc == WH_ERROR_OK && !sent &&
                    slot->op.hashRemaining == 0u) {
                    rc          = issueHashFinalRequest(ctx, slot);
                    slot->phase = WH_AUTOSAR_PHASE_HASH_FINAL;
                }
                else if (rc == WH_ERROR_OK) {
                    slot->phase = WH_AUTOSAR_PHASE_HASH_UPDATE;
                }
            }
            else {
                /* Zero-length input: skip straight to Final. */
                rc          = issueHashFinalRequest(ctx, slot);
                slot->phase = WH_AUTOSAR_PHASE_HASH_FINAL;
            }
            break;
        }

        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM: {
            const Crypto_PrimitiveInfoType* pi =
                job->jobPrimitiveInfo->primitiveInfo;
            int enc = isEncryptService(pi->service);
            rc      = wc_AesInit(&slot->op.wc.aes, NULL, WH_DEV_ID);
            if (rc != 0)
                break;
            slot->op.wc.aes.keylen = (int)(pi->algorithm.keyLength / 8u);
            rc = wh_Client_AesSetKeyId(&slot->op.wc.aes, keyId);
            if (rc == 0 && io->secondaryInputPtr != NULL &&
                slot->opKind != WH_AUTOSAR_OP_CIPHER_AES_ECB) {
                rc = wc_AesSetIV(&slot->op.wc.aes, io->secondaryInputPtr);
            }
            if (rc != 0)
                break;
            slot->op.cipherOut = io->outputPtr;
            slot->op.cipherLen = io->inputLength;
            slot->op.tagOut    = io->secondaryOutputPtr;
            slot->op.tagLen    = (io->secondaryOutputLengthPtr != NULL)
                                     ? *io->secondaryOutputLengthPtr
                                     : 16u;
            switch (slot->opKind) {
#ifdef HAVE_AES_ECB
                case WH_AUTOSAR_OP_CIPHER_AES_ECB:
                    rc = wh_Client_AesEcbRequest(ctx, &slot->op.wc.aes, enc,
                                                 io->inputPtr, io->inputLength);
                    break;
#endif
#ifdef HAVE_AES_CBC
                case WH_AUTOSAR_OP_CIPHER_AES_CBC:
                    rc = wh_Client_AesCbcRequest(ctx, &slot->op.wc.aes, enc,
                                                 io->inputPtr, io->inputLength);
                    break;
#endif
#ifdef WOLFSSL_AES_COUNTER
                case WH_AUTOSAR_OP_CIPHER_AES_CTR:
                    rc = wh_Client_AesCtrRequest(ctx, &slot->op.wc.aes, enc,
                                                 io->inputPtr, io->inputLength);
                    break;
#endif
#ifdef HAVE_AESGCM
                case WH_AUTOSAR_OP_AEAD_AES_GCM:
                    rc = wh_Client_AesGcmRequest(
                        ctx, &slot->op.wc.aes, enc, io->inputPtr,
                        io->inputLength, io->secondaryInputPtr,
                        io->secondaryInputLength, io->tertiaryInputPtr,
                        io->tertiaryInputLength,
                        enc ? NULL : io->secondaryOutputPtr, slot->op.tagLen);
                    break;
#endif
                default:
                    rc = WH_ERROR_NOTIMPL;
                    break;
            }
            break;
        }

        case WH_AUTOSAR_OP_SIG_ECDSA: {
            boolean verify = (job->jobPrimitiveInfo->primitiveInfo->service ==
                              CRYPTO_SIGNATUREVERIFY)
                                 ? TRUE
                                 : FALSE;
            rc             = wc_ecc_init_ex(&slot->op.wc.ecc, NULL, WH_DEV_ID);
            if (rc != 0)
                break;
            (void)wh_Client_EccSetKeyId(&slot->op.wc.ecc, keyId);
            if (verify) {
                rc = wh_Client_EccVerifyRequest(
                    ctx, keyId, io->secondaryInputPtr,
                    (uint16)io->secondaryInputLength, io->inputPtr,
                    (uint16)io->inputLength);
            }
            else {
                slot->op.rawOut   = io->outputPtr;
                slot->op.rawLen16 = (io->outputLengthPtr != NULL)
                                        ? (uint16)(*io->outputLengthPtr)
                                        : 0u;
                rc = wh_Client_EccSignRequest(ctx, keyId, io->inputPtr,
                                              (uint16)io->inputLength);
            }
            break;
        }

        case WH_AUTOSAR_OP_KEYAGREE_ECDH: {
            whKeyId partnerId;
            if (io->tertiaryInputPtr == NULL || io->tertiaryInputLength < 2u) {
                return WH_ERROR_BADARGS;
            }
            partnerId         = (whKeyId)(io->tertiaryInputPtr[0] |
                                  (io->tertiaryInputPtr[1] << 8));
            slot->op.rawOut   = io->outputPtr;
            slot->op.rawLen16 = (io->outputLengthPtr != NULL)
                                    ? (uint16)(*io->outputLengthPtr)
                                    : 0u;
            rc = wh_Client_EccSharedSecretRequest(ctx, keyId, partnerId);
            break;
        }

        case WH_AUTOSAR_OP_MAC_CMAC_AES: {
            boolean verify = (job->jobPrimitiveInfo->primitiveInfo->service ==
                              CRYPTO_MACVERIFY)
                                 ? TRUE
                                 : FALSE;
            uint32  macLen = verify ? io->secondaryInputLength : 16u;
            (void)memset(&slot->op.wc.cmac, 0, sizeof(slot->op.wc.cmac));
            rc = wh_Client_CmacSetKeyId(&slot->op.wc.cmac, keyId);
            if (rc != 0)
                break;
            if (verify) {
                /* Stash the expected MAC across the in-flight Request so
                 * the Response can constant-time compare. */
                slot->op.verifyRef    = io->secondaryInputPtr;
                slot->op.verifyRefLen = io->secondaryInputLength;
            }
            else {
                slot->op.rawOut = io->outputPtr;
                slot->op.rawLen32 =
                    (io->outputLengthPtr != NULL) ? *io->outputLengthPtr : 16u;
            }
            rc = wh_Client_CmacGenerateRequest(
                ctx, &slot->op.wc.cmac, WC_CMAC_AES, /*inline key*/ NULL,
                /*keyLen*/ 0u, io->inputPtr, io->inputLength, macLen);
            break;
        }

        /* RSA-PKCS#1-v1.5 async deliberately omitted: wolfHSM's
         * wh_Client_RsaFunctionRequest is a RAW RSA primitive
         * (RSA_PRIVATE_ENCRYPT / RSA_PUBLIC_DECRYPT), and wolfSSL
         * does not expose its v1.5 padding/unpadding routines as
         * public API. Wiring async RSA-PKCS1-v1.5 means duplicating
         * the padding block construction client-side, which is out
         * of scope for this port. Sync RSA-PKCS1-v1.5 goes through
         * wc_RsaSSL_Sign/Verify and remains supported. */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
    return rc;
}

/* --- Response half: returns WH_ERROR_NOTREADY if still waiting,
 *     WH_ERROR_OK on terminal success, negative on terminal error. --- */

static int pollAsyncResponse(wh_AutosarDriverObject* obj,
                             wh_AutosarJobSlot*      slot)
{
    whClientContext*                    ctx = &obj->client;
    Crypto_JobType*                     job = slot->job;
    Crypto_JobPrimitiveInputOutputType* io  = jobIo(job);
    int                                 rc  = WH_ERROR_NOTIMPL;

    switch (slot->opKind) {
        case WH_AUTOSAR_OP_RNG_GENERATE: {
            uint32 inout = slot->op.rawLen32;
            rc = wh_Client_RngGenerateResponse(ctx, slot->op.rawOut, &inout);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = inout;
            }
            break;
        }

#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_AUTOSAR_OP_HASH_SHA256:
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
#endif
        {
            if (slot->phase == WH_AUTOSAR_PHASE_HASH_UPDATE) {
                /* Drain the in-flight Update response. */
                if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA256) {
                    rc = wh_Client_Sha256UpdateResponse(ctx,
                                                        &slot->op.wc.sha256);
                }
#ifdef WOLFSSL_SHA384
                else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA384) {
                    rc = wh_Client_Sha384UpdateResponse(ctx,
                                                        &slot->op.wc.sha384);
                }
#endif
#ifdef WOLFSSL_SHA512
                else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA512) {
                    rc = wh_Client_Sha512UpdateResponse(ctx,
                                                        &slot->op.wc.sha512);
                }
#endif
                if (rc != WH_ERROR_OK)
                    break;
                /* Advance: more input → another Update; otherwise Final. */
                if (slot->op.hashRemaining > 0u) {
                    bool sent = false;
                    rc        = issueOneHashUpdate(ctx, slot, &sent);
                    if (rc != WH_ERROR_OK)
                        break;
                    if (!sent && slot->op.hashRemaining == 0u) {
                        rc = issueHashFinalRequest(ctx, slot);
                        if (rc != WH_ERROR_OK)
                            break;
                        slot->phase = WH_AUTOSAR_PHASE_HASH_FINAL;
                    }
                    /* Either way, more network round-trips to go. */
                    return WH_ERROR_NOTREADY;
                }
                /* No remaining input: issue Final and continue waiting. */
                rc = issueHashFinalRequest(ctx, slot);
                if (rc != WH_ERROR_OK)
                    break;
                slot->phase = WH_AUTOSAR_PHASE_HASH_FINAL;
                return WH_ERROR_NOTREADY;
            }
            /* phase == HASH_FINAL */
            if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA256) {
                if (slot->op.digestLen < WC_SHA256_DIGEST_SIZE) {
                    rc = WH_ERROR_BUFFER_SIZE;
                    break;
                }
                rc = wh_Client_Sha256FinalResponse(ctx, &slot->op.wc.sha256,
                                                   slot->op.digestOut);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = WC_SHA256_DIGEST_SIZE;
                }
            }
#ifdef WOLFSSL_SHA384
            else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA384) {
                if (slot->op.digestLen < WC_SHA384_DIGEST_SIZE) {
                    rc = WH_ERROR_BUFFER_SIZE;
                    break;
                }
                rc = wh_Client_Sha384FinalResponse(ctx, &slot->op.wc.sha384,
                                                   slot->op.digestOut);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = WC_SHA384_DIGEST_SIZE;
                }
            }
#endif
#ifdef WOLFSSL_SHA512
            else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA512) {
                if (slot->op.digestLen < WC_SHA512_DIGEST_SIZE) {
                    rc = WH_ERROR_BUFFER_SIZE;
                    break;
                }
                rc = wh_Client_Sha512FinalResponse(ctx, &slot->op.wc.sha512,
                                                   slot->op.digestOut);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = WC_SHA512_DIGEST_SIZE;
                }
            }
#endif
            break;
        }

#ifdef HAVE_AES_ECB
        case WH_AUTOSAR_OP_CIPHER_AES_ECB: {
            uint32 outSz = slot->op.cipherLen;
            rc           = wh_Client_AesEcbResponse(ctx, &slot->op.wc.aes,
                                                    slot->op.cipherOut, &outSz);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = outSz;
            }
            break;
        }
#endif
#ifdef HAVE_AES_CBC
        case WH_AUTOSAR_OP_CIPHER_AES_CBC: {
            uint32 outSz = slot->op.cipherLen;
            rc           = wh_Client_AesCbcResponse(ctx, &slot->op.wc.aes,
                                                    slot->op.cipherOut, &outSz);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = outSz;
            }
            break;
        }
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WH_AUTOSAR_OP_CIPHER_AES_CTR: {
            uint32 outSz = slot->op.cipherLen;
            rc           = wh_Client_AesCtrResponse(ctx, &slot->op.wc.aes,
                                                    slot->op.cipherOut, &outSz);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = outSz;
            }
            break;
        }
#endif
#ifdef HAVE_AESGCM
        case WH_AUTOSAR_OP_AEAD_AES_GCM: {
            uint32 outSz = 0u;
            int    enc =
                isEncryptService(job->jobPrimitiveInfo->primitiveInfo->service);
            rc = wh_Client_AesGcmResponse(
                ctx, &slot->op.wc.aes, slot->op.cipherOut, slot->op.cipherLen,
                &outSz, enc ? slot->op.tagOut : NULL, slot->op.tagLen);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = outSz;
            }
            if (!enc && rc != WH_ERROR_NOTREADY) {
                if (rc == WH_ERROR_OK) {
                    writeVerifyResult(job, TRUE);
                }
                else if (isVerifyRejection(rc)) {
                    /* GCM tag mismatch (or other wolfCrypt-side reject):
                     * SWS "API succeeded, verification failed". */
                    writeVerifyResult(job, FALSE);
                    rc = WH_ERROR_OK;
                }
                /* else: real wolfHSM transport error — let rc fall
                 * through, callback will fire with E_NOT_OK. */
            }
            break;
        }
#endif

        case WH_AUTOSAR_OP_SIG_ECDSA: {
            boolean verify = (job->jobPrimitiveInfo->primitiveInfo->service ==
                              CRYPTO_SIGNATUREVERIFY)
                                 ? TRUE
                                 : FALSE;
            if (verify) {
                int verifyRes = -1;
                rc = wh_Client_EccVerifyResponse(ctx, NULL, &verifyRes);
                if (verifyRes == 0 || verifyRes == 1) {
                    writeVerifyResult(job, verifyRes == 1);
                    rc = WH_ERROR_OK;
                }
                else if (isVerifyRejection(rc)) {
                    /* Malformed-DER or pre-math rejection: surface as
                     * E_OK with verifyPtr=NOT_OK per SWS. */
                    writeVerifyResult(job, FALSE);
                    rc = WH_ERROR_OK;
                }
            }
            else {
                uint16 sigLen = slot->op.rawLen16;
                rc = wh_Client_EccSignResponse(ctx, slot->op.rawOut, &sigLen);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = sigLen;
                }
            }
            break;
        }

        case WH_AUTOSAR_OP_KEYAGREE_ECDH: {
            uint16 sz = slot->op.rawLen16;
            rc = wh_Client_EccSharedSecretResponse(ctx, slot->op.rawOut, &sz);
            if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = sz;
            }
            break;
        }

        case WH_AUTOSAR_OP_MAC_CMAC_AES: {
            boolean verify = (job->jobPrimitiveInfo->primitiveInfo->service ==
                              CRYPTO_MACVERIFY)
                                 ? TRUE
                                 : FALSE;
            if (verify) {
                uint8  macBuf[16];
                uint32 macLen = (uint32)sizeof(macBuf);
                rc = wh_Client_CmacGenerateResponse(ctx, &slot->op.wc.cmac,
                                                    macBuf, &macLen);
                if (rc == WH_ERROR_OK) {
                    boolean ok = (slot->op.verifyRef != NULL &&
                                  slot->op.verifyRefLen == macLen &&
                                  wh_Autosar_ConstantCompare(
                                      macBuf, slot->op.verifyRef, macLen) != 0)
                                     ? TRUE
                                     : FALSE;
                    writeVerifyResult(job, ok);
                }
            }
            else {
                uint32 macLen = slot->op.rawLen32;
                rc = wh_Client_CmacGenerateResponse(ctx, &slot->op.wc.cmac,
                                                    slot->op.rawOut, &macLen);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = macLen;
                }
            }
            break;
        }

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
    return rc;
}

/* --- Public async entry: enqueue and return. ------------------------ */

Std_ReturnType wh_Autosar_ProcessJobAsync(wh_AutosarDriverObject* obj,
                                          Crypto_JobType*         job)
{
    wh_AutosarJobSlot* slot;
    wh_AutosarOpKind   op = resolveOpKind(job);

    if (op == WH_AUTOSAR_OP_INVALID) {
        return E_NOT_OK;
    }

    wh_Autosar_LockSlots(obj);
    slot = allocSlot(obj);
    if (slot == NULL) {
        wh_Autosar_UnlockSlots(obj);
        return E_NOT_OK;
    }
    slotInit(obj, slot, job, op);
    job->jobState = CRYPTO_JOBSTATE_ACTIVE;
    wh_Autosar_UnlockSlots(obj);

    return E_OK;
}

/* --- MainFunction driver -------------------------------------------- */

/* Promote the oldest QUEUED slot to PENDING by issuing its Request.
 * Called only when no other slot is in PENDING/CANCELLING (enforced by
 * the caller). Returns the slot if a Request was successfully issued
 * (slot is now PENDING) — or, if Request issuance failed, the slot is
 * already in COMPLETE state with result=E_NOT_OK and the caller will
 * pick it up on the next iteration. */
static void promoteOneQueued(wh_AutosarDriverObject* obj)
{
    wh_AutosarJobSlot* slot;
    int                rc;

    wh_Autosar_LockSlots(obj);
    slot = oldestQueuedSlot(obj);
    if (slot == NULL) {
        wh_Autosar_UnlockSlots(obj);
        return;
    }
    /* Reserve the slot under the lock so concurrent ProcessJobAsync /
     * CancelJob can't observe/modify it mid-issue. */
    slot->state        = WH_AUTOSAR_ASYNC_PENDING;
    slot->ticksAtIssue = obj->tickCount;
    wh_Autosar_UnlockSlots(obj);

    rc = issueAsyncRequest(obj, slot);
    if (rc != WH_ERROR_OK) {
        /* Request never went on the wire — free wolfCrypt resources
         * and surface the failure as a completion. */
        slotFreeWcResources(slot);
        wh_Autosar_LockSlots(obj);
        slot->result = E_NOT_OK;
        slot->state  = WH_AUTOSAR_ASYNC_COMPLETE;
        wh_Autosar_UnlockSlots(obj);
    }
}

void wh_Autosar_MainFunctionObject(wh_AutosarDriverObject* obj)
{
    wh_AutosarJobSlot* inFlight;
    wh_AutosarJobSlot* completeSlot   = NULL;
    Crypto_JobType*    completeJob    = NULL;
    Std_ReturnType     completeResult = E_NOT_OK;
    boolean            wasCancelled   = FALSE;

    obj->tickCount++;

    /* 1. Drive any in-flight slot. */
    wh_Autosar_LockSlots(obj);
    inFlight = findSlotInState(obj, WH_AUTOSAR_ASYNC_PENDING);
    if (inFlight == NULL) {
        inFlight = findSlotInState(obj, WH_AUTOSAR_ASYNC_CANCELLING);
    }
    wh_Autosar_UnlockSlots(obj);

    if (inFlight != NULL) {
        /* Timeout check runs BEFORE the response poll so a stalled
         * wire never blocks the deadline. Wrap-around safe via
         * unsigned subtraction. */
        if ((obj->tickCount - inFlight->ticksAtIssue) >
            CRYPTO_ASYNC_TIMEOUT_TICKS) {
            slotFreeWcResources(inFlight);
            wh_Autosar_LockSlots(obj);
            wasCancelled =
                (inFlight->state == WH_AUTOSAR_ASYNC_CANCELLING) ? TRUE : FALSE;
            if (wasCancelled) {
                inFlight->state = WH_AUTOSAR_ASYNC_IDLE;
                inFlight->job   = NULL;
            }
            else {
                inFlight->result = E_NOT_OK;
                inFlight->state  = WH_AUTOSAR_ASYNC_COMPLETE;
            }
            wh_Autosar_UnlockSlots(obj);
        }
        else {
            int rc = pollAsyncResponse(obj, inFlight);
            if (rc == WH_ERROR_NOTREADY) {
                /* Still in flight; don't promote QUEUED. */
                return;
            }
            slotFreeWcResources(inFlight);
            wh_Autosar_LockSlots(obj);
            wasCancelled =
                (inFlight->state == WH_AUTOSAR_ASYNC_CANCELLING) ? TRUE : FALSE;
            if (wasCancelled) {
                inFlight->state = WH_AUTOSAR_ASYNC_IDLE;
                inFlight->job   = NULL;
            }
            else {
                inFlight->result = (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
                inFlight->state  = WH_AUTOSAR_ASYNC_COMPLETE;
            }
            wh_Autosar_UnlockSlots(obj);
        }
    }

    /* 2. Surface any COMPLETE slot to CryIf. (No more than one per
     * MainFunction call to keep the callback latency predictable.) */
    wh_Autosar_LockSlots(obj);
    completeSlot = findSlotInState(obj, WH_AUTOSAR_ASYNC_COMPLETE);
    if (completeSlot != NULL) {
        completeJob         = completeSlot->job;
        completeResult      = completeSlot->result;
        completeSlot->state = WH_AUTOSAR_ASYNC_IDLE;
        completeSlot->job   = NULL;
    }
    wh_Autosar_UnlockSlots(obj);

    if (completeJob != NULL) {
        completeJob->jobState = CRYPTO_JOBSTATE_IDLE;
        CryIf_CallbackNotification(completeJob, completeResult);
    }

    /* 3. Promote the oldest QUEUED slot if no slot is in flight. */
    if (!anySlotInFlight(obj)) {
        promoteOneQueued(obj);
    }
}

/* -------------------------------------------------------------------
 * Test introspection
 * ------------------------------------------------------------------- */

uint32 wh_Autosar_DebugActiveSlotCount(const wh_AutosarDriverObject* obj)
{
    uint32 i;
    uint32 n = 0u;
    if (obj == NULL)
        return 0u;
    /* Lock cast: the public API takes a const pointer (read-only
     * observation), but the lock hook needs a non-const handle. We
     * are observing the state field; no mutation. */
    wh_Autosar_LockSlots((wh_AutosarDriverObject*)obj);
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        if (obj->asyncSlots[i].state != WH_AUTOSAR_ASYNC_IDLE) {
            n++;
        }
    }
    wh_Autosar_UnlockSlots((wh_AutosarDriverObject*)obj);
    return n;
}

uint32 wh_Autosar_DebugActiveHashStateCount(const wh_AutosarDriverObject* obj)
{
#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)obj;
    return 0u;
#else
    uint32 i;
    uint32 n = 0u;
    if (obj == NULL)
        return 0u;
    wh_Autosar_LockSlots((wh_AutosarDriverObject*)obj);
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        if (obj->hashStates[i].inUse) {
            n++;
        }
    }
    wh_Autosar_UnlockSlots((wh_AutosarDriverObject*)obj);
    return n;
#endif
}

void wh_Autosar_DebugAdvanceTicks(wh_AutosarDriverObject* obj, uint32 by)
{
    if (obj != NULL) {
        obj->tickCount += by;
    }
}

int wh_Autosar_DebugInjectFakePending(wh_AutosarDriverObject* obj,
                                      Crypto_JobType* job, wh_AutosarOpKind op)
{
    wh_AutosarJobSlot* slot;
    if (obj == NULL || job == NULL)
        return -1;
    wh_Autosar_LockSlots(obj);
    slot = allocSlot(obj);
    if (slot == NULL) {
        wh_Autosar_UnlockSlots(obj);
        return -1;
    }
    (void)memset(&slot->op, 0, sizeof(slot->op));
    slot->job          = job;
    slot->opKind       = op;
    slot->phase        = WH_AUTOSAR_PHASE_ONESHOT;
    slot->state        = WH_AUTOSAR_ASYNC_PENDING;
    slot->result       = E_OK;
    slot->seq          = obj->nextSeq++;
    slot->ticksAtIssue = obj->tickCount;
    wh_Autosar_UnlockSlots(obj);
    return 0;
}

void wh_Autosar_DebugForceResetSlots(wh_AutosarDriverObject* obj)
{
    uint32 i;
    if (obj == NULL)
        return;
    wh_Autosar_LockSlots(obj);
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        wh_AutosarJobSlot* slot = &obj->asyncSlots[i];
        if (slot->state != WH_AUTOSAR_ASYNC_IDLE) {
            /* The wolfCrypt context (if any) was allocated by us;
             * free it before the slot is recycled. */
            slotFreeWcResources(slot);
            slot->state = WH_AUTOSAR_ASYNC_IDLE;
            slot->job   = NULL;
            (void)memset(&slot->op, 0, sizeof(slot->op));
        }
    }
#ifndef WOLFHSM_CFG_NO_CRYPTO
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        if (obj->hashStates[i].inUse) {
            hashStateFreeWc(&obj->hashStates[i]);
            obj->hashStates[i].inUse = FALSE;
        }
    }
#endif
    wh_Autosar_UnlockSlots(obj);
}
