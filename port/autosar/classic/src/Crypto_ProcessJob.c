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
 * Sync and async job dispatch. Async jobs wait in slots until MainFunction
 * can issue them, one request in flight per client.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"
#include "wh_autosar_alg_map.h"
#include "wh_autosar_safe_compare.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_message_crypto.h"

#include <string.h>

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#include "Det.h"
#define CRYPTO_DET_REPORT(errid)                                \
    (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, \
                          CRYPTO_PROCESSJOB_SID, (errid))
#else
#define CRYPTO_DET_REPORT(errid) ((void)0)
#endif

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
#include "wolfssl/wolfcrypt/asn_public.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif
#include "wolfssl/wolfcrypt/hash.h"
#endif

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

/* CRYPTO_E_VER_OK is 0, so a verify job that fails early must say NOT_OK. */
static void presetVerifyResult(Crypto_JobType* job)
{
    Crypto_ServiceInfoType svc = job->jobPrimitiveInfo->primitiveInfo->service;
    if (svc == CRYPTO_MACVERIFY || svc == CRYPTO_SIGNATUREVERIFY ||
        svc == CRYPTO_AEADDECRYPT) {
        writeVerifyResult(job, FALSE);
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

static boolean isVerifyRejection(int rc)
{
    return wh_Autosar_IsVerifyRejection(rc) ? TRUE : FALSE;
}

/* Multi-call hash state */

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
    /* A re-START without FINISH reuses the job's entry. */
    wh_AutosarHashState* s = hashStateFind(obj, jobId);
    uint32               i;

    if (s != NULL) {
        hashStateFreeWc(s);
        (void)memset(s, 0, sizeof(*s));
        s->inUse = TRUE;
        s->jobId = jobId;
        return s;
    }
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        if (!obj->hashStates[i].inUse) {
            (void)memset(&obj->hashStates[i], 0, sizeof(obj->hashStates[i]));
            obj->hashStates[i].inUse = TRUE;
            obj->hashStates[i].jobId = jobId;
            return &obj->hashStates[i];
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
    s->busy  = FALSE;
}

/* TRUE while a START has been processed for jobId and FINISH has not. */
static boolean hashStreamOpen(wh_AutosarDriverObject* obj, uint32 jobId)
{
    boolean open;
    wh_Autosar_LockSlots(obj);
    open = (hashStateFind(obj, jobId) != NULL) ? TRUE : FALSE;
    wh_Autosar_UnlockSlots(obj);
    return open;
}


static int hashInit(whClientContext* ctx, wh_AutosarHashState* s,
                    wh_AutosarOpKind op)
{
    s->op = op;
    switch (op) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            return wc_InitSha256_ex(&s->wc.sha256, NULL, WH_CLIENT_DEVID(ctx));
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
            return wc_InitSha384_ex(&s->wc.sha384, NULL, WH_CLIENT_DEVID(ctx));
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
            return wc_InitSha512_ex(&s->wc.sha512, NULL, WH_CLIENT_DEVID(ctx));
#endif
        default:
            return WH_ERROR_NOTIMPL;
    }
}

/* Sends all input as blocking Update requests. */
static int hashUpdateSync(whClientContext* ctx, wh_AutosarHashState* s,
                          const uint8* in, uint32 inLen)
{
    int rc = WH_ERROR_OK;
    while (inLen > 0u) {
        bool   sent      = false;
        uint32 thisChunk = inLen;
        /* Halve on WH_ERROR_REQUEST_SIZE until the per-call capacity fits. */
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
            if (rc != WH_ERROR_REQUEST_SIZE)
                return rc;
            thisChunk /= 2u;
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
    boolean                             release =
        ((mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) ? TRUE : FALSE;
    uint32 outLen;
    int    rc = WH_ERROR_OK;

    /* busy keeps Crypto_CancelJob from freeing the state while in use. */
    wh_Autosar_LockSlots(obj);
    state = ((mode & CRYPTO_OPERATIONMODE_START) != 0u)
                ? hashStateAcquire(obj, job->jobId)
                : hashStateFind(obj, job->jobId);
    if (state != NULL) {
        state->busy = TRUE;
    }
    wh_Autosar_UnlockSlots(obj);
    if (state == NULL) {
        return E_NOT_OK;
    }

    if ((mode & CRYPTO_OPERATIONMODE_START) != 0u) {
        rc = hashInit(&obj->client, state, op);
        if (rc != WH_ERROR_OK) {
            release = TRUE;
        }
    }
    if (rc == WH_ERROR_OK && state->errored) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == WH_ERROR_OK && (mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u &&
        io->inputLength > 0u && io->inputPtr != NULL) {
        rc = hashUpdateSync(&obj->client, state, io->inputPtr, io->inputLength);
        if (rc != WH_ERROR_OK) {
            state->errored = TRUE;
        }
    }
    if (rc == WH_ERROR_OK && (mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) {
        if (io->outputPtr == NULL || io->outputLengthPtr == NULL) {
            rc = WH_ERROR_BADARGS;
        }
        else {
            outLen = *io->outputLengthPtr;
            rc = hashFinishSync(&obj->client, state, io->outputPtr, &outLen);
            if (rc == WH_ERROR_OK) {
                *io->outputLengthPtr = outLen;
            }
        }
    }

    wh_Autosar_LockSlots(obj);
    if (release) {
        hashStateRelease(state);
    }
    else {
        state->busy = FALSE;
    }
    wh_Autosar_UnlockSlots(obj);
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* Sync primitives */

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Takes the IV from CRYPTO_KE_CIPHER_IV, which every mode but ECB needs.
 * *ivLen is the capacity of iv on entry. */
static int takeIv(const Crypto_JobType* job, wh_AutosarOpKind op, uint8* iv,
                  uint32* ivLen)
{
    if (op == WH_AUTOSAR_OP_CIPHER_AES_ECB) {
        *ivLen = 0u;
        return WH_ERROR_OK;
    }
    if (wh_Autosar_KeyIvTake(job->cryptoKeyId, iv, ivLen) != E_OK) {
        return WH_ERROR_BADARGS;
    }
    if (op != WH_AUTOSAR_OP_AEAD_AES_GCM && *ivLen != AES_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }
    return WH_ERROR_OK;
}

static int aesPrepare(whClientContext* ctx, Aes* aes, Crypto_JobType* job,
                      whKeyId keyId, wh_AutosarOpKind op, const uint8* iv)
{
    const Crypto_PrimitiveInfoType* pi = job->jobPrimitiveInfo->primitiveInfo;
    int rc = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(ctx));

    if (rc != 0) {
        return rc;
    }
    /* The AES request builders read aes->keylen. */
    aes->keylen = (int)(pi->algorithm.keyLength / 8u);
    rc          = wh_Client_AesSetKeyId(aes, keyId);
    if (rc == 0 && op != WH_AUTOSAR_OP_CIPHER_AES_ECB &&
        op != WH_AUTOSAR_OP_AEAD_AES_GCM) {
        rc = wc_AesSetIV(aes, iv);
    }
    return rc;
}

static Std_ReturnType doAesSync(whClientContext* ctx, wh_AutosarOpKind op,
                                int enc, Crypto_JobType* job, whKeyId keyId)
{
    Aes                                 aes;
    int                                 rc;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    uint8                               iv[AES_BLOCK_SIZE];
    uint32                              ivLen   = (uint32)sizeof(iv);
    boolean                             tagFail = FALSE;

    rc = takeIv(job, op, iv, &ivLen);
    if (rc == 0) {
        rc = aesPrepare(ctx, &aes, job, keyId, op, iv);
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
                /* CTR is symmetric; the server mis-keys enc=0. */
                rc = wh_Client_AesCtr(ctx, &aes, 1, io->inputPtr,
                                      io->inputLength, io->outputPtr);
                break;
#endif
#ifdef HAVE_AESGCM
            case WH_AUTOSAR_OP_AEAD_AES_GCM: {
                uint32 tagLen = enc ? ((io->secondaryOutputLengthPtr != NULL)
                                           ? *io->secondaryOutputLengthPtr
                                           : 0u)
                                    : io->tertiaryInputLength;
                rc            = wh_Client_AesGcm(
                    ctx, &aes, enc, io->inputPtr, io->inputLength, iv, ivLen,
                    io->secondaryInputPtr, io->secondaryInputLength,
                    enc ? NULL : io->tertiaryInputPtr,
                    enc ? io->secondaryOutputPtr : NULL, tagLen, io->outputPtr);
                if (enc && rc == 0) {
                    *io->secondaryOutputLengthPtr = tagLen;
                }
                if (!enc) {
                    if (rc == 0) {
                        writeVerifyResult(job, TRUE);
                    }
                    else if (isVerifyRejection(rc)) {
                        /* Tag mismatch: E_OK with verifyPtr=NOT_OK and no
                         * plaintext. */
                        writeVerifyResult(job, FALSE);
                        tagFail = TRUE;
                        rc      = 0;
                    }
                }
                break;
            }
#endif
            default:
                rc = WH_ERROR_NOTIMPL;
                break;
        }
    }
    if (rc == 0) {
        *io->outputLengthPtr = tagFail ? 0u : io->inputLength;
    }
    wc_AesFree(&aes);
    return (rc == 0) ? E_OK : E_NOT_OK;
}

/* Compares the leading bits of mac against ref in constant time. */
static boolean macMatches(const uint8* mac, const uint8* ref, uint32 bits)
{
    uint32 full = bits / 8u;
    uint32 rem  = bits % 8u;
    int    diff = wh_Utils_ConstantCompare(mac, ref, full);

    if (rem != 0u) {
        diff |= (mac[full] ^ ref[full]) & (uint8)(0xFFu << (8u - rem));
    }
    return (diff == 0) ? TRUE : FALSE;
}

static Std_ReturnType doCmacSync(whClientContext* ctx, Crypto_JobType* job,
                                 whKeyId keyId, boolean verify)
{
    Cmac                                cmac;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    uint8                               macBuf[AES_BLOCK_SIZE];
    uint32                              macLen = (uint32)sizeof(macBuf);
    Std_ReturnType                      ret    = E_NOT_OK;
    int                                 rc;

    (void)memset(&cmac, 0, sizeof(cmac));
    rc = wh_Client_CmacSetKeyId(&cmac, keyId);
    if (rc == 0) {
        rc = wh_Client_Cmac(ctx, &cmac, WC_CMAC_AES, NULL, 0u, io->inputPtr,
                            io->inputLength, macBuf, &macLen);
    }
    if (rc == 0 && macLen == AES_BLOCK_SIZE) {
        if (verify) {
            /* MacVerify passes the MAC length in bits. */
            writeVerifyResult(job, macMatches(macBuf, io->secondaryInputPtr,
                                              io->secondaryInputLength));
        }
        else {
            if (*io->outputLengthPtr < macLen) {
                macLen = *io->outputLengthPtr;
            }
            (void)memcpy(io->outputPtr, macBuf, macLen);
            *io->outputLengthPtr = macLen;
        }
        ret = E_OK;
    }
    wh_Utils_ForceZero(macBuf, sizeof(macBuf));
    wh_Utils_ForceZero(&cmac, sizeof(cmac));
    return ret;
}

/* Digest to sign or verify: the input hashed with secondaryFamily, or the
 * input itself when secondaryFamily is NOT_SET. */
static int jobDigest(Crypto_JobType* job, uint8* out, uint32* outLen,
                     enum wc_HashType* outType)
{
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    Crypto_AlgorithmFamilyType          fam =
        job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;
    int    type = wh_AutosarMap_HashType((wh_AutosarAlgoFam)fam);
    int    rc   = WH_ERROR_BADARGS;
    word32 len  = io->inputLength;

    if (io->inputPtr == NULL && len != 0u) {
        return WH_ERROR_BADARGS;
    }
    if (type < 0 && fam != CRYPTO_ALGOFAM_NOT_SET) {
        return WH_ERROR_BADARGS;
    }
    if (type < 0) {
        if (len == 0u || len > *outLen) {
            return WH_ERROR_BADARGS;
        }
        (void)memcpy(out, io->inputPtr, len);
        *outLen  = len;
        *outType = (len == WC_SHA256_DIGEST_SIZE)   ? WC_HASH_TYPE_SHA256
                   : (len == WC_SHA384_DIGEST_SIZE) ? WC_HASH_TYPE_SHA384
                   : (len == WC_SHA512_DIGEST_SIZE) ? WC_HASH_TYPE_SHA512
                                                    : WC_HASH_TYPE_NONE;
        return WH_ERROR_OK;
    }
    switch (type) {
        case WC_HASH_TYPE_SHA256:
            rc = wc_Sha256Hash_ex(io->inputPtr, len, out, NULL, INVALID_DEVID);
            break;
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            rc = wc_Sha384Hash_ex(io->inputPtr, len, out, NULL, INVALID_DEVID);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            rc = wc_Sha512Hash_ex(io->inputPtr, len, out, NULL, INVALID_DEVID);
            break;
#endif
        default:
            break;
    }
    if (rc == 0) {
        *outLen  = (uint32)wc_HashGetDigestSize((enum wc_HashType)type);
        *outType = (enum wc_HashType)type;
    }
    return rc;
}

static Std_ReturnType doEcdsaSync(whClientContext* ctx, Crypto_JobType* job,
                                  whKeyId keyId, boolean verify)
{
    ecc_key                             key;
    int                                 rc;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    Std_ReturnType                      ret;
    uint8                               digest[WC_MAX_DIGEST_SIZE];
    uint32                              digestLen = (uint32)sizeof(digest);
    enum wc_HashType                    hashType;

    /* NONE: a raw input that is not a SHA-2 digest length. */
    if (jobDigest(job, digest, &digestLen, &hashType) != WH_ERROR_OK ||
        hashType == WC_HASH_TYPE_NONE) {
        return E_NOT_OK;
    }
    rc = wc_ecc_init_ex(&key, NULL, WH_CLIENT_DEVID(ctx));
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_EccSetKeyId(&key, keyId);
    if (rc == 0) {
        if (verify) {
            int verifyRes = -1;
            rc = wh_Client_EccVerify(ctx, &key, io->secondaryInputPtr,
                                     (uint16)io->secondaryInputLength, digest,
                                     (uint16)digestLen, &verifyRes);
            /* A malformed signature fails with a wolfCrypt error instead of
             * verifyRes=0; both mean E_OK with verifyPtr=NOT_OK. */
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
        }
        else {
            uint16 sigLen = (*io->outputLengthPtr > 0xFFFFu)
                                ? 0xFFFFu
                                : (uint16)(*io->outputLengthPtr);
            rc = wh_Client_EccSign(ctx, &key, digest, (uint16)digestLen,
                                   io->outputPtr, &sigLen);
            if (rc == 0 && io->outputLengthPtr != NULL) {
                *io->outputLengthPtr = sigLen;
            }
        }
    }
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

    rc = wc_ed25519_init_ex(&key, NULL, WH_CLIENT_DEVID(ctx));
    if (rc != 0)
        return E_NOT_OK;
    rc = wh_Client_Ed25519SetKeyId(&key, keyId);
    if (rc == 0) {
        if (verify) {
            int verifyRes = -1;
            rc = wh_Client_Ed25519Verify(ctx, &key, io->secondaryInputPtr,
                                         io->secondaryInputLength, io->inputPtr,
                                         io->inputLength, (uint8_t)Ed25519,
                                         NULL, 0u, &verifyRes);
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
                                       (uint8_t)Ed25519, NULL, 0u,
                                       io->outputPtr, &sigLen);
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
static int mgfFor(enum wc_HashType type)
{
    switch (type) {
        case WC_HASH_TYPE_SHA384:
            return WC_MGF1SHA384;
        case WC_HASH_TYPE_SHA512:
            return WC_MGF1SHA512;
        default:
            return WC_MGF1SHA256;
    }
}

/* RSASSA-PKCS1-v1_5 (DigestInfo-encoded digest) or RSASSA-PSS. The private
 * key operation runs on the HSM through the client's cryptocb. */
static Std_ReturnType doRsaSync(whClientContext* ctx, Crypto_JobType* job,
                                whKeyId keyId, boolean verify, boolean pss)
{
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    RsaKey                              rsa;
    WC_RNG                              rng;
    int                                 rngInited = 0;
    int                                 rc;
    Std_ReturnType                      ret = E_NOT_OK;
    uint8                               digest[WC_MAX_DIGEST_SIZE];
    uint32                              digestLen = (uint32)sizeof(digest);
    enum wc_HashType                    hashType;
    uint8                               enc[MAX_DER_DIGEST_SZ];
    word32                              encLen = 0u;
    uint8                               plain[512];

    if (jobDigest(job, digest, &digestLen, &hashType) != WH_ERROR_OK ||
        hashType == WC_HASH_TYPE_NONE) {
        return E_NOT_OK;
    }
    if (!pss) {
        encLen =
            wc_EncodeSignature(enc, digest, digestLen, wc_HashGetOID(hashType));
        if (encLen == 0u) {
            return E_NOT_OK;
        }
    }
    if (wc_InitRsaKey_ex(&rsa, NULL, WH_CLIENT_DEVID(ctx)) != 0) {
        return E_NOT_OK;
    }
    if (wh_Client_RsaSetKeyId(&rsa, keyId) != 0) {
        goto cleanup;
    }

    if (verify) {
        if (pss) {
            rc = wc_RsaPSS_VerifyCheck(io->secondaryInputPtr,
                                       io->secondaryInputLength, plain,
                                       (word32)sizeof(plain), digest, digestLen,
                                       hashType, mgfFor(hashType), &rsa);
        }
        else {
            rc = wc_RsaSSL_Verify(io->secondaryInputPtr,
                                  io->secondaryInputLength, plain,
                                  (word32)sizeof(plain), &rsa);
        }
        if (rc >= 0) {
            boolean ok =
                pss || ((word32)rc == encLen &&
                        wh_Utils_ConstantCompare(plain, enc, encLen) == 0);
            writeVerifyResult(job, ok);
            ret = E_OK;
        }
        else if (isVerifyRejection(rc)) {
            writeVerifyResult(job, FALSE);
            ret = E_OK;
        }
        goto cleanup;
    }

    if (io->outputPtr == NULL || io->outputLengthPtr == NULL ||
        wc_InitRng_ex(&rng, NULL, WH_CLIENT_DEVID(ctx)) != 0) {
        goto cleanup;
    }
    rngInited = 1;
    if (pss) {
        rc = wc_RsaPSS_Sign(digest, digestLen, io->outputPtr,
                            *io->outputLengthPtr, hashType, mgfFor(hashType),
                            &rsa, &rng);
    }
    else {
        rc = wc_RsaSSL_Sign(enc, encLen, io->outputPtr, *io->outputLengthPtr,
                            &rsa, &rng);
    }
    if (rc >= 0) {
        *io->outputLengthPtr = (uint32)rc;
        ret                  = E_OK;
    }

cleanup:
    if (rngInited)
        (void)wc_FreeRng(&rng);
    (void)wc_FreeRsaKey(&rsa);
    return ret;
}
#endif /* !NO_RSA */

#ifdef WOLFSSL_HAVE_MLDSA
/* Pure ML-DSA (FIPS 204) over the job input; level from the key descriptor. */
static Std_ReturnType doMlDsaSync(whClientContext* ctx, Crypto_JobType* job,
                                  whKeyId keyId, boolean verify)
{
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(job->cryptoKeyId);
    Crypto_JobPrimitiveInputOutputType* io  = jobIo(job);
    Std_ReturnType                      ret = E_NOT_OK;
    int                                 rc;
#ifdef WOLFSSL_SMALL_STACK
    MlDsaKey* key = NULL;
#else
    MlDsaKey  keyBuf;
    MlDsaKey* key = &keyBuf;
#endif

    if (desc == NULL) {
        return E_NOT_OK;
    }
#ifdef WOLFSSL_SMALL_STACK
    key = (MlDsaKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        return E_NOT_OK;
    }
#endif
    rc = wc_MlDsaKey_Init(key, NULL, WH_CLIENT_DEVID(ctx));
    if (rc != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return E_NOT_OK;
    }
    rc = wc_MlDsaKey_SetParams(key, (byte)desc->mlDsaLevel);
    if (rc == 0) {
        rc = wh_Client_MlDsaSetKeyId(key, keyId);
    }
    if (rc == 0 && verify) {
        int res = -1;
        rc      = wh_Client_MlDsaVerify(
            ctx, io->secondaryInputPtr, io->secondaryInputLength, io->inputPtr,
            io->inputLength, &res, key, NULL, 0u, WC_HASH_TYPE_NONE);
        if (res == 0 || res == 1) {
            writeVerifyResult(job, res == 1);
            ret = E_OK;
        }
        else if (isVerifyRejection(rc)) {
            writeVerifyResult(job, FALSE);
            ret = E_OK;
        }
    }
    else if (rc == 0 && io->outputLengthPtr != NULL) {
        word32 sigLen = *io->outputLengthPtr;
        rc            = wh_Client_MlDsaSign(ctx, io->inputPtr, io->inputLength,
                                            io->outputPtr, &sigLen, key, NULL, 0u,
                                            WC_HASH_TYPE_NONE);
        if (rc == 0) {
            *io->outputLengthPtr = sigLen;
            ret                  = E_OK;
        }
    }
    wc_MlDsaKey_Free(key);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA */

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

/* Sync entry */

/* Runs a job to completion on obj->client; the caller owns the wire. */
static Std_ReturnType dispatchJob(wh_AutosarDriverObject* obj,
                                  wh_AutosarOpKind op, Crypto_JobType* job)
{
    const Crypto_PrimitiveInfoType* pi = job->jobPrimitiveInfo->primitiveInfo;
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    whKeyId        keyId = wh_Autosar_ComposeKeyId(job->cryptoKeyId, 1u);
    Std_ReturnType ret   = E_NOT_OK;

    (void)pi;
    (void)keyId;
    switch (op) {
        case WH_AUTOSAR_OP_RNG_GENERATE:
            ret = doRngSync(&obj->client, job);
            break;
#ifndef WOLFHSM_CFG_NO_CRYPTO
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
                            pi->service == CRYPTO_SIGNATUREVERIFY, FALSE);
            break;
#ifdef WC_RSA_PSS
        case WH_AUTOSAR_OP_SIG_RSA_PSS:
            ret = doRsaSync(&obj->client, job, keyId,
                            pi->service == CRYPTO_SIGNATUREVERIFY, TRUE);
            break;
#endif
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case WH_AUTOSAR_OP_SIG_MLDSA:
            ret = doMlDsaSync(&obj->client, job, keyId,
                              pi->service == CRYPTO_SIGNATUREVERIFY);
            break;
#endif
#endif
        case WH_AUTOSAR_OP_KEY_GENERATE:
            ret = wh_Autosar_KeyGenerateImpl(&obj->client, job->cryptoKeyId);
            break;
        case WH_AUTOSAR_OP_KEY_DERIVE:
            ret = wh_Autosar_KeyDeriveImpl(&obj->client, job->cryptoKeyId,
                                           job->targetCryptoKeyId);
            break;
        case WH_AUTOSAR_OP_KEY_EXCHANGE_PUB:
            ret = wh_Autosar_KeyExchangeCalcPubValImpl(
                &obj->client, job->cryptoKeyId, io->outputPtr,
                io->outputLengthPtr);
            break;
        case WH_AUTOSAR_OP_KEY_EXCHANGE_SEC:
            ret = wh_Autosar_KeyExchangeCalcSecretImpl(
                &obj->client, job->cryptoKeyId, io->inputPtr, io->inputLength);
            break;
        case WH_AUTOSAR_OP_KEY_SET_VALID:
            ret = wh_Autosar_KeySetValidImpl(&obj->client, job->cryptoKeyId);
            break;
        case WH_AUTOSAR_OP_KEY_SET_INVALID:
            ret = wh_Autosar_KeyMarkInvalid(job->cryptoKeyId);
            break;
        case WH_AUTOSAR_OP_RANDOM_SEED:
            ret = Crypto_RandomSeed(job->cryptoKeyId, io->inputPtr,
                                    io->inputLength);
            break;
        default:
            ret = E_NOT_OK;
            break;
    }
    return ret;
}

#ifndef WOLFHSM_CFG_NO_CRYPTO
static boolean opIsAes(wh_AutosarOpKind op)
{
    return (op == WH_AUTOSAR_OP_CIPHER_AES_ECB ||
            op == WH_AUTOSAR_OP_CIPHER_AES_CBC ||
            op == WH_AUTOSAR_OP_CIPHER_AES_CTR ||
            op == WH_AUTOSAR_OP_AEAD_AES_GCM)
               ? TRUE
               : FALSE;
}
#endif

static boolean opIsKeyMgmt(wh_AutosarOpKind op)
{
    return (op == WH_AUTOSAR_OP_KEY_GENERATE ||
            op == WH_AUTOSAR_OP_KEY_DERIVE ||
            op == WH_AUTOSAR_OP_KEY_EXCHANGE_PUB ||
            op == WH_AUTOSAR_OP_KEY_EXCHANGE_SEC ||
            op == WH_AUTOSAR_OP_KEY_SET_VALID ||
            op == WH_AUTOSAR_OP_KEY_SET_INVALID)
               ? TRUE
               : FALSE;
}

static boolean opUsesJobKey(wh_AutosarOpKind op)
{
    switch (op) {
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM:
        case WH_AUTOSAR_OP_SIG_RSA_PKCS1_V1_5:
        case WH_AUTOSAR_OP_SIG_RSA_PSS:
        case WH_AUTOSAR_OP_SIG_ECDSA:
        case WH_AUTOSAR_OP_SIG_ED25519:
        case WH_AUTOSAR_OP_SIG_MLDSA:
            return TRUE;
        default:
            return FALSE;
    }
}

static uint32 digestSizeFor(wh_AutosarOpKind op)
{
    switch (op) {
        case WH_AUTOSAR_OP_HASH_SHA256:
            return 32u;
        case WH_AUTOSAR_OP_HASH_SHA384:
            return 48u;
        default:
            return 64u;
    }
}

/* Checks every job buffer the dispatcher reads or writes for this op. */
static Std_ReturnType validateJob(wh_AutosarOpKind op, Crypto_JobType* job)
{
    Crypto_JobPrimitiveInputOutputType* io = jobIo(job);
    Crypto_ServiceInfoType svc = job->jobPrimitiveInfo->primitiveInfo->service;
    uint8                  err = 0u;
    boolean                out = FALSE;

    if (op == WH_AUTOSAR_OP_INVALID) {
        return E_NOT_OK;
    }
    if (opUsesJobKey(op) &&
        (io->mode != CRYPTO_OPERATIONMODE_SINGLECALL ||
         wh_Autosar_ComposeKeyId(job->cryptoKeyId, 1u) == 0u)) {
        return E_NOT_OK;
    }
    if (opIsKeyMgmt(op) &&
        (wh_Autosar_ComposeKeyId(job->cryptoKeyId, 1u) == 0u ||
         (op == WH_AUTOSAR_OP_KEY_DERIVE &&
          wh_Autosar_ComposeKeyId(job->targetCryptoKeyId, 1u) == 0u))) {
        CRYPTO_DET_REPORT(CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if ((io->inputPtr == NULL && io->inputLength != 0u) ||
        ((svc == CRYPTO_MACVERIFY || svc == CRYPTO_SIGNATUREVERIFY ||
          svc == CRYPTO_AEADDECRYPT) &&
         io->verifyPtr == NULL)) {
        CRYPTO_DET_REPORT(CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    switch (op) {
        case WH_AUTOSAR_OP_RNG_GENERATE:
            out = TRUE;
            break;
        case WH_AUTOSAR_OP_HASH_SHA256:
        case WH_AUTOSAR_OP_HASH_SHA384:
        case WH_AUTOSAR_OP_HASH_SHA512:
            if ((io->mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) {
                out = TRUE;
                if (io->outputLengthPtr != NULL &&
                    *io->outputLengthPtr < digestSizeFor(op)) {
                    err = CRYPTO_E_SMALL_BUFFER;
                }
            }
            break;
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
            if (svc == CRYPTO_MACVERIFY) {
                if (io->secondaryInputPtr == NULL) {
                    err = CRYPTO_E_PARAM_POINTER;
                }
                else if (io->secondaryInputLength <
                             CRYPTO_CMAC_MIN_VERIFY_BITS ||
                         io->secondaryInputLength > 8u * AES_BLOCK_SIZE) {
                    err = CRYPTO_E_PARAM_VALUE;
                }
            }
            else {
                out = TRUE;
            }
            break;
        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM:
            out = TRUE;
            if (op != WH_AUTOSAR_OP_AEAD_AES_GCM &&
                (io->inputLength == 0u ||
                 (op != WH_AUTOSAR_OP_CIPHER_AES_CTR &&
                  (io->inputLength % AES_BLOCK_SIZE) != 0u))) {
                err = CRYPTO_E_PARAM_VALUE;
            }
            else if (op == WH_AUTOSAR_OP_AEAD_AES_GCM &&
                     ((svc == CRYPTO_AEADENCRYPT &&
                       (io->secondaryOutputPtr == NULL ||
                        io->secondaryOutputLengthPtr == NULL)) ||
                      (svc == CRYPTO_AEADDECRYPT &&
                       io->tertiaryInputPtr == NULL))) {
                err = CRYPTO_E_PARAM_POINTER;
            }
            else if (op == WH_AUTOSAR_OP_AEAD_AES_GCM &&
                     ((svc == CRYPTO_AEADENCRYPT &&
                       (*io->secondaryOutputLengthPtr <
                            CRYPTO_AEAD_MIN_TAG_LEN ||
                        *io->secondaryOutputLengthPtr > AES_BLOCK_SIZE)) ||
                      (svc == CRYPTO_AEADDECRYPT &&
                       (io->tertiaryInputLength < CRYPTO_AEAD_MIN_TAG_LEN ||
                        io->tertiaryInputLength > AES_BLOCK_SIZE)))) {
                err = CRYPTO_E_PARAM_VALUE;
            }
            else if (io->outputLengthPtr != NULL &&
                     *io->outputLengthPtr < io->inputLength) {
                err = CRYPTO_E_SMALL_BUFFER;
            }
            break;
        case WH_AUTOSAR_OP_SIG_RSA_PKCS1_V1_5:
        case WH_AUTOSAR_OP_SIG_RSA_PSS:
        case WH_AUTOSAR_OP_SIG_ECDSA:
        case WH_AUTOSAR_OP_SIG_ED25519:
        case WH_AUTOSAR_OP_SIG_MLDSA:
            if (svc == CRYPTO_SIGNATUREVERIFY) {
                if (io->secondaryInputPtr == NULL) {
                    err = CRYPTO_E_PARAM_POINTER;
                }
                else if (op == WH_AUTOSAR_OP_SIG_ECDSA &&
                         io->secondaryInputLength > 0xFFFFu) {
                    err = CRYPTO_E_PARAM_VALUE;
                }
            }
            else {
                out = TRUE;
            }
            break;
        default:
            break;
    }
    if (err == 0u && out &&
        (io->outputPtr == NULL || io->outputLengthPtr == NULL)) {
        err = CRYPTO_E_PARAM_POINTER;
    }
    if (err != 0u) {
        CRYPTO_DET_REPORT(err);
        return E_NOT_OK;
    }
    return E_OK;
}

/* A streamed hash stays ACTIVE between START and FINISH. */
static Crypto_JobStateType jobStateAfter(wh_AutosarDriverObject* obj,
                                         const Crypto_JobType*   job)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    if (hashStreamOpen(obj, job->jobId)) {
        return CRYPTO_JOBSTATE_ACTIVE;
    }
#else
    (void)obj;
    (void)job;
#endif
    return CRYPTO_JOBSTATE_IDLE;
}

Std_ReturnType wh_Autosar_ProcessJobSync(wh_AutosarDriverObject* obj,
                                         Crypto_JobType*         job)
{
    wh_AutosarOpKind op = resolveOpKind(job);
    Std_ReturnType   ret;

    presetVerifyResult(job);
    if (validateJob(op, job) != E_OK) {
        return E_NOT_OK;
    }
    if (opUsesJobKey(op) && !wh_Autosar_KeyIsValid(job->cryptoKeyId)) {
        return CRYPTO_E_KEY_NOT_VALID;
    }
    if (wh_Autosar_WireAcquire(obj) != E_OK) {
        return CRYPTO_E_BUSY;
    }
    job->jobState = CRYPTO_JOBSTATE_ACTIVE;
    ret           = dispatchJob(obj, op, job);
    job->jobState = jobStateAfter(obj, job);
    wh_Autosar_WireRelease(obj);
    return ret;
}

/* Async dispatch */

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

Std_ReturnType wh_Autosar_WireAcquire(wh_AutosarDriverObject* obj)
{
    Std_ReturnType ret = CRYPTO_E_BUSY;

    wh_Autosar_LockSlots(obj);
    if (!obj->wireBusy && !anySlotInFlight(obj)) {
        obj->wireBusy = TRUE;
        ret           = E_OK;
    }
    wh_Autosar_UnlockSlots(obj);
    return ret;
}

void wh_Autosar_WireRelease(wh_AutosarDriverObject* obj)
{
    wh_Autosar_LockSlots(obj);
    obj->wireBusy = FALSE;
    wh_Autosar_UnlockSlots(obj);
}

/* Ops with a wolfHSM Request/Response pair; the rest, and streamed hashes,
 * run blocking from Crypto_MainFunction once nothing else is in flight. */
static boolean opHasAsyncPair(wh_AutosarOpKind op, Crypto_JobType* job)
{
    if (jobIo(job)->mode != CRYPTO_OPERATIONMODE_SINGLECALL) {
        return FALSE;
    }
    switch (op) {
        case WH_AUTOSAR_OP_RNG_GENERATE:
            return (*jobIo(job)->outputLengthPtr <=
                    WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ)
                       ? TRUE
                       : FALSE;
#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_AUTOSAR_OP_HASH_SHA256:
#ifdef WOLFSSL_SHA384
        case WH_AUTOSAR_OP_HASH_SHA384:
#endif
#ifdef WOLFSSL_SHA512
        case WH_AUTOSAR_OP_HASH_SHA512:
#endif
        case WH_AUTOSAR_OP_CIPHER_AES_ECB:
        case WH_AUTOSAR_OP_CIPHER_AES_CBC:
        case WH_AUTOSAR_OP_CIPHER_AES_CTR:
        case WH_AUTOSAR_OP_AEAD_AES_GCM:
        case WH_AUTOSAR_OP_SIG_ECDSA:
            return TRUE;
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
            return (jobIo(job)->inputLength > 0u &&
                    jobIo(job)->inputLength <=
                        WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_GENERATE_SZ)
                       ? TRUE
                       : FALSE;
#endif
        default:
            return FALSE;
    }
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

/* Frees a slot's wolfCrypt state; finishSlot calls it on every exit. */
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
        case WH_AUTOSAR_OP_MAC_CMAC_AES:
            (void)wc_CmacFree(&slot->op.wc.cmac);
            break;
        default:
            break;
    }
#endif
}

/* Request half, run under the slot lock */

static int issueOneHashUpdate(whClientContext* ctx, wh_AutosarJobSlot* slot,
                              bool* outSent)
{
    int    rc   = WH_ERROR_NOTIMPL;
    uint32 want = slot->op.hashRemaining;

    *outSent = false;
    while (want > 0u) {
        switch (slot->opKind) {
            case WH_AUTOSAR_OP_HASH_SHA256:
                rc = wh_Client_Sha256UpdateRequest(ctx, &slot->op.wc.sha256,
                                                   slot->op.hashInput, want,
                                                   outSent);
                break;
#ifdef WOLFSSL_SHA384
            case WH_AUTOSAR_OP_HASH_SHA384:
                rc = wh_Client_Sha384UpdateRequest(ctx, &slot->op.wc.sha384,
                                                   slot->op.hashInput, want,
                                                   outSent);
                break;
#endif
#ifdef WOLFSSL_SHA512
            case WH_AUTOSAR_OP_HASH_SHA512:
                rc = wh_Client_Sha512UpdateRequest(ctx, &slot->op.wc.sha512,
                                                   slot->op.hashInput, want,
                                                   outSent);
                break;
#endif
            default:
                return WH_ERROR_NOTIMPL;
        }
        if (rc != WH_ERROR_REQUEST_SIZE) {
            break;
        }
        want /= 2u;
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
    whKeyId keyId = wh_Autosar_ComposeKeyId(job->cryptoKeyId, 1u);

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
                            ? wc_InitSha256_ex(&slot->op.wc.sha256, NULL,
                                               WH_CLIENT_DEVID(ctx))
#ifdef WOLFSSL_SHA384
                 : (slot->opKind == WH_AUTOSAR_OP_HASH_SHA384)
                     ? wc_InitSha384_ex(&slot->op.wc.sha384, NULL,
                                        WH_CLIENT_DEVID(ctx))
#endif
#ifdef WOLFSSL_SHA512
                 : (slot->opKind == WH_AUTOSAR_OP_HASH_SHA512)
                     ? wc_InitSha512_ex(&slot->op.wc.sha512, NULL,
                                        WH_CLIENT_DEVID(ctx))
#endif
                     : WH_ERROR_NOTIMPL;
            if (rc != 0)
                break;
            slot->op.digestOut = io->outputPtr;
            slot->op.digestLen =
                (io->outputLengthPtr != NULL) ? *io->outputLengthPtr : 0u;
            if (slot->op.digestLen < digestSizeFor(slot->opKind)) {
                rc = WH_ERROR_BUFFER_SIZE;
                break;
            }
            slot->op.hashInput     = io->inputPtr;
            slot->op.hashRemaining = io->inputLength;
            if (slot->op.hashRemaining > 0u) {
                rc = issueOneHashUpdate(ctx, slot, &sent);
                if (rc == WH_ERROR_OK && !sent) {
                    /* Buffered locally without a request; send the next. */
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
            rc = aesPrepare(ctx, &slot->op.wc.aes, job, keyId, slot->opKind,
                            slot->op.iv);
            if (rc != 0)
                break;
            slot->op.cipherOut = io->outputPtr;
            slot->op.cipherLen = io->inputLength;
            slot->op.tagOut    = io->secondaryOutputPtr;
            slot->op.tagLen    = enc ? ((io->secondaryOutputLengthPtr != NULL)
                                            ? *io->secondaryOutputLengthPtr
                                            : 0u)
                                     : io->tertiaryInputLength;
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
                    rc = wh_Client_AesCtrRequest(ctx, &slot->op.wc.aes, 1,
                                                 io->inputPtr, io->inputLength);
                    break;
#endif
#ifdef HAVE_AESGCM
                case WH_AUTOSAR_OP_AEAD_AES_GCM:
                    rc = wh_Client_AesGcmRequest(
                        ctx, &slot->op.wc.aes, enc, io->inputPtr,
                        io->inputLength, slot->op.iv, slot->op.ivLen,
                        io->secondaryInputPtr, io->secondaryInputLength,
                        enc ? NULL : io->tertiaryInputPtr, slot->op.tagLen);
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
            enum wc_HashType hashType;
            slot->op.sigDigestLen = (uint32)sizeof(slot->op.sigDigest);
            rc = jobDigest(job, slot->op.sigDigest, &slot->op.sigDigestLen,
                           &hashType);
            if (rc == 0 && hashType == WC_HASH_TYPE_NONE) {
                rc = WH_ERROR_BADARGS;
            }
            if (rc != 0)
                break;
            if (verify) {
                rc = wh_Client_EccVerifyRequest(
                    ctx, keyId, io->secondaryInputPtr,
                    (uint16)io->secondaryInputLength, slot->op.sigDigest,
                    (uint16)slot->op.sigDigestLen);
            }
            else {
                slot->op.rawOut   = io->outputPtr;
                slot->op.rawLen16 = (*io->outputLengthPtr > 0xFFFFu)
                                        ? 0xFFFFu
                                        : (uint16)(*io->outputLengthPtr);
                rc = wh_Client_EccSignRequest(ctx, keyId, slot->op.sigDigest,
                                              (uint16)slot->op.sigDigestLen);
            }
            break;
        }


        case WH_AUTOSAR_OP_MAC_CMAC_AES: {
            boolean verify = (job->jobPrimitiveInfo->primitiveInfo->service ==
                              CRYPTO_MACVERIFY)
                                 ? TRUE
                                 : FALSE;
            (void)memset(&slot->op.wc.cmac, 0, sizeof(slot->op.wc.cmac));
            rc = wh_Client_CmacSetKeyId(&slot->op.wc.cmac, keyId);
            if (rc != 0)
                break;
            if (verify) {
                slot->op.verifyRef    = io->secondaryInputPtr;
                slot->op.verifyRefLen = io->secondaryInputLength;
            }
            else {
                slot->op.rawOut   = io->outputPtr;
                slot->op.rawLen32 = *io->outputLengthPtr;
            }
            rc = wh_Client_CmacGenerateRequest(
                ctx, &slot->op.wc.cmac, WC_CMAC_AES, NULL, 0u, io->inputPtr,
                io->inputLength, AES_BLOCK_SIZE);
            break;
        }

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
    return rc;
}

/* Returns WH_ERROR_NOTREADY until the slot's response has arrived. */

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
                    slot->ticksAtIssue = obj->tickCount;
                    return WH_ERROR_NOTREADY;
                }
                rc = issueHashFinalRequest(ctx, slot);
                if (rc != WH_ERROR_OK)
                    break;
                slot->phase        = WH_AUTOSAR_PHASE_HASH_FINAL;
                slot->ticksAtIssue = obj->tickCount;
                return WH_ERROR_NOTREADY;
            }
            /* phase == HASH_FINAL */
            if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA256) {
                rc = wh_Client_Sha256FinalResponse(ctx, &slot->op.wc.sha256,
                                                   slot->op.digestOut);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = WC_SHA256_DIGEST_SIZE;
                }
            }
#ifdef WOLFSSL_SHA384
            else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA384) {
                rc = wh_Client_Sha384FinalResponse(ctx, &slot->op.wc.sha384,
                                                   slot->op.digestOut);
                if (rc == WH_ERROR_OK && io->outputLengthPtr != NULL) {
                    *io->outputLengthPtr = WC_SHA384_DIGEST_SIZE;
                }
            }
#endif
#ifdef WOLFSSL_SHA512
            else if (slot->opKind == WH_AUTOSAR_OP_HASH_SHA512) {
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
            if (enc && rc == WH_ERROR_OK &&
                io->secondaryOutputLengthPtr != NULL) {
                *io->secondaryOutputLengthPtr = slot->op.tagLen;
            }
            if (!enc && rc != WH_ERROR_NOTREADY) {
                if (rc == WH_ERROR_OK) {
                    writeVerifyResult(job, TRUE);
                }
                else if (isVerifyRejection(rc)) {
                    /* Tag mismatch: E_OK with verifyPtr=NOT_OK. */
                    writeVerifyResult(job, FALSE);
                    if (io->outputLengthPtr != NULL) {
                        *io->outputLengthPtr = 0u;
                    }
                    rc = WH_ERROR_OK;
                }
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
                    /* Malformed DER: E_OK with verifyPtr=NOT_OK. */
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


        case WH_AUTOSAR_OP_MAC_CMAC_AES: {
            uint8  macBuf[AES_BLOCK_SIZE];
            uint32 macLen = (uint32)sizeof(macBuf);
            rc = wh_Client_CmacGenerateResponse(ctx, &slot->op.wc.cmac, macBuf,
                                                &macLen);
            if (rc != WH_ERROR_OK) {
                wh_Utils_ForceZero(macBuf, sizeof(macBuf));
                break;
            }
            if (macLen != AES_BLOCK_SIZE) {
                rc = WH_ERROR_ABORTED;
            }
            else if (job->jobPrimitiveInfo->primitiveInfo->service ==
                     CRYPTO_MACVERIFY) {
                writeVerifyResult(job, macMatches(macBuf, slot->op.verifyRef,
                                                  slot->op.verifyRefLen));
            }
            else {
                if (slot->op.rawLen32 < macLen) {
                    macLen = slot->op.rawLen32;
                }
                (void)memcpy(slot->op.rawOut, macBuf, macLen);
                *io->outputLengthPtr = macLen;
            }
            wh_Utils_ForceZero(macBuf, sizeof(macBuf));
            break;
        }

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
    return rc;
}

/* Async entry */

Std_ReturnType wh_Autosar_ProcessJobAsync(wh_AutosarDriverObject* obj,
                                          Crypto_JobType*         job)
{
    wh_AutosarJobSlot* slot;
    wh_AutosarOpKind   op = resolveOpKind(job);

    presetVerifyResult(job);
    if (validateJob(op, job) != E_OK) {
        return E_NOT_OK;
    }
    if (opUsesJobKey(op) && !wh_Autosar_KeyIsValid(job->cryptoKeyId)) {
        return CRYPTO_E_KEY_NOT_VALID;
    }

    wh_Autosar_LockSlots(obj);
    slot = allocSlot(obj);
    if (slot == NULL) {
        wh_Autosar_UnlockSlots(obj);
        return E_NOT_OK;
    }
    slotInit(obj, slot, job, op);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    if (opIsAes(op)) {
        slot->op.ivLen = (uint32)sizeof(slot->op.iv);
        if (takeIv(job, op, slot->op.iv, &slot->op.ivLen) != WH_ERROR_OK) {
            slot->state = WH_AUTOSAR_ASYNC_IDLE;
            slot->job   = NULL;
            wh_Autosar_UnlockSlots(obj);
            return E_NOT_OK;
        }
    }
#endif
    job->jobState = CRYPTO_JOBSTATE_ACTIVE;
    wh_Autosar_UnlockSlots(obj);

    return E_OK;
}

/* MainFunction driver */

/* Completes a promoted slot unless it was cancelled meanwhile. */
static void finishPromoted(wh_AutosarDriverObject* obj, wh_AutosarJobSlot* slot,
                           Std_ReturnType result)
{
    wh_Autosar_LockSlots(obj);
    slot->blocking = FALSE;
    if (slot->state == WH_AUTOSAR_ASYNC_CANCELLING) {
        slot->state = WH_AUTOSAR_ASYNC_IDLE;
        slot->job   = NULL;
    }
    else {
        slot->result = result;
        slot->state  = WH_AUTOSAR_ASYNC_COMPLETE;
    }
    wh_Autosar_UnlockSlots(obj);
}

/* Issues the oldest QUEUED slot when nothing else holds the client. */
static void promoteOneQueued(wh_AutosarDriverObject* obj)
{
    wh_AutosarJobSlot* slot = NULL;
    Crypto_JobType*    job;
    int                rc;

    wh_Autosar_LockSlots(obj);
    if (!obj->wireBusy && !anySlotInFlight(obj)) {
        slot = oldestQueuedSlot(obj);
    }
    if (slot == NULL) {
        wh_Autosar_UnlockSlots(obj);
        return;
    }
    job                = slot->job;
    slot->state        = WH_AUTOSAR_ASYNC_PENDING;
    slot->ticksAtIssue = obj->tickCount;
    /* Cancel is refused while the job buffers are being read. */
    slot->blocking = TRUE;
    wh_Autosar_UnlockSlots(obj);

    /* The key may have been rewritten or invalidated while queued. */
    if (opUsesJobKey(slot->opKind) &&
        !wh_Autosar_KeyIsValid(job->cryptoKeyId)) {
        finishPromoted(obj, slot, CRYPTO_E_KEY_NOT_VALID);
        return;
    }
    if (!opHasAsyncPair(slot->opKind, job)) {
        finishPromoted(obj, slot, dispatchJob(obj, slot->opKind, job));
        return;
    }
    rc = issueAsyncRequest(obj, slot);
    if (rc != WH_ERROR_OK) {
        slotFreeWcResources(slot);
        finishPromoted(obj, slot, E_NOT_OK);
        return;
    }
    wh_Autosar_LockSlots(obj);
    slot->blocking = FALSE;
    wh_Autosar_UnlockSlots(obj);
}

/* Reads and discards the response of a cancelled request so nothing is
 * written to the job. */
static int drainCancelled(wh_AutosarDriverObject* obj)
{
    uint16 group;
    uint16 action;
    uint16 size;

    return wh_Client_RecvResponse(&obj->client, &group, &action, &size,
                                  WOLFHSM_CFG_COMM_DATA_LEN,
                                  wh_CommClient_GetDataPtr(obj->client.comm));
}

void wh_Autosar_MainFunctionObject(wh_AutosarDriverObject* obj)
{
    wh_AutosarJobSlot* inFlight;
    wh_AutosarJobSlot* completeSlot   = NULL;
    Crypto_JobType*    completeJob    = NULL;
    Std_ReturnType     completeResult = E_NOT_OK;
    boolean            cancelled      = FALSE;
    boolean            timedOut       = FALSE;
    int                rc             = WH_ERROR_OK;

    wh_Autosar_LockSlots(obj);
    obj->tickCount++;
    inFlight = findSlotInState(obj, WH_AUTOSAR_ASYNC_PENDING);
    if (inFlight == NULL) {
        inFlight = findSlotInState(obj, WH_AUTOSAR_ASYNC_CANCELLING);
    }
    if (inFlight != NULL) {
        cancelled =
            (inFlight->state == WH_AUTOSAR_ASYNC_CANCELLING) ? TRUE : FALSE;
        timedOut = ((obj->tickCount - inFlight->ticksAtIssue) >
                    CRYPTO_ASYNC_TIMEOUT_TICKS)
                       ? TRUE
                       : FALSE;
    }
    if (inFlight != NULL) {
        if (timedOut) {
            /* Nothing usable will arrive; let a late reply fail the
             * sequence check. */
            (void)wh_CommClient_AbortPending(obj->client.comm);
            rc = WH_ERROR_TIMEOUT;
        }
        else if (cancelled) {
            rc = drainCancelled(obj);
        }
        else {
            /* Polling is non-blocking; holding the lock keeps a concurrent
             * cancel from landing while results are copied to the job. */
            rc = pollAsyncResponse(obj, inFlight);
        }
        if (rc == WH_ERROR_NOTREADY) {
            wh_Autosar_UnlockSlots(obj);
            return;
        }
        slotFreeWcResources(inFlight);
        if (cancelled) {
            inFlight->state = WH_AUTOSAR_ASYNC_IDLE;
            inFlight->job   = NULL;
        }
        else {
            inFlight->result = (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
            inFlight->state  = WH_AUTOSAR_ASYNC_COMPLETE;
        }
    }
    wh_Autosar_UnlockSlots(obj);

    /* At most one callback per call, to bound callback latency. */
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
        completeJob->jobState = jobStateAfter(obj, completeJob);
        CryIf_CallbackNotification(completeJob, completeResult);
    }

    promoteOneQueued(obj);
}

boolean wh_Autosar_HashStateCancel(wh_AutosarDriverObject* obj, uint32 jobId)
{
#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)obj;
    (void)jobId;
    return FALSE;
#else
    wh_AutosarHashState* st = hashStateFind(obj, jobId);
    if (st == NULL || st->busy) {
        return FALSE;
    }
    hashStateRelease(st);
    return TRUE;
#endif
}

#ifdef WH_AUTOSAR_TEST_HOOKS
uint32 wh_Autosar_DebugActiveSlotCount(const wh_AutosarDriverObject* obj)
{
    uint32 i;
    uint32 n = 0u;
    if (obj == NULL)
        return 0u;
    /* The lock hook takes a non-const object; the state is only read. */
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
        wh_Autosar_LockSlots(obj);
        obj->tickCount += by;
        wh_Autosar_UnlockSlots(obj);
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
    (void)wh_CommClient_AbortPending(obj->client.comm);
    wh_Autosar_LockSlots(obj);
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        wh_AutosarJobSlot* slot = &obj->asyncSlots[i];
        if (slot->state != WH_AUTOSAR_ASYNC_IDLE) {
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
#endif /* WH_AUTOSAR_TEST_HOOKS */
