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
 * port/autosar/adaptive/src/crypto_provider.cpp
 *
 * Implementation of WolfhsmCryptoProvider plus its random and hash
 * contexts. Hash contexts stream: each Update sends the chunk to the
 * wolfHSM server via the Sha*UpdateRequest/Response pair rather than
 * buffering locally.
 *
 * Other ara::crypto context classes (cipher, MAC, signer, key-storage)
 * follow the same wolfHSM-client wrapping pattern and live in sibling
 * .cpp files; this Phase 1 file ships random + hash.
 */

#include "wolfhsm/ara_crypto/crypto_provider.hpp"

#include "wh_autosar_safe_compare.h"

#include <cstring>

extern "C" {
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_common.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/sha256.h"
#ifdef WOLFSSL_SHA384
#include "wolfssl/wolfcrypt/sha512.h"
#endif
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
}

namespace wolfhsm {
namespace ara_crypto {

/* ---------------- WolfhsmCryptoProvider ----------------------------- */

std::unique_ptr<RandomGeneratorCtx>
WolfhsmCryptoProvider::CreateRandomGeneratorCtx()
{
    return std::make_unique<RandomGeneratorCtx>(client_);
}

std::unique_ptr<HashFunctionCtx>
WolfhsmCryptoProvider::CreateHashFunctionCtx(CryptoAlgId algId)
{
    if (algId != AlgId::kSha256 && algId != AlgId::kSha384 &&
        algId != AlgId::kSha512) {
        return nullptr;
    }
    return std::make_unique<HashFunctionCtx>(client_, algId);
}

/* ---------------- RandomGeneratorCtx -------------------------------- */

Result<ByteVector> RandomGeneratorCtx::Generate(std::size_t count)
{
    if (client_ == nullptr || count == 0u) {
        return SecurityErrc::kInvalidArgument;
    }
    ByteVector out(count);
    int        rc = wh_Client_RngGenerate(client_, out.data(),
                                          static_cast<std::uint32_t>(count));
    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
}

/* ---------------- HashFunctionCtx ----------------------------------- */

HashFunctionCtx::HashFunctionCtx(whClientContext* client, CryptoAlgId algId)
    : client_(client), alg_(algId), started_(false)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    static_assert(sizeof(wc_Sha256) <= sizeof(state_),
                  "HashFunctionCtx::state_ too small for wc_Sha256");
#ifdef WOLFSSL_SHA384
    static_assert(sizeof(wc_Sha384) <= sizeof(state_),
                  "HashFunctionCtx::state_ too small for wc_Sha384");
#endif
#ifdef WOLFSSL_SHA512
    static_assert(sizeof(wc_Sha512) <= sizeof(state_),
                  "HashFunctionCtx::state_ too small for wc_Sha512");
#endif
#endif
    std::memset(state_, 0, sizeof(state_));
}

HashFunctionCtx::~HashFunctionCtx()
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    if (started_) {
        if (alg_ == AlgId::kSha256) {
            wc_Sha256Free(reinterpret_cast<wc_Sha256*>(state_));
        }
#ifdef WOLFSSL_SHA384
        else if (alg_ == AlgId::kSha384) {
            wc_Sha384Free(reinterpret_cast<wc_Sha384*>(state_));
        }
#endif
#ifdef WOLFSSL_SHA512
        else if (alg_ == AlgId::kSha512) {
            wc_Sha512Free(reinterpret_cast<wc_Sha512*>(state_));
        }
#endif
    }
#endif
}

Result<void> HashFunctionCtx::Start()
{
#ifdef WOLFHSM_CFG_NO_CRYPTO
    return SecurityErrc::kRuntimeFault;
#else
    int rc = WH_ERROR_NOTIMPL;
    /* Size of state_ is checked at class scope via static_assert in the
     * constructor; no need to repeat it here. */
    if (alg_ == AlgId::kSha256) {
        rc = wc_InitSha256_ex(reinterpret_cast<wc_Sha256*>(state_), nullptr,
                              WH_DEV_ID);
    }
#ifdef WOLFSSL_SHA384
    else if (alg_ == AlgId::kSha384) {
        rc = wc_InitSha384_ex(reinterpret_cast<wc_Sha384*>(state_), nullptr,
                              WH_DEV_ID);
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (alg_ == AlgId::kSha512) {
        rc = wc_InitSha512_ex(reinterpret_cast<wc_Sha512*>(state_), nullptr,
                              WH_DEV_ID);
    }
#endif
    if (rc != 0) {
        return SecurityErrc::kRuntimeFault;
    }
    started_ = true;
    return Result<void>();
#endif
}

#ifndef WOLFHSM_CFG_NO_CRYPTO
/* Issue one Sha*UpdateRequest of the given chunk size, halving on
 * BADARGS until the wolfHSM client accepts it (mirrors hashUpdateSync
 * in the Classic dispatcher). Returns WH_ERROR_OK on success;
 * *outSent / *outAccepted communicate whether a wire round-trip
 * occurred and how many bytes were actually consumed. */
static int oneSha256Chunk(whClientContext* c, wc_Sha256* s,
                          const std::uint8_t* in, std::uint32_t want,
                          bool* outSent, std::uint32_t* outAccepted)
{
    int rc = WH_ERROR_BADARGS;
    /* Always define the output values, including on the failure path,
     * so a caller that reads them on error sees a coherent state
     * rather than uninitialised stack. */
    *outSent     = false;
    *outAccepted = 0u;
    while (want > 0u) {
        bool sent = false;
        rc        = wh_Client_Sha256UpdateRequest(c, s, in, want, &sent);
        if (rc == WH_ERROR_OK) {
            if (sent) {
                do {
                    rc = wh_Client_Sha256UpdateResponse(c, s);
                } while (rc == WH_ERROR_NOTREADY);
            }
            *outSent     = sent;
            *outAccepted = want;
            return rc;
        }
        if (rc != WH_ERROR_BADARGS)
            return rc;
        want /= 2u;
    }
    return rc;
}
#ifdef WOLFSSL_SHA384
static int oneSha384Chunk(whClientContext* c, wc_Sha384* s,
                          const std::uint8_t* in, std::uint32_t want,
                          bool* outSent, std::uint32_t* outAccepted)
{
    int rc       = WH_ERROR_BADARGS;
    *outSent     = false;
    *outAccepted = 0u;
    while (want > 0u) {
        bool sent = false;
        rc        = wh_Client_Sha384UpdateRequest(c, s, in, want, &sent);
        if (rc == WH_ERROR_OK) {
            if (sent) {
                do {
                    rc = wh_Client_Sha384UpdateResponse(c, s);
                } while (rc == WH_ERROR_NOTREADY);
            }
            *outSent     = sent;
            *outAccepted = want;
            return rc;
        }
        if (rc != WH_ERROR_BADARGS)
            return rc;
        want /= 2u;
    }
    return rc;
}
#endif
#ifdef WOLFSSL_SHA512
static int oneSha512Chunk(whClientContext* c, wc_Sha512* s,
                          const std::uint8_t* in, std::uint32_t want,
                          bool* outSent, std::uint32_t* outAccepted)
{
    int rc       = WH_ERROR_BADARGS;
    *outSent     = false;
    *outAccepted = 0u;
    while (want > 0u) {
        bool sent = false;
        rc        = wh_Client_Sha512UpdateRequest(c, s, in, want, &sent);
        if (rc == WH_ERROR_OK) {
            if (sent) {
                do {
                    rc = wh_Client_Sha512UpdateResponse(c, s);
                } while (rc == WH_ERROR_NOTREADY);
            }
            *outSent     = sent;
            *outAccepted = want;
            return rc;
        }
        if (rc != WH_ERROR_BADARGS)
            return rc;
        want /= 2u;
    }
    return rc;
}
#endif
#endif

Result<void> HashFunctionCtx::Update(const std::uint8_t* data, std::size_t size)
{
    if (!started_) {
        return SecurityErrc::kProcessingNotStarted;
    }
    if (size == 0u) {
        return Result<void>();
    }
    if (data == nullptr) {
        return SecurityErrc::kInvalidArgument;
    }
#ifdef WOLFHSM_CFG_NO_CRYPTO
    return SecurityErrc::kRuntimeFault;
#else
    /* Chunk the input across as many Sha*UpdateRequest cycles as the
     * wolfHSM client's per-call inline capacity demands. Without this
     * loop, any payload exceeding the comm buffer slack returns
     * BADARGS and the hash silently fails. */
    std::uint32_t       remaining = static_cast<std::uint32_t>(size);
    const std::uint8_t* p         = data;
    int                 rc        = WH_ERROR_OK;
    while (remaining > 0u) {
        std::uint32_t accepted = 0u;
        bool          sent     = false;
        if (alg_ == AlgId::kSha256) {
            rc = oneSha256Chunk(client_, reinterpret_cast<wc_Sha256*>(state_),
                                p, remaining, &sent, &accepted);
        }
#ifdef WOLFSSL_SHA384
        else if (alg_ == AlgId::kSha384) {
            rc = oneSha384Chunk(client_, reinterpret_cast<wc_Sha384*>(state_),
                                p, remaining, &sent, &accepted);
        }
#endif
#ifdef WOLFSSL_SHA512
        else if (alg_ == AlgId::kSha512) {
            rc = oneSha512Chunk(client_, reinterpret_cast<wc_Sha512*>(state_),
                                p, remaining, &sent, &accepted);
        }
#endif
        else {
            rc = WH_ERROR_NOTIMPL;
        }
        if (rc != WH_ERROR_OK || accepted == 0u) {
            return SecurityErrc::kRuntimeFault;
        }
        p += accepted;
        remaining -= accepted;
    }
    (void)rc;
    return Result<void>();
#endif
}

Result<ByteVector> HashFunctionCtx::Finish()
{
    if (!started_) {
        return SecurityErrc::kProcessingNotStarted;
    }
#ifdef WOLFHSM_CFG_NO_CRYPTO
    return SecurityErrc::kRuntimeFault;
#else
    int        rc = WH_ERROR_NOTIMPL;
    ByteVector out;

    if (alg_ == AlgId::kSha256) {
        out.resize(WC_SHA256_DIGEST_SIZE);
        rc = wh_Client_Sha256FinalRequest(client_,
                                          reinterpret_cast<wc_Sha256*>(state_));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_Sha256FinalResponse(
                    client_, reinterpret_cast<wc_Sha256*>(state_), out.data());
            } while (rc == WH_ERROR_NOTREADY);
        }
    }
#ifdef WOLFSSL_SHA384
    else if (alg_ == AlgId::kSha384) {
        out.resize(WC_SHA384_DIGEST_SIZE);
        rc = wh_Client_Sha384FinalRequest(client_,
                                          reinterpret_cast<wc_Sha384*>(state_));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_Sha384FinalResponse(
                    client_, reinterpret_cast<wc_Sha384*>(state_), out.data());
            } while (rc == WH_ERROR_NOTREADY);
        }
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (alg_ == AlgId::kSha512) {
        out.resize(WC_SHA512_DIGEST_SIZE);
        rc = wh_Client_Sha512FinalRequest(client_,
                                          reinterpret_cast<wc_Sha512*>(state_));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_Sha512FinalResponse(
                    client_, reinterpret_cast<wc_Sha512*>(state_), out.data());
            } while (rc == WH_ERROR_NOTREADY);
        }
    }
#endif

    started_ = false; /* wolfCrypt resets state in FinalResponse */
    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
#endif
}

/* -------------------------------------------------------------------
 * Helpers shared by the new contexts.
 * ------------------------------------------------------------------- */

/* isVerifyRejection / wh_Autosar_ConstantCompare are defined in the
 * shared header port/autosar/common/include/wh_autosar_safe_compare.h
 * (included via crypto_provider.cpp's include block). One copy each
 * across the port; both Classic and Adaptive link against it. */

/* ---------------- SymmetricBlockCipherCtx --------------------------- */

#ifndef WOLFHSM_CFG_NO_CRYPTO

SymmetricBlockCipherCtx::SymmetricBlockCipherCtx(whClientContext* client,
                                                 CryptoAlgId algId, KeyId keyId,
                                                 std::uint32_t keyBits)
    : client_(client), alg_(algId), keyId_(keyId), keyBits_(keyBits)
{
}

SymmetricBlockCipherCtx::~SymmetricBlockCipherCtx() = default;

Result<ByteVector> SymmetricBlockCipherCtx::ProcessBlocks(
    const std::uint8_t* iv, std::size_t ivLen, const std::uint8_t* in,
    std::size_t inLen, bool encrypt)
{
    if (client_ == nullptr || in == nullptr) {
        return SecurityErrc::kInvalidArgument;
    }
    if ((inLen % AES_BLOCK_SIZE) != 0u) {
        return SecurityErrc::kInvalidInputSize;
    }
    if (alg_ != AlgId::kAesEcb && (iv == nullptr || ivLen != AES_BLOCK_SIZE)) {
        return SecurityErrc::kInvalidArgument;
    }

    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_DEV_ID);
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    aes.keylen = static_cast<int>(keyBits_ / 8u);
    rc         = wh_Client_AesSetKeyId(&aes, keyId_);
    if (rc == 0 && alg_ != AlgId::kAesEcb) {
        rc = wc_AesSetIV(&aes, iv);
    }
    if (rc != 0) {
        wc_AesFree(&aes);
        return SecurityErrc::kRuntimeFault;
    }

    ByteVector out(inLen);
    rc = WH_ERROR_NOTIMPL;
    if (alg_ == AlgId::kAesCbc) {
#ifdef HAVE_AES_CBC
        rc = wh_Client_AesCbc(client_, &aes, encrypt ? 1 : 0, in, inLen,
                              out.data());
#endif
    }
    else if (alg_ == AlgId::kAesCtr) {
#ifdef WOLFSSL_AES_COUNTER
        rc = wh_Client_AesCtr(client_, &aes, encrypt ? 1 : 0, in, inLen,
                              out.data());
#endif
    }
    else if (alg_ == AlgId::kAesEcb) {
#ifdef HAVE_AES_ECB
        rc = wh_Client_AesEcb(client_, &aes, encrypt ? 1 : 0, in, inLen,
                              out.data());
#endif
    }
    wc_AesFree(&aes);

    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
}

/* ---------------- AuthCipherCtx (AES-GCM) --------------------------- */

AuthCipherCtx::AuthCipherCtx(whClientContext* client, KeyId keyId,
                             std::uint32_t keyBits)
    : client_(client), keyId_(keyId), keyBits_(keyBits)
{
}

AuthCipherCtx::~AuthCipherCtx() = default;

Result<ByteVector>
AuthCipherCtx::ProcessEncrypt(const std::uint8_t* iv, std::size_t ivLen,
                              const std::uint8_t* aad, std::size_t aadLen,
                              const std::uint8_t* pt, std::size_t ptLen,
                              std::size_t tagLen)
{
#ifndef HAVE_AESGCM
    (void)iv;
    (void)ivLen;
    (void)aad;
    (void)aadLen;
    (void)pt;
    (void)ptLen;
    (void)tagLen;
    return SecurityErrc::kRuntimeFault;
#else
    if (client_ == nullptr || iv == nullptr || pt == nullptr || tagLen == 0u ||
        tagLen > 16u) {
        return SecurityErrc::kInvalidArgument;
    }
    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_DEV_ID);
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    aes.keylen = static_cast<int>(keyBits_ / 8u);
    rc         = wh_Client_AesSetKeyId(&aes, keyId_);
    if (rc != 0) {
        wc_AesFree(&aes);
        return SecurityErrc::kRuntimeFault;
    }
    ByteVector out(ptLen + tagLen);
    rc = wh_Client_AesGcm(client_, &aes, /*enc*/ 1, pt,
                          static_cast<std::uint32_t>(ptLen), iv,
                          static_cast<std::uint32_t>(ivLen), aad,
                          static_cast<std::uint32_t>(aadLen),
                          /*dec_tag*/ nullptr,
                          /*enc_tag*/ out.data() + ptLen,
                          static_cast<std::uint32_t>(tagLen), out.data());
    wc_AesFree(&aes);
    if (rc != 0) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
#endif
}

Result<ByteVector>
AuthCipherCtx::ProcessDecrypt(const std::uint8_t* iv, std::size_t ivLen,
                              const std::uint8_t* aad, std::size_t aadLen,
                              const std::uint8_t* ct, std::size_t ctLen,
                              const std::uint8_t* tag, std::size_t tagLen)
{
#ifndef HAVE_AESGCM
    (void)iv;
    (void)ivLen;
    (void)aad;
    (void)aadLen;
    (void)ct;
    (void)ctLen;
    (void)tag;
    (void)tagLen;
    return SecurityErrc::kRuntimeFault;
#else
    if (client_ == nullptr || iv == nullptr || ct == nullptr ||
        tag == nullptr || tagLen == 0u || tagLen > 16u) {
        return SecurityErrc::kInvalidArgument;
    }
    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_DEV_ID);
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    aes.keylen = static_cast<int>(keyBits_ / 8u);
    rc         = wh_Client_AesSetKeyId(&aes, keyId_);
    if (rc != 0) {
        wc_AesFree(&aes);
        return SecurityErrc::kRuntimeFault;
    }
    ByteVector out(ctLen);
    rc = wh_Client_AesGcm(
        client_, &aes, /*enc*/ 0, ct, static_cast<std::uint32_t>(ctLen), iv,
        static_cast<std::uint32_t>(ivLen), aad,
        static_cast<std::uint32_t>(aadLen),
        /*dec_tag*/ tag,
        /*enc_tag*/ nullptr, static_cast<std::uint32_t>(tagLen), out.data());
    wc_AesFree(&aes);
    if (rc != 0) {
        /* Tag mismatch surfaces here. Adapter translates this to the AP
         * runtime's ara::crypto::SecurityErrc::kAuthTagFail. */
        return SecurityErrc::kAuthTagMismatch;
    }
    return Result<ByteVector>(std::move(out));
#endif
}

/* ---------------- MessageAuthnCodeCtx (AES-CMAC) ------------------- */

MessageAuthnCodeCtx::MessageAuthnCodeCtx(whClientContext* client, KeyId keyId)
    : client_(client), keyId_(keyId)
{
}

Result<ByteVector> MessageAuthnCodeCtx::Generate(const std::uint8_t* in,
                                                 std::size_t         inLen)
{
#ifndef WOLFSSL_CMAC
    (void)in;
    (void)inLen;
    return SecurityErrc::kRuntimeFault;
#else
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    Cmac cmac;
    std::memset(&cmac, 0, sizeof(cmac));
    int rc = wh_Client_CmacSetKeyId(&cmac, keyId_);
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    std::uint8_t  macBuf[AES_BLOCK_SIZE];
    std::uint32_t macLen = sizeof(macBuf);
    rc = wh_Client_Cmac(client_, &cmac, WC_CMAC_AES, nullptr, 0u, in,
                        static_cast<std::uint32_t>(inLen), macBuf, &macLen);
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    return Result<ByteVector>(ByteVector(macBuf, macBuf + macLen));
#endif
}

Result<bool> MessageAuthnCodeCtx::Verify(const std::uint8_t* in,
                                         std::size_t         inLen,
                                         const std::uint8_t* mac,
                                         std::size_t         macLen)
{
    auto r = Generate(in, inLen);
    if (!r.HasValue())
        return r.Error();
    const auto& computed = r.Value();
    if (computed.size() != macLen)
        return Result<bool>(false);
    return Result<bool>(
        wh_Autosar_ConstantCompare(computed.data(), mac, macLen) != 0);
}

/* ---------------- SignerPrivateCtx --------------------------------- */

SignerPrivateCtx::SignerPrivateCtx(whClientContext* client, CryptoAlgId algId,
                                   KeyId keyId)
    : client_(client), alg_(algId), keyId_(keyId)
{
}

Result<ByteVector> SignerPrivateCtx::Sign(const std::uint8_t* in,
                                          std::size_t         inLen)
{
    if (client_ == nullptr || in == nullptr)
        return SecurityErrc::kInvalidArgument;

    if (alg_ == AlgId::kEcdsaP256) {
        ecc_key key;
        int     rc = wc_ecc_init_ex(&key, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_EccSetKeyId(&key, keyId_);
        /* Max DER-encoded ECDSA-P256 signature: ASN.1 SEQUENCE wrap (2) +
         * two INTEGER (3) of up to 33 bytes (high bit pad) = 72; round up
         * to 80 to leave slack for any wolfCrypt internal padding. */
        std::uint8_t  sig[80];
        std::uint16_t sigLen = sizeof(sig);
        rc                   = wh_Client_EccSign(client_, &key, in,
                                                 static_cast<std::uint16_t>(inLen), sig, &sigLen);
        wc_ecc_free(&key);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        return Result<ByteVector>(ByteVector(sig, sig + sigLen));
    }
#ifdef HAVE_ED25519
    if (alg_ == AlgId::kEd25519) {
        ed25519_key key;
        int         rc = wc_ed25519_init_ex(&key, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_Ed25519SetKeyId(&key, keyId_);
        std::uint8_t  sig[ED25519_SIG_SIZE];
        std::uint32_t sigLen = sizeof(sig);
        rc                   = wh_Client_Ed25519Sign(client_, &key, in,
                                                     static_cast<std::uint32_t>(inLen),
                                                     /*pure*/ 0u, nullptr, 0u, sig, &sigLen);
        wc_ed25519_free(&key);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        return Result<ByteVector>(ByteVector(sig, sig + sigLen));
    }
#endif
#ifndef NO_RSA
    if (alg_ == AlgId::kRsaPkcs1v15) {
        RsaKey rsa;
        WC_RNG rng;
        int    rc = wc_InitRsaKey_ex(&rsa, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        if (wh_Client_RsaSetKeyId(&rsa, keyId_) != 0 ||
            wc_InitRng_ex(&rng, nullptr, WH_DEV_ID) != 0) {
            wc_FreeRsaKey(&rsa);
            return SecurityErrc::kRuntimeFault;
        }
        ByteVector sig(512);
        int        outLen =
            wc_RsaSSL_Sign(in, static_cast<word32>(inLen), sig.data(),
                           static_cast<word32>(sig.size()), &rsa, &rng);
        (void)wc_FreeRng(&rng);
        (void)wc_FreeRsaKey(&rsa);
        if (outLen < 0)
            return SecurityErrc::kRuntimeFault;
        sig.resize(static_cast<std::size_t>(outLen));
        return Result<ByteVector>(std::move(sig));
    }
#endif
    return SecurityErrc::kInvalidArgument;
}

/* ---------------- VerifierPublicCtx -------------------------------- */

VerifierPublicCtx::VerifierPublicCtx(whClientContext* client, CryptoAlgId algId,
                                     KeyId keyId)
    : client_(client), alg_(algId), keyId_(keyId)
{
}

Result<bool> VerifierPublicCtx::Verify(const std::uint8_t* in,
                                       std::size_t         inLen,
                                       const std::uint8_t* sig,
                                       std::size_t         sigLen)
{
    if (client_ == nullptr || in == nullptr || sig == nullptr)
        return SecurityErrc::kInvalidArgument;

    if (alg_ == AlgId::kEcdsaP256) {
        ecc_key key;
        int     rc = wc_ecc_init_ex(&key, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_EccSetKeyId(&key, keyId_);
        int verifyRes = -1;
        rc            = wh_Client_EccVerify(client_, &key, sig,
                                            static_cast<std::uint16_t>(sigLen), in,
                                            static_cast<std::uint16_t>(inLen), &verifyRes);
        wc_ecc_free(&key);
        if (verifyRes == 0 || verifyRes == 1)
            return Result<bool>(verifyRes == 1);
        if (wh_Autosar_IsVerifyRejection(rc))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#ifdef HAVE_ED25519
    if (alg_ == AlgId::kEd25519) {
        ed25519_key key;
        int         rc = wc_ed25519_init_ex(&key, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_Ed25519SetKeyId(&key, keyId_);
        int verifyRes = -1;
        rc            = wh_Client_Ed25519Verify(
            client_, &key, sig, static_cast<std::uint32_t>(sigLen), in,
            static_cast<std::uint32_t>(inLen), 0u, nullptr, 0u, &verifyRes);
        wc_ed25519_free(&key);
        if (verifyRes == 0 || verifyRes == 1)
            return Result<bool>(verifyRes == 1);
        if (wh_Autosar_IsVerifyRejection(rc))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#endif
#ifndef NO_RSA
    if (alg_ == AlgId::kRsaPkcs1v15) {
        RsaKey rsa;
        int    rc = wc_InitRsaKey_ex(&rsa, nullptr, WH_DEV_ID);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        if (wh_Client_RsaSetKeyId(&rsa, keyId_) != 0) {
            wc_FreeRsaKey(&rsa);
            return SecurityErrc::kRuntimeFault;
        }
        /* Recovered-plaintext buffer sized to the largest RSA modulus we
         * support (4096 bits = 512 bytes). wolfCrypt-side check in
         * wc_RsaSSL_Verify bounds writes by the actual signature length,
         * which equals the modulus size. */
        std::uint8_t plain[512];
        int          plainLen =
            wc_RsaSSL_Verify(sig, static_cast<word32>(sigLen), plain,
                             static_cast<word32>(sizeof(plain)), &rsa);
        wc_FreeRsaKey(&rsa);
        if (plainLen >= 0) {
            return Result<bool>(static_cast<std::size_t>(plainLen) == inLen &&
                                wh_Autosar_ConstantCompare(plain, in, inLen) !=
                                    0);
        }
        if (wh_Autosar_IsVerifyRejection(plainLen))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#endif
    return SecurityErrc::kInvalidArgument;
}

/* ---------------- KeyAgreementPrivateCtx --------------------------- */

KeyAgreementPrivateCtx::KeyAgreementPrivateCtx(whClientContext* client,
                                               CryptoAlgId      algId,
                                               KeyId            privateKeyId)
    : client_(client), alg_(algId), privateKeyId_(privateKeyId)
{
}

Result<ByteVector> KeyAgreementPrivateCtx::AgreeKey(KeyId partnerPublicKeyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    if (alg_ == AlgId::kEcdhP256) {
        std::uint8_t  secret[80];
        std::uint16_t secretLen = sizeof(secret);
        int rc = wh_Client_EccSharedSecretRequest(client_, privateKeyId_,
                                                  partnerPublicKeyId);
        if (rc != WH_ERROR_OK)
            return SecurityErrc::kRuntimeFault;
        do {
            rc = wh_Client_EccSharedSecretResponse(client_, secret, &secretLen);
        } while (rc == WH_ERROR_NOTREADY);
        if (rc != WH_ERROR_OK)
            return SecurityErrc::kRuntimeFault;
        return Result<ByteVector>(ByteVector(secret, secret + secretLen));
    }
    /* X25519 is not wired through the AgreeKey path yet:
     * wh_Client_Curve25519SharedSecret operates on curve25519_key
     * structs rather than raw keyIds. The factory below already
     * refuses kX25519, so this branch is unreachable; surface
     * kInvalidArgument defensively in case a future caller bypasses
     * the factory. */
    return SecurityErrc::kInvalidArgument;
}

/* ---------------- KeyDerivationFunctionCtx ------------------------- */

KeyDerivationFunctionCtx::KeyDerivationFunctionCtx(whClientContext* client,
                                                   CryptoAlgId      algId,
                                                   KeyId            ikmKeyId)
    : client_(client), alg_(algId), ikmKeyId_(ikmKeyId)
{
}

Result<ByteVector> KeyDerivationFunctionCtx::Derive(std::size_t outBytes,
                                                    const std::uint8_t* salt,
                                                    std::size_t         saltLen,
                                                    const std::uint8_t* info,
                                                    std::size_t         infoLen)
{
    if (client_ == nullptr || outBytes == 0u)
        return SecurityErrc::kInvalidArgument;
    ByteVector out(outBytes);
    int        rc = WH_ERROR_NOTIMPL;
#ifdef HAVE_HKDF
    if (alg_ == AlgId::kHkdfSha256) {
        rc = wh_Client_HkdfMakeExportKey(
            client_, WC_HASH_TYPE_SHA256, ikmKeyId_, nullptr, 0u, salt,
            static_cast<std::uint32_t>(saltLen), info,
            static_cast<std::uint32_t>(infoLen), out.data(),
            static_cast<std::uint32_t>(outBytes));
    }
#endif
#ifdef HAVE_CMAC_KDF
    if (alg_ == AlgId::kCmacKdf) {
        rc = wh_Client_CmacKdfMakeExportKey(
            client_, ikmKeyId_, salt, static_cast<std::uint32_t>(saltLen),
            ikmKeyId_, nullptr, 0u, info, static_cast<std::uint32_t>(infoLen),
            out.data(), static_cast<std::uint32_t>(outBytes));
    }
#endif
    if (rc != WH_ERROR_OK)
        return SecurityErrc::kRuntimeFault;
    return Result<ByteVector>(std::move(out));
}

/* ---------------- KeyStorageProvider ------------------------------- */

Result<void> KeyStorageProvider::SaveKey(KeyId keyId, const std::uint8_t* key,
                                         std::size_t len)
{
    if (client_ == nullptr || key == nullptr || len == 0u || len > 0xFFFFu)
        return SecurityErrc::kInvalidArgument;
    std::uint8_t  label[WH_NVM_LABEL_LEN] = {0};
    std::uint16_t outId                   = keyId;
    int           rc                      = wh_Client_KeyCache(
        client_, static_cast<std::uint32_t>(WH_NVM_FLAGS_USAGE_ANY), label,
        sizeof(label), key, static_cast<std::uint16_t>(len), &outId);
    return (rc == WH_ERROR_OK) ? Result<void>()
                               : Result<void>(SecurityErrc::kRuntimeFault);
}

Result<ByteVector> KeyStorageProvider::LoadKey(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    std::uint8_t  label[WH_NVM_LABEL_LEN];
    std::uint8_t  buf[4096];
    std::uint16_t outSz = sizeof(buf);
    int           rc =
        wh_Client_KeyExport(client_, keyId, label, sizeof(label), buf, &outSz);
    if (rc != WH_ERROR_OK)
        return SecurityErrc::kUnknownIdentifier;
    return Result<ByteVector>(ByteVector(buf, buf + outSz));
}

Result<void> KeyStorageProvider::Commit(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    return (wh_Client_KeyCommit(client_, keyId) == WH_ERROR_OK)
               ? Result<void>()
               : Result<void>(SecurityErrc::kRuntimeFault);
}

Result<void> KeyStorageProvider::Erase(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    /* Revoke flips the policy bit so the server rejects every
     * subsequent operation (sign, encrypt, ...) on this key; Erase
     * removes the persisted NVM copy. Together they take the key out
     * of operational use, which is the AUTOSAR-side meaning of
     * "erase". Note: wolfHSM Revoke leaves the cache slot live, so a
     * raw KeyExport against the same id can still return the bytes
     * until the slot is evicted — Revoke does not zeroise. Treating
     * the keystore as a one-way door (write, use, revoke, never
     * re-export) is the contract callers must honour.
     *
     * At least one of the two backends must report success; if both
     * fail the key was unknown and we surface kUnknownIdentifier. */
    int rcRevoke = wh_Client_KeyRevoke(client_, keyId);
    int rcErase  = wh_Client_KeyErase(client_, keyId);
    if (rcRevoke == WH_ERROR_OK || rcErase == WH_ERROR_OK)
        return Result<void>();
    return SecurityErrc::kUnknownIdentifier;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* ---------------- Provider factory methods -------------------------- */

std::unique_ptr<SymmetricBlockCipherCtx>
WolfhsmCryptoProvider::CreateSymmetricBlockCipherCtx(CryptoAlgId   algId,
                                                     KeyId         keyId,
                                                     std::uint32_t keyBits)
{
    if (algId != AlgId::kAesEcb && algId != AlgId::kAesCbc &&
        algId != AlgId::kAesCtr) {
        return nullptr;
    }
    return std::make_unique<SymmetricBlockCipherCtx>(client_, algId, keyId,
                                                     keyBits);
}

std::unique_ptr<AuthCipherCtx>
WolfhsmCryptoProvider::CreateAuthCipherCtx(KeyId keyId, std::uint32_t keyBits)
{
    return std::make_unique<AuthCipherCtx>(client_, keyId, keyBits);
}

std::unique_ptr<MessageAuthnCodeCtx>
WolfhsmCryptoProvider::CreateMessageAuthnCodeCtx(KeyId keyId)
{
    return std::make_unique<MessageAuthnCodeCtx>(client_, keyId);
}

std::unique_ptr<SignerPrivateCtx>
WolfhsmCryptoProvider::CreateSignerPrivateCtx(CryptoAlgId algId, KeyId keyId)
{
    if (algId != AlgId::kEcdsaP256 && algId != AlgId::kEd25519 &&
        algId != AlgId::kRsaPkcs1v15) {
        return nullptr;
    }
    return std::make_unique<SignerPrivateCtx>(client_, algId, keyId);
}

std::unique_ptr<VerifierPublicCtx>
WolfhsmCryptoProvider::CreateVerifierPublicCtx(CryptoAlgId algId, KeyId keyId)
{
    if (algId != AlgId::kEcdsaP256 && algId != AlgId::kEd25519 &&
        algId != AlgId::kRsaPkcs1v15) {
        return nullptr;
    }
    return std::make_unique<VerifierPublicCtx>(client_, algId, keyId);
}

std::unique_ptr<KeyAgreementPrivateCtx>
WolfhsmCryptoProvider::CreateKeyAgreementPrivateCtx(CryptoAlgId algId,
                                                    KeyId       privateKeyId)
{
    /* X25519 is declared in CryptoAlgId but not yet wired through the
     * wolfHSM client surface (Curve25519 keys aren't addressable by
     * raw keyId). Reject at construction so adapters see "unsupported
     * algorithm" up front rather than a generic runtime fault on the
     * first AgreeKey call. */
    if (algId != AlgId::kEcdhP256)
        return nullptr;
    return std::make_unique<KeyAgreementPrivateCtx>(client_, algId,
                                                    privateKeyId);
}

std::unique_ptr<KeyDerivationFunctionCtx>
WolfhsmCryptoProvider::CreateKeyDerivationFunctionCtx(CryptoAlgId algId,
                                                      KeyId       ikmKeyId)
{
    if (algId != AlgId::kHkdfSha256 && algId != AlgId::kCmacKdf)
        return nullptr;
    return std::make_unique<KeyDerivationFunctionCtx>(client_, algId, ikmKeyId);
}

std::unique_ptr<KeyStorageProvider>
WolfhsmCryptoProvider::CreateKeyStorageProvider()
{
    return std::make_unique<KeyStorageProvider>(client_);
}

/* --- Note on SecurityErrc translation ------------------------------- */
/*
 * The SecurityErrc values declared in crypto_provider.hpp are this
 * provider's internal enumeration — they intentionally mirror the
 * ara::crypto::SecurityErrc shape but are not bound to the AUTOSAR
 * Consortium-licensed header set. The integrator's thin
 * ara::crypto::cryp::CryptoProvider adapter (see
 * docs/integration_adaptive.md) is responsible for translating these
 * values to the SecurityErrc values from their AP runtime's headers.
 * The mapping is direct: a value of kInvalidArgument here maps to
 * ara::crypto::SecurityErrc::kInvalidArgument, etc.
 */

} /* namespace ara_crypto */
} /* namespace wolfhsm */
