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
 * Implementation of WolfhsmCryptoProvider and its context classes.
 */

#include "wolfhsm/ara_crypto/crypto_provider.hpp"

#ifdef WOLFHSM_CFG_NO_CRYPTO
#error "The Adaptive CryptoProvider needs wolfCrypt (WOLFHSM_CFG_NO_CRYPTO)"
#endif

#include "wh_autosar_safe_compare.h"

#include <cstring>
#include <new>

extern "C" {
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"

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
#include "wolfssl/wolfcrypt/asn_public.h"
#endif
#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif
#include "wolfssl/wolfcrypt/hash.h"
}

namespace wolfhsm {
namespace ara_crypto {

static bool FitsU32(std::size_t n)
{
    return static_cast<std::uint64_t>(n) <= 0xFFFFFFFFull;
}

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

Result<ByteVector> RandomGeneratorCtx::Generate(std::size_t count)
{
    if (client_ == nullptr || count == 0u) {
        return SecurityErrc::kInvalidArgument;
    }
    if (!FitsU32(count)) {
        return SecurityErrc::kInvalidInputSize;
    }
    ByteVector out(count);
    int        rc = wh_Client_RngGenerate(client_, out.data(),
                                          static_cast<std::uint32_t>(count));
    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
}

HashFunctionCtx::HashFunctionCtx(whClientContext* client, CryptoAlgId algId)
    : client_(client), alg_(algId), started_(false)
{
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
    std::memset(state_, 0, sizeof(state_));
}

static void FreeShaState(CryptoAlgId alg, std::uint8_t* state)
{
    if (alg == AlgId::kSha256) {
        wc_Sha256Free(reinterpret_cast<wc_Sha256*>(state));
    }
#ifdef WOLFSSL_SHA384
    else if (alg == AlgId::kSha384) {
        wc_Sha384Free(reinterpret_cast<wc_Sha384*>(state));
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (alg == AlgId::kSha512) {
        wc_Sha512Free(reinterpret_cast<wc_Sha512*>(state));
    }
#endif
}

HashFunctionCtx::~HashFunctionCtx()
{
    if (started_) {
        FreeShaState(alg_, state_);
    }
    wh_Utils_ForceZero(state_, sizeof(state_));
}

Result<void> HashFunctionCtx::Start()
{
    int rc = WH_ERROR_NOTIMPL;
    if (alg_ == AlgId::kSha256) {
        rc = wc_InitSha256_ex(reinterpret_cast<wc_Sha256*>(state_), nullptr,
                              WH_CLIENT_DEVID(client_));
    }
#ifdef WOLFSSL_SHA384
    else if (alg_ == AlgId::kSha384) {
        rc = wc_InitSha384_ex(reinterpret_cast<wc_Sha384*>(state_), nullptr,
                              WH_CLIENT_DEVID(client_));
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (alg_ == AlgId::kSha512) {
        rc = wc_InitSha512_ex(reinterpret_cast<wc_Sha512*>(state_), nullptr,
                              WH_CLIENT_DEVID(client_));
    }
#endif
    if (rc != 0) {
        return SecurityErrc::kRuntimeFault;
    }
    started_ = true;
    return Result<void>();
}

/* Halve on WH_ERROR_REQUEST_SIZE until the client accepts the chunk. */
template <typename S>
static int
oneShaChunk(whClientContext* c, S* s, const std::uint8_t* in,
            std::uint32_t want, bool* outSent, std::uint32_t* outAccepted,
            int (*req)(whClientContext*, S*, const uint8_t*, uint32_t, bool*),
            int (*res)(whClientContext*, S*))
{
    int rc       = WH_ERROR_BADARGS;
    *outSent     = false;
    *outAccepted = 0u;
    while (want > 0u) {
        bool sent = false;
        rc        = req(c, s, in, want, &sent);
        if (rc == WH_ERROR_OK) {
            if (sent) {
                do {
                    rc = res(c, s);
                } while (rc == WH_ERROR_NOTREADY);
            }
            *outSent     = sent;
            *outAccepted = want;
            return rc;
        }
        if (rc != WH_ERROR_REQUEST_SIZE)
            return rc;
        want /= 2u;
    }
    return rc;
}

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
    if (!FitsU32(size)) {
        return SecurityErrc::kInvalidInputSize;
    }
    std::uint32_t       remaining = static_cast<std::uint32_t>(size);
    const std::uint8_t* p         = data;
    int                 rc        = WH_ERROR_OK;
    while (remaining > 0u) {
        std::uint32_t accepted = 0u;
        bool          sent     = false;
        if (alg_ == AlgId::kSha256) {
            rc = oneShaChunk(client_, reinterpret_cast<wc_Sha256*>(state_), p,
                             remaining, &sent, &accepted,
                             wh_Client_Sha256UpdateRequest,
                             wh_Client_Sha256UpdateResponse);
        }
#ifdef WOLFSSL_SHA384
        else if (alg_ == AlgId::kSha384) {
            rc = oneShaChunk(client_, reinterpret_cast<wc_Sha384*>(state_), p,
                             remaining, &sent, &accepted,
                             wh_Client_Sha384UpdateRequest,
                             wh_Client_Sha384UpdateResponse);
        }
#endif
#ifdef WOLFSSL_SHA512
        else if (alg_ == AlgId::kSha512) {
            rc = oneShaChunk(client_, reinterpret_cast<wc_Sha512*>(state_), p,
                             remaining, &sent, &accepted,
                             wh_Client_Sha512UpdateRequest,
                             wh_Client_Sha512UpdateResponse);
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
}

Result<ByteVector> HashFunctionCtx::Finish()
{
    if (!started_) {
        return SecurityErrc::kProcessingNotStarted;
    }
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

    FreeShaState(alg_, state_);
    wh_Utils_ForceZero(state_, sizeof(state_));
    started_ = false;
    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
}

/* Plain client key ids only: no global, wrapped or hardware flag bits. */
static bool KeyIdOk(KeyId keyId)
{
    return !WH_KEYID_ISERASED(keyId) &&
           (keyId & WH_CLIENT_KEYID_FLAGS_MASK) == 0u;
}

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
    if ((inLen % AES_BLOCK_SIZE) != 0u || !FitsU32(inLen)) {
        return SecurityErrc::kInvalidInputSize;
    }
    if (alg_ != AlgId::kAesEcb && (iv == nullptr || ivLen != AES_BLOCK_SIZE)) {
        return SecurityErrc::kInvalidArgument;
    }

    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_CLIENT_DEVID(client_));
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
        rc = wh_Client_AesCbc(client_, &aes, encrypt ? 1 : 0, in,
                              static_cast<std::uint32_t>(inLen), out.data());
#endif
    }
    else if (alg_ == AlgId::kAesCtr) {
#ifdef WOLFSSL_AES_COUNTER
        /* CTR is symmetric; the server mis-keys enc=0. */
        rc = wh_Client_AesCtr(client_, &aes, 1, in,
                              static_cast<std::uint32_t>(inLen), out.data());
#endif
    }
    else if (alg_ == AlgId::kAesEcb) {
#ifdef HAVE_AES_ECB
        rc = wh_Client_AesEcb(client_, &aes, encrypt ? 1 : 0, in,
                              static_cast<std::uint32_t>(inLen), out.data());
#endif
    }
    wc_AesFree(&aes);

    if (rc != WH_ERROR_OK) {
        return SecurityErrc::kRuntimeFault;
    }
    return Result<ByteVector>(std::move(out));
}

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
    if (client_ == nullptr || iv == nullptr || pt == nullptr || tagLen > 16u) {
        return SecurityErrc::kInvalidArgument;
    }
    if (tagLen < kMinTagLen || !FitsU32(ivLen) || !FitsU32(aadLen) ||
        !FitsU32(ptLen)) {
        return SecurityErrc::kInvalidInputSize;
    }
    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_CLIENT_DEVID(client_));
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
        tag == nullptr || tagLen > 16u) {
        return SecurityErrc::kInvalidArgument;
    }
    if (tagLen < kMinTagLen || !FitsU32(ivLen) || !FitsU32(aadLen) ||
        !FitsU32(ctLen)) {
        return SecurityErrc::kInvalidInputSize;
    }
    Aes aes;
    int rc = wc_AesInit(&aes, nullptr, WH_CLIENT_DEVID(client_));
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
    if (wh_Autosar_IsVerifyRejection(rc))
        return SecurityErrc::kAuthTagMismatch;
    if (rc != 0)
        return SecurityErrc::kRuntimeFault;
    return Result<ByteVector>(std::move(out));
#endif
}

MessageAuthnCodeCtx::MessageAuthnCodeCtx(whClientContext* client, KeyId keyId)
    : client_(client), keyId_(keyId)
{
}

SecurityErrc MessageAuthnCodeCtx::ComputeMac(const std::uint8_t* in,
                                             std::size_t         inLen,
                                             std::uint8_t (&mac)[kMacLen])
{
#ifndef WOLFSSL_CMAC
    (void)in;
    (void)inLen;
    (void)mac;
    return SecurityErrc::kRuntimeFault;
#else
    if (client_ == nullptr || (in == nullptr && inLen != 0u))
        return SecurityErrc::kInvalidArgument;
    if (!FitsU32(inLen))
        return SecurityErrc::kInvalidInputSize;
    Cmac cmac;
    std::memset(&cmac, 0, sizeof(cmac));
    std::uint32_t macLen = kMacLen;
    int           rc     = wh_Client_CmacSetKeyId(&cmac, keyId_);
    if (rc == 0)
        rc = wh_Client_Cmac(client_, &cmac, WC_CMAC_AES, nullptr, 0u, in,
                            static_cast<std::uint32_t>(inLen), mac, &macLen);
    wh_Utils_ForceZero(&cmac, sizeof(cmac));
    if (rc != 0 || macLen != kMacLen) {
        wh_Utils_ForceZero(mac, kMacLen);
        return SecurityErrc::kRuntimeFault;
    }
    return SecurityErrc::kOk;
#endif
}

Result<ByteVector> MessageAuthnCodeCtx::Generate(const std::uint8_t* in,
                                                 std::size_t         inLen)
{
    std::uint8_t macBuf[kMacLen];
    SecurityErrc err = ComputeMac(in, inLen, macBuf);
    if (err != SecurityErrc::kOk)
        return err;
    ByteVector out(macBuf, macBuf + kMacLen);
    wh_Utils_ForceZero(macBuf, sizeof(macBuf));
    return Result<ByteVector>(std::move(out));
}

Result<bool> MessageAuthnCodeCtx::Verify(const std::uint8_t* in,
                                         std::size_t         inLen,
                                         const std::uint8_t* mac,
                                         std::size_t         macLen)
{
    if (mac == nullptr || macLen == 0u || (in == nullptr && inLen != 0u))
        return SecurityErrc::kInvalidArgument;
    if (macLen < kMinMacLen || macLen > kMacLen)
        return SecurityErrc::kInvalidInputSize;
    std::uint8_t computed[kMacLen];
    SecurityErrc err = ComputeMac(in, inLen, computed);
    if (err != SecurityErrc::kOk)
        return err;
    bool match = wh_Utils_ConstantCompare(computed, mac, macLen) == 0;
    wh_Utils_ForceZero(computed, sizeof(computed));
    return Result<bool>(match);
}

#ifndef NO_RSA
/* Signer/verifier input for RSA is a SHA-2 digest; its length names the
 * hash. */
static enum wc_HashType digestHashType(std::size_t len)
{
    switch (len) {
        case WC_SHA256_DIGEST_SIZE:
            return WC_HASH_TYPE_SHA256;
        case WC_SHA384_DIGEST_SIZE:
            return WC_HASH_TYPE_SHA384;
        case WC_SHA512_DIGEST_SIZE:
            return WC_HASH_TYPE_SHA512;
        default:
            return WC_HASH_TYPE_NONE;
    }
}

static int pssMgf(enum wc_HashType type)
{
    return (type == WC_HASH_TYPE_SHA384)   ? WC_MGF1SHA384
           : (type == WC_HASH_TYPE_SHA512) ? WC_MGF1SHA512
                                           : WC_MGF1SHA256;
}
#endif

static bool EcdsaDigestLenOk(std::size_t len)
{
    return len == WC_SHA256_DIGEST_SIZE || len == WC_SHA384_DIGEST_SIZE ||
           len == WC_SHA512_DIGEST_SIZE;
}

#ifdef WOLFSSL_HAVE_MLDSA
static int mlDsaLevel(CryptoAlgId alg)
{
    return (alg == AlgId::kMlDsa44)   ? WC_ML_DSA_44
           : (alg == AlgId::kMlDsa65) ? WC_ML_DSA_65
           : (alg == AlgId::kMlDsa87) ? WC_ML_DSA_87
                                      : -1;
}
#endif

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
    if (!FitsU32(inLen))
        return SecurityErrc::kInvalidInputSize;

    if (alg_ == AlgId::kEcdsaP256) {
        ecc_key key;
        int     rc;
        if (!EcdsaDigestLenOk(inLen))
            return SecurityErrc::kInvalidInputSize;
        rc = wc_ecc_init_ex(&key, nullptr, WH_CLIENT_DEVID(client_));
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_EccSetKeyId(&key, keyId_);
        /* A DER ECDSA P-256 signature is at most 72 bytes. */
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
        int rc = wc_ed25519_init_ex(&key, nullptr, WH_CLIENT_DEVID(client_));
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_Ed25519SetKeyId(&key, keyId_);
        std::uint8_t  sig[ED25519_SIG_SIZE];
        std::uint32_t sigLen = sizeof(sig);
        rc                   = wh_Client_Ed25519Sign(
            client_, &key, in, static_cast<std::uint32_t>(inLen),
            (std::uint8_t)Ed25519, nullptr, 0u, sig, &sigLen);
        wc_ed25519_free(&key);
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        return Result<ByteVector>(ByteVector(sig, sig + sigLen));
    }
#endif
#ifndef NO_RSA
    if (alg_ == AlgId::kRsaPkcs1v15 || alg_ == AlgId::kRsaPss) {
        enum wc_HashType type = digestHashType(inLen);
        std::uint8_t     enc[MAX_DER_DIGEST_SZ];
        word32           encLen = 0u;
        RsaKey           rsa;
        WC_RNG           rng;
        int              outLen;

        if (type == WC_HASH_TYPE_NONE)
            return SecurityErrc::kInvalidInputSize;
        if (alg_ == AlgId::kRsaPkcs1v15) {
            encLen = wc_EncodeSignature(enc, in, static_cast<word32>(inLen),
                                        wc_HashGetOID(type));
            if (encLen == 0u)
                return SecurityErrc::kRuntimeFault;
        }
        if (wc_InitRsaKey_ex(&rsa, nullptr, WH_CLIENT_DEVID(client_)) != 0)
            return SecurityErrc::kRuntimeFault;
        if (wh_Client_RsaSetKeyId(&rsa, keyId_) != 0 ||
            wc_InitRng_ex(&rng, nullptr, WH_CLIENT_DEVID(client_)) != 0) {
            wc_FreeRsaKey(&rsa);
            return SecurityErrc::kRuntimeFault;
        }
        ByteVector sig(512);
        if (alg_ == AlgId::kRsaPkcs1v15) {
            outLen =
                wc_RsaSSL_Sign(enc, encLen, sig.data(),
                               static_cast<word32>(sig.size()), &rsa, &rng);
        }
        else {
#ifdef WC_RSA_PSS
            outLen = wc_RsaPSS_Sign(in, static_cast<word32>(inLen), sig.data(),
                                    static_cast<word32>(sig.size()), type,
                                    pssMgf(type), &rsa, &rng);
#else
            outLen = NOT_COMPILED_IN;
#endif
        }
        (void)wc_FreeRng(&rng);
        (void)wc_FreeRsaKey(&rsa);
        if (outLen < 0)
            return SecurityErrc::kRuntimeFault;
        sig.resize(static_cast<std::size_t>(outLen));
        return Result<ByteVector>(std::move(sig));
    }
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    if (mlDsaLevel(alg_) > 0) {
        std::unique_ptr<MlDsaKey> key(new (std::nothrow) MlDsaKey);
        if (key == nullptr ||
            wc_MlDsaKey_Init(key.get(), nullptr, WH_CLIENT_DEVID(client_)) != 0)
            return SecurityErrc::kRuntimeFault;
        ByteVector sig(DILITHIUM_MAX_SIG_SIZE);
        word32     sigLen = static_cast<word32>(sig.size());
        int        rc     = wc_MlDsaKey_SetParams(key.get(),
                                                  static_cast<byte>(mlDsaLevel(alg_)));
        if (rc == 0)
            rc = wh_Client_MlDsaSetKeyId(key.get(), keyId_);
        if (rc == 0)
            rc = wh_Client_MlDsaSign(client_, in, static_cast<word32>(inLen),
                                     sig.data(), &sigLen, key.get(), nullptr,
                                     0u, WC_HASH_TYPE_NONE);
        wc_MlDsaKey_Free(key.get());
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        sig.resize(sigLen);
        return Result<ByteVector>(std::move(sig));
    }
#endif
    return SecurityErrc::kInvalidArgument;
}

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
    if (!FitsU32(inLen) || !FitsU32(sigLen))
        return SecurityErrc::kInvalidInputSize;

    if (alg_ == AlgId::kEcdsaP256) {
        ecc_key key;
        int     rc;
        if (!EcdsaDigestLenOk(inLen) || sigLen > 0xFFFFu)
            return SecurityErrc::kInvalidInputSize;
        rc = wc_ecc_init_ex(&key, nullptr, WH_CLIENT_DEVID(client_));
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
        int rc = wc_ed25519_init_ex(&key, nullptr, WH_CLIENT_DEVID(client_));
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        (void)wh_Client_Ed25519SetKeyId(&key, keyId_);
        int verifyRes = -1;
        rc            = wh_Client_Ed25519Verify(
            client_, &key, sig, static_cast<std::uint32_t>(sigLen), in,
            static_cast<std::uint32_t>(inLen), (std::uint8_t)Ed25519, nullptr,
            0u, &verifyRes);
        wc_ed25519_free(&key);
        if (verifyRes == 0 || verifyRes == 1)
            return Result<bool>(verifyRes == 1);
        if (wh_Autosar_IsVerifyRejection(rc))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#endif
#ifndef NO_RSA
    if (alg_ == AlgId::kRsaPkcs1v15 || alg_ == AlgId::kRsaPss) {
        enum wc_HashType type = digestHashType(inLen);
        std::uint8_t     enc[MAX_DER_DIGEST_SZ];
        word32           encLen = 0u;
        std::uint8_t     plain[512];
        RsaKey           rsa;
        int              n;

        if (type == WC_HASH_TYPE_NONE)
            return SecurityErrc::kInvalidInputSize;
        if (alg_ == AlgId::kRsaPkcs1v15) {
            encLen = wc_EncodeSignature(enc, in, static_cast<word32>(inLen),
                                        wc_HashGetOID(type));
            if (encLen == 0u)
                return SecurityErrc::kRuntimeFault;
        }
        if (wc_InitRsaKey_ex(&rsa, nullptr, WH_CLIENT_DEVID(client_)) != 0)
            return SecurityErrc::kRuntimeFault;
        if (wh_Client_RsaSetKeyId(&rsa, keyId_) != 0) {
            wc_FreeRsaKey(&rsa);
            return SecurityErrc::kRuntimeFault;
        }
        if (alg_ == AlgId::kRsaPkcs1v15) {
            n = wc_RsaSSL_Verify(sig, static_cast<word32>(sigLen), plain,
                                 static_cast<word32>(sizeof(plain)), &rsa);
        }
        else {
#ifdef WC_RSA_PSS
            n = wc_RsaPSS_VerifyCheck(sig, static_cast<word32>(sigLen), plain,
                                      static_cast<word32>(sizeof(plain)), in,
                                      static_cast<word32>(inLen), type,
                                      pssMgf(type), &rsa);
#else
            n = NOT_COMPILED_IN;
#endif
        }
        wc_FreeRsaKey(&rsa);
        if (n >= 0) {
            return Result<bool>(
                alg_ == AlgId::kRsaPss ||
                (static_cast<word32>(n) == encLen &&
                 wh_Utils_ConstantCompare(plain, enc, encLen) == 0));
        }
        if (wh_Autosar_IsVerifyRejection(n))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    if (mlDsaLevel(alg_) > 0) {
        std::unique_ptr<MlDsaKey> key(new (std::nothrow) MlDsaKey);
        int                       res = -1;
        if (key == nullptr ||
            wc_MlDsaKey_Init(key.get(), nullptr, WH_CLIENT_DEVID(client_)) != 0)
            return SecurityErrc::kRuntimeFault;
        int rc = wc_MlDsaKey_SetParams(key.get(),
                                       static_cast<byte>(mlDsaLevel(alg_)));
        if (rc == 0)
            rc = wh_Client_MlDsaSetKeyId(key.get(), keyId_);
        if (rc == 0)
            rc = wh_Client_MlDsaVerify(
                client_, sig, static_cast<word32>(sigLen), in,
                static_cast<word32>(inLen), &res, key.get(), nullptr, 0u,
                WC_HASH_TYPE_NONE);
        wc_MlDsaKey_Free(key.get());
        if (res == 0 || res == 1)
            return Result<bool>(res == 1);
        if (wh_Autosar_IsVerifyRejection(rc))
            return Result<bool>(false);
        return SecurityErrc::kRuntimeFault;
    }
#endif
    return SecurityErrc::kInvalidArgument;
}

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
    if (!KeyIdOk(partnerPublicKeyId))
        return SecurityErrc::kUnknownIdentifier;
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
        ByteVector out;
        if (rc == WH_ERROR_OK)
            out.assign(secret, secret + secretLen);
        wh_Utils_ForceZero(secret, sizeof(secret));
        if (rc != WH_ERROR_OK)
            return SecurityErrc::kRuntimeFault;
        return Result<ByteVector>(std::move(out));
    }
#ifdef HAVE_CURVE25519
    if (alg_ == AlgId::kX25519) {
        curve25519_key priv;
        curve25519_key pub;
        std::uint8_t   secret[CURVE25519_KEYSIZE];
        std::uint16_t  secretLen = sizeof(secret);
        int            rc =
            wc_curve25519_init_ex(&priv, nullptr, WH_CLIENT_DEVID(client_));
        if (rc != 0)
            return SecurityErrc::kRuntimeFault;
        rc = wc_curve25519_init_ex(&pub, nullptr, WH_CLIENT_DEVID(client_));
        if (rc == 0) {
            rc = wh_Client_Curve25519SetKeyId(&priv, privateKeyId_);
            if (rc == 0)
                rc = wh_Client_Curve25519SetKeyId(&pub, partnerPublicKeyId);
            if (rc == 0)
                rc = wh_Client_Curve25519SharedSecret(client_, &priv, &pub,
                                                      EC25519_LITTLE_ENDIAN,
                                                      secret, &secretLen);
            wc_curve25519_free(&pub);
        }
        wc_curve25519_free(&priv);
        if (rc != WH_ERROR_OK)
            return SecurityErrc::kRuntimeFault;
        ByteVector out(secret, secret + secretLen);
        wh_Utils_ForceZero(secret, sizeof(secret));
        return Result<ByteVector>(std::move(out));
    }
#endif
    return SecurityErrc::kInvalidArgument;
}

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
    if (!FitsU32(outBytes) || !FitsU32(saltLen) || !FitsU32(infoLen))
        return SecurityErrc::kInvalidInputSize;
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

Result<void> KeyStorageProvider::SaveKey(KeyId keyId, const std::uint8_t* key,
                                         std::size_t len, bool exportable)
{
    if (client_ == nullptr || key == nullptr || len == 0u || len > 0xFFFFu)
        return SecurityErrc::kInvalidArgument;
    if (!KeyIdOk(keyId))
        return SecurityErrc::kUnknownIdentifier;
    std::uint8_t  label[WH_NVM_LABEL_LEN] = {0};
    std::uint16_t outId                   = keyId;
    std::uint32_t flags = static_cast<std::uint32_t>(WH_NVM_FLAGS_USAGE_ANY);
    if (!exportable)
        flags |= static_cast<std::uint32_t>(WH_NVM_FLAGS_NONEXPORTABLE);
    int rc = wh_Client_KeyCache(client_, flags, label, sizeof(label), key,
                                static_cast<std::uint16_t>(len), &outId);
    return (rc == WH_ERROR_OK) ? Result<void>()
                               : Result<void>(SecurityErrc::kRuntimeFault);
}

Result<ByteVector> KeyStorageProvider::LoadKey(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    if (!KeyIdOk(keyId))
        return SecurityErrc::kUnknownIdentifier;
    std::uint8_t  label[WH_NVM_LABEL_LEN];
    std::uint8_t  buf[4096];
    std::uint16_t outSz = sizeof(buf);
    int           rc =
        wh_Client_KeyExport(client_, keyId, label, sizeof(label), buf, &outSz);
    ByteVector out;
    if (rc == WH_ERROR_OK)
        out.assign(buf, buf + outSz);
    wh_Utils_ForceZero(buf, sizeof(buf));
    if (rc != WH_ERROR_OK)
        return SecurityErrc::kUnknownIdentifier;
    return Result<ByteVector>(std::move(out));
}

Result<void> KeyStorageProvider::Commit(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    if (!KeyIdOk(keyId))
        return SecurityErrc::kUnknownIdentifier;
    return (wh_Client_KeyCommit(client_, keyId) == WH_ERROR_OK)
               ? Result<void>()
               : Result<void>(SecurityErrc::kRuntimeFault);
}

Result<void> KeyStorageProvider::Erase(KeyId keyId)
{
    if (client_ == nullptr)
        return SecurityErrc::kInvalidArgument;
    if (!KeyIdOk(keyId))
        return SecurityErrc::kUnknownIdentifier;
    int rc = wh_Client_KeyErase(client_, keyId);
    if (rc == WH_ERROR_OK)
        return Result<void>();
    if (rc == WH_ERROR_NOTFOUND)
        return SecurityErrc::kUnknownIdentifier;
    if (rc != WH_ERROR_ACCESS)
        return SecurityErrc::kRuntimeFault;
    /* Erase refused: revoke blocks further use but leaves the key stored. */
    if (wh_Client_KeyRevoke(client_, keyId) != WH_ERROR_OK)
        return SecurityErrc::kRuntimeFault;
    return SecurityErrc::kAccessViolation;
}

std::unique_ptr<SymmetricBlockCipherCtx>
WolfhsmCryptoProvider::CreateSymmetricBlockCipherCtx(CryptoAlgId   algId,
                                                     KeyId         keyId,
                                                     std::uint32_t keyBits)
{
    if ((algId != AlgId::kAesEcb && algId != AlgId::kAesCbc &&
         algId != AlgId::kAesCtr) ||
        !KeyIdOk(keyId)) {
        return nullptr;
    }
    return std::make_unique<SymmetricBlockCipherCtx>(client_, algId, keyId,
                                                     keyBits);
}

std::unique_ptr<AuthCipherCtx>
WolfhsmCryptoProvider::CreateAuthCipherCtx(KeyId keyId, std::uint32_t keyBits)
{
    if (!KeyIdOk(keyId))
        return nullptr;
    return std::make_unique<AuthCipherCtx>(client_, keyId, keyBits);
}

std::unique_ptr<MessageAuthnCodeCtx>
WolfhsmCryptoProvider::CreateMessageAuthnCodeCtx(KeyId keyId)
{
    if (!KeyIdOk(keyId))
        return nullptr;
    return std::make_unique<MessageAuthnCodeCtx>(client_, keyId);
}

static bool IsSignatureAlg(CryptoAlgId algId)
{
    return algId == AlgId::kEcdsaP256 || algId == AlgId::kEd25519 ||
           algId == AlgId::kRsaPkcs1v15 || algId == AlgId::kRsaPss ||
           algId == AlgId::kMlDsa44 || algId == AlgId::kMlDsa65 ||
           algId == AlgId::kMlDsa87;
}

std::unique_ptr<SignerPrivateCtx>
WolfhsmCryptoProvider::CreateSignerPrivateCtx(CryptoAlgId algId, KeyId keyId)
{
    if (!IsSignatureAlg(algId) || !KeyIdOk(keyId)) {
        return nullptr;
    }
    return std::make_unique<SignerPrivateCtx>(client_, algId, keyId);
}

std::unique_ptr<VerifierPublicCtx>
WolfhsmCryptoProvider::CreateVerifierPublicCtx(CryptoAlgId algId, KeyId keyId)
{
    if (!IsSignatureAlg(algId) || !KeyIdOk(keyId)) {
        return nullptr;
    }
    return std::make_unique<VerifierPublicCtx>(client_, algId, keyId);
}

std::unique_ptr<KeyAgreementPrivateCtx>
WolfhsmCryptoProvider::CreateKeyAgreementPrivateCtx(CryptoAlgId algId,
                                                    KeyId       privateKeyId)
{
    if ((algId != AlgId::kEcdhP256 && algId != AlgId::kX25519) ||
        !KeyIdOk(privateKeyId))
        return nullptr;
    return std::make_unique<KeyAgreementPrivateCtx>(client_, algId,
                                                    privateKeyId);
}

std::unique_ptr<KeyDerivationFunctionCtx>
WolfhsmCryptoProvider::CreateKeyDerivationFunctionCtx(CryptoAlgId algId,
                                                      KeyId       ikmKeyId)
{
    if ((algId != AlgId::kHkdfSha256 && algId != AlgId::kCmacKdf) ||
        !KeyIdOk(ikmKeyId))
        return nullptr;
    return std::make_unique<KeyDerivationFunctionCtx>(client_, algId, ikmKeyId);
}

std::unique_ptr<KeyStorageProvider>
WolfhsmCryptoProvider::CreateKeyStorageProvider()
{
    return std::make_unique<KeyStorageProvider>(client_);
}

} /* namespace ara_crypto */
} /* namespace wolfhsm */
