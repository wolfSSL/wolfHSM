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
 * port/autosar/adaptive/include/wolfhsm/ara_crypto/crypto_provider.hpp
 *
 * Shape-compatible parallel to ara::crypto::cryp::CryptoProvider for
 * AUTOSAR Adaptive R22-11. We define types in wolfhsm::ara_crypto so the
 * port stays free of AUTOSAR-Consortium-licensed headers. Integrators
 * provide a small adapter that inherits from their AP runtime's
 * ara::crypto::cryp::CryptoProvider and forwards each call to the
 * matching method on WolfhsmCryptoProvider.
 */

#ifndef WOLFHSM_ARA_CRYPTO_CRYPTO_PROVIDER_HPP_
#define WOLFHSM_ARA_CRYPTO_CRYPTO_PROVIDER_HPP_

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <system_error>

extern "C" {
#include "wolfhsm/wh_client.h"
}

namespace wolfhsm {
namespace ara_crypto {

/* Error category aligned with ara::crypto::SecurityErrc values. */
enum class SecurityErrc : int32_t {
    kOk                    = 0,
    kBusyResource          = 1,
    kInsufficientResource  = 2,
    kInvalidArgument       = 3,
    kInvalidInputSize      = 4,
    kIncompatibleObject    = 5,
    kUnreservedResource    = 6,
    kModifiedResource      = 7,
    kUsageViolation        = 8,
    kAccessViolation       = 9,
    kUnknownIdentifier     = 10,
    kInsufficientCapacity  = 11,
    kProcessingNotStarted  = 12,
    kProcessingNotFinished = 13,
    kInvalidUsageOrder     = 14,
    kRuntimeFault          = 15,
    /* AEAD authentication-tag mismatch on decrypt. The Adaptive Platform
     * SWS surfaces this as ara::crypto::SecurityErrc::kAuthTagFail
     * (R22-11) — adapters that translate this enum into the real
     * ara::core::ErrorCode should map it to that value. */
    kAuthTagMismatch = 16
};

template <typename T>
class Result {
  public:
    Result(T value) : has_value_(true), value_(std::move(value)) {}
    Result(SecurityErrc err) : has_value_(false), err_(err) {}

    bool HasValue() const noexcept
    {
        return has_value_;
    }
    const T& Value() const
    {
        return value_;
    }
    T ValueOr(T fallback) const
    {
        return has_value_ ? value_ : fallback;
    }
    SecurityErrc Error() const noexcept
    {
        return err_;
    }

  private:
    bool         has_value_;
    T            value_{};
    SecurityErrc err_{SecurityErrc::kOk};
};

template <>
class Result<void> {
  public:
    Result() : has_value_(true) {}
    Result(SecurityErrc err) : has_value_(false), err_(err) {}
    bool HasValue() const noexcept
    {
        return has_value_;
    }
    SecurityErrc Error() const noexcept
    {
        return err_;
    }

  private:
    bool         has_value_{true};
    SecurityErrc err_{SecurityErrc::kOk};
};

using ByteVector  = std::vector<std::uint8_t>;
using CryptoAlgId = std::uint64_t;

/* --- Random generator context ---------------------------------------- */
class RandomGeneratorCtx {
  public:
    RandomGeneratorCtx(whClientContext* client) : client_(client) {}
    Result<ByteVector> Generate(std::size_t count);

  private:
    whClientContext* client_;
};

/* --- Hash function context ------------------------------------------- */
/* Streaming: Update sends each chunk to the wolfHSM server immediately
 * via Sha*UpdateRequest/Response. Internal storage is the wolfCrypt hash
 * state (kept opaque here as a raw byte array — sized to fit any of the
 * supported variants — so this header doesn't pull in wolfCrypt). */
class HashFunctionCtx {
  public:
    HashFunctionCtx(whClientContext* client, CryptoAlgId algId);
    ~HashFunctionCtx();

    Result<void>       Start();
    Result<void>       Update(const std::uint8_t* data, std::size_t size);
    Result<ByteVector> Finish();

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    bool             started_;
    /* Opaque storage for wc_Sha256 / wc_Sha384 / wc_Sha512. 512 bytes
     * comfortably exceeds the largest variant on every wolfCrypt build.
     * Aligned to 16 bytes — wc_Sha384/Sha512 may use 128-bit-aligned
     * fields on architectures with SHA-NI / SVE acceleration, and ARM /
     * RISC-V with strict-alignment traps reject misaligned 64-bit
     * loads. The static_asserts in the ctor verify size only; alignas
     * carries the alignment guarantee. */
    alignas(16) std::uint8_t state_[512];
};

/* --- Symmetric block cipher (AES ECB / CBC / CTR) -------------------
 * Single-call ProcessBlocks: one call processes the whole payload, IV
 * passed in. Streaming UPDATE / FINISH is a follow-up. */
using KeyId = std::uint16_t;

class SymmetricBlockCipherCtx {
  public:
    SymmetricBlockCipherCtx(whClientContext* client, CryptoAlgId algId,
                            KeyId keyId, std::uint32_t keyBits);
    ~SymmetricBlockCipherCtx();

    Result<ByteVector> ProcessBlocks(const std::uint8_t* iv, std::size_t ivLen,
                                     const std::uint8_t* in, std::size_t inLen,
                                     bool encrypt);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
    std::uint32_t    keyBits_;
};

/* --- Authenticated cipher (AES-GCM) --------------------------------- */
class AuthCipherCtx {
  public:
    AuthCipherCtx(whClientContext* client, KeyId keyId, std::uint32_t keyBits);
    ~AuthCipherCtx();

    /* Encrypt: returns ciphertext || tag concatenated, tag of tagLen bytes
     * appended at the end of the returned ByteVector. */
    Result<ByteVector> ProcessEncrypt(const std::uint8_t* iv, std::size_t ivLen,
                                      const std::uint8_t* aad,
                                      std::size_t         aadLen,
                                      const std::uint8_t* pt, std::size_t ptLen,
                                      std::size_t tagLen);
    /* Decrypt: takes ciphertext and tag separately; returns plaintext on
     * success, kAuthTagFail on tag mismatch. */
    Result<ByteVector> ProcessDecrypt(const std::uint8_t* iv, std::size_t ivLen,
                                      const std::uint8_t* aad,
                                      std::size_t         aadLen,
                                      const std::uint8_t* ct, std::size_t ctLen,
                                      const std::uint8_t* tag,
                                      std::size_t         tagLen);

  private:
    whClientContext* client_;
    KeyId            keyId_;
    std::uint32_t    keyBits_;
};

/* --- MAC (AES-CMAC) ------------------------------------------------- */
class MessageAuthnCodeCtx {
  public:
    MessageAuthnCodeCtx(whClientContext* client, KeyId keyId);

    Result<ByteVector> Generate(const std::uint8_t* in, std::size_t inLen);
    Result<bool>       Verify(const std::uint8_t* in, std::size_t inLen,
                              const std::uint8_t* mac, std::size_t macLen);

  private:
    whClientContext* client_;
    KeyId            keyId_;
};

/* --- Signature: signer / verifier ----------------------------------- */
/* ECDSA / Ed25519 / RSA-PKCS1-v1.5 share the same shell — algId picks. */
class SignerPrivateCtx {
  public:
    SignerPrivateCtx(whClientContext* client, CryptoAlgId algId, KeyId keyId);

    Result<ByteVector> Sign(const std::uint8_t* in, std::size_t inLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
};

class VerifierPublicCtx {
  public:
    VerifierPublicCtx(whClientContext* client, CryptoAlgId algId, KeyId keyId);

    /* Result is true on signature valid, false on invalid. Error variant
     * means the call failed (transport, key-not-found). */
    Result<bool> Verify(const std::uint8_t* in, std::size_t inLen,
                        const std::uint8_t* sig, std::size_t sigLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
};

/* --- Key agreement (ECDH P-256, X25519) ----------------------------
 *
 * Thread-safety: like all other context classes in this file, a single
 * KeyAgreementPrivateCtx instance is bound to one whClientContext and is
 * NOT safe to use concurrently from multiple threads. wolfHSM's
 * client-side protocol enforces a one-request-in-flight contract per
 * whClientContext, so concurrent AgreeKey() calls on the same ctx (or
 * on different ctxs sharing the same client) will collide. AP runtimes
 * that fan work out across worker threads must serialize at the
 * provider level or hand each thread its own whClientContext. */
class KeyAgreementPrivateCtx {
  public:
    KeyAgreementPrivateCtx(whClientContext* client, CryptoAlgId algId,
                           KeyId privateKeyId);

    Result<ByteVector> AgreeKey(KeyId partnerPublicKeyId);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            privateKeyId_;
};

/* --- KDF (HKDF, CMAC-KDF) ------------------------------------------ */
class KeyDerivationFunctionCtx {
  public:
    KeyDerivationFunctionCtx(whClientContext* client, CryptoAlgId algId,
                             KeyId ikmKeyId);

    /* Derives outBits bits of key material and exports to the caller. */
    Result<ByteVector> Derive(std::size_t outBytes, const std::uint8_t* salt,
                              std::size_t saltLen, const std::uint8_t* info,
                              std::size_t infoLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            ikmKeyId_;
};

/* --- Key storage ---------------------------------------------------- */
class KeyStorageProvider {
  public:
    KeyStorageProvider(whClientContext* client) : client_(client) {}

    /* Cache key material under the given whKeyId, with USAGE_ANY flags
     * so the server accepts the key for any subsequent operation. */
    Result<void> SaveKey(KeyId keyId, const std::uint8_t* key, std::size_t len);

    Result<ByteVector> LoadKey(KeyId keyId);

    /* Commit (persist to NVM) and erase (remove from cache). */
    Result<void> Commit(KeyId keyId);
    Result<void> Erase(KeyId keyId);

  private:
    whClientContext* client_;
};

/* --- Provider --------------------------------------------------------- */
class WolfhsmCryptoProvider {
  public:
    /* Construct over a configured wolfHSM client context. The provider
     * does not take ownership; the caller is responsible for the client
     * lifetime. */
    WolfhsmCryptoProvider(whClientContext* client) : client_(client) {}

    std::unique_ptr<RandomGeneratorCtx> CreateRandomGeneratorCtx();
    std::unique_ptr<HashFunctionCtx> CreateHashFunctionCtx(CryptoAlgId algId);
    std::unique_ptr<SymmetricBlockCipherCtx>
    CreateSymmetricBlockCipherCtx(CryptoAlgId algId, KeyId keyId,
                                  std::uint32_t keyBits);
    std::unique_ptr<AuthCipherCtx>       CreateAuthCipherCtx(KeyId         keyId,
                                                             std::uint32_t keyBits);
    std::unique_ptr<MessageAuthnCodeCtx> CreateMessageAuthnCodeCtx(KeyId keyId);
    std::unique_ptr<SignerPrivateCtx> CreateSignerPrivateCtx(CryptoAlgId algId,
                                                             KeyId       keyId);
    std::unique_ptr<VerifierPublicCtx>
    CreateVerifierPublicCtx(CryptoAlgId algId, KeyId keyId);
    std::unique_ptr<KeyAgreementPrivateCtx>
    CreateKeyAgreementPrivateCtx(CryptoAlgId algId, KeyId privateKeyId);
    std::unique_ptr<KeyDerivationFunctionCtx>
    CreateKeyDerivationFunctionCtx(CryptoAlgId algId, KeyId ikmKeyId);
    std::unique_ptr<KeyStorageProvider> CreateKeyStorageProvider();

    /* Provider identification used by manifest registration. */
    static constexpr const char* ProviderUuid()
    {
        return "f4a3d6f2-91b5-4d1e-9b1a-67c4a8e0d3b5";
    }
    static constexpr std::uint32_t MajorVersion()
    {
        return 1u;
    }
    static constexpr std::uint32_t MinorVersion()
    {
        return 0u;
    }

  private:
    whClientContext* client_;
};

/* CryptoAlgId values supported by this provider. Matches values used in
 * the execution manifest. */
namespace AlgId {
constexpr CryptoAlgId kSha256      = 0x0001'0006ull;
constexpr CryptoAlgId kSha384      = 0x0001'0007ull;
constexpr CryptoAlgId kSha512      = 0x0001'0008ull;
constexpr CryptoAlgId kAesEcb      = 0x0021'0001ull;
constexpr CryptoAlgId kAesCbc      = 0x0021'0002ull;
constexpr CryptoAlgId kAesCtr      = 0x0021'0006ull;
constexpr CryptoAlgId kAesGcm      = 0x0021'0009ull;
constexpr CryptoAlgId kCmacAes     = 0x0034'0000ull;
constexpr CryptoAlgId kEcdsaP256   = 0x0049'0040ull;
constexpr CryptoAlgId kEd25519     = 0x004D'0000ull;
constexpr CryptoAlgId kRsaPkcs1v15 = 0x0047'0033ull;
constexpr CryptoAlgId kEcdhP256    = 0x0049'0041ull;
constexpr CryptoAlgId kX25519      = 0x004E'0000ull;
constexpr CryptoAlgId kHkdfSha256  = 0x0071'0006ull;
constexpr CryptoAlgId kCmacKdf     = 0x0072'0000ull;
constexpr CryptoAlgId kRng         = 0x8000'0000ull;
} /* namespace AlgId */

} /* namespace ara_crypto */
} /* namespace wolfhsm */

#endif /* WOLFHSM_ARA_CRYPTO_CRYPTO_PROVIDER_HPP_ */
