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
 * WolfhsmCryptoProvider: an ara::crypto::cryp::CryptoProvider-shaped API over
 * wolfHSM that integrators forward to from their own CryptoProvider.
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
    /* AEAD tag mismatch, ara::crypto::SecurityErrc::kAuthTagFail. */
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

class RandomGeneratorCtx {
  public:
    RandomGeneratorCtx(whClientContext* client) : client_(client) {}
    Result<ByteVector> Generate(std::size_t count);

  private:
    whClientContext* client_;
};

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
    /* Opaque wc_Sha256/384/512 state, so this header needs no wolfCrypt. */
    alignas(16) std::uint8_t state_[512];
};

using KeyId = std::uint16_t;

class SymmetricBlockCipherCtx {
  public:
    SymmetricBlockCipherCtx(whClientContext* client, CryptoAlgId algId,
                            KeyId keyId, std::uint32_t keyBits);
    ~SymmetricBlockCipherCtx();

    /* inLen is a multiple of 16; CBC and CTR take a 16-byte IV, ECB none. */
    Result<ByteVector> ProcessBlocks(const std::uint8_t* iv, std::size_t ivLen,
                                     const std::uint8_t* in, std::size_t inLen,
                                     bool encrypt);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
    std::uint32_t    keyBits_;
};

class AuthCipherCtx {
  public:
    AuthCipherCtx(whClientContext* client, KeyId keyId, std::uint32_t keyBits);
    ~AuthCipherCtx();

    /* Tags are kMinTagLen to 16 bytes; shorter gives kInvalidInputSize. */
    static constexpr std::size_t kMinTagLen = 12u;

    /* Returns ciphertext || tag. */
    Result<ByteVector> ProcessEncrypt(const std::uint8_t* iv, std::size_t ivLen,
                                      const std::uint8_t* aad,
                                      std::size_t         aadLen,
                                      const std::uint8_t* pt, std::size_t ptLen,
                                      std::size_t tagLen);
    /* Returns kAuthTagMismatch when the tag does not verify. */
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

class MessageAuthnCodeCtx {
  public:
    MessageAuthnCodeCtx(whClientContext* client, KeyId keyId);

    static constexpr std::size_t kMacLen    = 16u;
    static constexpr std::size_t kMinMacLen = 8u;

    /* Returns the full kMacLen-byte AES-CMAC. */
    Result<ByteVector> Generate(const std::uint8_t* in, std::size_t inLen);
    /* Compares the leading macLen bytes; macLen must be 8 to 16. */
    Result<bool> Verify(const std::uint8_t* in, std::size_t inLen,
                        const std::uint8_t* mac, std::size_t macLen);

  private:
    SecurityErrc ComputeMac(const std::uint8_t* in, std::size_t inLen,
                            std::uint8_t (&mac)[kMacLen]);

    whClientContext* client_;
    KeyId            keyId_;
};

class SignerPrivateCtx {
  public:
    SignerPrivateCtx(whClientContext* client, CryptoAlgId algId, KeyId keyId);

    /* in is the message for Ed25519 and ML-DSA, else a 32/48/64-byte digest. */
    Result<ByteVector> Sign(const std::uint8_t* in, std::size_t inLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
};

class VerifierPublicCtx {
  public:
    VerifierPublicCtx(whClientContext* client, CryptoAlgId algId, KeyId keyId);

    /* false for a bad signature; an error only if the call itself failed. */
    Result<bool> Verify(const std::uint8_t* in, std::size_t inLen,
                        const std::uint8_t* sig, std::size_t sigLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            keyId_;
};

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

class KeyDerivationFunctionCtx {
  public:
    KeyDerivationFunctionCtx(whClientContext* client, CryptoAlgId algId,
                             KeyId ikmKeyId);

    /* Derives outBytes bytes of key material and exports to the caller. */
    Result<ByteVector> Derive(std::size_t outBytes, const std::uint8_t* salt,
                              std::size_t saltLen, const std::uint8_t* info,
                              std::size_t infoLen);

  private:
    whClientContext* client_;
    CryptoAlgId      alg_;
    KeyId            ikmKeyId_;
};

class KeyStorageProvider {
  public:
    KeyStorageProvider(whClientContext* client) : client_(client) {}

    /* Caches key with WH_NVM_FLAGS_USAGE_ANY; non-exportable unless asked. */
    Result<void> SaveKey(KeyId keyId, const std::uint8_t* key, std::size_t len,
                         bool exportable = false);

    /* Returns the plaintext key; kUnknownIdentifier on any failure. */
    Result<ByteVector> LoadKey(KeyId keyId);

    /* Persists the cached key to NVM. */
    Result<void> Commit(KeyId keyId);
    /* Removes the key from cache and NVM. If the server refuses, revokes it
     * instead and returns kAccessViolation; the key bytes stay stored. */
    Result<void> Erase(KeyId keyId);

  private:
    whClientContext* client_;
};

/* Not thread-safe: a wolfHSM client handles one request at a time. */
class WolfhsmCryptoProvider {
  public:
    /* Does not own client; the contexts it creates keep a pointer to it. */
    WolfhsmCryptoProvider(whClientContext* client) : client_(client) {}

    /* Create* returns nullptr for an unsupported algId or a keyId that is 0
     * or carries flag bits (global, wrapped, hardware). */
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

/* CryptoAlgId values, matching the execution manifest. */
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
constexpr CryptoAlgId kRsaPss      = 0x0047'0034ull;
constexpr CryptoAlgId kMlDsa44     = 0x0060'0002ull;
constexpr CryptoAlgId kMlDsa65     = 0x0060'0003ull;
constexpr CryptoAlgId kMlDsa87     = 0x0060'0005ull;
constexpr CryptoAlgId kEcdhP256    = 0x0049'0041ull;
constexpr CryptoAlgId kX25519      = 0x004E'0000ull;
constexpr CryptoAlgId kHkdfSha256  = 0x0071'0006ull;
constexpr CryptoAlgId kCmacKdf     = 0x0072'0000ull;
constexpr CryptoAlgId kRng         = 0x8000'0000ull;
} /* namespace AlgId */

} /* namespace ara_crypto */
} /* namespace wolfhsm */

#endif /* WOLFHSM_ARA_CRYPTO_CRYPTO_PROVIDER_HPP_ */
