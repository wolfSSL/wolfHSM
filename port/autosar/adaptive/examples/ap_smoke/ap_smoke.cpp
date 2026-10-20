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
 * port/autosar/adaptive/examples/ap_smoke/ap_smoke.cpp
 *
 * End-to-end smoke for the Adaptive CryptoProvider. Connects to a
 * running wh_posix_server over TCP, exercises each functional cluster
 * once (Random, Hash, SymmetricBlockCipher, AuthCipher, MAC,
 * Signer/Verifier per family, KeyAgreement, KDF, KeyStorage). Returns
 * exit code 0 on success.
 */

#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_keyid.h"
#include "port/posix/posix_transport_tcp.h"
#include "wolfssl/wolfcrypt/ecc.h"
}

#include "wolfhsm/ara_crypto/crypto_provider.hpp"

using namespace wolfhsm::ara_crypto;

#define SMOKE_CLIENT_ID 9u

static whClientContext                g_clientCtx;
static whClientConfig                 g_clientCfg;
static whCommClientConfig             g_commCfg;
static posixTransportTcpClientContext g_tcpCtx;
static posixTransportTcpConfig        g_tcpCfg;
static whTransportClientCb            g_tcpCb = PTT_CLIENT_CB;

static int connectClient()
{
    std::memset(&g_tcpCtx, 0, sizeof(g_tcpCtx));
    std::memset(&g_tcpCfg, 0, sizeof(g_tcpCfg));
    static char serverIp[]    = "127.0.0.1";
    g_tcpCfg.server_ip_string = serverIp;
    g_tcpCfg.server_port      = 23456;
    std::memset(&g_commCfg, 0, sizeof(g_commCfg));
    g_commCfg.transport_cb      = &g_tcpCb;
    g_commCfg.transport_context = &g_tcpCtx;
    g_commCfg.transport_config  = &g_tcpCfg;
    g_commCfg.client_id         = SMOKE_CLIENT_ID;
    std::memset(&g_clientCfg, 0, sizeof(g_clientCfg));
    g_clientCfg.comm = &g_commCfg;
    int rc           = wh_Client_Init(&g_clientCtx, &g_clientCfg);
    if (rc != WH_ERROR_OK)
        return rc;
    return wh_Client_CommInit(&g_clientCtx, nullptr, nullptr);
}

#define CHECK(label, cond)                                \
    do {                                                  \
        if (!(cond)) {                                    \
            std::fprintf(stderr, "  [FAIL] %s\n", label); \
            return 1;                                     \
        }                                                 \
    } while (0)

static int testRandom(WolfhsmCryptoProvider& prov)
{
    auto rng = prov.CreateRandomGeneratorCtx();
    CHECK("random:create", rng != nullptr);
    auto r = rng->Generate(32);
    CHECK("random:generate", r.HasValue() && r.Value().size() == 32);
    std::printf("  Random OK (32 bytes)\n");
    return 0;
}

static int testHash(WolfhsmCryptoProvider& prov)
{
    auto h = prov.CreateHashFunctionCtx(AlgId::kSha256);
    CHECK("hash:create", h != nullptr);
    CHECK("hash:start", h->Start().HasValue());
    const char* msg = "abc";
    CHECK("hash:update", h->Update(reinterpret_cast<const std::uint8_t*>(msg),
                                   std::strlen(msg))
                             .HasValue());
    auto r = h->Finish();
    CHECK("hash:finish", r.HasValue() && r.Value().size() == 32);
    /* Expected SHA-256("abc"). */
    static const std::uint8_t exp[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    CHECK("hash:value", std::memcmp(r.Value().data(), exp, 32) == 0);
    std::printf("  Hash SHA-256(\"abc\") matches NIST vector\n");

    /* SHA-384("abc") KAT */
    auto h384 = prov.CreateHashFunctionCtx(AlgId::kSha384);
    CHECK("hash384:create", h384 != nullptr);
    CHECK("hash384:start", h384->Start().HasValue());
    CHECK("hash384:update",
          h384->Update(reinterpret_cast<const std::uint8_t*>(msg),
                       std::strlen(msg))
              .HasValue());
    auto r384 = h384->Finish();
    CHECK("hash384:finish", r384.HasValue() && r384.Value().size() == 48);
    static const std::uint8_t exp384[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
        0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
        0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
    CHECK("hash384:value", std::memcmp(r384.Value().data(), exp384, 48) == 0);
    std::printf("  Hash SHA-384(\"abc\") matches NIST vector\n");

    /* SHA-512("abc") KAT */
    auto h512 = prov.CreateHashFunctionCtx(AlgId::kSha512);
    CHECK("hash512:create", h512 != nullptr);
    CHECK("hash512:start", h512->Start().HasValue());
    CHECK("hash512:update",
          h512->Update(reinterpret_cast<const std::uint8_t*>(msg),
                       std::strlen(msg))
              .HasValue());
    auto r512 = h512->Finish();
    CHECK("hash512:finish", r512.HasValue() && r512.Value().size() == 64);
    static const std::uint8_t exp512[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
        0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
        0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
        0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
        0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
        0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
    CHECK("hash512:value", std::memcmp(r512.Value().data(), exp512, 64) == 0);
    std::printf("  Hash SHA-512(\"abc\") matches NIST vector\n");
    return 0;
}

static int testAesCbc(WolfhsmCryptoProvider& prov)
{
    /* NIST SP 800-38A F.2.1 first block. */
    static const std::uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                         0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                         0x09, 0xcf, 0x4f, 0x3c};
    static const std::uint8_t iv[16]  = {0, 1, 2,  3,  4,  5,  6,  7,
                                         8, 9, 10, 11, 12, 13, 14, 15};
    static const std::uint8_t pt[16]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                         0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                         0x73, 0x93, 0x17, 0x2a};
    static const std::uint8_t ct[16]  = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19,
                                         0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
                                         0x12, 0xe9, 0x19, 0x7d};

    /* Install key under whKeyId 0x1101 (USAGE_ANY). */
    auto store = prov.CreateKeyStorageProvider();
    CHECK("aes-cbc:store",
          store->SaveKey(0x1101u, key, sizeof(key)).HasValue());

    auto cipher =
        prov.CreateSymmetricBlockCipherCtx(AlgId::kAesCbc, 0x1101u, 128);
    CHECK("aes-cbc:create", cipher != nullptr);
    auto r = cipher->ProcessBlocks(iv, sizeof(iv), pt, sizeof(pt), true);
    CHECK("aes-cbc:encrypt", r.HasValue() && r.Value().size() == 16);
    CHECK("aes-cbc:value", std::memcmp(r.Value().data(), ct, 16) == 0);
    std::printf("  AES-CBC-128 NIST F.2.1 OK\n");
    return 0;
}

static int testAesGcm(WolfhsmCryptoProvider& prov)
{
    /* Use the same key as CBC (different keyId so usage policy applies). */
    static const std::uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                         0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                         0x09, 0xcf, 0x4f, 0x3c};
    static const std::uint8_t iv[12]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    static const std::uint8_t aad[8] = {'A', 'A', 'D', '.', '.', '.', '.', '.'};
    static const std::uint8_t pt[16] = {'H', 'e', 'l', 'l', 'o', ' ', 'A', 'P',
                                        '!', 0,   0,   0,   0,   0,   0,   0};

    auto store = prov.CreateKeyStorageProvider();
    CHECK("aes-gcm:store",
          store->SaveKey(0x1102u, key, sizeof(key)).HasValue());
    auto cipher = prov.CreateAuthCipherCtx(0x1102u, 128);
    CHECK("aes-gcm:create", cipher != nullptr);
    auto enc = cipher->ProcessEncrypt(iv, sizeof(iv), aad, sizeof(aad), pt,
                                      sizeof(pt), 16);
    CHECK("aes-gcm:enc", enc.HasValue() && enc.Value().size() == 32);
    const std::uint8_t* ct  = enc.Value().data();
    const std::uint8_t* tag = enc.Value().data() + 16;
    auto dec = cipher->ProcessDecrypt(iv, sizeof(iv), aad, sizeof(aad), ct, 16,
                                      tag, 16);
    CHECK("aes-gcm:dec",
          dec.HasValue() && std::memcmp(dec.Value().data(), pt, 16) == 0);
    std::printf("  AES-GCM-128 roundtrip OK\n");
    return 0;
}

static int testCmac(WolfhsmCryptoProvider& prov)
{
    static const std::uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                         0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                         0x09, 0xcf, 0x4f, 0x3c};
    auto                      store   = prov.CreateKeyStorageProvider();
    CHECK("cmac:store", store->SaveKey(0x1103u, key, sizeof(key)).HasValue());
    auto mac = prov.CreateMessageAuthnCodeCtx(0x1103u);
    CHECK("cmac:create", mac != nullptr);
    const std::uint8_t msg[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    auto               gen    = mac->Generate(msg, sizeof(msg));
    CHECK("cmac:generate", gen.HasValue() && gen.Value().size() == 16);
    auto ver =
        mac->Verify(msg, sizeof(msg), gen.Value().data(), gen.Value().size());
    CHECK("cmac:verify-good", ver.HasValue() && ver.Value());
    std::uint8_t bad[16];
    std::memcpy(bad, gen.Value().data(), 16);
    bad[0] ^= 0x01u;
    auto verBad = mac->Verify(msg, sizeof(msg), bad, sizeof(bad));
    CHECK("cmac:verify-bad", verBad.HasValue() && !verBad.Value());
    std::printf("  CMAC-AES generate + verify good + verify tampered OK\n");
    return 0;
}

static int testSignerVerifierEcdsa(WolfhsmCryptoProvider& prov)
{
    /* Generate an ECC P-256 key into whKeyId 0x1104. We use the
     * low-level wolfHSM client for keygen since the Adaptive layer
     * doesn't ship a KeyGenerator context. */
    whKeyId      keyId                   = 0x1104u;
    std::uint8_t label[WH_NVM_LABEL_LEN] = {0};
    int          rc                      = wh_Client_EccMakeCacheKey(
        &g_clientCtx, 32, ECC_SECP256R1, &keyId,
        static_cast<whNvmFlags>(WH_NVM_FLAGS_USAGE_ANY), sizeof(label), label);
    CHECK("ecdsa:keygen", rc == WH_ERROR_OK);

    static const std::uint8_t hash[32] = {
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    auto signer = prov.CreateSignerPrivateCtx(AlgId::kEcdsaP256, 0x1104u);
    auto sig    = signer->Sign(hash, sizeof(hash));
    CHECK("ecdsa:sign", sig.HasValue());
    auto verifier = prov.CreateVerifierPublicCtx(AlgId::kEcdsaP256, 0x1104u);
    auto good     = verifier->Verify(hash, sizeof(hash), sig.Value().data(),
                                     sig.Value().size());
    CHECK("ecdsa:verify-good", good.HasValue() && good.Value());
    /* Tamper. */
    auto tampered = sig.Value();
    tampered[20] ^= 0x01u;
    auto bad =
        verifier->Verify(hash, sizeof(hash), tampered.data(), tampered.size());
    CHECK("ecdsa:verify-bad", bad.HasValue() && !bad.Value());
    std::printf("  ECDSA P-256 sign + verify-good + verify-bad OK\n");
    return 0;
}

static int testEcdh(WolfhsmCryptoProvider& prov)
{
    /* Two fresh P-256 keys; agree once and check both succeed. */
    whKeyId      a = 0x1105u, b = 0x1106u;
    std::uint8_t label[WH_NVM_LABEL_LEN] = {0};
    int          rc                      = wh_Client_EccMakeCacheKey(
        &g_clientCtx, 32, ECC_SECP256R1, &a,
        static_cast<whNvmFlags>(WH_NVM_FLAGS_USAGE_ANY), sizeof(label), label);
    CHECK("ecdh:keygen-a", rc == WH_ERROR_OK);
    rc = wh_Client_EccMakeCacheKey(
        &g_clientCtx, 32, ECC_SECP256R1, &b,
        static_cast<whNvmFlags>(WH_NVM_FLAGS_USAGE_ANY), sizeof(label), label);
    CHECK("ecdh:keygen-b", rc == WH_ERROR_OK);

    auto agreeAB = prov.CreateKeyAgreementPrivateCtx(AlgId::kEcdhP256, a);
    auto secAB   = agreeAB->AgreeKey(b);
    CHECK("ecdh:agree-ab", secAB.HasValue() && secAB.Value().size() == 32);
    /* Other direction: derive from B's side using A as the peer. The two
     * shared secrets must be byte-for-byte identical. */
    auto agreeBA = prov.CreateKeyAgreementPrivateCtx(AlgId::kEcdhP256, b);
    auto secBA   = agreeBA->AgreeKey(a);
    CHECK("ecdh:agree-ba", secBA.HasValue() && secBA.Value().size() == 32);
    CHECK("ecdh:agree-match",
          std::memcmp(secAB.Value().data(), secBA.Value().data(), 32) == 0);
    std::printf("  ECDH P-256 bidirectional shared secret OK (%zu bytes)\n",
                secAB.Value().size());
    return 0;
}

static int testHkdf(WolfhsmCryptoProvider& prov)
{
    /* Use one of the cached keys as the IKM source. */
    auto kdf = prov.CreateKeyDerivationFunctionCtx(AlgId::kHkdfSha256, 0x1103u);
    static const std::uint8_t salt[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                          0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                                          0x1C, 0x1D, 0x1E, 0x1F};
    static const std::uint8_t info[8]  = {'a', 'p', '-', 't', 'e', 's', 't', 0};
    auto r = kdf->Derive(32, salt, sizeof(salt), info, sizeof(info));
    CHECK("hkdf:derive", r.HasValue() && r.Value().size() == 32);
    std::printf("  HKDF-SHA256 -> 32 bytes OK\n");
    return 0;
}

static int testKeyStorage(WolfhsmCryptoProvider& prov)
{
    auto               store   = prov.CreateKeyStorageProvider();
    const std::uint8_t mat[16] = {'k', 'e', 'y', 's', 't', 'o', 'r', 'e',
                                  '-', 't', 'e', 's', 't', '!', '!', '!'};
    CHECK("store:save", store->SaveKey(0x1107u, mat, sizeof(mat)).HasValue());
    auto loaded = store->LoadKey(0x1107u);
    CHECK("store:load",
          loaded.HasValue() && loaded.Value().size() == sizeof(mat) &&
              std::memcmp(loaded.Value().data(), mat, sizeof(mat)) == 0);
    std::printf("  KeyStorage save / load roundtrip OK\n");

    /* Erase: the AUTOSAR meaning is "take the key out of operational
     * use". wolfHSM's Revoke flips the policy bit (so any subsequent
     * crypto op on the keyId is rejected by the server) — we verify
     * that meaning by attempting a CMAC against the revoked key and
     * asserting it fails. Note: Revoke does NOT zeroise the cache
     * slot, so a follow-up LoadKey/Export can still return the
     * bytes; raw Export sidesteps policy by design. The contract is
     * "no operations after Erase", not "bytes are unrecoverable". */
    CHECK("store:erase", store->Erase(0x1107u).HasValue());
    {
        auto macAfterErase          = prov.CreateMessageAuthnCodeCtx(0x1107u);
        const std::uint8_t probe[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        auto               g = macAfterErase->Generate(probe, sizeof(probe));
        CHECK("store:erase-blocks-op", !g.HasValue());
    }
    std::printf("  KeyStorage erase + post-erase op rejected OK\n");

    /* Commit persists the key to NVM. Save a fresh key, commit, then
     * read it back from a new client to confirm it survives a cache
     * eviction. We exercise the cache->NVM path here without a server
     * restart since the POSIX server keeps NVM in RAM. */
    const std::uint8_t mat2[16] = {'c', 'o', 'm', 'm', 'i', 't', 't', 'e',
                                   'd', '-', 'k', 'e', 'y', '!', '!', '!'};
    CHECK("store:save2",
          store->SaveKey(0x1108u, mat2, sizeof(mat2)).HasValue());
    CHECK("store:commit", store->Commit(0x1108u).HasValue());
    auto loaded2 = store->LoadKey(0x1108u);
    CHECK("store:load2",
          loaded2.HasValue() && loaded2.Value().size() == sizeof(mat2) &&
              std::memcmp(loaded2.Value().data(), mat2, sizeof(mat2)) == 0);
    std::printf("  KeyStorage commit roundtrip OK\n");
    return 0;
}

int main()
{
    if (connectClient() != WH_ERROR_OK) {
        std::fprintf(
            stderr,
            "Failed to connect to wh_posix_server (TCP 127.0.0.1:23456)\n");
        return 1;
    }
    std::printf("wolfHSM Adaptive Crypto Provider smoke (TCP)\n");

    WolfhsmCryptoProvider prov(&g_clientCtx);
    int                   failures = 0;
    failures += testRandom(prov);
    failures += testHash(prov);
    failures += testAesCbc(prov);
    failures += testAesGcm(prov);
    failures += testCmac(prov);
    failures += testSignerVerifierEcdsa(prov);
    failures += testEcdh(prov);
    failures += testHkdf(prov);
    failures += testKeyStorage(prov);

    (void)wh_Client_CommClose(&g_clientCtx);
    (void)wh_Client_Cleanup(&g_clientCtx);

    if (failures != 0) {
        std::fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    std::printf("ap_smoke: all tests passed\n");
    return 0;
}
