#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"


#if !defined(WC_NO_RNG)
#include "wolfssl/wolfcrypt/random.h"
#endif

#if !defined(NO_RSA)
#include "wolfssl/wolfcrypt/rsa.h"
#endif

#if defined(HAVE_ECC)
#include "wolfssl/wolfcrypt/ecc.h"
#endif

#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif

#if !defined(NO_AES)
#include "wolfssl/wolfcrypt/aes.h"
#endif

#if defined(WOLFSSL_CMAC)
#include "wolfssl/wolfcrypt/cmac.h"
#endif

#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)
#include "wolfssl/wolfcrypt/kdf.h"
#endif

#include "wh_demo_client_crypto.h"

#if !defined(NO_RSA)

/*
 * Generates an RSA key pair on the HSM and uses it to encrypt and decrypt a
 * plaintext string. The key is ephemeral, meaning key material is generated
 * on the HSM but stored locally on the client. Keys are imported and cached
 * when requested for use, then evicted from the cache immediately after use.
 */
int wh_DemoClient_CryptoRsa(whClientContext* clientContext)
{
    (void)clientContext;

    int        ret           = 0;
    int        encSz         = 0;
    const char plainString[] = "The quick brown fox jumps over the lazy dog.";
    byte       plainText[256];
    byte       cipherText[256];
    RsaKey     rsa[1];
    WC_RNG     rng[1];

    /* set the plainText to the test string */
    strcpy((char*)plainText, plainString);

    /* initialize rng to make the rsa key */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* make the rsa key */
    ret = wc_MakeRsaKey(rsa, 2048, 65537, rng);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_MakeRsaKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    encSz = ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString),
                                      cipherText, sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, encSz, plainText, sizeof(plainText),
                               rsa);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        WOLFHSM_CFG_PRINTF("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        WOLFHSM_CFG_PRINTF("RSA Decryption matches original plaintext\n");

exit:
    (void)wc_FreeRng(rng);
    (void)wc_FreeRsaKey(rsa);
    return ret;
}

/*
 * Imports an RSA key from a DER file, and caches it on the HSM. The key is
 * then used to encrypt and decrypt a plaintext string. The key is referred to
 * by keyId on the client and not resident in the local wolfCrypt struct
 */
int wh_DemoClient_CryptoRsaImport(whClientContext* clientContext)
{
    int        ret   = 0;
    int        encSz = 0;
    int        keyFd;
    int        keySz;
    int        needEvict     = 0;
    whKeyId    keyId         = WH_KEYID_ERASED;
    char       keyFile[]     = "../../demo/certs/rsa-2048-key.der";
    const char plainString[] = "The quick brown fox jumps over the lazy dog.";
    char       keyLabel[]    = "baby's first key";
    uint8_t    keyBuf[2048];
    byte       plainText[256];
    byte       cipherText[256];
    RsaKey     rsa[1];
    WC_RNG     rng[1];

    /* set the plainText to the test string */
    strcpy((char*)plainText, plainString);

    /* initialize rng to encrypt with the rsa key */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* open the RSA key */
    ret = keyFd = open(keyFile, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyFile, ret);
        goto exit;
    }

    /* read the RSA key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to read %s %d\n", keyFile, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        (uint8_t*)keyLabel, strlen(keyLabel), keyBuf, keySz, &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    needEvict = 1;

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_RsaSetKeyId(rsa, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    encSz = ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString),
                                      cipherText, sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, encSz, plainText, sizeof(plainText),
                               rsa);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        WOLFHSM_CFG_PRINTF("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        WOLFHSM_CFG_PRINTF("RSA Decryption matches original plaintext with imported key\n");
exit:
    (void)wc_FreeRng(rng);
    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}
#endif

#ifdef HAVE_CURVE25519

/*
 * Generate two curve25519 key pairs on the HSM and use them two generate two
 * matching shared secrets. This example uses ephemeral keys, meaning key
 * material is generated on the HSM but stored locally on the client. Keys are
 * imported and cached when requested for use, then evicted from the cache
 * immediately after use.
 */
int wh_DemoClient_CryptoCurve25519(whClientContext* clientContext)
{
    (void)clientContext;

    int            ret = 0;
    word32         outLen;
    uint8_t        sharedOne[CURVE25519_KEYSIZE];
    uint8_t        sharedTwo[CURVE25519_KEYSIZE];
    curve25519_key curve25519PrivateKey[1];
    /* public from the first shared secret's perspective, actually private */
    curve25519_key curve25519PublicKey[1];
    WC_RNG         rng[1];

    /* initialize rng to make the curve25519 keys */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the keys */
    ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* generate the keys on the HSM */
    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    /* generate shared secrets from both perspectives */
    outLen = sizeof(sharedOne);
    ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey,
                                      sharedOne, (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    outLen = sizeof(sharedTwo);
    ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey,
                                      sharedTwo, (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        WOLFHSM_CFG_PRINTF("CURVE25519 shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        WOLFHSM_CFG_PRINTF("CURVE25519 shared secrets match\n");
    }
exit:
    /* free the key structs */
    wc_curve25519_free(curve25519PrivateKey);
    wc_curve25519_free(curve25519PublicKey);
    (void)wc_FreeRng(rng);
    return ret;
}


/*
 * Imports two curve25519 key pairs from DER files, and caches them on the HSM.
 * The keys are then used to generate two matching shared secrets. Key material
 * is not resident on in the wolfCrypt structure used by the client, and are
 * referred to by keyId.
 */
int wh_DemoClient_CryptoCurve25519Import(whClientContext* clientContext)
{
    int     ret = 0;
    int     keyFd;
    int     keySz;
    word32  outLen;
    whKeyId keyIdBob           = WH_KEYID_ERASED;
    whKeyId keyIdAlice         = WH_KEYID_ERASED;
    char    keyPairFileBob[]   = "../../demo/certs/curve25519_keyBob.der";
    char    keyPairFileAlice[] = "../../demo/certs/curve25519_keyAlice.der";
    char    keyLabel[]         = "baby's first key";
    uint8_t keyBuf[256];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];

    curve25519_key aliceKey[1];
    curve25519_key bobKey[1];

    /* open Bob's key pair file and read it into a local buffer */
    ret = keyFd = open(keyPairFileBob, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyPairFileBob, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        goto exit;
    }
    close(keyFd);


    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, WH_NVM_FLAGS_USAGE_DERIVE,
                             (uint8_t*)keyLabel, strlen(keyLabel), keyBuf,
                             keySz, &keyIdBob);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the wolfCrypt struct to use the cached key */
    ret = wc_curve25519_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_Curve25519SetKeyId(bobKey, keyIdBob);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_Curve25519SetKeyId %d\n", ret);
        goto exit;
    }


    /* open Alice's key pair file and read it into a local buffer */
    ret = keyFd = open(keyPairFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyPairFileAlice, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to read %s %d\n", keyPairFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, WH_NVM_FLAGS_USAGE_DERIVE,
                             (uint8_t*)keyLabel, strlen(keyLabel), keyBuf,
                             keySz, &keyIdAlice);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* Initialize the wolfCrypt struct to use the cached key */
    ret = wc_curve25519_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_Curve25519SetKeyId(aliceKey, keyIdAlice);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_Curve25519SetKeyId %d\n", ret);
        goto exit;
    }

    /* Generate a shared secret from Bob's perspective */
    outLen = sizeof(sharedOne);
    ret    = wc_curve25519_shared_secret(bobKey, aliceKey, sharedOne,
                                         (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Generate a shared secret from Alice's perspective */
    outLen = sizeof(sharedTwo);
    ret    = wc_curve25519_shared_secret(aliceKey, bobKey, sharedTwo,
                                         (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        WOLFHSM_CFG_PRINTF("CURVE25519 import: shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        WOLFHSM_CFG_PRINTF("CURVE25519 import: shared secrets match\n");
    }

exit:
    wc_curve25519_free(aliceKey);
    wc_curve25519_free(bobKey);

    /* (Optional) Evict the keys from the HSM cache */
    if (keyIdBob != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdBob);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    if (keyIdAlice != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdAlice);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_ECC)

/*
 * Generate two ECC key pairs on the HSM and use them to generate two matching
 * shared secrets. This example uses ephemeral keys, meaning key material is
 * generated on the HSM but stored locally on the client. Keys are imported and
 * cached when requested for use, then evicted from the cache immediately after
 * use.
 */
int wh_DemoClient_CryptoEcc(whClientContext* clientContext)
{
    (void)clientContext;

    int        ret = 0;
    int        res;
    word32     outLen;
    ecc_key    aliceKey[1];
    ecc_key    bobKey[1];
    WC_RNG     rng[1];
    byte       sharedOne[32];
    byte       sharedTwo[32];
    const char plainMessage[] = "The quick brown fox jumps over the lazy dog.";
    byte       message[sizeof(plainMessage)];
    byte       signature[128];

    /* Set the message to the test string */
    strcpy((char*)message, plainMessage);

    /* Initialize the rng to make the ecc keys */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* Initialize the local wolfCrypt structs */
    ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* Make the keys. These are generated on the HSM as ephemeral keys and sent
     * back to the client to store locally in the ecc_key structs */
    ret = wc_ecc_make_key(rng, 32, aliceKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }
    ret = wc_ecc_make_key(rng, 32, bobKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }

    /* Generate the shared secrets */
    outLen = 32;
    ret    = wc_ecc_shared_secret(aliceKey, bobKey, (byte*)sharedOne,
                                  (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_shared_secret(bobKey, aliceKey, (byte*)sharedTwo,
                               (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        WOLFHSM_CFG_PRINTF("ECC shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        WOLFHSM_CFG_PRINTF("ECC shared secrets match\n");
    }

    /* Sign the plaintext using the private component of Alice's key */
    outLen = sizeof(signature);
    ret    = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
                              (word32*)&outLen, rng, aliceKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Verify the hash using the public component of Alice's key. Note that
     * the keys generated for Alice and Bob contain both public and private
     * parts. In a real scenario, the signing and verifying would occur at
     * separate times, and only the public key would be distributed */
    ret = wc_ecc_verify_hash((void*)signature, outLen, (void*)message,
                             sizeof(message), &res, aliceKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        WOLFHSM_CFG_PRINTF("ECC sign/verify successful\n");
    else {
        WOLFHSM_CFG_PRINTF("ECC sign/verify failure\n");
        ret = -1;
        goto exit;
    }
exit:
    /* Free the keys */
    (void)wc_ecc_free(aliceKey);
    (void)wc_ecc_free(bobKey);
    /* Free the rng */
    (void)wc_FreeRng(rng);

    /* Since all keys are ephemeral, we don't need to evict them from the HSM
     * cache, as this happens automatically */
    return ret;
}


/*
 * Imports two ECC key pairs from DER files, and caches them on the HSM. The
 * keys are then used to generate two matching shared secrets. Key material is
 * not resident on in the wolfCrypt structure used by the client, and are
 * referred to by keyId.
 */
int wh_DemoClient_CryptoEccImport(whClientContext* clientContext)
{
    int        ret = 0;
    int        res;
    int        keyFd;
    int        keySz;
    whKeyId    keyIdAlice = WH_KEYID_ERASED;
    whKeyId    keyIdBob   = WH_KEYID_ERASED;
    word32     outLen;
    word32     sigLen;
    char       keyFileAlice[] = "../../demo/certs/alice-ecc256-key.der";
    char       keyFileBob[]   = "../../demo/certs/bob-ecc256-key.der";
    char       keyLabel[]     = "baby's first key";
    ecc_key    aliceKey[1];
    ecc_key    bobKey[1];
    WC_RNG     rng[1];
    byte       sharedOne[32];
    byte       sharedTwo[32];
    const char plainMessage[] = "The quick brown fox jumps over the lazy dog.";
    byte       message[sizeof(plainMessage)];
    byte       signature[128];
    uint8_t    keyBuf[256];

    /* Set the message to the test string */
    strcpy((char*)message, plainMessage);

    /* Initialize the rng for signature signing */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* Open Alice's keypair file and read it into a local buffer */
    ret = keyFd = open(keyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyFileAlice, ret);
        goto exit;
    }
    /* Read the first private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to read %s %d\n", keyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);
    /* Cache the key in the HSM, get HSM assigned keyId. From here on out, the
     * keys are stored in the HSM and can be referred to by keyId */
    ret = wh_Client_KeyCache(
        clientContext,
        WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_USAGE_SIGN |
            WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, strlen(keyLabel), keyBuf, keySz, &keyIdAlice);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* At this point we could also commit the key to NVM if required */

    /* Initialize the local wolfCrypt struct, and configure it to use the cached
     * key */
    ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_EccSetKeyId(aliceKey, keyIdAlice);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_EccSetKeyId %d\n", ret);
        goto exit;
    }
    /* Configure the local struct to expect the correct curve */
    ret = wc_ecc_set_curve(aliceKey, 32, -1);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }


    /* Now we can do the same procedure for Bob's keypair */

    /* Open Bob's keypair file and read it into a local buffer */
    ret = keyFd = open(keyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to open %s %d\n", keyFileBob, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        WOLFHSM_CFG_PRINTF("Failed to read %s %d\n", keyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);
    /* Cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(
        clientContext,
        WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_USAGE_SIGN |
            WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, strlen(keyLabel), keyBuf, keySz, &keyIdBob);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* Initialize the local wolfCrypt struct, and configure it to use the cached
     * key */
    ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_EccSetKeyId(bobKey, keyIdBob);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_EccSetKeyId %d\n", ret);
        goto exit;
    }
    /* Configure the local struct to expect the correct curve */
    ret = wc_ecc_set_curve(bobKey, 32, -1);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* Generate a 32-byte shared secret from Alice's perspective */
    outLen = 32;
    ret    = wc_ecc_shared_secret(aliceKey, bobKey, (byte*)sharedOne,
                                  (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Generate a 32-byte shared secret from Bob's perspective */
    outLen = 32;
    ret    = wc_ecc_shared_secret(bobKey, aliceKey, (byte*)sharedTwo,
                                  (word32*)&outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        WOLFHSM_CFG_PRINTF("ECC shared secrets don't match with imported keys\n");
        ret = -1;
        goto exit;
    }
    else {
        WOLFHSM_CFG_PRINTF("ECC shared secrets match with imported keys\n");
    }

    /* Sign the plaintext with Alice's private key */
    sigLen = sizeof(signature);
    ret    = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
                              (word32*)&sigLen, rng, aliceKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_sign_hash %d\n", ret);
        goto exit;
    }

    /* Verify the hash with Alice's public key. Note that the key cached on the
     * HSM contains both public and private parts. In a real scenario, the
     * signing and verifying would occur at separate times, and only the public
     * key would be distributed */
    ret = wc_ecc_verify_hash((void*)signature, sigLen, (void*)message,
                             sizeof(message), &res, aliceKey);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        WOLFHSM_CFG_PRINTF("ECC sign/verify successful with imported keys\n");
    else {
        WOLFHSM_CFG_PRINTF("ECC sign/verify failure with imported keys\n");
        ret = -1;
        goto exit;
    }
exit:
    /* Free the key structs */
    (void)wc_ecc_free(aliceKey);
    (void)wc_ecc_free(bobKey);
    /* Free the rng */
    (void)wc_FreeRng(rng);

    /* (Optional) evict the keys from the HSM cache */
    if (keyIdBob != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdBob);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    if (keyIdAlice != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdAlice);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    return ret;
}
#endif /* HAVE_ECC */

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
/*
 * Demonstrates AES CBC encryption and decryption using an ephemeral key.
 * Keys are imported and cached when requested for use, then evicted from the
 * cache immediately after use.
 */
int wh_DemoClient_CryptoAesCbc(whClientContext* clientContext)
{
    (void)clientContext;

    int  ret = 0;
    Aes  aes[1];
    byte key[]       = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesInit %d\n", ret);
    }
    else {
        /* set the key on the client side */
        ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_ENCRYPTION);
        if (ret != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wc_AesSetKey %d\n", ret);
        }
        if (ret == 0) {
            /* encrypt the plaintext */
            ret =
                wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
            if (ret != 0) {
                WOLFHSM_CFG_PRINTF("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }

        if (ret == 0) {
            /* Reset the IV so we can decrypt */
            ret = wc_AesSetIV(aes, NULL);
            if (ret != 0) {
                WOLFHSM_CFG_PRINTF("Failed to wc_AesSetIV %d\n", ret);
            }
        }

        if (ret == 0) {
            /* decrypt the ciphertext */
            ret =
                wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
            if (ret != 0) {
                WOLFHSM_CFG_PRINTF("Failed to wc_AesCbcDecrypt %d\n", ret);
            }
        }

        if (ret == 0) {
            /* compare final and plain */
            if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                WOLFHSM_CFG_PRINTF("AES CBC doesn't match after decryption\n");
                ret = -1;
            }
            else {
                WOLFHSM_CFG_PRINTF("AES CBC matches after decryption\n");
            }
        }

        /* Clear the context */
        (void)wc_AesFree(aes);
    }
    return ret;
}

/*
 * Demonstrates AES CBC encryption and decryption using an key cached on the
 * HSM. Once cached, the key is referred to by keyId on the client and not
 * resident in the local wolfCrypt struct.
 */
int wh_DemoClient_CryptoAesCbcImport(whClientContext* clientContext)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    byte    key[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char    keyLabel[] = "baby's first key";
    byte plainText[]   = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* Initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }

    /* Reset the IV so we can decrypt */
    ret = wc_AesSetIV(aes, NULL);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesSetIV %d\n", ret);
    }

    /* decrypt the ciphertext */
    ret = wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }

    /* compare final and plain */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        WOLFHSM_CFG_PRINTF("AES CBC doesn't match after decryption with imported key\n");
        ret = -1;
        goto exit;
    }
    WOLFHSM_CFG_PRINTF("AES CBC matches after decryption with imported key\n");
exit:
    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}
#endif /* !NO_AES && HAVE_AES_CBC*/

#if !defined(NO_AES) && defined(HAVE_AESGCM)
/*
 * Demonstrates AES GCM encryption and decryption using an ephemeral key.
 * Keys are imported and cached when requested for use, then evicted from the
 * cache immediately after use.
 */
int wh_DemoClient_CryptoAesGcm(whClientContext* clientContext)
{
    (void)clientContext;

    int  ret = 0;
    Aes  aes[1];
    byte key[]    = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte iv[]     = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authIn[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte authTag[16];
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* set the key and iv on the client side */
    ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare the finaltext to the plaintext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        WOLFHSM_CFG_PRINTF("AES GCM doesn't match after decryption\n");
        ret = -1;
        goto exit;
    }
    WOLFHSM_CFG_PRINTF("AES GCM matches after decryption\n");
exit:
    return ret;
}

/*
 * Demonstrates AES GCM encryption and decryption using an key cached on the
 * HSM. Once cached, the key is referred to by keyId on the client and not
 * resident in the local wolfCrypt struct.
 */
int wh_DemoClient_CryptoAesGcmImport(whClientContext* clientContext)
{
    int     ret       = 0;
    int     needEvict = 0;
    whKeyId keyId     = WH_KEYID_ERASED;
    Aes     aes[1];
    byte    key[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char    keyLabel[] = "baby's first key";
    byte    iv[]       = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte    authIn[]   = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte    authTag[16];
    byte plainText[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    byte cipherText[16];
    byte finalText[16];

    /* initialize the aes struct */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* set the iv */
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare plaintext and finaltext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        WOLFHSM_CFG_PRINTF("AES GCM doesn't match after decryption with imported keys\n");
        ret = -1;
        goto exit;
    }
    WOLFHSM_CFG_PRINTF("AES GCM matches after decryption with imported keys\n");
exit:
    wc_AesFree(aes);
    if (needEvict) {
        /* evict the key from the cache */
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    return ret;
}
#endif /* !NOAES && HAVE_ASEGCM */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
/*
 * Demonstrates CMAC verification using an ephemeral key.
 * Keys are imported and cached when requested for use, then evicted from the
 * cache immediately after use.
 */
int wh_DemoClient_CryptoCmac(whClientContext* clientContext)
{
    (void)clientContext;

    int    ret = 0;
    word32 outLen;
    Cmac   cmac[1];
    byte   key[]     = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char   message[] = "hash and verify me!";
    byte   tag[16];

    /* initialize the cmac struct and set the key */
    ret = wc_InitCmac_ex(cmac, key, sizeof(key), WC_CMAC_AES, NULL, NULL,
                         WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, strlen(message));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret    = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* verify the tag */
    ret =
        wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                            strlen(message), key, sizeof(key), NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("CMAC hash and verify failed %d\n", ret);
        goto exit;
    }

    WOLFHSM_CFG_PRINTF("CMAC hash and verify succeeded\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}

/*
 * Demonstrates CMAC verification using an key cached on the HSM. Once cached,
 * the key is referred to by keyId on the client and not resident in the local
 * wolfCrypt struct.
 */
int wh_DemoClient_CryptoCmacImport(whClientContext* clientContext)
{
    int     ret = 0;
    word32  outLen;
    whKeyId keyId = WH_KEYID_ERASED;
    Cmac    cmac[1];
    byte    key[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char    keyLabel[] = "baby's first key";
    char    message[]  = "hash and verify me!";
    byte    tag[16];

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, sizeof(message));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret    = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* Now let's verify the CMAC we just computed We should reinitialize the
     * CMAC struct and set the keyId again since we finalized the CMAC operation
     */

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM. This is required because the key is evicted
     * after the non-DMA CMAC operation is finalized */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* verify the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    ret = wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                              sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("CMAC hash and verify failed with imported key %d\n", ret);
        goto exit;
    }

    WOLFHSM_CFG_PRINTF("CMAC hash and verify succeeded with imported key\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}

/*
 * Demonstrates CMAC generation and verification with the one-shot API using an
 * key cached on the HSM. Once cached, the key is referred to by keyId on the
 * client and not resident in the local wolfCrypt struct.
 */
int wh_DemoClient_CryptoCmacOneshotImport(whClientContext* clientContext)
{
    int     ret = 0;
    word32  outLen;
    whKeyId keyId = WH_KEYID_ERASED;
    Cmac    cmac[1];
    byte    key[]      = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    char    keyLabel[] = "baby's first key";
    char    message[]  = "hash and verify me!";
    byte    tag[16];

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* generate the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    outLen = sizeof(tag);
    ret    = wc_AesCmacGenerate_ex(cmac, tag, &outLen, (byte*)message,
                                   sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_AesCmacGenerate %d\n", ret);
        goto exit;
    }

    /* Now, to verify, we need to re-initialize the CMAC struct and set the
     * keyId again. This is because the key is evicted after the non-DMA CMAC
     * operation is finalized */

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM again, cmac keys are evicted after non-DMA CMAC
     * operations are finalized is called */
    ret = wh_Client_KeyCache(
        clientContext, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY,
        (uint8_t*)keyLabel, sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* verify the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    ret = wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                              sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("CMAC hash and verify oneshot failed with imported key %d\n",
               ret);
        goto exit;
    }

    WOLFHSM_CFG_PRINTF("CMAC hash and verify oneshot succeeded with imported key\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES */

#if defined(HAVE_HKDF)
/*
 * Demonstrates deriving key material using HKDF and exporting it directly to
 * the client with the wolfCrypt API. This example provides the HKDF operation
 * with input keying material (IKM), optional salt, and info. The derived output
 * key material (OKM) is produced on the HSM and returned to the client buffer.
 *
 * After deriving the OKM, you can use it as a symmetric key (for example as an
 * AES key) or application-specific secret.
 */
int wh_DemoClient_CryptoHkdfExport(whClientContext* clientContext)
{
    int ret   = 0;
    int devId = WH_DEV_ID;

    /* Example inputs for HKDF. Data is from RFC 5869 test case 1 */
    const byte ikm[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const byte salt[] = {0xA0, 0xA1, 0xA2, 0xA3};
    const byte info[] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4};
    byte       okm[32]; /* 32 bytes for WC_SHA256-based HKDF */

    (void)clientContext; /* Unused */

    /* Derive 32 bytes using HKDF with SHA-256. The OKM is exported directly
     * back to the client buffer 'okm'. */
    ret = wc_HKDF_ex(WC_SHA256, ikm, sizeof(ikm), salt, sizeof(salt), info,
                     sizeof(info), okm, (word32)sizeof(okm), NULL, devId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_HKDF_ex %d\n", ret);
    }

    /* At this point 'okm' holds the derived key material.
     * Now you can use the key for your application. */

    return ret;
}

/*
 * Demonstrates deriving key material using HKDF and storing it in the HSM
 * key cache. The client does not receive the key material; instead, it gets a
 * keyId that can be used with compatible operations (for example, attaching
 * the keyId to an AES context).
 *
 * After the key is cached, you can reference it by keyId for relevant
 * operations. This example optionally evicts the cached key at the end.
 */
int wh_DemoClient_CryptoHkdfCache(whClientContext* clientContext)
{
    int     ret       = 0;
    whKeyId keyId     = WH_KEYID_ERASED;

    /* Example inputs for HKDF. */
    const byte     ikm[]  = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const byte     salt[] = {0xC0, 0xC1, 0xC2, 0xC3};
    const byte     info[] = {0xD0, 0xD1, 0xD2};
    const uint32_t outSz  = 32; /* arbitrary output size */

    /* Metadata flags/label for the cached key. Adjust to your requirements. */
    whNvmFlags flags   = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_DERIVE;
    char       label[] = "hkdf-derived key";

    /* Request the HSM to derive HKDF output and store it in the key cache.
     * On success, 'keyId' is assigned by the HSM (unless pre-set) and can be
     * used to reference the cached key material. */
    ret = wh_Client_HkdfMakeCacheKey(
        clientContext, WC_SHA256, WH_KEYID_ERASED, ikm, (uint32_t)sizeof(ikm),
        salt, (uint32_t)sizeof(salt), info, (uint32_t)sizeof(info), &keyId,
        flags, (const uint8_t*)label, (uint32_t)strlen(label), outSz);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_HkdfMakeCacheKey %d\n", ret);
        return ret;
    }

    /* Now you can use the cached key, referring to it by ID for relevant
     * operations. */

    /* Optionally evict the key from the cache once we are done using it */
    ret = wh_Client_KeyEvict(clientContext, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", ret);
    }

    return ret;
}

/*
 * Demonstrates deriving key material using HKDF with a cached input key.
 * This example shows how to use a key already stored in the HSM key cache
 * as the input keying material for HKDF, instead of passing the key data
 * directly from the client. The derived output is exported to the client.
 */
int wh_DemoClient_CryptoHkdfCacheInputKey(whClientContext* clientContext)
{
    int     ret        = 0;
    whKeyId keyIdIn    = WH_KEYID_ERASED;
    whKeyId keyIdOut   = WH_KEYID_ERASED;
    char    keyLabel[] = "hkdf-input-key";

    /* Input key material to cache */
    const byte ikm[]  = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                         0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    const byte salt[] = {0xE0, 0xE1, 0xE2, 0xE3};
    const byte info[] = {0xF0, 0xF1, 0xF2};
    byte       okm[32]; /* Output key material */

    /* First, cache the input key material in the HSM */
    ret = wh_Client_KeyCache(clientContext, WH_NVM_FLAGS_USAGE_DERIVE,
                             (uint8_t*)keyLabel, (uint32_t)strlen(keyLabel),
                             ikm, (uint32_t)sizeof(ikm), &keyIdIn);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        return ret;
    }

    /* The input key material is now cached on the HSM. You can, at a later
     * time, use the cached keyId as the keyIdIn parameter to use the
     * cached key material as input for HKDF operations. */

    /* Now derive additional key material using the cached key as input.
     * Set inKey to NULL and inKeySz to 0 to indicate we want to use
     * the key from cache identified by keyIdIn. */
    ret = wh_Client_HkdfMakeCacheKey(
        clientContext, WC_SHA256, keyIdIn, NULL, 0, salt,
        (uint32_t)sizeof(salt), info, (uint32_t)sizeof(info), &keyIdOut,
        WH_NVM_FLAGS_NONE, NULL, 0, (uint32_t)sizeof(okm));
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_HkdfMakeCacheKey with cached input %d\n",
               ret);
        (void)wh_Client_KeyEvict(clientContext, keyIdIn);
        return ret;
    }

    /* Now you can use the cached key, referring to it by ID for relevant
     * operations. */

    /* Optionally evict the input key from the cache. Failure checking omitted
     * for readability */
    (void)wh_Client_KeyEvict(clientContext, keyIdIn);

    /* Optionally evict the output key from the cache. Failure checking omitted
     * for readability */
    (void)wh_Client_KeyEvict(clientContext, keyIdOut);

    return ret;
}
#endif /* HAVE_HKDF */

#if defined(HAVE_CMAC_KDF) && defined(WOLFSSL_CMAC)

#define WH_DEMO_CMAC_KDF_OUT_SZ 40

/* Test vectors based on wolfSSL CMAC KDF implementation test vectors for
 * NIST SP 800-108 KDF in Counter Mode using CMAC */
static const uint8_t demoCmacKdfSalt[] = {
    0x20, 0x51, 0xAF, 0x34, 0x76, 0x2E, 0xBE, 0x55, 0x6F, 0x72, 0xA5, 0xC6,
    0xED, 0xC7, 0x77, 0x1E, 0xB9, 0x24, 0x5F, 0xAD, 0x76, 0xF0, 0x34, 0xBE};
static const uint8_t demoCmacKdfZ[] = {
    0xAE, 0x8E, 0x93, 0xC9, 0xC9, 0x91, 0xCF, 0x89, 0x6A, 0x49, 0x1A,
    0x89, 0x07, 0xDF, 0x4E, 0x4B, 0xE5, 0x18, 0x6A, 0xE4, 0x96, 0xCD,
    0x34, 0x0D, 0xC1, 0x9B, 0x23, 0x78, 0x21, 0xDB, 0x7B, 0x60};
static const uint8_t demoCmacKdfFixedInfo[] = {
    0xA2, 0x59, 0xCA, 0xE2, 0xC4, 0xA3, 0x6B, 0x89, 0x56, 0x3C, 0xB1, 0x48,
    0xC7, 0x82, 0x51, 0x34, 0x3B, 0xBF, 0xAB, 0xDC, 0x13, 0xCA, 0x7A, 0xC2,
    0x17, 0x1C, 0x2E, 0xB6, 0x02, 0x1F, 0x44, 0x77, 0xFE, 0xA3, 0x3B, 0x28,
    0x72, 0x4D, 0xA7, 0x21, 0xEE, 0x08, 0x7B, 0xFF, 0xD7, 0x94, 0xA1, 0x56,
    0x37, 0x54, 0xB4, 0x25, 0xA8, 0xD0, 0x9B, 0x3E, 0x0D, 0xA5, 0xFF, 0xED};

/*
 * Demonstrates deriving key material using the two-step CMAC KDF through the
 * wolfCrypt API. The HSM performs the derivation and returns the output
 * directly to the client buffer.
 */
int wh_DemoClient_CryptoCmacKdfExport(whClientContext* clientContext)
{
    int     ret = 0;
    uint8_t derived[WH_DEMO_CMAC_KDF_OUT_SZ];

    (void)clientContext;

    memset(derived, 0, sizeof(derived));

    ret = wc_KDA_KDF_twostep_cmac(
        demoCmacKdfSalt, (word32)sizeof(demoCmacKdfSalt), demoCmacKdfZ,
        (word32)sizeof(demoCmacKdfZ), demoCmacKdfFixedInfo,
        (word32)sizeof(demoCmacKdfFixedInfo), derived, (word32)sizeof(derived),
        NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_KDA_KDF_twostep_cmac %d\n", ret);
    }

    /* The key has now been derived and is stored in the 'derived' array */

    return ret;
}

/*
 * Demonstrates deriving key material using the CMAC KDF and storing it in the
 * HSM key cache. The derived key is kept non-exportable and referenced by its
 * assigned keyId.
 */
int wh_DemoClient_CryptoCmacKdfCache(whClientContext* clientContext)
{
    int        ret     = 0;
    whKeyId    keyId   = WH_KEYID_ERASED;
    whNvmFlags flags   = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_DERIVE;
    const char label[] = "cmac-kdf cache";

    ret = wh_Client_CmacKdfMakeCacheKey(
        clientContext, WH_KEYID_ERASED, demoCmacKdfSalt,
        (uint32_t)sizeof(demoCmacKdfSalt), WH_KEYID_ERASED, demoCmacKdfZ,
        (uint32_t)sizeof(demoCmacKdfZ), demoCmacKdfFixedInfo,
        (uint32_t)sizeof(demoCmacKdfFixedInfo), &keyId, flags,
        (const uint8_t*)label, (uint32_t)strlen(label),
        WH_DEMO_CMAC_KDF_OUT_SZ);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_CmacKdfMakeCacheKey %d\n", ret);
        return ret;
    }

    /* The key has now been derived and can be referenced by the client via its
     * keyId in subsequent wolfCrypt or wolfHSM API calls */

    /* Example: evict the key from cache once we are done with it */
    ret = wh_Client_KeyEvict(clientContext, keyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
    }

    return ret;
}

/*
 * Demonstrates deriving CMAC KDF output using cached salt and shared secret
 * inputs and caching the derived output for subsequent use by keyId
 */
int wh_DemoClient_CryptoCmacKdfCacheInputs(whClientContext* clientContext)
{
    int        ret       = 0;
    whKeyId    saltKeyId = WH_KEYID_ERASED;
    whKeyId    zKeyId    = WH_KEYID_ERASED;
    whKeyId    outKeyId  = WH_KEYID_ERASED;
    uint8_t    derived[WH_DEMO_CMAC_KDF_OUT_SZ];
    const char label[] = "cmac-kdf inputs";

    /* Cache the input to be used as salt. This is typically not necessary,
     * as the salt is usually not sensitive information. If it is desired to use
     * HSM-only information as salt, then this would likely be provisioned
     * as an offline step */
    ret = wh_Client_KeyCache(clientContext, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0,
                             demoCmacKdfSalt, (uint32_t)sizeof(demoCmacKdfSalt),
                             &saltKeyId);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to cache CMAC KDF salt %d\n", ret);
        return ret;
    }

    /* Cache the Z input. This would typically be done offline during the HSM
     * provisioning step, but is shown here for completeness */
    ret = wh_Client_KeyCache(clientContext, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0,
                             demoCmacKdfZ, (uint32_t)sizeof(demoCmacKdfZ),
                             &zKeyId);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to cache CMAC KDF Z input %d\n", ret);
        /* Optionally evict the salt key if not needed anymore */
        (void)wh_Client_KeyEvict(clientContext, saltKeyId);
        return ret;
    }

    /* Cached inputs are now present on the HSM. At a later time, they can be
     * used to derive a key */


    /* Derive and cache the new key based on the cached input */
    memset(derived, 0, sizeof(derived));

    ret = wh_Client_CmacKdfMakeCacheKey(
        clientContext, saltKeyId, NULL, 0, zKeyId, NULL, 0,
        demoCmacKdfFixedInfo, (uint32_t)sizeof(demoCmacKdfFixedInfo), &outKeyId,
        WH_NVM_FLAGS_NONE, (const uint8_t*)label, (uint32_t)strlen(label),
        WH_DEMO_CMAC_KDF_OUT_SZ);

    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to CMAC KDF with cached inputs %d\n", ret);
    }


    /* We can now refer to the generated key by its keyID from the client */

    /* Optionally evict the keys from the cache if not needed anymore.
     * Ignore failure checking for readability */
    (void)wh_Client_KeyEvict(clientContext, outKeyId);
    (void)wh_Client_KeyEvict(clientContext, zKeyId);
    (void)wh_Client_KeyEvict(clientContext, saltKeyId);

    return ret;
}

#endif /* HAVE_CMAC_KDF && WOLFSSL_CMAC */

#endif /* WOLFHSM_CFG_NO_CRYPTO */
