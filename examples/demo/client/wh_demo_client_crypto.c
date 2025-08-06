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
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* make the rsa key */
    ret = wc_MakeRsaKey(rsa, 2048, 65537, rng);
    if (ret != 0) {
        printf("Failed to wc_MakeRsaKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    encSz = ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString),
                                      cipherText, sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, encSz, plainText, sizeof(plainText),
                               rsa);
    if (ret < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        printf("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        printf("RSA Decryption matches original plaintext\n");

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
    char       keyFile[]     = "../../../demo/certs/rsa-2048-key.der";
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
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* open the RSA key */
    ret = keyFd = open(keyFile, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFile, ret);
        goto exit;
    }

    /* read the RSA key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFile, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             strlen(keyLabel), keyBuf, keySz, &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }
    needEvict = 1;

    /* initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRsaKey_ex %d\n", ret);
        goto exit;
    }

    /* set the assigned keyId */
    ret = wh_Client_RsaSetKeyId(rsa, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    encSz = ret = wc_RsaPublicEncrypt(plainText, sizeof(plainString),
                                      cipherText, sizeof(cipherText), rsa, rng);
    if (ret < 0) {
        printf("Failed to wc_RsaPublicEncrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* decrypt the ciphertext */
    ret = wc_RsaPrivateDecrypt(cipherText, encSz, plainText, sizeof(plainText),
                               rsa);
    if (ret < 0) {
        printf("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        goto exit;
    }
    ret = 0;

    /* verify the decryption output */
    if (memcmp(plainText, plainString, sizeof(plainString)) != 0) {
        printf("Failed to verify RSA output\n");
        ret = -1;
    }
    else
        printf("RSA Decryption matches original plaintext with imported key\n");
exit:
    (void)wc_FreeRng(rng);
    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
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
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* initialize the keys */
    ret = wc_curve25519_init_ex(curve25519PrivateKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_init_ex(curve25519PublicKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }

    /* generate the keys on the HSM */
    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PrivateKey);
    if (ret != 0) {
        printf("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, curve25519PublicKey);
    if (ret != 0) {
        printf("Failed to wc_curve25519_make_key %d\n", ret);
        goto exit;
    }

    /* generate shared secrets from both perspectives */
    outLen = sizeof(sharedOne);
    ret = wc_curve25519_shared_secret(curve25519PrivateKey, curve25519PublicKey,
                                      sharedOne, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    outLen = sizeof(sharedTwo);
    ret = wc_curve25519_shared_secret(curve25519PublicKey, curve25519PrivateKey,
                                      sharedTwo, (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("CURVE25519 shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("CURVE25519 shared secrets match\n");
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
    #if 0
    char    keyPairFileBob[]   = "../../../demo/certs/curve25519_keyBob.der";
    char    keyPairFileAlice[] = "../../../demo/certs/curve25519_keyAlice.der";
    #else
    char    keyPairFileBob[]   = "../../../demo/certs/curve25519_keyBob.der";
    char    keyPairFileAlice[] = "../../../demo/certs/curve25519_keyAlice.der";
    #endif
    char    keyLabel[]         = "baby's first key";
    uint8_t keyBuf[256];
    uint8_t sharedOne[CURVE25519_KEYSIZE];
    uint8_t sharedTwo[CURVE25519_KEYSIZE];

    curve25519_key aliceKey[1];
    curve25519_key bobKey[1];

    /* open Bob's key pair file and read it into a local buffer */
    ret = keyFd = open(keyPairFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyPairFileBob, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        goto exit;
    }
    close(keyFd);


    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             strlen(keyLabel), keyBuf, keySz, &keyIdBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* initialize the wolfCrypt struct to use the cached key */
    ret = wc_curve25519_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_Curve25519SetKeyId(bobKey, keyIdBob);
    if (ret != 0) {
        printf("Failed to wh_Client_Curve25519SetKeyId %d\n", ret);
        goto exit;
    }


    /* open Alice's key pair file and read it into a local buffer */
    ret = keyFd = open(keyPairFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyPairFileAlice, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyPairFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);

    /* cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             strlen(keyLabel), keyBuf, keySz, &keyIdAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* Initialize the wolfCrypt struct to use the cached key */
    ret = wc_curve25519_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_curve25519_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_Curve25519SetKeyId(aliceKey, keyIdAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_Curve25519SetKeyId %d\n", ret);
        goto exit;
    }

    /* Generate a shared secret from Bob's perspective */
    outLen = sizeof(sharedOne);
    ret    = wc_curve25519_shared_secret(bobKey, aliceKey, sharedOne,
                                         (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Generate a shared secret from Alice's perspective */
    outLen = sizeof(sharedTwo);
    ret    = wc_curve25519_shared_secret(aliceKey, bobKey, sharedTwo,
                                         (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_curve25519_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("CURVE25519 import: shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("CURVE25519 import: shared secrets match\n");
    }

exit:
    wc_curve25519_free(aliceKey);
    wc_curve25519_free(bobKey);

    /* (Optional) Evict the keys from the HSM cache */
    if (keyIdBob != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdBob);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    if (keyIdAlice != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdAlice);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
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
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* Initialize the local wolfCrypt structs */
    ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }

    /* Make the keys. These are generated on the HSM as ephemeral keys and sent
     * back to the client to store locally in the ecc_key structs */
    ret = wc_ecc_make_key(rng, 32, aliceKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }
    ret = wc_ecc_make_key(rng, 32, bobKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_make_key %d\n", ret);
        goto exit;
    }

    /* Generate the shared secrets */
    outLen = 32;
    ret    = wc_ecc_shared_secret(aliceKey, bobKey, (byte*)sharedOne,
                                  (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_shared_secret(bobKey, aliceKey, (byte*)sharedTwo,
                               (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("ECC shared secrets don't match\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("ECC shared secrets match\n");
    }

    /* Sign the plaintext using the private component of Alice's key */
    outLen = sizeof(signature);
    ret    = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
                              (word32*)&outLen, rng, aliceKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Verify the hash using the public component of Alice's key. Note that
     * the keys generated for Alice and Bob contain both public and private
     * parts. In a real scenario, the signing and verifying would occur at
     * separate times, and only the public key would be distributed */
    ret = wc_ecc_verify_hash((void*)signature, outLen, (void*)message,
                             sizeof(message), &res, aliceKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        printf("ECC sign/verify successful\n");
    else {
        printf("ECC sign/verify failure\n");
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
    char       keyFileAlice[] = "../../../demo/certs/alice-ecc256-key.der";
    char       keyFileBob[]   = "../../../demo/certs/bob-ecc256-key.der";
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
        printf("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }

    /* Open Alice's keypair file and read it into a local buffer */
    ret = keyFd = open(keyFileAlice, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFileAlice, ret);
        goto exit;
    }
    /* Read the first private key to local buffer */
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFileAlice, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);
    /* Cache the key in the HSM, get HSM assigned keyId. From here on out, the
     * keys are stored in the HSM and can be referred to by keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             strlen(keyLabel), keyBuf, keySz, &keyIdAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* At this point we could also commit the key to NVM if required */

    /* Initialize the local wolfCrypt struct, and configure it to use the cached
     * key */
    ret = wc_ecc_init_ex(aliceKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_EccSetKeyId(aliceKey, keyIdAlice);
    if (ret != 0) {
        printf("Failed to wh_Client_EccSetKeyId %d\n", ret);
        goto exit;
    }
    /* Configure the local struct to expect the correct curve */
    ret = wc_ecc_set_curve(aliceKey, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }


    /* Now we can do the same procedure for Bob's keypair */

    /* Open Bob's keypair file and read it into a local buffer */
    ret = keyFd = open(keyFileBob, O_RDONLY, 0);
    if (ret < 0) {
        printf("Failed to open %s %d\n", keyFileBob, ret);
        goto exit;
    }
    ret = keySz = read(keyFd, keyBuf, sizeof(keyBuf));
    if (ret < 0) {
        printf("Failed to read %s %d\n", keyFileBob, ret);
        close(keyFd);
        goto exit;
    }
    close(keyFd);
    /* Cache the key in the HSM, get HSM assigned keyId */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             strlen(keyLabel), keyBuf, keySz, &keyIdBob);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* Initialize the local wolfCrypt struct, and configure it to use the cached
     * key */
    ret = wc_ecc_init_ex(bobKey, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    ret = wh_Client_EccSetKeyId(bobKey, keyIdBob);
    if (ret != 0) {
        printf("Failed to wh_Client_EccSetKeyId %d\n", ret);
        goto exit;
    }
    /* Configure the local struct to expect the correct curve */
    ret = wc_ecc_set_curve(bobKey, 32, -1);
    if (ret != 0) {
        printf("Failed to wc_ecc_set_curve %d\n", ret);
        goto exit;
    }

    /* Generate a 32-byte shared secret from Alice's perspective */
    outLen = 32;
    ret    = wc_ecc_shared_secret(aliceKey, bobKey, (byte*)sharedOne,
                                  (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Generate a 32-byte shared secret from Bob's perspective */
    outLen = 32;
    ret    = wc_ecc_shared_secret(bobKey, aliceKey, (byte*)sharedTwo,
                                  (word32*)&outLen);
    if (ret != 0) {
        printf("Failed to wc_ecc_shared_secret %d\n", ret);
        goto exit;
    }

    /* Compare the shared secrets, they should match */
    if (memcmp(sharedOne, sharedTwo, outLen) != 0) {
        printf("ECC shared secrets don't match with imported keys\n");
        ret = -1;
        goto exit;
    }
    else {
        printf("ECC shared secrets match with imported keys\n");
    }

    /* Sign the plaintext with Alice's private key */
    sigLen = sizeof(signature);
    ret    = wc_ecc_sign_hash(message, sizeof(message), (void*)signature,
                              (word32*)&sigLen, rng, aliceKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_sign_hash %d\n", ret);
        goto exit;
    }

    /* Verify the hash with Alice's public key. Note that the key cached on the
     * HSM contains both public and private parts. In a real scenario, the
     * signing and verifying would occur at separate times, and only the public
     * key would be distributed */
    ret = wc_ecc_verify_hash((void*)signature, sigLen, (void*)message,
                             sizeof(message), &res, aliceKey);
    if (ret != 0) {
        printf("Failed to wc_ecc_verify_hash %d\n", ret);
        goto exit;
    }

    if (res == 1)
        printf("ECC sign/verify successful with imported keys\n");
    else {
        printf("ECC sign/verify failure with imported keys\n");
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
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    if (keyIdAlice != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyIdAlice);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
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
        printf("Failed to wc_AesInit %d\n", ret);
    }
    else {
        /* set the key on the client side */
        ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_ENCRYPTION);
        if (ret != 0) {
            printf("Failed to wc_AesSetKey %d\n", ret);
        }
        if (ret == 0) {
            /* encrypt the plaintext */
            ret =
                wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
            if (ret != 0) {
                printf("Failed to wc_AesCbcEncrypt %d\n", ret);
            }
        }

        if (ret == 0) {
            /* Reset the IV so we can decrypt */
            ret = wc_AesSetIV(aes, NULL);
            if (ret != 0) {
                printf("Failed to wc_AesSetIV %d\n", ret);
            }
        }

        if (ret == 0) {
            /* decrypt the ciphertext */
            ret =
                wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
            if (ret != 0) {
                printf("Failed to wc_AesCbcDecrypt %d\n", ret);
            }
        }

        if (ret == 0) {
            /* compare final and plain */
            if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                printf("AES CBC doesn't match after decryption\n");
                ret = -1;
            }
            else {
                printf("AES CBC matches after decryption\n");
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
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesCbcEncrypt(aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcEncrypt %d\n", ret);
        goto exit;
    }

    /* Reset the IV so we can decrypt */
    ret = wc_AesSetIV(aes, NULL);
    if (ret != 0) {
        printf("Failed to wc_AesSetIV %d\n", ret);
    }

    /* decrypt the ciphertext */
    ret = wc_AesCbcDecrypt(aes, finalText, cipherText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to wc_AesCbcDecrypt %d\n", ret);
        goto exit;
    }

    /* compare final and plain */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES CBC doesn't match after decryption with imported key\n");
        ret = -1;
        goto exit;
    }
    printf("AES CBC matches after decryption with imported key\n");
exit:
    if (needEvict) {
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
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
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* set the key and iv on the client side */
    ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("Failed to wc_AesSetKey %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare the finaltext to the plaintext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES GCM doesn't match after decryption\n");
        ret = -1;
        goto exit;
    }
    printf("AES GCM matches after decryption\n");
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
        printf("Failed to wc_AesInit %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    needEvict = 1;

    /* set the keyId on the struct */
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* set the iv */
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* encrypt the plaintext */
    ret = wc_AesGcmEncrypt(aes, cipherText, plainText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto exit;
    }

    /* decrypt the ciphertext */
    ret = wc_AesGcmDecrypt(aes, finalText, cipherText, sizeof(plainText), iv,
                           sizeof(iv), authTag, sizeof(authTag), authIn,
                           sizeof(authIn));
    if (ret != 0) {
        printf("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto exit;
    }

    /* compare plaintext and finaltext */
    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
        printf("AES GCM doesn't match after decryption with imported keys\n");
        ret = -1;
        goto exit;
    }
    printf("AES GCM matches after decryption with imported keys\n");
exit:
    wc_AesFree(aes);
    if (needEvict) {
        /* evict the key from the cache */
        int evictRet = wh_Client_KeyEvict(clientContext, keyId);
        if (evictRet != 0) {
            printf("Failed to wh_Client_KeyEvict %d\n", evictRet);
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
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, strlen(message));
    if (ret != 0) {
        printf("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret    = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        printf("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* verify the tag */
    ret =
        wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                            strlen(message), key, sizeof(key), NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("CMAC hash and verify failed %d\n", ret);
        goto exit;
    }

    printf("CMAC hash and verify succeeded\n");
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
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* hash the message */
    ret = wc_CmacUpdate(cmac, (byte*)message, sizeof(message));
    if (ret != 0) {
        printf("Failed to wc_CmacUpdate %d\n", ret);
        goto exit;
    }

    /* get the cmac tag */
    outLen = sizeof(tag);
    ret    = wc_CmacFinal(cmac, tag, &outLen);
    if (ret != 0) {
        printf("Failed to wc_CmacFinal %d\n", ret);
        goto exit;
    }

    /* Now let's verify the CMAC we just computed We should reinitialize the
     * CMAC struct and set the keyId again since we finalized the CMAC operation
     */

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM. This is required because the key is evicted
     * after the non-DMA CMAC operation is finalized */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* verify the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    ret = wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                              sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("CMAC hash and verify failed with imported key %d\n", ret);
        goto exit;
    }

    printf("CMAC hash and verify succeeded with imported key\n");
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
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* generate the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    outLen = sizeof(tag);
    ret    = wc_AesCmacGenerate_ex(cmac, tag, &outLen, (byte*)message,
                                   sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wh_Client_AesCmacGenerate %d\n", ret);
        goto exit;
    }

    /* Now, to verify, we need to re-initialize the CMAC struct and set the
     * keyId again. This is because the key is evicted after the non-DMA CMAC
     * operation is finalized */

    /* initialize the cmac struct */
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitCmac_ex %d\n", ret);
        goto exit;
    }

    /* cache the key on the HSM again, cmac keys are evicted after non-DMA CMAC
     * operations are finalized is called */
    ret = wh_Client_KeyCache(clientContext, 0, (uint8_t*)keyLabel,
                             sizeof(keyLabel), key, sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        goto exit;
    }

    /* set the keyId on the struct */
    ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret != 0) {
        printf("Failed to wh_Client_SetKeyIdAes %d\n", ret);
        goto exit;
    }

    /* verify the cmac tag using the wolfCrypt oneshot API, which should yield
     * the best one-shot performance. No need to pass a key since the key is
     * cached on the HSM and the keyId is associated with the CMAC struct */
    ret = wc_AesCmacVerify_ex(cmac, tag, sizeof(tag), (byte*)message,
                              sizeof(message), NULL, 0, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("CMAC hash and verify oneshot failed with imported key %d\n",
               ret);
        goto exit;
    }

    printf("CMAC hash and verify oneshot succeeded with imported key\n");
exit:
    (void)wc_CmacFree(cmac);
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES */
