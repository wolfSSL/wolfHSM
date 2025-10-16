#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wh_demo_client_keystore.h"


int wh_DemoClient_KeystoreBasic(whClientContext* clientContext)
{
    int      ret;
    uint8_t  key[]                  = "0123456789abcdef";
    uint8_t  label[]                = "my secret key";
    uint16_t keyId                  = WH_KEYID_ERASED;

    /* Cache the key in the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to cache key: %d\n", ret);
        return ret;
    }
    printf("Key cached with ID: %d\n", keyId);

    /* Now that the key is cached (stored in RAM on the HSM), the key can be
     * used for any crypto or other keystore operation using the keyId. Note
     * that the key cache entry is only valid for the lifetime of the server
     * context, so will not persist if the server process is shutdown or the
     * server context is reinitialized */

    /* Evict the key from the HSM cache. The key will no longer be active in the
     * RAM cache and it will not be usable. Any operations requested that refer
     * to this keyId will fail with an error */
    ret = wh_Client_KeyEvict(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to evict key: %d\n", ret);
        return ret;
    }
    printf("Key %d evicted\n", keyId);

    return WH_ERROR_OK;
}


int wh_DemoClient_KeystoreCommitKey(whClientContext* clientContext)
{
    int      ret;
    uint16_t keyId                      = WH_KEYID_ERASED;
    uint8_t  key[]                      = "0123456789abcdef";
    uint8_t  label[]                    = "my secret key";
    uint8_t  exportKey[sizeof(key)]     = {0};
    uint8_t  exportLabel[sizeof(label)] = {0};
    uint16_t exportKeySz                = 0;

    /* Cache the key in the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to cache key: %d\n", ret);
        return ret;
    }
    printf("Key cached with ID: %d\n", keyId);

    /* Now that the key is cached (stored in RAM on the HSM), the key can be
     * used for any crypto or other keystore operation using the keyId. Note
     * that the key cache entry is only valid for the lifetime of the server
     * context, so will not persist if the server process is shutdown or the
     * server context is reinitialized */

    /* (Optionally) commit the key to non-volatile storage */
    ret = wh_Client_KeyCommit(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to commit key: %d\n", ret);
        return ret;
    }
    printf("Key committed with ID: %d\n", keyId);

    /* Now that the key is committed to NVM, the keyId will persist and can be
     * used at any time, including across server restarts. Note that
     * the remainder of this function could occur later, including after a
     * server restart */

    /* Evict the key from the HSM. This will remove the key from the RAM cache
     * temporarily, in case you needed free space for other cached keys. The key
     * remains in NVM and the keyId can still be used */
    ret = wh_Client_KeyEvict(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to evict key: %d\n", ret);
        return ret;
    }
    printf("Key evicted with ID: %d\n", keyId);

    /* We can still do work with the evicted key, and after using it, it will be
     * repopulated in the cache */

    /* Erase the key from the HSM key storage. Its keyId will no longer be
     * usable */
    ret = wh_Client_KeyErase(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to erase key: %d\n", ret);
        return ret;
    }

    /* Key is erased, so no more work can be done. For example, attempting to
     * export the key will fail */
    ret = wh_Client_KeyExport(clientContext, keyId, exportLabel,
                              sizeof(exportLabel), exportKey, &exportKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        printf("Key should not be found: instead got %d\n", ret);
        return ret;
    }

    return WH_ERROR_OK;
}

#if !defined(NO_AES) && !defined(WOLFHSM_CFG_NO_CRYPTO)
int wh_DemoClient_KeystoreAes(whClientContext* clientContext)
{
    int      ret;
    Aes      aes = {0};
    uint8_t  key[AES_128_KEY_SIZE] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t  iv[AES_IV_SIZE]       = {'1', '2', '3', '4', '5', '6', '7', '8',
                                      '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t  label[]               = "my secret AES key";
    uint8_t  plainText[]           = "This is a test.";
    uint8_t  cipherText[sizeof(plainText)];
    uint8_t  decryptedText[sizeof(plainText)];
    uint16_t keyId = WH_KEYID_ERASED;

    /* Cache the AES key in the HSM */
    ret = wh_Client_KeyCache(clientContext, 0, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        printf("Failed to cache key: %d\n", ret);
        return ret;
    }
    printf("Key cached with ID: %d\n", keyId);

    /* Now that the key is cached (stored in RAM on the HSM), the key can be
     * used for any crypto or other keystore operation using the keyId. Note
     * that the key cache entry is only valid for the lifetime of the server
     * context, so will not persist if the server process is shutdown or the
     * server context is reinitialized */

    /* (Optionally) commit the key to non-volatile storage */
    ret = wh_Client_KeyCommit(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to commit key: %d\n", ret);
        return ret;
    }
    printf("Key committed with ID: %d\n", keyId);

    /* Now that the key is committed to NVM, the keyId will persist and can be
     * used at any time, including across server restarts */

    /* Initialize AES context to use wolfHSM offload */
    ret = wc_AesInit(&aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to initialize AES: %d\n", ret);
        return ret;
    }

    /* set AES context to use the cached key */
    ret = wh_Client_AesSetKeyId(&aes, keyId);
    if (ret != 0) {
        printf("Failed to set key: %d\n", ret);
        return ret;
    }

    /* Set the IV */
    ret = wc_AesSetIV(&aes, iv);
    if (ret != 0) {
        printf("Failed to set IV: %d\n", ret);
        return ret;
    }

    /* Encrypt the plaintext on the HSM */
    ret = wc_AesCbcEncrypt(&aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to encrypt: %d\n", ret);
        return ret;
    }
    printf("Encryption successful\n");

    /* Re-set the IV, as the CBC operation will overwrite it */
    ret = wc_AesSetIV(&aes, iv);
    if (ret != 0) {
        printf("Failed to set IV: %d\n", ret);
        return ret;
    }

    /* Decrypt the ciphertext */
    ret = wc_AesCbcDecrypt(&aes, decryptedText, cipherText, sizeof(cipherText));
    if (ret != 0) {
        printf("Failed to decrypt: %d\n", ret);
        return ret;
    }
    printf("Decryption successful\n");

    /* Verify the decrypted text matches the original plaintext */
    if (memcmp(plainText, decryptedText, sizeof(plainText)) == 0) {
        printf("Decryption matches original plaintext\n");
    }
    else {
        printf("Decryption does not match original plaintext\n");
        return -1;
    }

    /* Evict the key from the HSM */
    ret = wh_Client_KeyEvict(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to evict key: %d\n", ret);
        return ret;
    }
    printf("Key evicted with ID: %d\n", keyId);

    /* Though the key is evicted, we can still use it for crypto operations,
     * usage will just require the server to load the key from NVM. The key will
     * be restored in the cache after using it */
    ret = wc_AesInit(&aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to initialize AES: %d\n", ret);
        return ret;
    }
    ret = wh_Client_AesSetKeyId(&aes, keyId);
    if (ret != 0) {
        printf("Failed to set key: %d\n", ret);
        return ret;
    }
    ret = wc_AesSetIV(&aes, iv);
    if (ret != 0) {
        printf("Failed to set IV: %d\n", ret);
        return ret;
    }
    ret = wc_AesCbcEncrypt(&aes, cipherText, plainText, sizeof(plainText));
    if (ret != 0) {
        printf("Failed to encrypt: %d\n", ret);
        return ret;
    }
    ret = wc_AesSetIV(&aes, iv);
    if (ret != 0) {
        printf("Failed to set IV: %d\n", ret);
        return ret;
    }
    ret = wc_AesCbcDecrypt(&aes, decryptedText, cipherText, sizeof(cipherText));
    if (ret != 0) {
        printf("Failed to decrypt: %d\n", ret);
        return ret;
    }
    if (memcmp(plainText, decryptedText, sizeof(plainText)) == 0) {
        printf("Decryption matches original plaintext\n");
    }
    else {
        printf("Decryption does not match original plaintext\n");
        return -1;
    }

    /* Erase the key from the HSM key storage. Its keyId will no longer be
     * usable */
    ret = wh_Client_KeyErase(clientContext, keyId);
    if (ret != 0) {
        printf("Failed to erase key: %d\n", ret);
        return ret;
    }

    /* Key was erased, so should be unusable */
    (void)wh_Client_AesSetKeyId(&aes, keyId);
    ret = wc_AesCbcEncrypt(&aes, cipherText, plainText, sizeof(plainText));
    if (ret != WH_ERROR_NOTFOUND) {
        printf("Key should not be found: instead got %d\n", ret);
        return ret;
    }

    /* Clean up AES context */
    wc_AesFree(&aes);

    return WH_ERROR_OK;
}
#endif /* !NO_AES */

