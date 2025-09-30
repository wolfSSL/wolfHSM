#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* for read */
#include <time.h> /* For nanosleep */
#include <fcntl.h> /* For open, close, lseek */
#include <libgen.h>
#include <sys/mman.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wh_demo_client_secboot.h"


/* Provisioning process:
 * 1. Generate a server keypair into key cache as keyId 27
 * 2. Commit the server keypair to server NVM
 * 3. Map a file into memory and ask server to hash it using SHA256
 * 4. Sign the hash using the server keypair
 * 5. Store the signature to server NVM as object 29
 * 6. Hexdump hash, public key, and signature
 * Note: Provisioning can also be done offline using the whnvmtool
 *
 * SecBoot process:
 * 1. Load the signature from server NVM as object 29
 * 2. Map a file into memory and ask server to hash it using SHA256
 * 3. Verify the signature using server keyId 27
 * 4. Hexdump hash, public key, and signature
 *
 * Zeroization process:
 * 1. Destroy keyId 27
 * 2. Destroy nvmId 29
 */
const whKeyId prov_keyId = 27;
const uint8_t prov_keyLabel[] = "Provision Keypair";

const whNvmId sig_nvmId = 29;
const uint8_t sig_nvmLabel[] = "File Signature";

const char file_to_measure[] = "/bin/sh";

/* Forward declarations */
static int _showNvm(whClientContext* clientContext);

static int _provisionMakeCommitKey(whClientContext* clientContext);
static int _sha256File(const char* file_to_measure, uint8_t* hash);
static int _signHash(const uint8_t* hash, size_t hash_len, uint8_t* sig,
                     uint16_t* sig_len);
static int _verifyHash(const uint8_t* hash, size_t hash_len, const uint8_t* sig,
                       uint16_t sig_len, int32_t* rc);

static int _showNvm(whClientContext* clientContext)
{
    int ret = 0;
    whNvmAccess access = WH_NVM_ACCESS_ANY;
    whNvmFlags  flags  = WH_NVM_FLAGS_NONE;
    whNvmId id = 0;
    whNvmId count = 0;

    printf("NVM Contents:\n");
    do {
        ret = wh_Client_NvmList(clientContext, access, flags, id, NULL, &count,
                                &id);
        if (ret != WH_ERROR_OK) {
            printf("wh_Client_NvmList failed with ret:%d\n", ret);
            break;
        }
        printf("NVM List: count=%u, id=%u\n", (unsigned int)count,
               (unsigned int)id);

        if (count > 0) {
            whNvmSize data_len = 0;
            uint8_t label[WH_NVM_LABEL_LEN] = {0};
            ret =
                wh_Client_NvmGetMetadata(clientContext, id, NULL, NULL, NULL,
                                         NULL, &data_len, sizeof(label), label);
            if (ret != WH_ERROR_OK) {
                printf("wh_Client_NvmGetMetadata failed with ret:%d\n", ret);
                break;
            }

            printf("NVM Object ID %u has label '%-*s' and size:%u\n",
                   (unsigned int)id, (int)sizeof(label), label,
                   (unsigned int)data_len);
        }
    } while (count > 0);
    printf("End of NVM Contents\n");
    return ret;
}

static int _provisionMakeCommitKey(whClientContext* clientContext)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    int ret;

    /* Use the default ECC curve for 32 byte key, likely P256r1 */
    whKeyId keyId = prov_keyId;
    uint8_t keyLabel[WH_NVM_LABEL_LEN] = {0};
    memcpy(keyLabel, prov_keyLabel, sizeof(prov_keyLabel));

    ret = wh_Client_EccMakeCacheKey(clientContext, 32, ECC_CURVE_DEF, &keyId,
                                    WH_NVM_FLAGS_NONE, sizeof(prov_keyLabel),
                                    keyLabel);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyCommit(clientContext, prov_keyId);
    }
    return ret;
#else
    (void)clientContext;
    return WH_ERROR_NOTIMPL;
#endif
}

static int _sha256File(const char* file_to_measure, uint8_t* hash)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    int ret = 0;
    int fd = open(file_to_measure, O_RDONLY);
    if (fd >= 0) {
        /* Get filesize */
        off_t size = lseek(fd, 0, SEEK_END);
        void* ptr = NULL;
        ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (ptr != (void*)-1) {
            printf("Generating SHA256 of %s over %u bytes at %p\n",
                   file_to_measure, (unsigned int)size, ptr);
            wc_Sha256 sha256[1];
            ret = wc_InitSha256_ex(sha256, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wc_Sha256Update(sha256, ptr, (word32)size);
                if (ret == 0) {
                    ret = wc_Sha256Final(sha256, hash);
                }
                (void)wc_Sha256Free(sha256);
            }
            (void)munmap(ptr, size);

            wh_Utils_Hexdump("Hash:\n", hash, sizeof(hash));
        } else {
            perror("Unable to mmap input file:");
            ret = WH_ERROR_BADARGS;
        }
    } else {
        perror("Unable to open input file:");
        ret = WH_ERROR_BADARGS;
    }
    return ret;
#else
    (void)file_to_measure;
    (void)hash;
    return WH_ERROR_NOTIMPL;
#endif
}

static int _signHash(const uint8_t* hash, size_t hash_len, uint8_t* sig,
                     uint16_t* sig_len)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    ecc_key key[1];
    int ret = wc_ecc_init_ex(key, NULL, WH_DEV_ID);
    if (ret == 0) {
        ret = wh_Client_EccSetKeyId(key, prov_keyId);
        if (ret == 0) {
            word32 siglen32 = *sig_len;
            /* III Rng is not necessary since server will be doing the work */
            ret = wc_ecc_sign_hash(hash, hash_len, sig, &siglen32, NULL, key);
            if(ret == 0) {
                *sig_len = (uint16_t)siglen32;
            }
        }
        (void)wc_ecc_free(key);
    }
    return ret;
#else
    (void)hash;
    (void)hash_len;
    (void)sig;
    (void)sig_len;
    return WH_ERROR_NOTIMPL;
#endif
}

static int _verifyHash(const uint8_t* hash, size_t hash_len, const uint8_t* sig,
                       uint16_t sig_len, int32_t* rc)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    ecc_key key[1];
    int ret = wc_ecc_init_ex(key, NULL, WH_DEV_ID);
    if (ret == 0) {
        ret = wh_Client_EccSetKeyId(key, prov_keyId);
        if (ret == 0) {
            int res = 0;
            ret     = wc_ecc_verify_hash(sig, (word32)sig_len, hash,
                                         (word32)hash_len, &res, key);
            if (ret == 0) {
                *rc = res;
            }
        }
        (void)wc_ecc_free(key);
    }
    return ret;
#else
    (void)hash;
    (void)hash_len;
    (void)sig;
    (void)sig_len;
    (void)rc;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_DemoClient_SecBoot_Provision(whClientContext* clientContext)
{
    int ret = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    if (clientContext == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_CommInit(clientContext, &client_id, &server_id);
    if (ret == WH_ERROR_OK) {
        printf("Provision client connected to server id %u with client id %u\n",
                server_id, client_id);
        _showNvm(clientContext);

        printf("Server generating and committing keypair...\n");
        ret = _provisionMakeCommitKey(clientContext);
        if (ret == WH_ERROR_OK) {
            uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};

            printf("Measuring image %s...\n", file_to_measure);
            ret = _sha256File(file_to_measure, hash);
            if (ret == WH_ERROR_OK) {
                uint8_t sig[ECC_MAX_SIG_SIZE] = {0};
                uint16_t siglen = sizeof(sig);

                printf("Signing hash...\n");
                ret = _signHash(hash, sizeof(hash), sig, &siglen);
                if (ret == WH_ERROR_OK) {
                    int32_t rc = 0;
                    uint8_t sigLabel[WH_NVM_LABEL_LEN] = {0};
                    memcpy(sigLabel, sig_nvmLabel, sizeof(sig_nvmLabel));

                    wh_Utils_Hexdump("Signature:\n", sig, siglen);
                    printf("Storing the signature in NVM as nvmId %u\n",
                            sig_nvmId);
                    ret = wh_Client_NvmAddObject(
                        clientContext, sig_nvmId, WH_NVM_ACCESS_NONE,
                        WH_NVM_FLAGS_NONE, sizeof(sig_nvmLabel), sigLabel,
                        siglen, sig, &rc);
                    printf("Stored signature with ret:%d and rc:%d\n", ret, rc);
                }
            }
            _showNvm(clientContext);
        }
    }
    printf("Provision Client completed with ret:%d\n", ret);
    return ret;
}

int wh_DemoClient_SecBoot_Boot(whClientContext* clientContext)
{
    int ret = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    if (clientContext == NULL) {
        return WH_ERROR_BADARGS;
    }
    printf("SecBoot Client starting...\n");
    ret = wh_Client_CommInit(clientContext, &client_id, &server_id);
    if (ret == WH_ERROR_OK) {
        printf("SecBoot Client connected to server id %u with client id %u\n",
                server_id, client_id);

        _showNvm(clientContext);

        uint8_t sig[ECC_MAX_SIG_SIZE] = {0};
        whNvmSize siglen = 0;
        int32_t rc = 0;
        printf("SecBoot Client loading signature from NVM as nvmId %u\n",
                sig_nvmId);
        ret = wh_Client_NvmGetMetadata(clientContext,
            sig_nvmId, &rc, NULL, NULL, NULL, &siglen, 0, NULL);
        if (ret != WH_ERROR_OK) {
            printf("wh_Client_NvmGetMetadata failed with ret:%d\n", ret);
            return ret;
        }
        printf("SecBoot got siglen %d with ret:%d rc:%d\n", siglen, ret, rc);
        ret = wh_Client_NvmRead(clientContext, sig_nvmId, 0, siglen, &rc, NULL,
                                sig);
        if (ret != WH_ERROR_OK || rc != 0) {
            printf("Read Object %d failed with error code: %d, server error "
                   "code: %d\n",
                   sig_nvmId, ret, rc);
            return (ret != WH_ERROR_OK) ? ret : rc;
        }
        wh_Utils_Hexdump("Signature:\n", sig, siglen);


        uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
        printf("Measuring image %s...\n", file_to_measure);
        ret = _sha256File(file_to_measure, hash);
        if (ret == WH_ERROR_OK) {

            printf("SecBoot Client Verifying signature using keyId %u\n", prov_keyId);
            ret = _verifyHash(hash, sizeof(hash), sig, siglen, &rc);
            printf("ecc_verify:%d rc:%d\n", ret, rc);

            if ((ret == 0) && (rc == 1)) {
                printf("SecBoot Client signature verified successfully!!\n");
            } else {
                printf("SecBoot Client failed with ret:%d and rc:%d\n", ret, rc);
            }
        }
    }
    printf("SecBoot Client completed with ret:%d\n", ret);
    return ret;
}

int wh_DemoClient_SecBoot_Zeroize(whClientContext* clientContext)
{
    int ret = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    if (clientContext == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_CommInit(clientContext, &client_id, &server_id);
    printf("Connected to server id %u with client id %u: %d\n",
            server_id, client_id, ret);
    if (ret == WH_ERROR_OK) {
        int rc = 0;
        _showNvm(clientContext);

        ret = wh_Client_KeyErase(clientContext, prov_keyId);
        printf("Zeroize Client erased keyId:%u ret:%d\n", prov_keyId, ret);

        ret = wh_Client_NvmDestroyObjects(clientContext, 1, &sig_nvmId, &rc);
        printf("Zeroize Client destroyed NVM object:%u ret:%d with rc:%d\n",
               sig_nvmId, ret, rc);

        _showNvm(clientContext);
    }
    printf("SecBoot Zeroize Client completed with ret:%d\n", ret);
    return ret;
}
