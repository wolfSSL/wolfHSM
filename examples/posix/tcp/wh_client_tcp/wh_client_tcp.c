/*
 * wolfHSM Client TCP Example
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* for read */
#include <time.h> /* For nanosleep */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "port/posix/posix_transport_tcp.h"

#include "wolfhsm/wh_utils.h"
#include <libgen.h>
#include <sys/mman.h>
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wh_demo_client_all.h"

/** Local declarations */
static int wh_ClientTask(void* cf);


static void sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

void hexdump(const char* initial, const uint8_t* ptr, size_t size)
{
#define HEXDUMP_BYTES_PER_LINE 16
    int count = 0;
    if(initial != NULL)
        printf("%s ",initial);
    while(size > 0) {
        printf ("%02X ", *ptr);
        ptr++;
        size --;
        count++;
        if (count % HEXDUMP_BYTES_PER_LINE == 0) {
            printf("\n");
        }
    }
    if((count % HEXDUMP_BYTES_PER_LINE) != 0) {
        printf("\n");
    }
}

enum {
	REPEAT_COUNT = 10,
	REQ_SIZE = 32,
	RESP_SIZE = 64,
	ONE_MS = 1,
};

#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_CLIENT_ID 12

static int wh_ClientTask(void* cf)
{
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;
    whClientContext client[1];
    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len = 0;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Client_Init(client, config);

    printf("Client connecting to server...\n");

    if (ret != 0) {
        perror("Init error:");
        return -1;
    }
    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        sprintf((char*)tx_req,"Request:%u",counter);
        tx_req_len = strlen((char*)tx_req);
        do {
            ret = wh_Client_EchoRequest(client,
                    tx_req_len, tx_req);
            if (ret != WH_ERROR_NOTREADY) {
                if (ret == 0) {
                    printf("Client sent request successfully\n");
                } else {
                    printf("wh_CLient_EchoRequest failed with ret=%d\n", ret);
                }
            }
            sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(client,
                    &rx_resp_len, rx_resp);
            sleepMs(ONE_MS);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }
    }

    /* run the client demos */
    ret = wh_DemoClient_All(client);
    if (ret != 0) {
        printf("Client demo failed: ret=%d\n", ret);
    }


    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    printf("Client disconnected\n");
    return ret;
}


/* Provisioning process:
 * 1. Generate a server keypair into key cache as keyId 27
 * 2. Commit the server keypair to server NVM 
 * 3. Map a file into memory and ask server to hash it using SHA256
 * 4. Sign the hash using the server keypair
 * 5. Store the signature to server NVM as object 29 
 * 6. Hexdump hash, public key, and signature
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
whKeyId prov_keyId = 27;
uint8_t prov_keyLabel[] = "Provision Keypair";

whNvmId sig_nvmId = 29;
uint8_t sig_nvmLabel[] = "File Signature";

char file_to_measure[] = "/bin/sh";

static int wh_Client_ShowNvm(whClientContext* client)   
{
    int ret = 0;
    whNvmAccess access = WH_NVM_ACCESS_ANY;
    whNvmFlags flags = WH_NVM_FLAGS_ANY;
    whNvmId id = 0;
    whNvmId count = 0;

    printf("NVM Contents:\n");
    do {
        ret = wh_Client_NvmList(client, access, flags, id, NULL, &count, &id);
        if (ret != 0) {
            printf("wh_Client_NvmList failed with ret=%d\n", ret);
            return ret;
        }
        whNvmSize data_len = 0;
        uint8_t label[WH_NVM_LABEL_LEN] = {0};
        ret = wh_Client_NvmGetMetadata(client, id, 
                                        NULL, NULL, 
                                        NULL, NULL, 
                                        &data_len, 
                                        sizeof(label), label);
        printf("NVM List: count=%u, id=%u\n", (unsigned int)count, (unsigned int)id);

        if (count > 0) {
            printf("NVM Object ID %u has label '%-*s' and size:%u\n", 
                 (unsigned int)id, 
                 (int)sizeof(label), label, 
                (unsigned int)data_len);
        }
    } while (count > 0);
    printf("End of NVM Contents\n");
    return ret;
}

static int wh_ClientProvision(void* cf)
{
    whClientContext client[1];
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Client_Init(client, config);
    if (ret != 0) {
        perror("Provision Client Init error:");
        return -1;
    }

    printf("Provision Client connecting to server...\n");

    uint32_t client_id = 0;
    uint32_t server_id = 0;
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    printf("Connected to server id %u with client id %u: %d\n",
            server_id, client_id, ret);
    
    wh_Client_ShowNvm(client);

    printf("Server generating keypair...\n");
    uint16_t serv_label_size = sizeof(prov_keyLabel);
    
    /* Use the default ECC curve for 32 byte key, likely P256r1 */
    ret = wh_Client_EccMakeCacheKey(client, 32, ECC_CURVE_DEF, 
                                        &prov_keyId, WH_NVM_FLAGS_NONE, 
                                        serv_label_size, prov_keyLabel);
    printf("make keypair:%d\n", ret);

    printf("Server committing keypair to nvm...\n");
    ret = wh_Client_KeyCommit(client, prov_keyId);
    printf("commit keypair:%d\n", ret);

    uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
    printf("Generate image hash of %s...\n", file_to_measure);
    int fd = open(file_to_measure, O_RDONLY);
    if (fd >= 0) {
        /* Get filesize */
        off_t size = lseek(fd, -1, SEEK_END);
        void* ptr = NULL;
        ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (ptr != (void*)-1) {
            printf("Generating SHA256 over %u bytes at %p\n", 
                (unsigned int)size, ptr);
            wc_Sha256 sha256[1];
            wc_InitSha256_ex(sha256, NULL, WH_DEV_ID);
            printf("init\n");
            wc_Sha256Update(sha256, ptr, size);
            printf("update\n");
            wc_Sha256Final(sha256, hash);
            printf("final\n");
            wc_Sha256Free(sha256);
            printf("free\n");
            (void)munmap(ptr, size);
        } else {
            printf("Unable to mmap input file.  Using hash = 0x00's\n");
        }

        hexdump("Hash:", hash, sizeof(hash));
        printf("Signing hash...\n");
        ecc_key key[1];
        uint8_t sig[ECC_MAX_SIG_SIZE] = {0};
        uint16_t siglen = sizeof(sig);
        wc_ecc_init_ex(key, NULL, WH_DEV_ID);
        wh_Client_EccSetKeyId(key, prov_keyId);
        ret = wh_Client_EccSign(client, key, hash, sizeof(hash), sig, &siglen);
        printf("ecc_sign:%d\n", ret);
        /* III The public key is exported to this key during EccSign */
        wc_ecc_free(key);
        hexdump("Signature:", sig, siglen);
        printf("Storing the signature in NVM as nvmId %u\n", sig_nvmId);
        int32_t rc = 0;
        ret = wh_Client_NvmAddObject(client, sig_nvmId,
                            WH_NVM_ACCESS_NONE, WH_NVM_FLAGS_NONE, 
                            sizeof(sig_nvmLabel), sig_nvmLabel,
                            siglen, sig, 
                            &rc);
        printf("Stored signature with ret:%d and rc:%d\n", ret, rc);
    }

    wh_Client_ShowNvm(client);

    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    printf("Provision Client disconnected\n");
    return ret;
}

static int wh_ClientSecBoot(void* cf)
{
    whClientContext client[1];
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Client_Init(client, config);
    if (ret != 0) {
        perror("SecBoot Client Init error:");
        return -1;
    }

    printf("SecBoot Client connecting to server...\n");

    uint32_t client_id = 0;
    uint32_t server_id = 0;
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    printf("Connected to server id %u with client id %u: %d\n",
            server_id, client_id, ret);
    
    wh_Client_ShowNvm(client);

    uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
    printf("Generate image hash of %s...\n", file_to_measure);
    int fd = open(file_to_measure, O_RDONLY);
    if (fd >= 0) {
        /* Get filesize */
        off_t size = lseek(fd, -1, SEEK_END);
        void* ptr = NULL;
        ptr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (ptr != (void*)-1) {
            printf("Generating SHA256 over %u bytes\n", (unsigned int)size);
            wc_Sha256 sha256[1];
            wc_InitSha256_ex(sha256, NULL, WH_DEV_ID);
            wc_Sha256Update(sha256, ptr, size);
            wc_Sha256Final(sha256, hash);
            wc_Sha256Free(sha256);
            (void)munmap(ptr, size);
        } else {
            printf("Unable to mmap input file.  Using hash = 0x00's\n");
        }
    }
    hexdump("Hash:", hash, sizeof(hash));
    printf("SecBoot Client loading signature from NVM as nvmId %u\n",
            sig_nvmId);
    uint8_t sig[ECC_MAX_SIG_SIZE] = {0};
    whNvmSize siglen = 0;
    int32_t rc = 0;
    ret = wh_Client_NvmGetMetadata(client,
        sig_nvmId, &rc, NULL, NULL, NULL, &siglen, 0, NULL);
    printf("SecBoot got siglen %d with ret:%d rc:%d\n", siglen, ret, rc);
    ret = wh_Client_NvmRead(client, sig_nvmId, 0, siglen, &rc, NULL, sig);
    hexdump("Signature:", sig, siglen);

    printf("SecBoot Client Verifying signature using keyId %u\n", prov_keyId);
    ecc_key key[1];
    wc_ecc_init_ex(key, NULL, WH_DEV_ID);
    wh_Client_EccSetKeyId(key, prov_keyId);
    ret = wh_Client_EccVerify(  client, key, 
                                sig, siglen, 
                                hash, sizeof(hash), 
                                &rc);
    printf("ecc_verify:%d rc:%d\n", ret, rc);

    /* III The public key is exported to this key during EccVerify */
    (void)wc_ecc_free(key);

    if ((ret == 0) && (rc == 1)) {
        printf("SecBoot Client signature verified successfully!!\n");
    } else {
        printf("SecBoot Client failed with ret:%d and rc:%d\n", ret, rc);
    }

    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    printf("SecBoot Client disconnected\n");
    return ret;
}

static int wh_ClientZeroize(void* cf)
{
    whClientContext client[1];
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;

    if (config == NULL) {
        return -1;
    }

    ret = wh_Client_Init(client, config);
    if (ret != 0) {
        perror("Zeroize Client Init error:");
        return -1;
    }

    printf("Zeroize Client connecting to server...\n");

    uint32_t client_id = 0;
    uint32_t server_id = 0;
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    printf("Connected to server id %u with client id %u: %d\n",
            server_id, client_id, ret);

    wh_Client_ShowNvm(client);

    wh_Client_KeyErase(client, prov_keyId);
    printf("Zeroize Client erased keyId %u :%d\n", prov_keyId, ret);

    int rc = 0;
    wh_Client_NvmDestroyObjects(client,1, &sig_nvmId, &rc);
    printf("Zeroize Client destroyed NVM object %u :%d with rc:%d\n", 
        sig_nvmId, ret, rc);

    wh_Client_ShowNvm(client);

    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);
    printf("Zeroize Client disconnected\n");
    return ret;
}

int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    /* Client configuration/contexts */
    whTransportClientCb pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1] = {};
    posixTransportTcpConfig mytcpconfig[1] = {{
            .server_ip_string = WH_SERVER_TCP_IPSTRING,
            .server_port = WH_SERVER_TCP_PORT,
    }};

    whCommClientConfig cc_conf[1] = {{
            .transport_cb = pttccb,
            .transport_context = (void*)tcc,
            .transport_config = (void*)mytcpconfig,
            .client_id = WH_CLIENT_ID,
    }};
    whClientConfig c_conf[1] = {{
            .comm = cc_conf,
    }};

    char* execname = basename(argv[0]);
    if (strcmp(execname, "wh_client_provision.elf") == 0) {
        return wh_ClientProvision(c_conf);
    } else if(strcmp(execname, "wh_client_secboot.elf") == 0) {
        return wh_ClientSecBoot(c_conf);
    } else if(strcmp(execname, "wh_client_zeroize.elf") == 0) {
        return wh_ClientZeroize(c_conf);
    } else {
        return wh_ClientTask(c_conf);
    }
}