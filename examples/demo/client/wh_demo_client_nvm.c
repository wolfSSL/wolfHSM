#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_demo_client_nvm.h"

/**
  * @brief Demonstrates use of client NVM API

  * @param clientContext an initialized client context
  * @return 0 on success, error code on failure
 */
int wh_DemoClient_Nvm(whClientContext* clientContext)
{
    const int NUM_OBJECTS = 3;

    int32_t  rc;
    int32_t  serverRc;
    uint32_t availSize;
    uint32_t reclaimSize;
    whNvmId  availObjects;
    whNvmId  reclaimObjects;

    whNvmId   objectIds[] = {1, 2, 3};
    uint8_t   labels[][6] = {"label1", "label2", "label3"};
    uint8_t   data[][6]   = {"data1", "data2", "data3"};
    uint8_t   readData[6];
    whNvmSize dataLen = 6;
    whNvmSize readLen;

    if (clientContext == NULL) {
        printf("Client context is NULL\n");
        return WH_ERROR_BADARGS;
    }

    /* Initialize NVM */
    rc = wh_Client_NvmInit(clientContext, &serverRc, NULL, NULL);
    if (rc != 0 || serverRc != 0) {
        printf("NVM Init failed with error code: %d, server error code: %d\n",
               rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("NVM Initialized successfully\n");

    /* Add multiple objects, reading back each one and comparing the data
     * against what we wrote */
    for (int i = 0; i < NUM_OBJECTS; i++) {
        /* Add an object */
        rc = wh_Client_NvmAddObject(clientContext, objectIds[i],
                                    WH_NVM_ACCESS_ANY,
                                    WH_NVM_FLAGS_ANY, sizeof(labels[i]),
                                    labels[i], dataLen, data[i], &serverRc);
        if (rc != 0 || serverRc != 0) {
            printf("Add Object %d failed with error code: %d, server error "
                   "code: %d\n",
                   objectIds[i], rc, serverRc);
            return (rc != 0) ? rc : serverRc;
        }
        printf("Object %d added successfully\n", objectIds[i]);

        /* Read the object data */
        rc = wh_Client_NvmRead(clientContext, objectIds[i], 0, dataLen,
                               &serverRc, &readLen, readData);
        if (rc != 0 || serverRc != 0) {
            printf("Read Object %d failed with error code: %d, server error "
                   "code: %d\n",
                   objectIds[i], rc, serverRc);
            return (rc != 0) ? rc : serverRc;
        }
        printf("Object %d read successfully: Data=%s\n", objectIds[i],
               readData);

        /* Ensure data we read matches data we wrote */
        if (memcmp(data[i], readData, dataLen) != 0) {
            printf("Readback check failed for Object %d: Data read does not "
                   "match data written\n",
                   objectIds[i]);
            return WH_ERROR_ABORTED;
        }
        printf("Readback check passed for Object %d: Data read matches data "
               "written\n",
               objectIds[i]);
    }

    /* Get available objects */
    rc =
        wh_Client_NvmGetAvailable(clientContext, &serverRc, &availSize,
                                  &availObjects, &reclaimSize, &reclaimObjects);
    if (rc != 0 || serverRc != 0) {
        printf("Get Available Objects failed with error code: %d, server error "
               "code: %d\n",
               rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("Available Objects retrieved successfully: Available Size=%d, "
           "Available Objects=%d, Reclaim Size=%d, Reclaim Objects=%d\n",
           availSize, availObjects, reclaimSize, reclaimObjects);

    /* Delete one object */
    rc = wh_Client_NvmDestroyObjects(clientContext, 1, objectIds, &serverRc);
    if (rc != 0 || serverRc != 0) {
        printf("Delete Objects failed with error code: %d, server error code: "
               "%d\n",
               rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("Objects deleted successfully\n");

    /* Delete multiple objects */
    rc = wh_Client_NvmDestroyObjects(clientContext, NUM_OBJECTS - 1,
                                     &objectIds[1], &serverRc);
    if (rc != 0 || serverRc != 0) {
        printf("Delete Objects failed with error code: %d, server error code: "
               "%d\n",
               rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("Objects deleted successfully\n");

    /* Reclaim space */
    rc =
        wh_Client_NvmDestroyObjects(clientContext, 0, NULL, &serverRc);
    if (rc != 0 || serverRc != 0) {
        printf("Reclaim Objects failed with error code: %d, server error code: "
               "%d\n",
               rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("Reclaimed space successfully\n");

    /* Cleanup NVM */
    rc = wh_Client_NvmCleanup(clientContext, &serverRc);
    if (rc != 0 || serverRc != 0) {
        printf(
            "NVM Cleanup failed with error code: %d, server error code: %d\n",
            rc, serverRc);
        return (rc != 0) ? rc : serverRc;
    }
    printf("NVM Cleaned up successfully\n");

    return 0;
}
