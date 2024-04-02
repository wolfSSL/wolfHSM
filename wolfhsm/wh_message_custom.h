#ifndef WH_MESSAGE_CUSTOM_H_
#define WH_MESSAGE_CUSTOM_H_

#include <stdint.h>

#define WH_MESSAGE_CUSTOM_BUF_SIZE (256)

/* Type indicator for custom request/response messages. Indicates how
 * to interpret whMessageCustomData */
typedef enum {
    /* message types reserved for internal usage*/
    WH_MESSAGE_CUSTOM_TYPE_QUERY      = 0,
    WH_MESSAGE_CUSTOM_TYPE_DMA32      = 1,
    WH_MESSAGE_CUSTOM_TYPE_DMA64      = 2,
    WH_MESSAGE_CUSTOM_TYPE_RESERVED_3 = 3,
    WH_MESSAGE_CUSTOM_TYPE_RESERVED_4 = 4,
    WH_MESSAGE_CUSTOM_TYPE_RESERVED_5 = 5,
    WH_MESSAGE_CUSTOM_TYPE_RESERVED_6 = 6,
    WH_MESSAGE_CUSTOM_TYPE_RESERVED_7 = 7,
    /* User-defined types start from here, up to UINT32_MAX */
    WH_MESSAGE_CUSTOM_TYPE_USER_DEFINED_START = 8,
} whMessageCustom_Type;


/* union providing some helpful abstractions for passing pointers in/out of
 * custom callbacks on top of a raw data buffer */
typedef union {
    /* pointer/size pairs for 32-bit systems */
    struct {
        uint32_t client_addr;
        uint32_t client_sz;
        uint32_t server_addr;
        uint32_t server_sz;
    } dma32;
    /* pointer/size pairs for 64-bit systems */
    struct {
        uint64_t client_addr;
        uint64_t client_sz;
        uint64_t server_addr;
        uint64_t server_sz;
    } dma64;
    /* raw data buffer for user-defined schema */
    struct {
        uint8_t data[WH_MESSAGE_CUSTOM_BUF_SIZE];
    } buffer;
} whMessageCustom_Data;

/* request message to the custom server callback */
typedef struct {
    uint16_t             id;   /* indentifier of registered callback  */
    uint32_t             type; /* whMessageCustom_Type */
    whMessageCustom_Data data;
} whMessageCustom_Request;

/* response message from the custom server callback */
typedef struct {
    uint16_t id;   /* indentifier of registered callback  */
    uint32_t type; /* whMessageCustom_Type */
    int32_t  rc;   /* Return code from custom callback. Invalid if err != 0 */
    int32_t  err;  /* wolfHSM-specific error. If err != 0, rc is invalid */
    whMessageCustom_Data data;
} whMessageCustom_Response;


/* Translates a custom request message. The whMessageCustom_Request.data field
 * will not be translated for whMessageCustom_Request.type values greater than
 * WH_MESSAGE_CUSTOM_TYPE_USER_DEFINED_START */
int wh_MessageCustom_TranslateRequest(uint16_t                       magic,
                                      const whMessageCustom_Request* src,
                                      whMessageCustom_Request*       dst);

/* Translates a custom response message. The whMessageCustom_Request.data field
 * will not be translated for whMessageCustom_Request.type values greater than
 * WH_MESSAGE_CUSTOM_TYPE_USER_DEFINED_START */
int wh_MessageCustom_TranslateResponse(uint16_t                        magic,
                                       const whMessageCustom_Response* src,
                                       whMessageCustom_Response*       dst);

#endif /* WH_MESSAGE_CUSTOM_H_*/