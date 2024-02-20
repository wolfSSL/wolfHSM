/*
 * src/wh_message_comm.c
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wolfhsm/wh_comm.h>
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_message.h>

#include <wolfhsm/wh_message_comm.h>

int wh_MessageComm_TranslateInitRequest(uint16_t magic,
        const whMessageCommInitRequest* src,
        whMessageCommInitRequest* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    dest->client_id = wh_Translate32(magic, src->client_id);
    return 0;
}

int wh_MessageComm_TranslateInitResponse(uint16_t magic,
        const whMessageCommInitResponse* src,
        whMessageCommInitResponse* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    dest->client_id = wh_Translate32(magic, src->client_id);
    dest->server_id = wh_Translate32(magic, src->server_id);
    return 0;
}

int wh_MessageComm_TranslateLenData(uint16_t magic,
        const whMessageCommLenData* src,
        whMessageCommLenData* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    dest->len = wh_Translate16(magic, src->len);
    /* III Note that we can't use src->len to minimize this copy */
    memcpy(dest->data, src->data, sizeof(dest->data));
    return 0;
}

