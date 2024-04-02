#include <stddef.h>

#include "wolfhsm/wh_message_custom.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"


int wh_MessageCustom_TranslateRequest(uint16_t                       magic,
                                      const whMessageCustom_Request* src,
                                      whMessageCustom_Request*       dst)
{
    if ((src == NULL) || (dst == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dst->id = wh_Translate16(magic, src->id);

    return WH_ERROR_OK;
}

int wh_MessageCustom_TranslateResponse(uint16_t                        magic,
                                       const whMessageCustom_Response* src,
                                       whMessageCustom_Response*       dst)
{
    if ((src == NULL) || (dst == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dst->rc  = wh_Translate32(magic, src->rc);
    dst->err = wh_Translate32(magic, src->err);

    return WH_ERROR_OK;
}