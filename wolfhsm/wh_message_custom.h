#ifndef WH_MESSAGE_CUSTOM_H_
#define WH_MESSAGE_CUSTOM_H_

#include <stdint.h>

typedef struct {
    uint16_t id;
    /* TODO: pass I/O pointers and sizes? Mimic NVM DMA request? */
} whMessageCustom_Request;

typedef struct {
    int32_t rc;  /* Return code from custom callback */
    int32_t err; /* wolfHSM-specific error */
} whMessageCustom_Response;


int wh_MessageCustom_TranslateRequest(uint16_t                       magic,
                                      const whMessageCustom_Request* src,
                                      whMessageCustom_Request*       dst);

int wh_MessageCustom_TranslateResponse(uint16_t                        magic,
                                       const whMessageCustom_Response* src,
                                       whMessageCustom_Response*       dst);

#endif /* WH_MESSAGE_CUSTOM_H_*/