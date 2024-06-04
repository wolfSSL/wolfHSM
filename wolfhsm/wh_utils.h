#ifndef WH_UTILS_H_
#define WH_UTILS_H_

#include <stdint.h>

uint32_t wh_Utils_htonl(uint32_t hostlong);
uint32_t wh_Utils_ntohl(uint32_t networklong);

int wh_Utils_memeqzero(uint8_t* buffer, uint32_t size);



#endif /* WH_UTILS_H_ */
