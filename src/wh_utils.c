#include "wolfhsm/wh_utils.h"

static int isLittleEndian() {
    unsigned int x = 1; /* 0x00000001 */
    char *c = (char*)&x;
    return (int)*c;
}

/* Converts a 32-bit value from host to network byte order */
uint32_t wh_Utils_htonl(uint32_t hostlong) {
    if (isLittleEndian()) {
        return ((hostlong & 0x000000FF) << 24) | ((hostlong & 0x0000FF00) << 8)
            | ((hostlong & 0x00FF0000) >> 8) | ((hostlong & 0xFF000000) >> 24);
    }
    return hostlong; /* No conversion needed if not little endian */
}

uint32_t wh_Utils_ntohl(uint32_t networklong) {
    /* same operation */
    return wh_Utils_htonl(networklong);
}


int wh_Utils_memeqzero(uint8_t* buffer, uint32_t size)
{
    while (size > 1) {
        size--;
        if (buffer[size] != 0)
            return 0;
    }
    return 1;
}
