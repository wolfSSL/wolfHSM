#ifndef WH_POSIX_SERVER_CFG_H
#define WH_POSIX_SERVER_CFG_H

#include <stdint.h>

int Server_ExampleDMAConfig(void* s_conf);
int Server_ExampleSHMConfig(void* s_conf);
int Server_ExampleTCPConfig(void* s_conf);
int Server_ExampleNVMConfig(void* conf, const char* nvmInitFilePath);
int Server_ExampleRAMSimConfig(void* conf, uint8_t* memory);

#endif /* WH_POSIX_SERVER_CFG_H */