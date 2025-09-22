#ifndef WH_POSIX_SERVER_CFG_H
#define WH_POSIX_SERVER_CFG_H

#include <stdint.h>

int wh_PosixServer_ExampleDMAConfig(void* s_conf);
int wh_PosixServer_ExampleSHMConfig(void* s_conf);
int wh_PosixServer_ExampleTCPConfig(void* s_conf);
int wh_PosixServer_ExampleNVMConfig(void* conf, const char* nvmInitFilePath);
int wh_PosixServer_ExampleRAMSimConfig(void* conf, uint8_t* memory);

#endif /* WH_POSIX_SERVER_CFG_H */