#ifndef WH_POSIX_SERVER_CFG_H
#define WH_POSIX_SERVER_CFG_H

#include <stdint.h>

int wh_PosixServer_ExampleShmDmaConfig(void* s_conf);
int wh_PosixServer_ExampleShmConfig(void* s_conf);
int wh_PosixServer_ExampleTcpConfig(void* s_conf);
int wh_PosixServer_ExampleNvmConfig(void* conf, const char* nvmInitFilePath);
int wh_PosixServer_ExampleRamSimConfig(void* conf, uint8_t* memory);

#endif /* WH_POSIX_SERVER_CFG_H */