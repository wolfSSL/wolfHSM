#ifndef WH_POSIX_CLIENT_CFG_H
#define WH_POSIX_CLIENT_CFG_H

int wh_PosixClient_ExampleShmDmaConfig(void* c_conf);
int wh_PosixClient_ExampleShmConfig(void* c_conf);
int wh_PosixClient_ExampleTcpConfig(void* c_conf);
#ifdef WOLFHSM_CFG_TLS
int wh_PosixClient_ExampleTlsConfig(void* c_conf);
#if !defined(NO_PSK)
int wh_PosixClient_ExamplePskConfig(void* c_conf);
#endif /* !NO_PSK */
#endif /* WOLFHSM_CFG_TLS */
int wh_PosixClient_ExampleSetupDmaMemory(void* ctx, void* c_conf);
#endif /* WH_POSIX_CLIENT_CFG_H */
