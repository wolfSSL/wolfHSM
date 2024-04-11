#ifndef WH_TEST_CLIENTSERVER_H_
#define WH_TEST_CLIENTSERVER_H_

/*
 * Runs the client/server async tests in a single thread using a memory
 * transport backend.
 *
 * Multithreaded tests are also run if WH_CFG_TEST_POSIX is defined.
 * Returns 0 on success and a non-zero error code on failure
 */
int whTest_ClientServer(void);
int whTest_ClientCfg(whClientConfig* clientCfg);
int whTest_ServerCfgLoop(whServerConfig* serverCfg);

#endif /* WH_TEST_CLIENTSERVER_H_ */
