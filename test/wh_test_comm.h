
/*
 * Runs the comms tests using a memory transport backend.
 * Returns 0 on success and a non-zero error code on failure
 */
int whTest_CommMem(void);

/* Runs all the comms tests using a memory transport as the backend, and
 * optionally using the POSIX TCP backend if WH_CFG_TEST_POSIX is defined.
 *
 * Multithreaded tests are also run if WH_CFG_TEST_POSIX is defined.
 *
 * Returns 0 on success and a non-zero error code on failure
 */
int whTest_Comm(void);
