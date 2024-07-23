# Testing

wolfHSM unit tests need to be portable and platform-agnostic (e.g. no system dependencies) such that they are  able to run on a bare-metal system.
One notable exception is for tests that use the POSIX API (sockets, pthreads, etc.), which must be conditionally compiled in with the `WOLFHSM_CFG_TEST_POSIX` preprocessor macro.

##  Running Tests
Tests for each module should be defined in their own source file and export their API in a corresponding header. Tests are run by the main test driver in `wh_test.c`.
Embedded systems that wish to only compile and run a subset of the tests should be able to pick and choose individual tests from their respective files and run them
without needing to run the entire test suite.

To build and run the tests on a `*nix` system, simply run:

```
make run
```

This will run all tests, including the POSIX tests
