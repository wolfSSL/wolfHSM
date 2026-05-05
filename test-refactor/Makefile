## Top-level forwarder for the test-refactor suite.
## Delegates to the POSIX port Makefile so tests can be run with
## `cd test-refactor && make check` instead of navigating into posix/.

.DEFAULT_GOAL := check

.PHONY: check run build_app clean

check run build_app clean:
	$(MAKE) -C posix $@
