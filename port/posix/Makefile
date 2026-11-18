## Makefile for building the generic wolfHSM client and server
## using the POSIX port implementation.

.PHONY: all client server clean

all: client server

client:
	$(MAKE) -C client build_app

server:
	$(MAKE) -C server build_app

clean:
	$(MAKE) -C client clean
	$(MAKE) -C server clean
