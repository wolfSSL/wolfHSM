
.PHONY: all test benchmark tools examples clean

all: test benchmark tools examples

test:
	make -C test

benchmark:
	make -C benchmark

tools:
	make -C tools

examples:
	make -C examples

clean:
	make -C test clean
	make -C benchmark clean
	make -C tools clean
	make -C examples clean
